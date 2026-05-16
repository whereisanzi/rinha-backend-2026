use std::mem;
use std::os::unix::io::{AsRawFd, RawFd};
use std::ptr;

use io_uring::{IoUring, opcode, types};

use crate::DIM;
use crate::ctrl;
use crate::dataset::Dataset;
use crate::http::{self, Parsed};
use crate::{ivf, json, responses, vectorizer};

const REQ_BUF_SIZE: usize = 4096;
const RING_QD: u32 = 4096;
const MAX_CONNS: usize = 1024;
const PREWARM_ITERS: usize = 200;

const OP_RECVMSG: u8 = 1;
const OP_RECV: u8 = 2;
const OP_SEND: u8 = 3;

const GEN_MASK: u64 = 0x00ff_ffff;
const GEN_SHIFT: u32 = 32;
const SLOT_MASK: u64 = 0xffff_ffff;
const OP_SHIFT: u32 = 56;

const CTRL_SLOT: u32 = 0;

#[inline(always)]
fn pack(op: u8, generation: u32, slot: u32) -> u64 {
    ((op as u64) << OP_SHIFT)
        | (((generation as u64) & GEN_MASK) << GEN_SHIFT)
        | ((slot as u64) & SLOT_MASK)
}
#[inline(always)]
fn unpack_op(u: u64) -> u8 {
    (u >> OP_SHIFT) as u8
}
#[inline(always)]
fn unpack_gen(u: u64) -> u32 {
    ((u >> GEN_SHIFT) & GEN_MASK) as u32
}
#[inline(always)]
fn unpack_slot(u: u64) -> u32 {
    (u & SLOT_MASK) as u32
}

struct Conn {
    fd: RawFd,
    generation: u32,
    req_buf: Vec<u8>,
    req_len: usize,
    out_data: &'static [u8],
    out_sent: usize,
    close_after: bool,
}

impl Conn {
    fn new() -> Self {
        Self {
            fd: -1,
            generation: 0,
            req_buf: vec![0u8; REQ_BUF_SIZE],
            req_len: 0,
            out_data: b"",
            out_sent: 0,
            close_after: false,
        }
    }
    fn reset_state(&mut self) {
        self.req_len = 0;
        self.out_data = b"";
        self.out_sent = 0;
        self.close_after = false;
    }
}

#[repr(C)]
struct CtrlState {
    fd: RawFd,
    payload: u8,
    iov: libc::iovec,
    msg: libc::msghdr,
    cmsg_buf: [u8; 64],
}

impl CtrlState {
    fn new(fd: RawFd) -> Self {
        Self {
            fd,
            payload: 0,
            iov: libc::iovec {
                iov_base: ptr::null_mut(),
                iov_len: 0,
            },
            msg: unsafe { mem::zeroed() },
            cmsg_buf: [0u8; 64],
        }
    }

    fn prepare(&mut self) {
        self.iov.iov_base = &mut self.payload as *mut _ as *mut libc::c_void;
        self.iov.iov_len = 1;
        self.msg.msg_name = ptr::null_mut();
        self.msg.msg_namelen = 0;
        self.msg.msg_iov = &mut self.iov as *mut _;
        self.msg.msg_iovlen = 1;
        self.msg.msg_control = self.cmsg_buf.as_mut_ptr() as *mut libc::c_void;
        self.msg.msg_controllen = self.cmsg_buf.len() as _;
        self.msg.msg_flags = 0;
    }
}

pub struct Config {
    pub uds_path: String,
    pub uds_mode: u32,
    pub nprobe: usize,
    pub backlog: i32,
}

pub fn run(cfg: Config, ds: &'static Dataset) -> std::io::Result<()> {
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }

    let ctrl_path = format!("{}.ctrl", cfg.uds_path);
    let t0 = std::time::Instant::now();
    let listener = ctrl::bind_ctrl_listener(&ctrl_path, cfg.uds_mode)?;
    eprintln!("api ctrl bind: {:?} (path={})", t0.elapsed(), ctrl_path);

    let nprobe = cfg.nprobe;
    std::thread::Builder::new()
        .name("prewarm".into())
        .spawn(move || {
            let t = std::time::Instant::now();
            prewarm(ds, nprobe);
            eprintln!("api prewarm (bg): {:?}", t.elapsed());
        })
        .expect("spawn prewarm");

    let t2 = std::time::Instant::now();
    let (ctrl_conn, _addr) = listener.accept()?;
    let ctrl_fd = ctrl_conn.as_raw_fd();
    eprintln!("api ctrl accept: {:?} (fd={})", t2.elapsed(), ctrl_fd);
    std::mem::forget(ctrl_conn);

    eprintln!(
        "api listening on ctrl={} (qd={}, nprobe={}, scm_rights handoff)",
        ctrl_path, RING_QD, cfg.nprobe
    );

    let _ = cfg.backlog;

    let mut ring: IoUring = IoUring::builder()
        .setup_single_issuer()
        .setup_coop_taskrun()
        .build(RING_QD)?;

    let mut conns: Vec<Conn> = (0..MAX_CONNS).map(|_| Conn::new()).collect();
    let mut free_slots: Vec<u32> = (1..=MAX_CONNS as u32).rev().collect();

    let mut ctrl_state = Box::new(CtrlState::new(ctrl_fd));
    push_recvmsg(&mut ring, &mut ctrl_state);

    let mut cqes: Vec<io_uring::cqueue::Entry> = Vec::with_capacity(RING_QD as usize);

    loop {
        ring.submit_and_wait(1)?;

        cqes.clear();
        cqes.extend(ring.completion());
        for cqe in cqes.drain(..) {
            let ud = cqe.user_data();
            let res = cqe.result();
            match unpack_op(ud) {
                OP_RECVMSG => {
                    handle_recvmsg(
                        &mut ring,
                        res,
                        &mut ctrl_state,
                        &mut conns,
                        &mut free_slots,
                    );
                }
                OP_RECV => {
                    let slot = unpack_slot(ud) as usize;
                    let gen_id = unpack_gen(ud);
                    if conns[slot - 1].generation == gen_id {
                        handle_recv(
                            &mut ring,
                            slot,
                            res,
                            &mut conns,
                            &mut free_slots,
                            ds,
                            cfg.nprobe,
                        );
                    }
                }
                OP_SEND => {
                    let slot = unpack_slot(ud) as usize;
                    let gen_id = unpack_gen(ud);
                    if conns[slot - 1].generation == gen_id {
                        handle_send(
                            &mut ring,
                            slot,
                            res,
                            &mut conns,
                            &mut free_slots,
                            ds,
                            cfg.nprobe,
                        );
                    }
                }
                _ => {}
            }
        }
    }
}

fn prewarm(ds: &'static Dataset, nprobe: usize) {
    let legit = br#"{"id":"x","transaction":{"amount":41.12,"installments":2,"requested_at":"2026-03-11T18:45:53Z"},"customer":{"avg_amount":82.24,"tx_count_24h":3,"known_merchants":["MERC-016"]},"merchant":{"id":"MERC-016","mcc":"5411","avg_amount":60.25},"terminal":{"is_online":false,"card_present":true,"km_from_home":29.23},"last_transaction":null}"#;
    let fraud = br#"{"id":"x","transaction":{"amount":9505.97,"installments":10,"requested_at":"2026-03-14T05:15:12Z"},"customer":{"avg_amount":81.28,"tx_count_24h":20,"known_merchants":["MERC-A"]},"merchant":{"id":"MERC-068","mcc":"7802","avg_amount":54.86},"terminal":{"is_online":false,"card_present":true,"km_from_home":952.27},"last_transaction":null}"#;

    let q_legit: [f32; DIM] = vectorizer::vectorize(&json::parse(legit).expect("prewarm parse legit"));
    let q_fraud: [f32; DIM] = vectorizer::vectorize(&json::parse(fraud).expect("prewarm parse fraud"));

    let t = std::time::Instant::now();
    for i in 0..PREWARM_ITERS {
        let q = if i % 2 == 0 { &q_legit } else { &q_fraud };
        let _ = std::hint::black_box(ivf::search_fraud_count(q, ds, nprobe));
    }
    eprintln!(
        "prewarm: {} iters in {:?} (avg {:?}/it)",
        PREWARM_ITERS,
        t.elapsed(),
        t.elapsed() / PREWARM_ITERS as u32
    );
}

fn push_sqe(ring: &mut IoUring, entry: io_uring::squeue::Entry) {
    loop {
        let r = unsafe { ring.submission().push(&entry) };
        if r.is_ok() {
            return;
        }
        ring.submit().expect("submit");
    }
}

fn push_recvmsg(ring: &mut IoUring, ctrl_state: &mut CtrlState) {
    ctrl_state.prepare();
    let entry = opcode::RecvMsg::new(
        types::Fd(ctrl_state.fd),
        &mut ctrl_state.msg as *mut _,
    )
    .build()
    .user_data(pack(OP_RECVMSG, 0, CTRL_SLOT));
    push_sqe(ring, entry);
}

fn handle_recvmsg(
    ring: &mut IoUring,
    res: i32,
    ctrl_state: &mut CtrlState,
    conns: &mut [Conn],
    free_slots: &mut Vec<u32>,
) {
    if res <= 0 {
        eprintln!("ctrl recvmsg returned {} — re-arming", res);
        push_recvmsg(ring, ctrl_state);
        return;
    }

    let fd = unsafe { ctrl::extract_fd(&ctrl_state.msg) };
    push_recvmsg(ring, ctrl_state);

    let client_fd = match fd {
        Some(f) if f >= 0 => f,
        _ => return,
    };

    adopt_fd(client_fd, ring, conns, free_slots);
}

fn adopt_fd(fd: RawFd, ring: &mut IoUring, conns: &mut [Conn], free_slots: &mut Vec<u32>) {
    let slot = match free_slots.pop() {
        Some(s) => s as usize,
        None => {
            unsafe {
                libc::close(fd);
            }
            return;
        }
    };
    let conn = &mut conns[slot - 1];
    conn.fd = fd;
    conn.generation = conn.generation.wrapping_add(1) & (GEN_MASK as u32);
    conn.reset_state();
    push_recv(ring, slot as u32, conn);
}

fn push_recv(ring: &mut IoUring, slot: u32, conn: &mut Conn) {
    let buf_ptr = unsafe { conn.req_buf.as_mut_ptr().add(conn.req_len) };
    let buf_len = (REQ_BUF_SIZE - conn.req_len) as u32;
    let entry = opcode::Recv::new(types::Fd(conn.fd), buf_ptr, buf_len)
        .build()
        .user_data(pack(OP_RECV, conn.generation, slot));
    push_sqe(ring, entry);
}

fn push_send(ring: &mut IoUring, slot: u32, conn: &Conn) {
    let buf_ptr = unsafe { conn.out_data.as_ptr().add(conn.out_sent) };
    let buf_len = (conn.out_data.len() - conn.out_sent) as u32;
    let entry = opcode::Send::new(types::Fd(conn.fd), buf_ptr, buf_len)
        .build()
        .user_data(pack(OP_SEND, conn.generation, slot));
    push_sqe(ring, entry);
}

fn close_conn(slot: usize, conns: &mut [Conn], free_slots: &mut Vec<u32>) {
    let c = &mut conns[slot - 1];
    if c.fd >= 0 {
        unsafe {
            libc::close(c.fd);
        }
    }
    c.fd = -1;
    c.generation = c.generation.wrapping_add(1) & (GEN_MASK as u32);
    c.reset_state();
    free_slots.push(slot as u32);
}

fn handle_recv(
    ring: &mut IoUring,
    slot: usize,
    res: i32,
    conns: &mut [Conn],
    free_slots: &mut Vec<u32>,
    ds: &'static Dataset,
    nprobe: usize,
) {
    if conns[slot - 1].fd < 0 {
        return;
    }
    if res <= 0 {
        close_conn(slot, conns, free_slots);
        return;
    }
    conns[slot - 1].req_len += res as usize;
    drive(ring, slot, conns, free_slots, ds, nprobe);
}

fn handle_send(
    ring: &mut IoUring,
    slot: usize,
    res: i32,
    conns: &mut [Conn],
    free_slots: &mut Vec<u32>,
    ds: &'static Dataset,
    nprobe: usize,
) {
    if conns[slot - 1].fd < 0 {
        return;
    }
    if res <= 0 {
        close_conn(slot, conns, free_slots);
        return;
    }
    conns[slot - 1].out_sent += res as usize;
    if conns[slot - 1].out_sent < conns[slot - 1].out_data.len() {
        push_send(ring, slot as u32, &conns[slot - 1]);
        return;
    }
    if conns[slot - 1].close_after {
        close_conn(slot, conns, free_slots);
        return;
    }

    conns[slot - 1].out_data = b"";
    conns[slot - 1].out_sent = 0;
    conns[slot - 1].close_after = false;

    drive(ring, slot, conns, free_slots, ds, nprobe);
}

fn drive(
    ring: &mut IoUring,
    slot: usize,
    conns: &mut [Conn],
    free_slots: &mut Vec<u32>,
    ds: &'static Dataset,
    nprobe: usize,
) {
    let idx = slot - 1;
    if conns[idx].fd < 0 {
        return;
    }

    let parsed = http::parse(&conns[idx].req_buf[..conns[idx].req_len]);
    match parsed {
        Parsed::Incomplete => {
            if conns[idx].req_len >= REQ_BUF_SIZE - 1 {
                push_close_response(ring, slot, conns, responses::RESP_PAYLOAD_TOO_LARGE);
                return;
            }
            push_recv(ring, slot as u32, &mut conns[idx]);
        }
        Parsed::Bad => {
            push_close_response(ring, slot, conns, responses::RESP_BAD_REQUEST);
        }
        Parsed::Ready { consumed } => {
            advance_buf(&mut conns[idx], consumed);
            push_keepalive_response(ring, slot, conns, responses::RESP_READY);
        }
        Parsed::NotFound { consumed } => {
            advance_buf(&mut conns[idx], consumed);
            push_keepalive_response(ring, slot, conns, responses::RESP_NOT_FOUND);
        }
        Parsed::FraudScore {
            body_start,
            body_end,
            consumed,
        } => {
            let frauds_or_bad = {
                let body = &conns[idx].req_buf[body_start..body_end];
                match json::parse(body) {
                    Some(p) => {
                        let q = vectorizer::vectorize(&p);
                        let f = ivf::search_fraud_count(&q, ds, nprobe);
                        Ok(f.min(5) as usize)
                    }
                    None => Err(()),
                }
            };
            advance_buf(&mut conns[idx], consumed);
            match frauds_or_bad {
                Ok(i) => push_keepalive_response(ring, slot, conns, responses::RESP_FRAUD[i]),
                Err(()) => push_close_response(ring, slot, conns, responses::RESP_BAD_REQUEST),
            }
        }
    }
    let _ = free_slots;
}

fn push_keepalive_response(
    ring: &mut IoUring,
    slot: usize,
    conns: &mut [Conn],
    resp: &'static [u8],
) {
    let conn = &mut conns[slot - 1];
    conn.out_data = resp;
    conn.out_sent = 0;
    conn.close_after = false;
    push_send(ring, slot as u32, conn);
}

fn push_close_response(
    ring: &mut IoUring,
    slot: usize,
    conns: &mut [Conn],
    resp: &'static [u8],
) {
    let conn = &mut conns[slot - 1];
    conn.out_data = resp;
    conn.out_sent = 0;
    conn.close_after = true;
    push_send(ring, slot as u32, conn);
}

fn advance_buf(conn: &mut Conn, consumed: usize) {
    if consumed == 0 || conn.req_len == 0 {
        return;
    }
    let consumed = consumed.min(conn.req_len);
    let remaining = conn.req_len - consumed;
    if remaining > 0 {
        conn.req_buf.copy_within(consumed..consumed + remaining, 0);
    }
    conn.req_len = remaining;
}
