use std::ffi::CString;
use std::mem;
use std::os::unix::io::RawFd;
use std::ptr;

use io_uring::{IoUring, opcode, types};

const DEFAULT_PORT: u16 = 9999;
const DEFAULT_BUF_SIZE: usize = 4096;
const DEFAULT_BACKLOG: i32 = 4096;
const MAX_CONNS: usize = 2048;
const RING_QD: u32 = 4096;

const CQE_F_MORE: u32 = 1 << 1;

const OP_ACCEPT: u8 = 1;
const OP_CONNECT: u8 = 2;
const OP_RECV_C: u8 = 3;
const OP_SEND_B: u8 = 4;
const OP_RECV_B: u8 = 5;
const OP_SEND_C: u8 = 6;

const GEN_MASK: u64 = 0x00ff_ffff;
const GEN_SHIFT: u32 = 32;
const SLOT_MASK: u64 = 0xffff_ffff;
const OP_SHIFT: u32 = 56;

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

struct Buffer {
    data: Box<[u8]>,
    off: usize,
    len: usize,
}

impl Buffer {
    fn new(cap: usize) -> Self {
        Self {
            data: vec![0u8; cap].into_boxed_slice(),
            off: 0,
            len: 0,
        }
    }
    fn cap(&self) -> usize {
        self.data.len()
    }
    fn reset(&mut self) {
        self.off = 0;
        self.len = 0;
    }
}

struct Conn {
    in_use: bool,
    generation: u32,
    client_fd: RawFd,
    backend_fd: RawFd,
    upstream_idx: usize,
    c2b: Buffer,
    b2c: Buffer,
}

impl Conn {
    fn new(buf_size: usize) -> Self {
        Self {
            in_use: false,
            generation: 0,
            client_fd: -1,
            backend_fd: -1,
            upstream_idx: 0,
            c2b: Buffer::new(buf_size),
            b2c: Buffer::new(buf_size),
        }
    }
}

struct Upstream {
    addr: libc::sockaddr_un,
    addr_len: libc::socklen_t,
    path: String,
}

pub fn run() -> std::io::Result<()> {
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }

    let port = env_u32("PORT", DEFAULT_PORT as u32) as u16;
    let buf_size = env_usize("BUF_SIZE", DEFAULT_BUF_SIZE).max(512);
    let backlog = env_u32("BACKLOG", DEFAULT_BACKLOG as u32) as i32;
    let upstream_str = std::env::var("UPSTREAMS")
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "UPSTREAMS env required"))?;

    let upstreams = parse_upstreams(&upstream_str)?;
    if upstreams.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "UPSTREAMS empty",
        ));
    }

    let listen_fd = create_listener(port, backlog)?;

    let mut ring: IoUring = IoUring::builder()
        .setup_single_issuer()
        .setup_coop_taskrun()
        .setup_defer_taskrun()
        .setup_taskrun_flag()
        .build(RING_QD)?;

    eprintln!(
        "lb listen=:{} buf={} backlog={} upstreams=[{}] (io_uring qd={})",
        port,
        buf_size,
        backlog,
        upstreams
            .iter()
            .map(|u| u.path.as_str())
            .collect::<Vec<_>>()
            .join(", "),
        RING_QD,
    );

    let mut conns: Vec<Conn> = (0..MAX_CONNS).map(|_| Conn::new(buf_size)).collect();
    let mut free_slots: Vec<u32> = (0..MAX_CONNS as u32).rev().collect();
    let mut rr: usize = 0;

    push_accept(&mut ring, listen_fd);

    let mut cqes: Vec<io_uring::cqueue::Entry> = Vec::with_capacity(RING_QD as usize);

    loop {
        ring.submit_and_wait(1)?;

        cqes.clear();
        cqes.extend(ring.completion());
        for cqe in cqes.drain(..) {
            let ud = cqe.user_data();
            let res = cqe.result();
            let flags = cqe.flags();
            match unpack_op(ud) {
                OP_ACCEPT => {
                    handle_accept(
                        &mut ring,
                        listen_fd,
                        res,
                        flags,
                        &mut conns,
                        &mut free_slots,
                        &upstreams,
                        &mut rr,
                    );
                }
                OP_CONNECT => {
                    let slot = unpack_slot(ud) as usize;
                    let gen_id = unpack_gen(ud);
                    if conns[slot].generation == gen_id {
                        handle_connect(&mut ring, slot, res, &mut conns, &mut free_slots);
                    }
                }
                OP_RECV_C => {
                    let slot = unpack_slot(ud) as usize;
                    let gen_id = unpack_gen(ud);
                    if conns[slot].generation == gen_id {
                        handle_recv_c(&mut ring, slot, res, &mut conns, &mut free_slots);
                    }
                }
                OP_SEND_B => {
                    let slot = unpack_slot(ud) as usize;
                    let gen_id = unpack_gen(ud);
                    if conns[slot].generation == gen_id {
                        handle_send_b(&mut ring, slot, res, &mut conns, &mut free_slots);
                    }
                }
                OP_RECV_B => {
                    let slot = unpack_slot(ud) as usize;
                    let gen_id = unpack_gen(ud);
                    if conns[slot].generation == gen_id {
                        handle_recv_b(&mut ring, slot, res, &mut conns, &mut free_slots);
                    }
                }
                OP_SEND_C => {
                    let slot = unpack_slot(ud) as usize;
                    let gen_id = unpack_gen(ud);
                    if conns[slot].generation == gen_id {
                        handle_send_c(&mut ring, slot, res, &mut conns, &mut free_slots);
                    }
                }
                _ => {}
            }
        }
    }
}

fn handle_accept(
    ring: &mut IoUring,
    listen_fd: RawFd,
    res: i32,
    flags: u32,
    conns: &mut [Conn],
    free_slots: &mut Vec<u32>,
    upstreams: &[Upstream],
    rr: &mut usize,
) {
    if (flags & CQE_F_MORE) == 0 {
        push_accept(ring, listen_fd);
    }
    if res < 0 {
        return;
    }
    let client_fd = res as RawFd;

    set_tcp_nodelay(client_fd);

    let slot = match free_slots.pop() {
        Some(s) => s as usize,
        None => {
            unsafe {
                libc::close(client_fd);
            }
            return;
        }
    };
    let backend_fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if backend_fd < 0 {
        unsafe {
            libc::close(client_fd);
        }
        free_slots.push(slot as u32);
        return;
    }

    let conn = &mut conns[slot];
    conn.in_use = true;
    conn.generation = conn.generation.wrapping_add(1);
    conn.client_fd = client_fd;
    conn.backend_fd = backend_fd;
    conn.c2b.reset();
    conn.b2c.reset();

    let idx = *rr % upstreams.len();
    *rr = rr.wrapping_add(1);
    conn.upstream_idx = idx;

    push_connect(ring, slot, conn.generation, backend_fd, &upstreams[idx]);
}

fn handle_connect(
    ring: &mut IoUring,
    slot: usize,
    res: i32,
    conns: &mut [Conn],
    free_slots: &mut Vec<u32>,
) {
    if res < 0 {
        close_conn(slot, conns, free_slots);
        return;
    }
    let gen_id = conns[slot].generation;
    push_recv_c(ring, slot, gen_id, conns);
    push_recv_b(ring, slot, gen_id, conns);
}

fn handle_recv_c(
    ring: &mut IoUring,
    slot: usize,
    res: i32,
    conns: &mut [Conn],
    free_slots: &mut Vec<u32>,
) {
    if res <= 0 {
        close_conn(slot, conns, free_slots);
        return;
    }
    let n = res as usize;
    let gen_id = conns[slot].generation;
    let conn = &mut conns[slot];
    conn.c2b.len += n;
    if conn.c2b.len > conn.c2b.off {
        push_send_b(ring, slot, gen_id, conns);
    } else {
        push_recv_c(ring, slot, gen_id, conns);
    }
}

fn handle_send_b(
    ring: &mut IoUring,
    slot: usize,
    res: i32,
    conns: &mut [Conn],
    free_slots: &mut Vec<u32>,
) {
    if res < 0 {
        close_conn(slot, conns, free_slots);
        return;
    }
    let m = res as usize;
    let gen_id = conns[slot].generation;
    let conn = &mut conns[slot];
    conn.c2b.off += m;
    if conn.c2b.off >= conn.c2b.len {
        conn.c2b.reset();
        push_recv_c(ring, slot, gen_id, conns);
    } else {
        push_send_b(ring, slot, gen_id, conns);
    }
}

fn handle_recv_b(
    ring: &mut IoUring,
    slot: usize,
    res: i32,
    conns: &mut [Conn],
    free_slots: &mut Vec<u32>,
) {
    if res <= 0 {
        close_conn(slot, conns, free_slots);
        return;
    }
    let n = res as usize;
    let gen_id = conns[slot].generation;
    let conn = &mut conns[slot];
    conn.b2c.len += n;
    if conn.b2c.len > conn.b2c.off {
        push_send_c(ring, slot, gen_id, conns);
    } else {
        push_recv_b(ring, slot, gen_id, conns);
    }
}

fn handle_send_c(
    ring: &mut IoUring,
    slot: usize,
    res: i32,
    conns: &mut [Conn],
    free_slots: &mut Vec<u32>,
) {
    if res < 0 {
        close_conn(slot, conns, free_slots);
        return;
    }
    let m = res as usize;
    let gen_id = conns[slot].generation;
    let conn = &mut conns[slot];
    conn.b2c.off += m;
    if conn.b2c.off >= conn.b2c.len {
        conn.b2c.reset();
        push_recv_b(ring, slot, gen_id, conns);
    } else {
        push_send_c(ring, slot, gen_id, conns);
    }
}

fn close_conn(slot: usize, conns: &mut [Conn], free_slots: &mut Vec<u32>) {
    let conn = &mut conns[slot];
    if !conn.in_use {
        return;
    }
    if conn.client_fd >= 0 {
        unsafe {
            libc::close(conn.client_fd);
        }
        conn.client_fd = -1;
    }
    if conn.backend_fd >= 0 {
        unsafe {
            libc::close(conn.backend_fd);
        }
        conn.backend_fd = -1;
    }
    conn.in_use = false;
    conn.c2b.reset();
    conn.b2c.reset();
    free_slots.push(slot as u32);
}

fn push_accept(ring: &mut IoUring, listen_fd: RawFd) {
    let sqe = opcode::AcceptMulti::new(types::Fd(listen_fd))
        .build()
        .user_data(pack(OP_ACCEPT, 0, 0));
    push_sqe(ring, sqe);
}

fn push_connect(
    ring: &mut IoUring,
    slot: usize,
    gen_id: u32,
    fd: RawFd,
    up: &Upstream,
) {
    let sqe = opcode::Connect::new(
        types::Fd(fd),
        &up.addr as *const _ as *const libc::sockaddr,
        up.addr_len,
    )
    .build()
    .user_data(pack(OP_CONNECT, gen_id, slot as u32));
    push_sqe(ring, sqe);
}

fn push_recv_c(ring: &mut IoUring, slot: usize, gen_id: u32, conns: &mut [Conn]) {
    let conn = &mut conns[slot];
    if conn.client_fd < 0 {
        return;
    }
    let cap = conn.c2b.cap();
    if conn.c2b.len >= cap {
        return;
    }
    let ptr = unsafe { conn.c2b.data.as_mut_ptr().add(conn.c2b.len) };
    let len = (cap - conn.c2b.len) as u32;
    let sqe = opcode::Recv::new(types::Fd(conn.client_fd), ptr, len)
        .build()
        .user_data(pack(OP_RECV_C, gen_id, slot as u32));
    push_sqe(ring, sqe);
}

fn push_recv_b(ring: &mut IoUring, slot: usize, gen_id: u32, conns: &mut [Conn]) {
    let conn = &mut conns[slot];
    if conn.backend_fd < 0 {
        return;
    }
    let cap = conn.b2c.cap();
    if conn.b2c.len >= cap {
        return;
    }
    let ptr = unsafe { conn.b2c.data.as_mut_ptr().add(conn.b2c.len) };
    let len = (cap - conn.b2c.len) as u32;
    let sqe = opcode::Recv::new(types::Fd(conn.backend_fd), ptr, len)
        .build()
        .user_data(pack(OP_RECV_B, gen_id, slot as u32));
    push_sqe(ring, sqe);
}

fn push_send_b(ring: &mut IoUring, slot: usize, gen_id: u32, conns: &mut [Conn]) {
    let conn = &mut conns[slot];
    if conn.backend_fd < 0 {
        return;
    }
    if conn.c2b.off >= conn.c2b.len {
        return;
    }
    let ptr = unsafe { conn.c2b.data.as_ptr().add(conn.c2b.off) };
    let len = (conn.c2b.len - conn.c2b.off) as u32;
    let sqe = opcode::Send::new(types::Fd(conn.backend_fd), ptr, len)
        .build()
        .user_data(pack(OP_SEND_B, gen_id, slot as u32));
    push_sqe(ring, sqe);
}

fn push_send_c(ring: &mut IoUring, slot: usize, gen_id: u32, conns: &mut [Conn]) {
    let conn = &mut conns[slot];
    if conn.client_fd < 0 {
        return;
    }
    if conn.b2c.off >= conn.b2c.len {
        return;
    }
    let ptr = unsafe { conn.b2c.data.as_ptr().add(conn.b2c.off) };
    let len = (conn.b2c.len - conn.b2c.off) as u32;
    let sqe = opcode::Send::new(types::Fd(conn.client_fd), ptr, len)
        .build()
        .user_data(pack(OP_SEND_C, gen_id, slot as u32));
    push_sqe(ring, sqe);
}

fn push_sqe(ring: &mut IoUring, sqe: io_uring::squeue::Entry) {
    loop {
        unsafe {
            if ring.submission().push(&sqe).is_ok() {
                return;
            }
        }
        let _ = ring.submit();
    }
}

fn create_listener(port: u16, backlog: i32) -> std::io::Result<RawFd> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let one: libc::c_int = 1;
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &one as *const _ as *const libc::c_void,
            mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEPORT,
            &one as *const _ as *const libc::c_void,
            mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }

    let mut addr: libc::sockaddr_in = unsafe { mem::zeroed() };
    addr.sin_family = libc::AF_INET as libc::sa_family_t;
    addr.sin_port = port.to_be();
    addr.sin_addr.s_addr = libc::INADDR_ANY.to_be();
    let rc = unsafe {
        libc::bind(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        let err = std::io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        return Err(err);
    }
    let rc = unsafe { libc::listen(fd, backlog) };
    if rc < 0 {
        let err = std::io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        return Err(err);
    }
    Ok(fd)
}

fn set_tcp_nodelay(fd: RawFd) {
    let one: libc::c_int = 1;
    unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_NODELAY,
            &one as *const _ as *const libc::c_void,
            mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
}

fn parse_upstreams(s: &str) -> std::io::Result<Vec<Upstream>> {
    let mut out = Vec::new();
    for part in s.split(',') {
        let p = part.trim();
        if p.is_empty() {
            continue;
        }
        let mut addr: libc::sockaddr_un = unsafe { mem::zeroed() };
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
        let cstr = CString::new(p)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid path"))?;
        let bytes = cstr.as_bytes_with_nul();
        if bytes.len() > addr.sun_path.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "uds path too long",
            ));
        }
        unsafe {
            ptr::copy_nonoverlapping(
                bytes.as_ptr() as *const libc::c_char,
                addr.sun_path.as_mut_ptr(),
                bytes.len(),
            );
        }
        let addr_len =
            (mem::size_of::<libc::sa_family_t>() + bytes.len() - 1) as libc::socklen_t;
        out.push(Upstream {
            addr,
            addr_len,
            path: p.to_string(),
        });
    }
    Ok(out)
}

fn env_u32(name: &str, default: u32) -> u32 {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}
