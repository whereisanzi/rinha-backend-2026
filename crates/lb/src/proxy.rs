use std::ffi::CString;
use std::mem;
use std::os::unix::io::RawFd;
use std::ptr;

use io_uring::{IoUring, opcode, types};

const DEFAULT_PORT: u16 = 9999;
const DEFAULT_BACKLOG: i32 = 4096;
const MAX_HANDOFFS: usize = 4096;
const RING_QD: u32 = 4096;
const CONNECT_RETRY_MS: u64 = 50;

const CQE_F_MORE: u32 = 1 << 1;

const OP_ACCEPT: u8 = 1;
const OP_SENDMSG: u8 = 2;

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

#[repr(C)]
struct Handoff {
    in_use: bool,
    generation: u32,
    client_fd: RawFd,
    payload: u8,
    iov: libc::iovec,
    msg: libc::msghdr,
    cmsg_buf: [u8; 32],
}

impl Handoff {
    fn new() -> Self {
        Self {
            in_use: false,
            generation: 0,
            client_fd: -1,
            payload: 0,
            iov: libc::iovec {
                iov_base: ptr::null_mut(),
                iov_len: 0,
            },
            msg: unsafe { mem::zeroed() },
            cmsg_buf: [0u8; 32],
        }
    }
}

struct Upstream {
    addr: libc::sockaddr_un,
    addr_len: libc::socklen_t,
    path: String,
    ctrl_fd: RawFd,
}

pub fn run() -> std::io::Result<()> {
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }

    let port = env_u32("PORT", DEFAULT_PORT as u32) as u16;
    let backlog = env_u32("BACKLOG", DEFAULT_BACKLOG as u32) as i32;
    let upstream_str = std::env::var("UPSTREAMS")
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "UPSTREAMS env required"))?;

    let mut upstreams = parse_upstreams(&upstream_str)?;
    if upstreams.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "UPSTREAMS empty",
        ));
    }

    for u in upstreams.iter_mut() {
        u.ctrl_fd = connect_ctrl_retry(u);
    }

    let listen_fd = create_listener(port, backlog)?;

    let mut ring: IoUring = IoUring::builder()
        .setup_single_issuer()
        .setup_coop_taskrun()
        .setup_defer_taskrun()
        .setup_taskrun_flag()
        .build(RING_QD)?;

    eprintln!(
        "lb listen=:{} backlog={} upstreams=[{}] (io_uring qd={}, scm_rights handoff)",
        port,
        backlog,
        upstreams
            .iter()
            .map(|u| u.path.as_str())
            .collect::<Vec<_>>()
            .join(", "),
        RING_QD,
    );

    let mut handoffs: Vec<Box<Handoff>> =
        (0..MAX_HANDOFFS).map(|_| Box::new(Handoff::new())).collect();
    let mut free_slots: Vec<u32> = (0..MAX_HANDOFFS as u32).rev().collect();
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
                        &mut handoffs,
                        &mut free_slots,
                        &upstreams,
                        &mut rr,
                    );
                }
                OP_SENDMSG => {
                    let slot = unpack_slot(ud) as usize;
                    let gen_id = unpack_gen(ud);
                    if handoffs[slot].in_use && handoffs[slot].generation == gen_id {
                        handle_sendmsg(slot, res, &mut handoffs, &mut free_slots);
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
    handoffs: &mut [Box<Handoff>],
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

    let idx = *rr % upstreams.len();
    *rr = rr.wrapping_add(1);

    let h = &mut handoffs[slot];
    h.in_use = true;
    h.generation = h.generation.wrapping_add(1) & (GEN_MASK as u32);
    h.client_fd = client_fd;
    setup_handoff_msg(h);

    push_sendmsg(
        ring,
        slot,
        h.generation,
        upstreams[idx].ctrl_fd,
        &mut h.msg as *mut _,
    );
}

fn handle_sendmsg(
    slot: usize,
    _res: i32,
    handoffs: &mut [Box<Handoff>],
    free_slots: &mut Vec<u32>,
) {
    let h = &mut handoffs[slot];
    if h.client_fd >= 0 {
        unsafe {
            libc::close(h.client_fd);
        }
        h.client_fd = -1;
    }
    h.in_use = false;
    free_slots.push(slot as u32);
}

fn setup_handoff_msg(h: &mut Handoff) {
    h.payload = 0;
    h.iov.iov_base = &mut h.payload as *mut _ as *mut libc::c_void;
    h.iov.iov_len = 1;

    h.msg.msg_name = ptr::null_mut();
    h.msg.msg_namelen = 0;
    h.msg.msg_iov = &mut h.iov as *mut _;
    h.msg.msg_iovlen = 1;
    h.msg.msg_control = h.cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    h.msg.msg_controllen = unsafe { libc::CMSG_SPACE(mem::size_of::<RawFd>() as u32) } as _;
    h.msg.msg_flags = 0;

    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&h.msg as *const _);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(mem::size_of::<RawFd>() as u32) as _;
        let data = libc::CMSG_DATA(cmsg) as *mut RawFd;
        ptr::write_unaligned(data, h.client_fd);
    }
}

fn push_accept(ring: &mut IoUring, listen_fd: RawFd) {
    let sqe = opcode::AcceptMulti::new(types::Fd(listen_fd))
        .build()
        .user_data(pack(OP_ACCEPT, 0, 0));
    push_sqe(ring, sqe);
}

fn push_sendmsg(
    ring: &mut IoUring,
    slot: usize,
    gen_id: u32,
    ctrl_fd: RawFd,
    msg: *mut libc::msghdr,
) {
    let sqe = opcode::SendMsg::new(types::Fd(ctrl_fd), msg)
        .build()
        .user_data(pack(OP_SENDMSG, gen_id, slot as u32));
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

fn connect_ctrl_retry(u: &Upstream) -> RawFd {
    let mut tries = 0u32;
    loop {
        let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
        if fd >= 0 {
            let rc = unsafe {
                libc::connect(fd, &u.addr as *const _ as *const libc::sockaddr, u.addr_len)
            };
            if rc == 0 {
                if tries > 0 {
                    eprintln!("connected ctrl {} after {} retries", u.path, tries);
                }
                return fd;
            }
            unsafe {
                libc::close(fd);
            }
        }
        tries += 1;
        if tries % 40 == 0 {
            eprintln!("waiting for ctrl {} ({}s)", u.path, tries / 20);
        }
        std::thread::sleep(std::time::Duration::from_millis(CONNECT_RETRY_MS));
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
        let ctrl_path = format!("{}.ctrl", p);
        let mut addr: libc::sockaddr_un = unsafe { mem::zeroed() };
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
        let cstr = CString::new(ctrl_path.clone())
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
            path: ctrl_path,
            ctrl_fd: -1,
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
