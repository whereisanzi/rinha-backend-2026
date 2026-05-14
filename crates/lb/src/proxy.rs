use std::ffi::CString;
use std::mem;
use std::os::unix::io::RawFd;
use std::ptr;

use io_uring::{IoUring, opcode, types};

const DEFAULT_PORT: u16 = 9999;
const DEFAULT_BACKLOG: i32 = 4096;
const RING_QD: u32 = 4096;
const CONNECT_RETRY_MS: u64 = 50;

const CQE_F_MORE: u32 = 1 << 1;

const OP_ACCEPT: u8 = 1;

const OP_SHIFT: u32 = 56;

#[inline(always)]
fn pack(op: u8) -> u64 {
    (op as u64) << OP_SHIFT
}

#[inline(always)]
fn unpack_op(u: u64) -> u8 {
    (u >> OP_SHIFT) as u8
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

    let t0 = std::time::Instant::now();
    let listen_fd = create_listener(port, backlog)?;
    eprintln!("lb tcp bind: {:?}", t0.elapsed());

    let t1 = std::time::Instant::now();
    for u in upstreams.iter_mut() {
        u.ctrl_fd = connect_ctrl_retry(u);
    }
    eprintln!("lb ctrl connect: {:?}", t1.elapsed());

    let mut ring: IoUring = IoUring::builder()
        .setup_single_issuer()
        .setup_coop_taskrun()
        .build(RING_QD)?;

    eprintln!(
        "lb listen=:{} backlog={} upstreams=[{}] (io_uring qd={}, sync sendmsg handoff)",
        port,
        backlog,
        upstreams
            .iter()
            .map(|u| u.path.as_str())
            .collect::<Vec<_>>()
            .join(", "),
        RING_QD,
    );

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
                    handle_accept(&mut ring, listen_fd, res, flags, &upstreams, &mut rr);
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

    let idx = *rr % upstreams.len();
    *rr = rr.wrapping_add(1);

    unsafe {
        send_fd_to(upstreams[idx].ctrl_fd, client_fd);
        libc::close(client_fd);
    }
}

unsafe fn send_fd_to(ctrl: RawFd, fd: RawFd) {
    let cmsg_space = libc::CMSG_SPACE(mem::size_of::<libc::c_int>() as u32) as usize;
    let mut cmsg_buf: [u8; 32] = [0u8; 32];

    let mut dummy: u8 = 0;
    let mut iov = libc::iovec {
        iov_base: &mut dummy as *mut u8 as *mut libc::c_void,
        iov_len: 1,
    };

    let mut msg: libc::msghdr = mem::zeroed();
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_space as _;

    let cmsg = libc::CMSG_FIRSTHDR(&msg);
    (*cmsg).cmsg_level = libc::SOL_SOCKET;
    (*cmsg).cmsg_type = libc::SCM_RIGHTS;
    (*cmsg).cmsg_len = libc::CMSG_LEN(mem::size_of::<libc::c_int>() as u32) as _;
    let data = libc::CMSG_DATA(cmsg) as *mut libc::c_int;
    ptr::write_unaligned(data, fd);

    libc::sendmsg(ctrl, &msg, 0);
}

fn push_accept(ring: &mut IoUring, listen_fd: RawFd) {
    let sqe = opcode::AcceptMulti::new(types::Fd(listen_fd))
        .build()
        .user_data(pack(OP_ACCEPT));
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
