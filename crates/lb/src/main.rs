// Minimal single-host TCP dispatcher: accepts on :PORT and hands each client FD
// to a round-robin API instance over a UNIX control socket via SCM_RIGHTS. The
// API then owns the FD and serves the connection directly (no per-request
// proxying). Health checks (GET <HEALTH_PATH>) are answered here.
//
// Blocking accept loop only — the LB does per-connection work, not per-request,
// so it needs no io_uring/epoll, and uses only syscalls in the default Docker
// seccomp allowlist (io_uring_setup is blocked there).

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("lb requires Linux (SCM_RIGHTS handoff)");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
fn main() -> std::io::Result<()> {
    linux::run()
}

#[cfg(target_os = "linux")]
mod linux {
    use std::ffi::CString;
    use std::mem;
    use std::os::unix::io::RawFd;
    use std::ptr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicI32, Ordering};

    const DEFAULT_PORT: u16 = 9999;
    const DEFAULT_BACKLOG: i32 = 4096;
    const CONNECT_RETRY_MS: u64 = 50;

    struct Upstream {
        addr: libc::sockaddr_un,
        addr_len: libc::socklen_t,
        path: String,
        ctrl_fd: AtomicI32,
    }

    pub fn run() -> std::io::Result<()> {
        unsafe {
            libc::signal(libc::SIGPIPE, libc::SIG_IGN);
        }

        let port = env_u32("PORT", DEFAULT_PORT as u32) as u16;
        let backlog = env_u32("BACKLOG", DEFAULT_BACKLOG as u32) as i32;
        let upstream_str = std::env::var("UPSTREAMS").map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "UPSTREAMS env required")
        })?;
        let health_path: Option<Vec<u8>> = std::env::var("HEALTH_PATH")
            .ok()
            .filter(|s| !s.is_empty())
            .map(|s| s.into_bytes());

        let upstreams: Arc<Vec<Upstream>> = Arc::new(parse_upstreams(&upstream_str)?);
        if upstreams.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "UPSTREAMS empty",
            ));
        }

        let listen_fd = create_listener(port, backlog)?;

        for i in 0..upstreams.len() {
            let ups = Arc::clone(&upstreams);
            std::thread::Builder::new()
                .name(format!("ctrl-connect-{i}"))
                .spawn(move || {
                    let fd = connect_ctrl_retry(&ups[i]);
                    ups[i].ctrl_fd.store(fd, Ordering::Release);
                })
                .expect("spawn ctrl-connect");
        }

        eprintln!(
            "lb listen=:{port} backlog={backlog} upstreams=[{}] health={} (blocking accept)",
            upstreams
                .iter()
                .map(|u| u.path.as_str())
                .collect::<Vec<_>>()
                .join(", "),
            health_path
                .as_ref()
                .map(|p| std::str::from_utf8(p).unwrap_or("<bin>"))
                .unwrap_or("<off>"),
        );

        let mut rr: usize = 0;
        loop {
            let client_fd = unsafe { libc::accept(listen_fd, ptr::null_mut(), ptr::null_mut()) };
            if client_fd < 0 {
                continue; // EINTR / ECONNABORTED / transient — retry
            }

            set_tcp_nodelay(client_fd);

            if let Some(path) = health_path.as_deref() {
                if peek_is_health(client_fd, path) {
                    send_health_ok(client_fd);
                    unsafe { libc::close(client_fd) };
                    continue;
                }
            }

            let idx = rr % upstreams.len();
            rr = rr.wrapping_add(1);
            if !try_send_fd_with_reconnect(&upstreams[idx], client_fd) {
                eprintln!("send_fd failed to {} (giving up)", upstreams[idx].path);
            }
            unsafe { libc::close(client_fd) };
        }
    }

    unsafe fn send_fd_to(ctrl: RawFd, fd: RawFd) -> isize {
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

        libc::sendmsg(ctrl, &msg, 0)
    }

    const HEALTH_OK_RESPONSE: &[u8] =
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    const HEALTH_PEEK_LEN: usize = 64;
    const HEALTH_GET_PREFIX: &[u8] = b"GET ";

    fn peek_is_health(fd: RawFd, path: &[u8]) -> bool {
        let mut buf = [0u8; HEALTH_PEEK_LEN];
        let n = unsafe {
            libc::recv(
                fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                libc::MSG_PEEK | libc::MSG_DONTWAIT,
            )
        };
        if n <= 0 {
            return false;
        }
        let data = &buf[..n as usize];
        let need = HEALTH_GET_PREFIX.len() + path.len() + 1;
        if data.len() < need {
            return false;
        }
        if &data[..HEALTH_GET_PREFIX.len()] != HEALTH_GET_PREFIX {
            return false;
        }
        if &data[HEALTH_GET_PREFIX.len()..HEALTH_GET_PREFIX.len() + path.len()] != path {
            return false;
        }
        let next = data[HEALTH_GET_PREFIX.len() + path.len()];
        next == b' ' || next == b'?'
    }

    fn send_health_ok(fd: RawFd) {
        unsafe {
            libc::send(
                fd,
                HEALTH_OK_RESPONSE.as_ptr() as *const libc::c_void,
                HEALTH_OK_RESPONSE.len(),
                libc::MSG_NOSIGNAL,
            );
        }
    }

    fn try_send_fd_with_reconnect(u: &Upstream, client_fd: RawFd) -> bool {
        for _ in 0..2 {
            let ctrl = u.ctrl_fd.load(Ordering::Acquire);
            if ctrl >= 0 {
                let rc = unsafe { send_fd_to(ctrl, client_fd) };
                if rc >= 0 {
                    return true;
                }
                let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                if !is_recoverable(errno) {
                    return false;
                }
                unsafe { libc::close(ctrl) };
                u.ctrl_fd.store(-1, Ordering::Release);
            }
            match reconnect_ctrl(u) {
                Some(fd) => u.ctrl_fd.store(fd, Ordering::Release),
                None => return false,
            }
        }
        false
    }

    fn is_recoverable(errno: i32) -> bool {
        matches!(
            errno,
            libc::EPIPE | libc::ECONNRESET | libc::EBADF | libc::ENOTCONN
        )
    }

    fn reconnect_ctrl(u: &Upstream) -> Option<RawFd> {
        for _ in 0..3 {
            let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
            if fd >= 0 {
                let rc = unsafe {
                    libc::connect(fd, &u.addr as *const _ as *const libc::sockaddr, u.addr_len)
                };
                if rc == 0 {
                    return Some(fd);
                }
                unsafe { libc::close(fd) };
            }
            std::thread::sleep(std::time::Duration::from_millis(CONNECT_RETRY_MS));
        }
        None
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
                unsafe { libc::close(fd) };
            }
            tries += 1;
            if tries % 40 == 0 {
                eprintln!("waiting for ctrl {} ({}s)", u.path, tries / 20);
            }
            std::thread::sleep(std::time::Duration::from_millis(CONNECT_RETRY_MS));
        }
    }

    fn create_listener(port: u16, backlog: i32) -> std::io::Result<RawFd> {
        let fd =
            unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
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
            unsafe { libc::close(fd) };
            return Err(err);
        }
        if unsafe { libc::listen(fd, backlog) } < 0 {
            let err = std::io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(err);
        }
        let defer: libc::c_int = 1;
        unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_DEFER_ACCEPT,
                &defer as *const _ as *const libc::c_void,
                mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
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
            let cstr = CString::new(ctrl_path.clone()).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid path")
            })?;
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
            let addr_len = (mem::size_of::<libc::sa_family_t>() + bytes.len() - 1) as libc::socklen_t;
            out.push(Upstream {
                addr,
                addr_len,
                path: ctrl_path,
                ctrl_fd: AtomicI32::new(-1),
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
}
