

use std::ffi::CString;
use std::mem;
use std::os::unix::io::RawFd;
use std::ptr;

const DEFAULT_PORT: u16 = 9999;
const DEFAULT_BUF_SIZE: usize = 4096;
const DEFAULT_BACKLOG: i32 = 4096;
const DEFAULT_MAX_EVENTS: usize = 1024;
const MAX_CONNS: usize = 2048;

const LISTEN_TAG: u64 = 1u64 << 63;

#[inline(always)]
fn pack_endpoint(slot: usize, side: Side) -> u64 {
    ((slot as u64) << 1) | (side as u64)
}
#[inline(always)]
fn unpack_endpoint(u: u64) -> (usize, Side) {
    (
        (u >> 1) as usize,
        if (u & 1) == 0 {
            Side::Client
        } else {
            Side::Backend
        },
    )
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
enum Side {
    Client = 0,
    Backend = 1,
}

struct Buffer {
    data: Vec<u8>,
    off: usize,
    len: usize,
}

impl Buffer {
    fn new(cap: usize) -> Self {
        Self {
            data: vec![0u8; cap],
            off: 0,
            len: 0,
        }
    }
    fn cap(&self) -> usize {
        self.data.len()
    }
    fn empty(&self) -> bool {
        self.len == 0
    }
    fn clear(&mut self) {
        self.off = 0;
        self.len = 0;
    }
}

struct Conn {
    in_use: bool,
    connecting: bool,
    client_fd: RawFd,
    backend_fd: RawFd,
    client_events: u32,
    backend_events: u32,

    c2b: Buffer,

    b2c: Buffer,
}

impl Conn {
    fn new(buf_size: usize) -> Self {
        Self {
            in_use: false,
            connecting: false,
            client_fd: -1,
            backend_fd: -1,
            client_events: 0,
            backend_events: 0,
            c2b: Buffer::new(buf_size),
            b2c: Buffer::new(buf_size),
        }
    }
    fn fd(&self, side: Side) -> RawFd {
        match side {
            Side::Client => self.client_fd,
            Side::Backend => self.backend_fd,
        }
    }
    fn events(&self, side: Side) -> u32 {
        match side {
            Side::Client => self.client_events,
            Side::Backend => self.backend_events,
        }
    }
    fn set_events(&mut self, side: Side, events: u32) {
        match side {
            Side::Client => self.client_events = events,
            Side::Backend => self.backend_events = events,
        }
    }

    fn in_buf(&mut self, side: Side) -> &mut Buffer {
        match side {
            Side::Client => &mut self.c2b,
            Side::Backend => &mut self.b2c,
        }
    }

    fn out_buf(&mut self, side: Side) -> &mut Buffer {
        match side {
            Side::Client => &mut self.b2c,
            Side::Backend => &mut self.c2b,
        }
    }
}

const PEER: [Side; 2] = [Side::Backend, Side::Client];

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
    let max_events = env_usize("MAX_EVENTS", DEFAULT_MAX_EVENTS).max(64);
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
    let epfd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
    if epfd < 0 {
        return Err(std::io::Error::last_os_error());
    }

    epoll_add(epfd, listen_fd, libc::EPOLLIN as u32, LISTEN_TAG)?;

    eprintln!(
        "lb listen=:{} buf={} backlog={} upstreams=[{}]",
        port,
        buf_size,
        backlog,
        upstreams
            .iter()
            .map(|u| u.path.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );

    let mut conns: Vec<Conn> = (0..MAX_CONNS).map(|_| Conn::new(buf_size)).collect();
    let mut events_buf: Vec<libc::epoll_event> =
        vec![unsafe { mem::zeroed() }; max_events];
    let mut rr: usize = 0;

    loop {
        let n = unsafe {
            libc::epoll_wait(
                epfd,
                events_buf.as_mut_ptr(),
                max_events as i32,
                -1,
            )
        };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(err);
        }

        for i in 0..n as usize {
            let ev = events_buf[i];
            let data = ev.u64;
            let events = ev.events;

            if data == LISTEN_TAG {
                accept_loop(epfd, listen_fd, &upstreams, &mut conns, &mut rr);
                continue;
            }
            let (slot, side) = unpack_endpoint(data);
            handle_endpoint(epfd, slot, side, events, &mut conns);
        }
    }
}

fn accept_loop(
    epfd: RawFd,
    listen_fd: RawFd,
    upstreams: &[Upstream],
    conns: &mut [Conn],
    rr: &mut usize,
) {
    loop {
        let client_fd = unsafe { libc::accept(listen_fd, ptr::null_mut(), ptr::null_mut()) };
        if client_fd < 0 {
            let errno = unsafe { *libc::__errno_location() };
            if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
                return;
            }
            if errno == libc::EINTR {
                continue;
            }
            return;
        }
        if let Err(_) = open_conn(epfd, client_fd, upstreams, conns, rr) {
            unsafe {
                libc::close(client_fd);
            }
        }
    }
}

fn open_conn(
    epfd: RawFd,
    client_fd: RawFd,
    upstreams: &[Upstream],
    conns: &mut [Conn],
    rr: &mut usize,
) -> std::io::Result<()> {
    set_nonblock(client_fd)?;
    set_tcp_nodelay(client_fd);

    let backend_fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if backend_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if set_nonblock(backend_fd).is_err() {
        unsafe {
            libc::close(backend_fd);
        }
        return Err(std::io::Error::last_os_error());
    }

    let idx = *rr % upstreams.len();
    *rr = rr.wrapping_add(1);
    let up = &upstreams[idx];

    let rc = unsafe {
        libc::connect(
            backend_fd,
            &up.addr as *const _ as *const libc::sockaddr,
            up.addr_len,
        )
    };
    if rc != 0 {
        let errno = unsafe { *libc::__errno_location() };
        if errno != libc::EINPROGRESS {
            unsafe {
                libc::close(backend_fd);
            }
            return Err(std::io::Error::last_os_error());
        }
    }

    let slot = match conns.iter().position(|c| !c.in_use) {
        Some(s) => s,
        None => {
            unsafe {
                libc::close(backend_fd);
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "conn pool exhausted",
            ));
        }
    };
    let conn = &mut conns[slot];
    conn.in_use = true;
    conn.connecting = true;
    conn.client_fd = client_fd;
    conn.backend_fd = backend_fd;
    conn.c2b.clear();
    conn.b2c.clear();

    let client_evs = libc::EPOLLRDHUP as u32;
    let backend_evs = (libc::EPOLLOUT | libc::EPOLLRDHUP) as u32;

    if epoll_add(epfd, client_fd, client_evs, pack_endpoint(slot, Side::Client)).is_err()
        || epoll_add(epfd, backend_fd, backend_evs, pack_endpoint(slot, Side::Backend)).is_err()
    {
        let _ = epoll_del(epfd, client_fd);
        let _ = epoll_del(epfd, backend_fd);
        unsafe {
            libc::close(client_fd);
            libc::close(backend_fd);
        }
        conn.in_use = false;
        conn.client_fd = -1;
        conn.backend_fd = -1;
        return Err(std::io::Error::last_os_error());
    }
    conn.client_events = client_evs;
    conn.backend_events = backend_evs;
    Ok(())
}

fn handle_endpoint(epfd: RawFd, slot: usize, side: Side, events: u32, conns: &mut [Conn]) {
    if !conns[slot].in_use {
        return;
    }

    if events & (libc::EPOLLERR as u32) != 0 {
        close_conn(epfd, slot, conns);
        return;
    }

    if conns[slot].connecting && side == Side::Backend && (events & libc::EPOLLOUT as u32) != 0 {
        match complete_connect(epfd, slot, conns) {
            Ok(()) => return,
            Err(_) => {
                close_conn(epfd, slot, conns);
                return;
            }
        }
    }

    if events & (libc::EPOLLOUT as u32) != 0 {
        if !flush_to_endpoint(epfd, slot, side, conns) {
            close_conn(epfd, slot, conns);
            return;
        }
    }
    if events & (libc::EPOLLIN as u32) != 0 {
        if !read_from_endpoint(epfd, slot, side, conns) {
            close_conn(epfd, slot, conns);
            return;
        }
    }
    if events & (libc::EPOLLRDHUP as u32) != 0
        && conns[slot].out_buf(side).empty()
        && conns[slot].out_buf(PEER[side as usize]).empty()
    {
        close_conn(epfd, slot, conns);
    }
}

fn complete_connect(epfd: RawFd, slot: usize, conns: &mut [Conn]) -> std::io::Result<()> {
    let backend_fd = conns[slot].backend_fd;
    let mut err: libc::c_int = 0;
    let mut len: libc::socklen_t = mem::size_of::<libc::c_int>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            backend_fd,
            libc::SOL_SOCKET,
            libc::SO_ERROR,
            &mut err as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 || err != 0 {
        return Err(std::io::Error::from_raw_os_error(if err != 0 { err } else { 1 }));
    }
    conns[slot].connecting = false;

    let in_evs = (libc::EPOLLIN | libc::EPOLLRDHUP) as u32;
    epoll_mod_endpoint(epfd, slot, Side::Backend, in_evs, conns)?;
    epoll_mod_endpoint(epfd, slot, Side::Client, in_evs, conns)?;
    Ok(())
}

fn read_from_endpoint(epfd: RawFd, slot: usize, side: Side, conns: &mut [Conn]) -> bool {
    let in_buf_empty = conns[slot].in_buf(side).empty();
    if !in_buf_empty {

        let cur = conns[slot].events(side);
        let _ = epoll_mod_endpoint(epfd, slot, side, cur & !(libc::EPOLLIN as u32), conns);
        return true;
    }

    let fd = conns[slot].fd(side);
    let buf_ptr;
    let cap;
    {
        let buf = conns[slot].in_buf(side);
        buf_ptr = buf.data.as_mut_ptr();
        cap = buf.cap();
    }
    let n = unsafe { libc::recv(fd, buf_ptr as *mut libc::c_void, cap, 0) };
    if n > 0 {
        let n = n as usize;
        let buf = conns[slot].in_buf(side);
        buf.off = 0;
        buf.len = n;

        let cur = conns[slot].events(side);
        if epoll_mod_endpoint(
            epfd,
            slot,
            side,
            cur & !(libc::EPOLLIN as u32),
            conns,
        )
        .is_err()
        {
            return false;
        }

        let peer = PEER[side as usize];
        let cur_peer = conns[slot].events(peer);
        if epoll_mod_endpoint(
            epfd,
            slot,
            peer,
            cur_peer | (libc::EPOLLOUT | libc::EPOLLRDHUP) as u32,
            conns,
        )
        .is_err()
        {
            return false;
        }
        return true;
    }
    if n == 0 {
        return false;
    }
    let errno = unsafe { *libc::__errno_location() };
    errno == libc::EAGAIN || errno == libc::EWOULDBLOCK
}

fn flush_to_endpoint(epfd: RawFd, slot: usize, side: Side, conns: &mut [Conn]) -> bool {
    loop {
        let (fd, ptr, len, off) = {
            let conn = &mut conns[slot];
            let fd = conn.fd(side);
            let buf = conn.out_buf(side);
            if buf.off >= buf.len {
                break;
            }
            (fd, buf.data.as_mut_ptr(), buf.len, buf.off)
        };
        let n = unsafe {
            libc::send(
                fd,
                (ptr as *mut u8).add(off) as *const libc::c_void,
                len - off,
                libc::MSG_NOSIGNAL,
            )
        };
        if n > 0 {
            conns[slot].out_buf(side).off += n as usize;
            continue;
        }
        if n == 0 {
            return false;
        }
        let errno = unsafe { *libc::__errno_location() };
        if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
            return true;
        }
        return false;
    }

    conns[slot].out_buf(side).clear();
    let cur = conns[slot].events(side);
    if epoll_mod_endpoint(
        epfd,
        slot,
        side,
        (cur & !(libc::EPOLLOUT as u32)) | (libc::EPOLLIN | libc::EPOLLRDHUP) as u32,
        conns,
    )
    .is_err()
    {
        return false;
    }

    let peer = PEER[side as usize];
    let cur_peer = conns[slot].events(peer);
    if epoll_mod_endpoint(
        epfd,
        slot,
        peer,
        cur_peer | (libc::EPOLLIN | libc::EPOLLRDHUP) as u32,
        conns,
    )
    .is_err()
    {
        return false;
    }
    true
}

fn close_conn(epfd: RawFd, slot: usize, conns: &mut [Conn]) {
    let conn = &mut conns[slot];
    if !conn.in_use {
        return;
    }
    if conn.client_fd >= 0 {
        let _ = epoll_del(epfd, conn.client_fd);
        unsafe {
            libc::close(conn.client_fd);
        }
        conn.client_fd = -1;
    }
    if conn.backend_fd >= 0 {
        let _ = epoll_del(epfd, conn.backend_fd);
        unsafe {
            libc::close(conn.backend_fd);
        }
        conn.backend_fd = -1;
    }
    conn.client_events = 0;
    conn.backend_events = 0;
    conn.connecting = false;
    conn.in_use = false;
    conn.c2b.clear();
    conn.b2c.clear();
}

fn epoll_add(epfd: RawFd, fd: RawFd, events: u32, data: u64) -> std::io::Result<()> {
    let mut ev: libc::epoll_event = unsafe { mem::zeroed() };
    ev.events = events;
    ev.u64 = data;
    let rc = unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, fd, &mut ev) };
    if rc < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn epoll_del(epfd: RawFd, fd: RawFd) -> std::io::Result<()> {
    let rc = unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_DEL, fd, ptr::null_mut()) };
    if rc < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn epoll_mod_endpoint(
    epfd: RawFd,
    slot: usize,
    side: Side,
    events: u32,
    conns: &mut [Conn],
) -> std::io::Result<()> {
    let fd = conns[slot].fd(side);
    if fd < 0 {
        return Ok(());
    }
    if conns[slot].events(side) == events {
        return Ok(());
    }
    let mut ev: libc::epoll_event = unsafe { mem::zeroed() };
    ev.events = events;
    ev.u64 = pack_endpoint(slot, side);
    let rc = unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_MOD, fd, &mut ev) };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    conns[slot].set_events(side, events);
    Ok(())
}

fn create_listener(port: u16, backlog: i32) -> std::io::Result<RawFd> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
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
            mem::size_of_val(&one) as libc::socklen_t,
        );
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEPORT,
            &one as *const _ as *const libc::c_void,
            mem::size_of_val(&one) as libc::socklen_t,
        );
    }
    if set_nonblock(fd).is_err() {
        unsafe {
            libc::close(fd);
        }
        return Err(std::io::Error::last_os_error());
    }
    let mut addr: libc::sockaddr_in = unsafe { mem::zeroed() };
    addr.sin_family = libc::AF_INET as u16;
    addr.sin_port = port.to_be();
    addr.sin_addr.s_addr = libc::INADDR_ANY.to_be();
    if unsafe {
        libc::bind(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    } < 0
    {
        unsafe {
            libc::close(fd);
        }
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { libc::listen(fd, backlog) } < 0 {
        unsafe {
            libc::close(fd);
        }
        return Err(std::io::Error::last_os_error());
    }
    Ok(fd)
}

fn set_nonblock(fd: RawFd) -> std::io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL, 0) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if rc < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn set_tcp_nodelay(fd: RawFd) {
    let one: libc::c_int = 1;
    unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_NODELAY,
            &one as *const _ as *const libc::c_void,
            mem::size_of_val(&one) as libc::socklen_t,
        );
    }
}

fn parse_upstreams(env: &str) -> std::io::Result<Vec<Upstream>> {
    let mut out = Vec::new();
    for raw in env.split(',') {
        let path = raw.trim();
        if path.is_empty() {
            continue;
        }
        let mut addr: libc::sockaddr_un = unsafe { mem::zeroed() };
        addr.sun_family = libc::AF_UNIX as u16;
        let bytes = path.as_bytes();
        if bytes.len() >= addr.sun_path.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("upstream path too long: {}", path),
            ));
        }
        for (i, &b) in bytes.iter().enumerate() {
            addr.sun_path[i] = b as libc::c_char;
        }
        let addr_len =
            (mem::size_of::<libc::sa_family_t>() + bytes.len() + 1) as libc::socklen_t;

        if CString::new(path).is_err() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "upstream path contains nul byte",
            ));
        }
        out.push(Upstream {
            addr,
            addr_len,
            path: path.to_string(),
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
