use std::io;
use std::os::unix::io::{AsRawFd, RawFd};

use crate::ctrl;
use api::dataset::Dataset;
use api::http::{self, Parsed};
use api::{ivf, json, responses, vectorizer};

const REQ_BUF_SIZE: usize = 4096;
const MAX_EVENTS: usize = 1024;
const MAX_FD: usize = 65536;
const PREWARM_ITERS: usize = 20_000;

static SEARCH_MODE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

static BUSY_POLL_US: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

#[inline]
fn fraud_count(q: &[f32; api::DIM], ds: &'static Dataset) -> usize {
    match SEARCH_MODE.load(std::sync::atomic::Ordering::Relaxed) {
        1 => ivf::search_fraud_count(q, ds, ivf::nprobe_default()) as usize,
        2 => 0,
        3 => ivf::search_fraud_count_probe(q, ds) as usize,
        _ => ivf::search_fraud_count_exact(q, ds) as usize,
    }
}

pub struct Config {
    pub uds_path: String,
    pub uds_mode: u32,
    pub cpu_pin: Option<usize>,
    pub search_mode: u8,
}

struct Conn {
    buf: Box<[u8; REQ_BUF_SIZE]>,
    len: usize,
}

impl Conn {
    fn new() -> Box<Self> {
        Box::new(Conn {
            buf: Box::new([0u8; REQ_BUF_SIZE]),
            len: 0,
        })
    }
}

pub fn run(cfg: Config, ds: &'static Dataset) -> io::Result<()> {
    SEARCH_MODE.store(cfg.search_mode, std::sync::atomic::Ordering::Relaxed);
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
        if libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) != 0 {
            eprintln!("mlockall failed (non-fatal): {}", io::Error::last_os_error());
        }
    }

    pin_and_prioritize(cfg.cpu_pin);

    prewarm(ds);

    let ctrl_path = format!("{}.ctrl", cfg.uds_path);
    let listener = ctrl::bind_ctrl_listener(&ctrl_path, cfg.uds_mode)?;

    let (ctrl_conn, _addr) = listener.accept()?;
    let ctrl_fd = ctrl_conn.as_raw_fd();
    std::mem::forget(ctrl_conn);
    set_nonblocking(ctrl_fd);
    eprintln!("api listening (epoll reactor, ctrl={ctrl_path}, cpu_pin={:?})", cfg.cpu_pin);

    let epfd = unsafe { libc::epoll_create1(0) };
    if epfd < 0 {
        return Err(io::Error::last_os_error());
    }
    epoll_add(epfd, ctrl_fd);

    let busy_poll_us: u32 = std::env::var("BUSY_POLL_US")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    BUSY_POLL_US.store(busy_poll_us, std::sync::atomic::Ordering::Relaxed);
    if busy_poll_us > 0 {
        configure_busy_poll(epfd, busy_poll_us);
    }

    let spin_us: u64 = std::env::var("SPIN_US")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let idle_us: i64 = std::env::var("EPOLL_IDLE_US")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    let mut conns: Vec<Option<Box<Conn>>> = (0..MAX_FD).map(|_| None).collect();
    let mut events = vec![libc::epoll_event { events: 0, u64: 0 }; MAX_EVENTS];

    loop {
        let n = wait_events(epfd, events.as_mut_ptr(), spin_us, idle_us);
        if n < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(io::Error::last_os_error());
        }
        for ev in &events[..n as usize] {
            let fd = ev.u64 as RawFd;
            if fd == ctrl_fd {
                accept_new_fds(ctrl_fd, epfd, &mut conns);
            } else {
                handle_client(fd, epfd, &mut conns, ds);
            }
        }
    }
}

#[inline]
fn wait_events(epfd: RawFd, events: *mut libc::epoll_event, spin_us: u64, idle_us: i64) -> i32 {
    let n = unsafe { libc::epoll_wait(epfd, events, MAX_EVENTS as i32, 0) };
    if n != 0 {
        return n;
    }
    if spin_us > 0 {
        let start = std::time::Instant::now();
        while (start.elapsed().as_micros() as u64) < spin_us {
            std::hint::spin_loop();
            let n = unsafe { libc::epoll_wait(epfd, events, MAX_EVENTS as i32, 0) };
            if n != 0 {
                return n;
            }
        }
    }
    if idle_us > 0 {
        let ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: idle_us * 1000,
        };
        let r = unsafe {
            libc::syscall(
                libc::SYS_epoll_pwait2,
                epfd as libc::c_long,
                events as libc::c_long,
                MAX_EVENTS as libc::c_long,
                &ts as *const libc::timespec as libc::c_long,
                0i64,
                0i64,
            )
        };
        if r >= 0 {
            return r as i32;
        }
    }
    unsafe { libc::epoll_wait(epfd, events, MAX_EVENTS as i32, -1) }
}

#[repr(C)]
struct EpollParams {
    busy_poll_usecs: u32,
    busy_poll_budget: u16,
    prefer_busy_poll: u8,
    __pad: u8,
}

const EPIOCSPARAMS: u64 = 0x4008_8A01;

fn configure_busy_poll(epfd: RawFd, usecs: u32) {
    let params = EpollParams {
        busy_poll_usecs: usecs,
        busy_poll_budget: 8,
        prefer_busy_poll: 1,
        __pad: 0,
    };
    let rc = unsafe { libc::ioctl(epfd, EPIOCSPARAMS as _, &params) };
    if rc != 0 {
        eprintln!(
            "EPIOCSPARAMS busy-poll not available (non-fatal): {}",
            io::Error::last_os_error()
        );
    }
}

fn accept_new_fds(ctrl_fd: RawFd, epfd: RawFd, conns: &mut [Option<Box<Conn>>]) {
    loop {
        match ctrl::recv_fd(ctrl_fd) {
            Ok(Some(fd)) if fd >= 0 && (fd as usize) < MAX_FD => {
                set_nonblocking(fd);
                set_socket_options(fd);
                conns[fd as usize] = Some(Conn::new());
                epoll_add(epfd, fd);
            }
            Ok(Some(_)) => {}
            Ok(None) => return,
            Err(_) => return,
        }
    }
}

fn handle_client(fd: RawFd, epfd: RawFd, conns: &mut [Option<Box<Conn>>], ds: &'static Dataset) {
    let idx = fd as usize;
    if idx >= MAX_FD || conns[idx].is_none() {
        return;
    }
    if conns[idx].as_ref().unwrap().len >= REQ_BUF_SIZE {
        let _ = send_all(fd, responses::RESP_PAYLOAD_TOO_LARGE);
        close_conn(fd, epfd, conns);
        return;
    }
    let n = {
        let conn = conns[idx].as_mut().unwrap();
        unsafe {
            libc::recv(
                fd,
                conn.buf.as_mut_ptr().add(conn.len) as *mut _,
                REQ_BUF_SIZE - conn.len,
                0,
            )
        }
    };
    if n < 0 {
        return;
    }
    if n == 0 {
        close_conn(fd, epfd, conns);
        return;
    }
    conns[idx].as_mut().unwrap().len += n as usize;
    if !process_buffer(fd, conns, ds) {
        close_conn(fd, epfd, conns);
    }
}

fn process_buffer(fd: RawFd, conns: &mut [Option<Box<Conn>>], ds: &'static Dataset) -> bool {
    let idx = fd as usize;
    loop {
        let conn = match conns[idx].as_mut() {
            Some(c) => c,
            None => return false,
        };
        let parsed = http::parse(&conn.buf[..conn.len]);
        match parsed {
            Parsed::Incomplete => return true,
            Parsed::Bad => {
                let _ = send_all(fd, responses::RESP_BAD_REQUEST);
                return false;
            }
            Parsed::Ready { consumed } => {
                if !send_all(fd, responses::RESP_READY) {
                    return false;
                }
                advance(conn, consumed);
            }
            Parsed::NotFound { consumed } => {
                if !send_all(fd, responses::RESP_NOT_FOUND) {
                    return false;
                }
                advance(conn, consumed);
            }
            Parsed::FraudScore {
                body_start,
                body_end,
                consumed,
            } => {
                let resp = match json::parse(&conn.buf[body_start..body_end]) {
                    Some(p) => {
                        let q = vectorizer::vectorize(&p);
                        let f = fraud_count(&q, ds);
                        responses::RESP_FRAUD[f.min(5)]
                    }
                    None => responses::RESP_BAD_REQUEST,
                };
                let ok = send_all(fd, resp);
                if !ok || std::ptr::eq(resp.as_ptr(), responses::RESP_BAD_REQUEST.as_ptr()) {
                    return false;
                }
                advance(conn, consumed);
            }
        }
    }
}

#[inline]
fn advance(conn: &mut Conn, consumed: usize) {
    if consumed == 0 || conn.len == 0 {
        return;
    }
    let c = consumed.min(conn.len);
    let remaining = conn.len - c;
    if remaining > 0 {
        conn.buf.copy_within(c..c + remaining, 0);
    }
    conn.len = remaining;
}

fn close_conn(fd: RawFd, epfd: RawFd, conns: &mut [Option<Box<Conn>>]) {
    unsafe {
        libc::epoll_ctl(epfd, libc::EPOLL_CTL_DEL, fd, std::ptr::null_mut());
        libc::close(fd);
    }
    let idx = fd as usize;
    if idx < conns.len() {
        conns[idx] = None;
    }
}

fn send_all(fd: RawFd, data: &[u8]) -> bool {
    let mut sent = 0usize;
    while sent < data.len() {
        let n = unsafe {
            libc::send(
                fd,
                data.as_ptr().add(sent) as *const _,
                data.len() - sent,
                libc::MSG_NOSIGNAL,
            )
        };
        if n > 0 {
            sent += n as usize;
            continue;
        }
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::WouldBlock {
                continue;
            }
        }
        return false;
    }
    true
}

fn epoll_add(epfd: RawFd, fd: RawFd) {
    let mut ev = libc::epoll_event {
        events: libc::EPOLLIN as u32,
        u64: fd as u64,
    };
    unsafe {
        libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, fd, &mut ev);
    }
}

fn set_nonblocking(fd: RawFd) {
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL, 0);
        libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }
}

fn set_socket_options(fd: RawFd) {
    let one: libc::c_int = 1;
    unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_NODELAY,
            &one as *const _ as *const _,
            std::mem::size_of::<libc::c_int>() as _,
        );
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_QUICKACK,
            &one as *const _ as *const _,
            std::mem::size_of::<libc::c_int>() as _,
        );
        let bp = BUSY_POLL_US.load(std::sync::atomic::Ordering::Relaxed) as libc::c_int;
        if bp > 0 {

            const SO_BUSY_POLL: libc::c_int = 46;
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                SO_BUSY_POLL,
                &bp as *const _ as *const _,
                std::mem::size_of::<libc::c_int>() as _,
            );
        }
    }
}

fn pin_and_prioritize(cpu_pin: Option<usize>) {
    if let Some(cpu) = cpu_pin {
        unsafe {
            let mut cpuset: libc::cpu_set_t = std::mem::zeroed();
            libc::CPU_SET(cpu, &mut cpuset);
            libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &cpuset);
        }
    }

    let sched = std::env::var("SCHED").unwrap_or_else(|_| "fifo".into());
    if sched == "fifo" {
        unsafe {
            let mut p: libc::sched_param = std::mem::zeroed();
            p.sched_priority = 10;
            libc::sched_setscheduler(0, libc::SCHED_FIFO, &p);
        }
    }
}

fn prewarm(ds: &'static Dataset) {
    let legit = br#"{"id":"x","transaction":{"amount":41.12,"installments":2,"requested_at":"2026-03-11T18:45:53Z"},"customer":{"avg_amount":82.24,"tx_count_24h":3,"known_merchants":["MERC-016"]},"merchant":{"id":"MERC-016","mcc":"5411","avg_amount":60.25},"terminal":{"is_online":false,"card_present":true,"km_from_home":29.23},"last_transaction":null}"#;
    let fraud = br#"{"id":"x","transaction":{"amount":9505.97,"installments":10,"requested_at":"2026-03-14T05:15:12Z"},"customer":{"avg_amount":81.28,"tx_count_24h":20,"known_merchants":["MERC-A"]},"merchant":{"id":"MERC-068","mcc":"7802","avg_amount":54.86},"terminal":{"is_online":false,"card_present":true,"km_from_home":952.27},"last_transaction":null}"#;

    let q_legit = vectorizer::vectorize(&json::parse(legit).expect("prewarm parse legit"));
    let q_fraud = vectorizer::vectorize(&json::parse(fraud).expect("prewarm parse fraud"));
    for i in 0..PREWARM_ITERS {
        let q = if i % 2 == 0 { &q_legit } else { &q_fraud };
        let _ = std::hint::black_box(ivf::search_fraud_count_exact(q, ds));
    }
}
