use std::io;
use std::os::unix::io::{AsRawFd, RawFd};
use std::thread;
use std::time::Instant;

use crate::DIM;
use crate::ctrl;
use crate::dataset::Dataset;
use crate::http::{self, Parsed};
use crate::{ivf, json, responses, vectorizer};

const REQ_BUF_SIZE: usize = 4096;
const WORKER_STACK: usize = 128 * 1024;
const PREWARM_ITERS: usize = 200;

pub struct Config {
    pub uds_path: String,
    pub uds_mode: u32,
    pub nprobe: usize,
    #[allow(dead_code)]
    pub backlog: i32,
    pub cpu_pin: Option<usize>,
}

pub fn run(cfg: Config, ds: &'static Dataset) -> io::Result<()> {
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
        if libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) != 0 {
            eprintln!(
                "mlockall failed (non-fatal): {}",
                io::Error::last_os_error()
            );
        }
    }

    let ctrl_path = format!("{}.ctrl", cfg.uds_path);
    let t0 = Instant::now();
    let listener = ctrl::bind_ctrl_listener(&ctrl_path, cfg.uds_mode)?;
    eprintln!("api ctrl bind: {:?} (path={})", t0.elapsed(), ctrl_path);

    let t1 = Instant::now();
    prewarm(ds, cfg.nprobe);
    eprintln!("api prewarm (sync): {:?}", t1.elapsed());

    let t2 = Instant::now();
    let (ctrl_conn, _addr) = listener.accept()?;
    let ctrl_fd = ctrl_conn.as_raw_fd();
    eprintln!("api ctrl accept: {:?} (fd={})", t2.elapsed(), ctrl_fd);
    std::mem::forget(ctrl_conn);

    eprintln!(
        "api listening on ctrl={} (thread-per-conn, nprobe={}, cpu_pin={:?})",
        ctrl_path, cfg.nprobe, cfg.cpu_pin
    );

    let nprobe = cfg.nprobe;
    let cpu_pin = cfg.cpu_pin;

    loop {
        let fd = match ctrl::recv_fd(ctrl_fd) {
            Ok(Some(f)) if f >= 0 => f,
            Ok(_) => continue,
            Err(e) => {
                eprintln!("ctrl recvmsg error: {} — sleeping 100ms", e);
                thread::sleep(std::time::Duration::from_millis(100));
                continue;
            }
        };

        let _ = thread::Builder::new()
            .name("worker".into())
            .stack_size(WORKER_STACK)
            .spawn(move || {
                setup_worker_thread(cpu_pin);
                set_socket_options(fd);
                worker_loop(fd, ds, nprobe);
            });
    }
}

fn setup_worker_thread(cpu_pin: Option<usize>) {
    if let Some(cpu) = cpu_pin {
        unsafe {
            let mut cpuset: libc::cpu_set_t = std::mem::zeroed();
            libc::CPU_SET(cpu, &mut cpuset);
            libc::sched_setaffinity(
                0,
                std::mem::size_of::<libc::cpu_set_t>(),
                &cpuset,
            );
        }
    }
    unsafe {
        let mut p: libc::sched_param = std::mem::zeroed();
        p.sched_priority = 10;
        libc::sched_setscheduler(0, libc::SCHED_FIFO, &p);
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
    }
}

fn worker_loop(fd: RawFd, ds: &'static Dataset, nprobe: usize) {
    let mut buf = vec![0u8; REQ_BUF_SIZE];
    let mut req_len: usize = 0;

    loop {
        if req_len >= REQ_BUF_SIZE {
            let _ = send_all(fd, responses::RESP_PAYLOAD_TOO_LARGE);
            break;
        }

        let n = unsafe {
            libc::recv(
                fd,
                buf.as_mut_ptr().add(req_len) as *mut _,
                REQ_BUF_SIZE - req_len,
                0,
            )
        };
        if n <= 0 {
            break;
        }
        req_len += n as usize;

        loop {
            match http::parse(&buf[..req_len]) {
                Parsed::Incomplete => break,
                Parsed::Bad => {
                    let _ = send_all(fd, responses::RESP_BAD_REQUEST);
                    unsafe { libc::close(fd) };
                    return;
                }
                Parsed::Ready { consumed } => {
                    if !send_all(fd, responses::RESP_READY) {
                        unsafe { libc::close(fd) };
                        return;
                    }
                    advance(&mut buf, &mut req_len, consumed);
                }
                Parsed::NotFound { consumed } => {
                    if !send_all(fd, responses::RESP_NOT_FOUND) {
                        unsafe { libc::close(fd) };
                        return;
                    }
                    advance(&mut buf, &mut req_len, consumed);
                }
                Parsed::FraudScore {
                    body_start,
                    body_end,
                    consumed,
                } => {
                    let resp_idx_or_bad = {
                        let body = &buf[body_start..body_end];
                        match json::parse(body) {
                            Some(p) => {
                                let q = vectorizer::vectorize(&p);
                                let f = ivf::search_fraud_count(&q, ds, nprobe);
                                Ok((f as usize).min(5))
                            }
                            None => Err(()),
                        }
                    };
                    match resp_idx_or_bad {
                        Ok(i) => {
                            if !send_all(fd, responses::RESP_FRAUD[i]) {
                                unsafe { libc::close(fd) };
                                return;
                            }
                        }
                        Err(()) => {
                            let _ = send_all(fd, responses::RESP_BAD_REQUEST);
                            unsafe { libc::close(fd) };
                            return;
                        }
                    }
                    advance(&mut buf, &mut req_len, consumed);
                }
            }
        }
    }

    unsafe { libc::close(fd) };
}

fn send_all(fd: RawFd, data: &[u8]) -> bool {
    let mut sent: usize = 0;
    while sent < data.len() {
        let n = unsafe {
            libc::send(
                fd,
                data.as_ptr().add(sent) as *const _,
                data.len() - sent,
                libc::MSG_NOSIGNAL,
            )
        };
        if n <= 0 {
            return false;
        }
        sent += n as usize;
    }
    true
}

fn advance(buf: &mut [u8], req_len: &mut usize, consumed: usize) {
    if consumed == 0 || *req_len == 0 {
        return;
    }
    let c = consumed.min(*req_len);
    let remaining = *req_len - c;
    if remaining > 0 {
        buf.copy_within(c..c + remaining, 0);
    }
    *req_len = remaining;
}

fn prewarm(ds: &'static Dataset, nprobe: usize) {
    let legit = br#"{"id":"x","transaction":{"amount":41.12,"installments":2,"requested_at":"2026-03-11T18:45:53Z"},"customer":{"avg_amount":82.24,"tx_count_24h":3,"known_merchants":["MERC-016"]},"merchant":{"id":"MERC-016","mcc":"5411","avg_amount":60.25},"terminal":{"is_online":false,"card_present":true,"km_from_home":29.23},"last_transaction":null}"#;
    let fraud = br#"{"id":"x","transaction":{"amount":9505.97,"installments":10,"requested_at":"2026-03-14T05:15:12Z"},"customer":{"avg_amount":81.28,"tx_count_24h":20,"known_merchants":["MERC-A"]},"merchant":{"id":"MERC-068","mcc":"7802","avg_amount":54.86},"terminal":{"is_online":false,"card_present":true,"km_from_home":952.27},"last_transaction":null}"#;

    let q_legit: [f32; DIM] =
        vectorizer::vectorize(&json::parse(legit).expect("prewarm parse legit"));
    let q_fraud: [f32; DIM] =
        vectorizer::vectorize(&json::parse(fraud).expect("prewarm parse fraud"));

    for i in 0..PREWARM_ITERS {
        let q = if i % 2 == 0 { &q_legit } else { &q_fraud };
        let _ = std::hint::black_box(ivf::search_fraud_count(q, ds, nprobe));
    }
}
