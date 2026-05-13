use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::{Arc, Mutex};

pub struct CtrlChannel {
    pub queue: Arc<Mutex<Vec<RawFd>>>,
    pub eventfd: RawFd,
}

pub fn bind_ctrl_listener(path: &str, mode: u32) -> std::io::Result<UnixListener> {
    if let Some(parent) = Path::new(path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path)?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    Ok(listener)
}

pub fn create_eventfd() -> std::io::Result<RawFd> {
    let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(fd)
}

pub fn drain_eventfd(fd: RawFd) {
    let mut buf = [0u8; 8];
    loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut _, 8) };
        if n != 8 {
            break;
        }
    }
}

pub fn spawn_ctrl_thread(listener: UnixListener, ch: CtrlChannel) {
    std::thread::spawn(move || {
        for incoming in listener.incoming() {
            match incoming {
                Ok(stream) => {
                    let ch = ch.clone();
                    std::thread::spawn(move || handle_ctrl_conn(stream, ch));
                }
                Err(_) => continue,
            }
        }
    });
}

fn handle_ctrl_conn(stream: UnixStream, ch: CtrlChannel) {
    let fd = stream.as_raw_fd();
    loop {
        match unsafe { recv_fd_once(fd) } {
            Some(client_fd) => {
                ch.queue.lock().unwrap().push(client_fd);
                let one: u64 = 1;
                unsafe {
                    libc::write(
                        ch.eventfd,
                        &one as *const _ as *const libc::c_void,
                        8,
                    );
                }
            }
            None => break,
        }
    }
}

unsafe fn recv_fd_once(sock: RawFd) -> Option<RawFd> {
    let cmsg_space = libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as u32) as usize;
    let mut cmsg_buf: Vec<u8> = vec![0u8; cmsg_space];

    let mut dummy: u8 = 0;
    let mut iov = libc::iovec {
        iov_base: &mut dummy as *mut u8 as *mut libc::c_void,
        iov_len: 1,
    };

    let mut msg: libc::msghdr = std::mem::zeroed();
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_space as _;

    let ret = libc::recvmsg(sock, &mut msg, 0);
    if ret <= 0 {
        return None;
    }

    let cmsg = libc::CMSG_FIRSTHDR(&msg);
    if cmsg.is_null() {
        return None;
    }
    if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
        let data = libc::CMSG_DATA(cmsg) as *const libc::c_int;
        return Some(std::ptr::read_unaligned(data));
    }
    None
}

impl Clone for CtrlChannel {
    fn clone(&self) -> Self {
        Self {
            queue: self.queue.clone(),
            eventfd: self.eventfd,
        }
    }
}
