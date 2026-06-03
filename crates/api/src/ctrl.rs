use std::io;
use std::mem;
use std::os::unix::io::RawFd;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::ptr;

pub fn bind_ctrl_listener(path: &str, mode: u32) -> io::Result<UnixListener> {
    if let Some(parent) = Path::new(path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path)?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    Ok(listener)
}

pub fn recv_fd(ctrl_fd: RawFd) -> io::Result<Option<RawFd>> {
    let mut payload = 0u8;
    let mut iov = libc::iovec {
        iov_base: &mut payload as *mut _ as *mut libc::c_void,
        iov_len: 1,
    };
    let mut cmsg_buf = [0u8; 64];
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = &mut iov as *mut _;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_buf.len() as _;
    msg.msg_name = ptr::null_mut();
    msg.msg_namelen = 0;
    msg.msg_flags = 0;

    let n = unsafe { libc::recvmsg(ctrl_fd, &mut msg as *mut _, 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    if n == 0 {
        return Ok(None);
    }
    Ok(unsafe { extract_fd(&msg) })
}

unsafe fn extract_fd(msg: &libc::msghdr) -> Option<RawFd> {
    let cmsg = libc::CMSG_FIRSTHDR(msg);
    if cmsg.is_null() {
        return None;
    }
    if (*cmsg).cmsg_level != libc::SOL_SOCKET || (*cmsg).cmsg_type != libc::SCM_RIGHTS {
        return None;
    }
    let data = libc::CMSG_DATA(cmsg) as *const RawFd;
    Some(ptr::read_unaligned(data))
}
