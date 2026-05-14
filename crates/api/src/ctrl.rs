use std::os::unix::io::RawFd;
use std::os::unix::net::UnixListener;
use std::path::Path;

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

pub unsafe fn extract_fd(msg: &libc::msghdr) -> Option<RawFd> {
    let cmsg = libc::CMSG_FIRSTHDR(msg);
    if cmsg.is_null() {
        return None;
    }
    if (*cmsg).cmsg_level != libc::SOL_SOCKET || (*cmsg).cmsg_type != libc::SCM_RIGHTS {
        return None;
    }
    let data = libc::CMSG_DATA(cmsg) as *const RawFd;
    Some(std::ptr::read_unaligned(data))
}
