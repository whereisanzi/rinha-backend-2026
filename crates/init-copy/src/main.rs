use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;
use std::time::Instant;

const SRC: &str = "/index.bin";
const DST: &str = "/resources/index.bin";
const CHUNK: usize = 1024 * 1024;

fn main() -> std::io::Result<()> {
    let t0 = Instant::now();
    let mut src = File::open(SRC)?;
    let mut dst = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(DST)?;

    let src_fd = src.as_raw_fd();
    let dst_fd = dst.as_raw_fd();

    unsafe {
        libc::posix_fadvise(src_fd, 0, 0, libc::POSIX_FADV_SEQUENTIAL);
    }

    let mut buf = vec![0u8; CHUNK];
    let mut offset: i64 = 0;

    loop {
        let n = src.read(&mut buf)?;
        if n == 0 {
            break;
        }
        dst.write_all(&buf[..n])?;
        offset += n as i64;

        unsafe {
            libc::posix_fadvise(src_fd, 0, offset, libc::POSIX_FADV_DONTNEED);
        }
    }

    dst.flush()?;
    unsafe {
        libc::fdatasync(dst_fd);
        libc::posix_fadvise(dst_fd, 0, 0, libc::POSIX_FADV_DONTNEED);
    }

    eprintln!(
        "init-copy: {} -> {} ({} bytes in {:?})",
        SRC,
        DST,
        offset,
        t0.elapsed()
    );
    Ok(())
}
