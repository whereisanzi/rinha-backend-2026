#[cfg(target_os = "linux")]
mod proxy;

#[cfg(target_os = "linux")]
fn main() -> std::io::Result<()> {
    proxy::run()
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("lb requires Linux (epoll); current OS = {}", std::env::consts::OS);
    std::process::exit(1);
}
