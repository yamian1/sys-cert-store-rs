#[cfg(target_os = "linux")]
mod certutil_linux;

#[cfg(target_os = "linux")]
fn main() {
    certutil_linux::run();
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("certutil is currently supported only on Linux");
    std::process::exit(1);
}
