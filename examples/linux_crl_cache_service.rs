#[cfg(target_os = "linux")]
#[path = "service_common/mod.rs"]
mod service_common;

#[cfg(target_os = "linux")]
mod app {
    use super::service_common;
    use std::ffi::CStr;
    use std::path::{Path, PathBuf};
    use std::ptr;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};
    use sys_cert_store::api_types::{
        CERT_STORE_OPEN_EXISTING_FLAG, CERT_STORE_READONLY_FLAG, CERT_SYSTEM_STORE_LOCAL_MACHINE,
        FALSE,
    };
    use sys_cert_store::safe::{CertificateChainHandle, CertificateStore};
    use sys_cert_store::{GetLastError, SysCertGetLastErrorMessage, SysCertPopulateDotNetCrlCache};

    const DEFAULT_CONFIG_PATH: &str = "/etc/sys-cert-store/linux-crl-cache-service.conf";
    static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);

    struct Options {
        config: PathBuf,
        once: bool,
    }

    fn last_error(operation: &str) -> String {
        let message = SysCertGetLastErrorMessage();
        let detail = if message.is_null() {
            "no diagnostic message".into()
        } else {
            unsafe { CStr::from_ptr(message) }
                .to_string_lossy()
                .into_owned()
        };
        format!("{operation} failed (0x{:08x}): {detail}", GetLastError())
    }

    fn open_machine_my() -> Result<CertificateStore, String> {
        CertificateStore::open_system_with_flags(
            "MY",
            CERT_SYSTEM_STORE_LOCAL_MACHINE
                | CERT_STORE_OPEN_EXISTING_FLAG
                | CERT_STORE_READONLY_FLAG,
        )
        .map_err(|_| last_error("opening LocalMachine MY"))
    }

    fn build_chains(store: &CertificateStore) -> Result<(usize, usize), String> {
        let certificates = store
            .certificates()
            .map_err(|_| last_error("enumerating LocalMachine MY"))?;
        let mut failures = 0;
        let mut first_failure = None;

        for certificate in &certificates {
            if CertificateChainHandle::build(certificate, Some(store)).is_err() {
                failures += 1;
                first_failure.get_or_insert_with(|| last_error("building a certificate chain"));
            }
        }

        if let Some(first_failure) = first_failure {
            eprintln!("{failures} certificate chain(s) failed; first failure: {first_failure}");
        }
        Ok((certificates.len(), failures))
    }

    fn run_cycle() -> Result<(), String> {
        let store = open_machine_my()?;
        let (certificates, chain_failures) = build_chains(&store)?;
        // SAFETY: null selects the current account and requires no pointed-to
        // storage.
        if unsafe { SysCertPopulateDotNetCrlCache(ptr::null()) } == FALSE {
            return Err(last_error("populating the .NET CRL caches"));
        }
        eprintln!(
            "processed {certificates} LocalMachine MY certificate(s); \
             {chain_failures} chain failure(s); .NET CRL caches primed"
        );
        Ok(())
    }

    unsafe extern "C" fn stop_handler(_: libc::c_int) {
        STOP_REQUESTED.store(true, Ordering::SeqCst);
    }

    fn install_signal_handlers() {
        unsafe {
            let handler = stop_handler as *const () as libc::sighandler_t;
            libc::signal(libc::SIGINT, handler);
            libc::signal(libc::SIGTERM, handler);
        }
    }

    fn wait(duration: Duration) {
        let deadline = Instant::now() + duration;
        while !STOP_REQUESTED.load(Ordering::SeqCst) {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            std::thread::sleep(remaining.min(Duration::from_secs(1)));
        }
    }

    fn parse_options() -> Result<Options, String> {
        let mut config = PathBuf::from(DEFAULT_CONFIG_PATH);
        let mut once = false;
        let mut arguments = std::env::args_os().skip(1);
        while let Some(argument) = arguments.next() {
            if argument == "--once" {
                once = true;
            } else if argument == "--config" {
                config = arguments
                    .next()
                    .map(PathBuf::from)
                    .ok_or_else(|| "--config requires a path".to_owned())?;
            } else if argument == "--help" || argument == "-h" {
                println!(
                    "Usage: linux_crl_cache_service [--once] [--config PATH]\n\
                     Default configuration: {DEFAULT_CONFIG_PATH}"
                );
                std::process::exit(0);
            } else {
                return Err(format!("unknown argument: {}", argument.to_string_lossy()));
            }
        }
        Ok(Options { config, once })
    }

    fn run(options: Options) -> Result<(), String> {
        if options.once {
            return run_cycle();
        }

        install_signal_handlers();
        while !STOP_REQUESTED.load(Ordering::SeqCst) {
            if let Err(error) = run_cycle() {
                eprintln!("{error}");
            }
            let interval = service_common::read_interval(Path::new(&options.config))?;
            wait(interval);
        }
        Ok(())
    }

    pub fn main() {
        match parse_options().and_then(run) {
            Ok(()) => {}
            Err(error) => {
                eprintln!("{error}");
                std::process::exit(1);
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn main() {
    app::main();
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("linux_crl_cache_service is supported only on Linux");
    std::process::exit(1);
}
