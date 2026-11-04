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
    use sys_cert_store::api_types::*;
    use sys_cert_store::{
        CertCloseStore, CertEnumCertificatesInStore, CertFreeCertificateChain,
        CertGetCertificateChain, CertOpenStore, GetLastError, SysCertGetLastErrorMessage,
        SysCertPopulateDotNetCrlCache,
    };

    const DEFAULT_CONFIG_PATH: &str = "/etc/sys-cert-store/linux-crl-cache-service.conf";
    static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);

    struct Store(HCERTSTORE);

    impl Drop for Store {
        fn drop(&mut self) {
            CertCloseStore(self.0, 0);
        }
    }

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

    fn wide(value: &str) -> Vec<WCHAR> {
        value.encode_utf16().chain([0]).collect()
    }

    fn open_machine_my() -> Result<Store, String> {
        let name = wide("MY");
        let store = CertOpenStore(
            PROVIDER_SYSTEM_W as LPCSTR,
            0,
            0,
            CERT_SYSTEM_STORE_LOCAL_MACHINE
                | CERT_STORE_OPEN_EXISTING_FLAG
                | CERT_STORE_READONLY_FLAG,
            name.as_ptr().cast(),
        );
        if store.is_null() {
            Err(last_error("opening LocalMachine MY"))
        } else {
            Ok(Store(store))
        }
    }

    fn build_chains(store: HCERTSTORE) -> Result<(usize, usize), String> {
        let parameters = CERT_CHAIN_PARA {
            cbSize: std::mem::size_of::<CERT_CHAIN_PARA>() as DWORD,
            ..CERT_CHAIN_PARA::default()
        };
        let mut certificate = ptr::null();
        let mut certificates = 0;
        let mut failures = 0;
        let mut first_failure = None;

        loop {
            certificate = CertEnumCertificatesInStore(store, certificate);
            if certificate.is_null() {
                if GetLastError() == CRYPT_E_NOT_FOUND {
                    break;
                }
                return Err(last_error("enumerating LocalMachine MY"));
            }
            certificates += 1;
            let mut chain = ptr::null();
            if CertGetCertificateChain(
                ptr::null_mut(),
                certificate,
                ptr::null(),
                store,
                &parameters,
                0,
                ptr::null_mut(),
                &mut chain,
            ) == FALSE
            {
                failures += 1;
                first_failure.get_or_insert_with(|| last_error("building a certificate chain"));
                continue;
            }
            CertFreeCertificateChain(chain);
        }

        if let Some(first_failure) = first_failure {
            eprintln!("{failures} certificate chain(s) failed; first failure: {first_failure}");
        }
        Ok((certificates, failures))
    }

    fn run_cycle() -> Result<(), String> {
        let store = open_machine_my()?;
        let (certificates, chain_failures) = build_chains(store.0)?;
        if SysCertPopulateDotNetCrlCache(ptr::null()) == FALSE {
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
