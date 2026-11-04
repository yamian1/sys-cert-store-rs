#[cfg(target_os = "windows")]
#[path = "service_common/mod.rs"]
mod service_common;

#[cfg(target_os = "windows")]
mod app {
    use super::service_common;
    use core::ffi::c_void;
    use std::collections::HashSet;
    use std::ffi::CStr;
    use std::fs::{self, OpenOptions};
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use std::ptr;
    use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
    use std::time::{Duration, Instant, SystemTime};
    use sys_cert_store::api_types::*;
    use sys_cert_store::{
        CertAddCertificateContextToStore, CertCloseStore, CertEnumCertificatesInStore,
        CertFreeCertificateChain, CertFreeCertificateContext, CertGetCertificateChain,
        CertOpenStore, GetLastError,
    };
    use windows_sys::Win32::Foundation::{LocalFree, NO_ERROR};
    use windows_sys::Win32::Security::Cryptography as win;
    use windows_sys::Win32::System::Services as services;

    const SERVICE_NAME: &str = "SysCertStoreAiaService";
    const AIA_OID: &[u8] = b"1.3.6.1.5.5.7.1.1";
    const CA_ISSUERS_OID: &[u8] = b"1.3.6.1.5.5.7.48.2";
    const CERT_ALT_NAME_URL: DWORD = 7;
    const DOWNLOAD_TIMEOUT_MS: DWORD = 15_000;

    static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);
    static STATUS_HANDLE: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

    struct Store(HCERTSTORE);

    impl Drop for Store {
        fn drop(&mut self) {
            CertCloseStore(self.0, 0);
        }
    }

    struct Chain(*const CERT_CHAIN_CONTEXT);

    impl Drop for Chain {
        fn drop(&mut self) {
            CertFreeCertificateChain(self.0);
        }
    }

    struct LocalAllocation(*mut c_void);

    impl Drop for LocalAllocation {
        fn drop(&mut self) {
            unsafe {
                LocalFree(self.0);
            }
        }
    }

    struct Options {
        config: PathBuf,
        mode: Mode,
    }

    enum Mode {
        Service,
        Console,
        Once,
    }

    #[derive(Default)]
    struct FailureSummary {
        count: usize,
        first: String,
    }

    impl FailureSummary {
        fn add(&mut self, message: impl Into<String>) {
            self.count += 1;
            if self.first.is_empty() {
                self.first = message.into();
            }
        }
    }

    fn program_data_directory() -> PathBuf {
        std::env::var_os("ProgramData")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
            .join("sys-cert-store")
    }

    fn default_config_path() -> PathBuf {
        program_data_directory().join("windows-aia-service.conf")
    }

    fn log(message: &str) {
        let directory = program_data_directory();
        if fs::create_dir_all(&directory).is_err() {
            eprintln!("{message}");
            return;
        }
        let path = directory.join("windows-aia-service.log");
        match OpenOptions::new().create(true).append(true).open(path) {
            Ok(mut file) => {
                let _ = writeln!(file, "{:?} {message}", SystemTime::now());
            }
            Err(_) => eprintln!("{message}"),
        }
    }

    fn error(operation: &str) -> String {
        format!("{operation} failed (0x{:08x})", GetLastError())
    }

    fn wide(value: &str) -> Vec<WCHAR> {
        value.encode_utf16().chain([0]).collect()
    }

    fn wide_string(pointer: LPCWSTR) -> Result<String, String> {
        if pointer.is_null() {
            return Err("AIA URL is null".to_owned());
        }
        let mut length = 0usize;
        while unsafe { *pointer.add(length) } != 0 {
            length += 1;
            if length > 32_768 {
                return Err("AIA URL exceeds 32,768 UTF-16 code units".to_owned());
            }
        }
        String::from_utf16(unsafe { std::slice::from_raw_parts(pointer, length) })
            .map_err(|_| "AIA URL contains invalid UTF-16".to_owned())
    }

    fn open_machine_store(name: &str, read_only: bool) -> Result<Store, String> {
        let name = wide(name);
        let mut flags = CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_OPEN_EXISTING_FLAG;
        if read_only {
            flags |= CERT_STORE_READONLY_FLAG;
        }
        let store = CertOpenStore(
            PROVIDER_SYSTEM_W as LPCSTR,
            0,
            0,
            flags,
            name.as_ptr().cast(),
        );
        if store.is_null() {
            Err(error("opening a LocalMachine certificate store"))
        } else {
            Ok(Store(store))
        }
    }

    unsafe fn aia_urls(certificate: *const CERT_CONTEXT) -> Result<Vec<String>, String> {
        let information = unsafe {
            certificate
                .as_ref()
                .and_then(|context| context.pCertInfo.as_ref())
        }
        .ok_or_else(|| "certificate context has no CERT_INFO".to_owned())?;
        if information.cExtension == 0 {
            return Ok(Vec::new());
        }
        if information.rgExtension.is_null() {
            return Err("certificate has a null extension array".to_owned());
        }

        let extensions = unsafe {
            std::slice::from_raw_parts(information.rgExtension, information.cExtension as usize)
        };
        let Some(extension) = extensions.iter().find(|extension| {
            !extension.pszObjId.is_null()
                && unsafe { CStr::from_ptr(extension.pszObjId) }.to_bytes() == AIA_OID
        }) else {
            return Ok(Vec::new());
        };

        let mut decoded = ptr::null_mut();
        let mut decoded_size = 0;
        if unsafe {
            win::CryptDecodeObjectEx(
                X509_ASN_ENCODING,
                win::X509_AUTHORITY_INFO_ACCESS,
                extension.Value.pbData,
                extension.Value.cbData,
                win::CRYPT_DECODE_ALLOC_FLAG,
                ptr::null(),
                (&mut decoded as *mut *mut c_void).cast(),
                &mut decoded_size,
            )
        } == FALSE
        {
            return Err(error("decoding an Authority Information Access extension"));
        }
        let allocation = LocalAllocation(decoded);
        let access = unsafe {
            allocation
                .0
                .cast::<win::CERT_AUTHORITY_INFO_ACCESS>()
                .as_ref()
        }
        .ok_or_else(|| "decoded AIA extension is null".to_owned())?;
        if access.cAccDescr == 0 {
            return Ok(Vec::new());
        }
        if access.rgAccDescr.is_null() {
            return Err("decoded AIA extension has a null description array".to_owned());
        }

        let descriptions =
            unsafe { std::slice::from_raw_parts(access.rgAccDescr, access.cAccDescr as usize) };
        let mut urls = Vec::new();
        for description in descriptions {
            if description.pszAccessMethod.is_null()
                || unsafe { CStr::from_ptr(description.pszAccessMethod.cast()) }.to_bytes()
                    != CA_ISSUERS_OID
                || description.AccessLocation.dwAltNameChoice != CERT_ALT_NAME_URL
            {
                continue;
            }
            urls.push(wide_string(unsafe {
                description.AccessLocation.Anonymous.pwszURL
            })?);
        }
        Ok(urls)
    }

    fn download_and_install(url: &str, ca_store: HCERTSTORE) -> Result<(), String> {
        let url = wide(url);
        let mut object = ptr::null_mut();
        if unsafe {
            win::CryptRetrieveObjectByUrlW(
                url.as_ptr(),
                win::CONTEXT_OID_CERTIFICATE,
                0,
                DOWNLOAD_TIMEOUT_MS,
                &mut object,
                0,
                ptr::null(),
                ptr::null(),
                ptr::null_mut(),
            )
        } == FALSE
        {
            return Err(error("downloading an AIA issuer certificate"));
        }

        let certificate = object.cast::<CERT_CONTEXT>();
        let added = CertAddCertificateContextToStore(
            ca_store,
            certificate,
            CERT_STORE_ADD_USE_EXISTING,
            ptr::null_mut(),
        );
        CertFreeCertificateContext(certificate);
        if added == FALSE {
            Err(error(
                "installing an AIA issuer certificate in LocalMachine CA",
            ))
        } else {
            Ok(())
        }
    }

    unsafe fn process_chain(
        chain: *const CERT_CHAIN_CONTEXT,
        ca_store: HCERTSTORE,
        seen_urls: &mut HashSet<String>,
        failures: &mut FailureSummary,
    ) -> Result<usize, String> {
        let chain = unsafe { chain.as_ref() }
            .ok_or_else(|| "certificate chain context is null".to_owned())?;
        if chain.cChain != 0 && chain.rgpChain.is_null() {
            return Err("certificate chain has a null simple-chain array".to_owned());
        }
        let simple_chains =
            unsafe { std::slice::from_raw_parts(chain.rgpChain, chain.cChain as usize) };
        let mut installed = 0;
        for simple_chain in simple_chains {
            let simple_chain = unsafe { simple_chain.as_ref() }
                .ok_or_else(|| "certificate chain contains a null simple chain".to_owned())?;
            if simple_chain.cElement != 0 && simple_chain.rgpElement.is_null() {
                return Err("simple chain has a null element array".to_owned());
            }
            let elements = unsafe {
                std::slice::from_raw_parts(simple_chain.rgpElement, simple_chain.cElement as usize)
            };
            for element in elements {
                let element = unsafe { element.as_ref() }
                    .ok_or_else(|| "simple chain contains a null element".to_owned())?;
                let urls = match unsafe { aia_urls(element.pCertContext) } {
                    Ok(urls) => urls,
                    Err(error) => {
                        failures.add(error);
                        continue;
                    }
                };
                for url in urls {
                    if seen_urls.insert(url.clone()) {
                        match download_and_install(&url, ca_store) {
                            Ok(()) => {
                                installed += 1;
                                log(&format!("installed AIA issuer certificate from {url}"));
                            }
                            Err(error) => failures.add(format!("{url}: {error}")),
                        }
                    }
                }
            }
        }
        Ok(installed)
    }

    fn run_cycle() -> Result<(), String> {
        let my_store = open_machine_store("MY", true)?;
        let ca_store = open_machine_store("CA", false)?;
        let parameters = CERT_CHAIN_PARA {
            cbSize: std::mem::size_of::<CERT_CHAIN_PARA>() as DWORD,
            ..CERT_CHAIN_PARA::default()
        };
        let mut certificate = ptr::null();
        let mut certificates = 0;
        let mut installed = 0;
        let mut seen_urls = HashSet::new();
        let mut failures = FailureSummary::default();

        loop {
            certificate = CertEnumCertificatesInStore(my_store.0, certificate);
            if certificate.is_null() {
                if GetLastError() == CRYPT_E_NOT_FOUND {
                    break;
                }
                return Err(error("enumerating LocalMachine MY"));
            }
            certificates += 1;
            let mut chain = ptr::null();
            if CertGetCertificateChain(
                ptr::null_mut(),
                certificate,
                ptr::null(),
                my_store.0,
                &parameters,
                0,
                ptr::null_mut(),
                &mut chain,
            ) == FALSE
            {
                failures.add(error("building a certificate chain"));
                continue;
            }
            let chain = Chain(chain);
            installed +=
                unsafe { process_chain(chain.0, ca_store.0, &mut seen_urls, &mut failures) }?;
        }

        log(&format!(
            "processed {certificates} LocalMachine MY certificate(s); \
             installed {installed} AIA issuer certificate(s); {} failure(s)",
            failures.count
        ));
        if failures.count != 0 {
            log(&format!("first AIA processing failure: {}", failures.first));
        }
        Ok(())
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

    fn run_loop(config: &Path) -> Result<(), String> {
        while !STOP_REQUESTED.load(Ordering::SeqCst) {
            if let Err(error) = run_cycle() {
                log(&error);
            }
            let interval = service_common::read_interval(config)?;
            wait(interval);
        }
        Ok(())
    }

    fn report_status(state: DWORD, accepted: DWORD, exit_code: DWORD, wait_hint: DWORD) {
        let handle = STATUS_HANDLE.load(Ordering::SeqCst);
        if handle.is_null() {
            return;
        }
        let status = services::SERVICE_STATUS {
            dwServiceType: services::SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState: state,
            dwControlsAccepted: accepted,
            dwWin32ExitCode: exit_code,
            dwServiceSpecificExitCode: 0,
            dwCheckPoint: 0,
            dwWaitHint: wait_hint,
        };
        unsafe {
            services::SetServiceStatus(handle, &status);
        }
    }

    unsafe extern "system" fn control_handler(
        control: DWORD,
        _: DWORD,
        _: *mut c_void,
        _: *mut c_void,
    ) -> DWORD {
        if control == services::SERVICE_CONTROL_STOP {
            STOP_REQUESTED.store(true, Ordering::SeqCst);
            report_status(services::SERVICE_STOP_PENDING, 0, NO_ERROR, 5_000);
        }
        NO_ERROR
    }

    fn run_service() -> Result<(), String> {
        STOP_REQUESTED.store(false, Ordering::SeqCst);
        let service_name = wide(SERVICE_NAME);
        let handle = unsafe {
            services::RegisterServiceCtrlHandlerExW(
                service_name.as_ptr(),
                Some(control_handler),
                ptr::null(),
            )
        };
        if handle.is_null() {
            return Err(error("registering the Windows service control handler"));
        }
        STATUS_HANDLE.store(handle, Ordering::SeqCst);
        report_status(services::SERVICE_START_PENDING, 0, NO_ERROR, 5_000);
        report_status(
            services::SERVICE_RUNNING,
            services::SERVICE_ACCEPT_STOP,
            NO_ERROR,
            0,
        );

        let result = run_loop(&default_config_path());
        let exit_code = if result.is_ok() {
            NO_ERROR
        } else {
            ERROR_GEN_FAILURE
        };
        if let Err(error) = &result {
            log(error);
        }
        report_status(services::SERVICE_STOPPED, 0, exit_code, 0);
        result
    }

    unsafe extern "system" fn service_main(_: DWORD, _: *mut *mut WCHAR) {
        let result = std::panic::catch_unwind(run_service);
        if result.is_err() {
            log("the Windows service panicked");
            report_status(services::SERVICE_STOPPED, 0, ERROR_GEN_FAILURE, 0);
        }
    }

    fn run_dispatcher() -> Result<(), String> {
        let mut service_name = wide(SERVICE_NAME);
        let entries = [
            services::SERVICE_TABLE_ENTRYW {
                lpServiceName: service_name.as_mut_ptr(),
                lpServiceProc: Some(service_main),
            },
            services::SERVICE_TABLE_ENTRYW::default(),
        ];
        if unsafe { services::StartServiceCtrlDispatcherW(entries.as_ptr()) } == FALSE {
            Err(error("starting the Windows service dispatcher"))
        } else {
            Ok(())
        }
    }

    fn parse_options() -> Result<Options, String> {
        let mut config = default_config_path();
        let mut mode = Mode::Service;
        let mut arguments = std::env::args_os().skip(1);
        while let Some(argument) = arguments.next() {
            if argument == "--once" {
                mode = Mode::Once;
            } else if argument == "--console" {
                mode = Mode::Console;
            } else if argument == "--config" {
                config = arguments
                    .next()
                    .map(PathBuf::from)
                    .ok_or_else(|| "--config requires a path".to_owned())?;
            } else if argument == "--help" || argument == "-h" {
                println!(
                    "Usage: windows_aia_service [--once | --console] [--config PATH]\n\
                     Without arguments, the executable connects to the Windows SCM.\n\
                     Default configuration: {}",
                    default_config_path().display()
                );
                std::process::exit(0);
            } else {
                return Err(format!("unknown argument: {}", argument.to_string_lossy()));
            }
        }
        if matches!(mode, Mode::Service) && config != default_config_path() {
            return Err("--config requires --once or --console".to_owned());
        }
        Ok(Options { config, mode })
    }

    fn run(options: Options) -> Result<(), String> {
        match options.mode {
            Mode::Service => run_dispatcher(),
            Mode::Once => run_cycle(),
            Mode::Console => {
                STOP_REQUESTED.store(false, Ordering::SeqCst);
                run_loop(&options.config)
            }
        }
    }

    pub fn main() {
        match parse_options().and_then(run) {
            Ok(()) => {}
            Err(error) => {
                log(&error);
                eprintln!("{error}");
                std::process::exit(1);
            }
        }
    }
}

#[cfg(target_os = "windows")]
fn main() {
    app::main();
}

#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("windows_aia_service is supported only on Windows");
    std::process::exit(1);
}
