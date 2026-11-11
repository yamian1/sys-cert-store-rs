use std::ffi::{CStr, CString};
use std::fs::{self, OpenOptions};
use std::io::{IsTerminal, Write};
use std::mem::MaybeUninit;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::ptr;
use sys_cert_store::api_types::*;
use sys_cert_store::cert::Certificate as NativeCertificate;
use sys_cert_store::*;
use zeroize::Zeroizing;

const HELP: &str = r#"sys-cert-store certutil (Linux; not NSS certutil)
Usage: certutil [options] command [arguments]
  -enumstore                           List stores (ROOT, CA, MY and custom)
  -store [Store [CertId [OutFile]]]   Show certificates; default store CA
  -addstore Store InFile              Import PEM/DER certificates or PKCS#7
  -delstore Store CertId              Delete exactly one matching certificate
  -importPFX [Store] InFile           Import a PFX and its key; default MY
  -exportPFX [Store] CertId OutFile [NoChain|NoRoot]
                                       Export one key and certificate chain
  -dump InFile                         Show PEM/DER certificates or PKCS#7
  -? | --help                          Show this help

Options:
  -user | -machine                     User or computer scope (default computer)
  -f                                   Replace an addstore match or output file
  -v                                   Full certificate details for store/dump
  -p Password                          PFX password (visible in process arguments)
  --password-file File                 Read password from a private UTF-8 file
  --format der|pem|pkcs7               Format for -store OutFile (default DER)
  --allow-native-write                 Explicit permission for computer ROOT writes
  --user-store-dir Dir                 Relocate user metadata (absolute path)
  --machine-store-dir Dir              Relocate computer metadata (absolute path)
  --system-root Dir                    Relocate native trust paths, NOT a sandbox
  --                                   End options; remaining tokens are arguments

CertId: zero-based index, serial hex, SHA-1/SHA-256 hash, subject substring, or *.
Disambiguate with index:, serial:, sha1:, sha256:, or subject: prefixes.
"#;

#[derive(Default)]
struct Options {
    command: String,
    args: Vec<String>,
    scope: DWORD,
    force: bool,
    verbose: bool,
    native_write: bool,
    help: bool,
    format: Option<String>,
    password: Option<Zeroizing<String>>,
    password_file: Option<PathBuf>,
    user_directory: Option<CString>,
    machine_directory: Option<CString>,
    system_root: Option<CString>,
}

#[derive(Debug)]
struct Usage(String);

fn usage(condition: bool, message: impl Into<String>) -> Result<(), Usage> {
    if condition {
        Ok(())
    } else {
        Err(Usage(message.into()))
    }
}

fn lower(value: &str) -> String {
    value.to_ascii_lowercase()
}

fn parse_options() -> Result<Options, Usage> {
    let arguments = Zeroizing::new(std::env::args().skip(1).collect::<Vec<_>>());
    let mut result = Options {
        scope: CERT_SYSTEM_STORE_LOCAL_MACHINE,
        ..Options::default()
    };
    let mut positional = false;
    let mut scope_set = false;
    let commands = [
        "-enumstore",
        "-store",
        "-addstore",
        "-delstore",
        "-importpfx",
        "-exportpfx",
        "-dump",
    ];
    let mut index = 0;
    while index < arguments.len() {
        let token = &arguments[index];
        let name = lower(token);
        let mut value = || -> Result<String, Usage> {
            index += 1;
            usage(
                index < arguments.len(),
                format!("Missing value for {token}"),
            )?;
            Ok(arguments[index].clone())
        };
        if positional {
            result.args.push(token.clone());
        } else if name == "--" {
            positional = true;
        } else if matches!(name.as_str(), "-?" | "--help" | "-h") {
            result.help = true;
        } else if commands.contains(&name.as_str()) {
            usage(result.command.is_empty(), "Specify exactly one command")?;
            result.command = name;
        } else if matches!(name.as_str(), "-user" | "-machine") {
            usage(!scope_set, "Specify scope only once")?;
            result.scope = if name == "-user" {
                CERT_SYSTEM_STORE_CURRENT_USER
            } else {
                CERT_SYSTEM_STORE_LOCAL_MACHINE
            };
            scope_set = true;
        } else if name == "-f" {
            result.force = true;
        } else if name == "-v" {
            result.verbose = true;
        } else if name == "--allow-native-write" {
            result.native_write = true;
        } else if name == "-p" {
            usage(
                result.password.is_none() && result.password_file.is_none(),
                "Specify one password source",
            )?;
            result.password = Some(Zeroizing::new(value()?));
        } else if name == "--password-file" {
            usage(
                result.password.is_none() && result.password_file.is_none(),
                "Specify one password source",
            )?;
            result.password_file = Some(PathBuf::from(value()?));
        } else if name == "--format" {
            result.format = Some(lower(&value()?));
        } else if name == "--user-store-dir" {
            result.user_directory =
                Some(CString::new(value()?).map_err(|_| Usage("Path contains NUL".into()))?);
        } else if name == "--machine-store-dir" {
            result.machine_directory =
                Some(CString::new(value()?).map_err(|_| Usage("Path contains NUL".into()))?);
        } else if name == "--system-root" {
            result.system_root =
                Some(CString::new(value()?).map_err(|_| Usage("Path contains NUL".into()))?);
        } else if token.starts_with('-') {
            return Err(Usage(format!("Unsupported command or option: {token}")));
        } else {
            result.args.push(token.clone());
        }
        index += 1;
    }
    if result.help || arguments.is_empty() {
        result.help = true;
        return Ok(result);
    }
    if result.command.is_empty() && result.args.len() == 1 {
        result.command = "-dump".into();
    }
    usage(
        !result.command.is_empty(),
        "Missing command; use -? for help",
    )?;
    let count = result.args.len();
    usage(
        (result.command == "-enumstore" && count == 0)
            || (result.command == "-store" && count <= 3)
            || (matches!(result.command.as_str(), "-addstore" | "-delstore") && count == 2)
            || (result.command == "-importpfx" && (1..=2).contains(&count))
            || (result.command == "-exportpfx" && (2..=4).contains(&count))
            || (result.command == "-dump" && count == 1),
        format!(
            "Invalid arguments for {}; use -? for syntax",
            result.command
        ),
    )?;
    usage(
        result.format.is_none() || (result.command == "-store" && count == 3),
        "--format requires -store with an output file",
    )?;
    usage(
        result
            .format
            .as_deref()
            .is_none_or(|value| matches!(value, "der" | "pem" | "pkcs7")),
        "Unsupported output format",
    )?;
    usage(
        !result.verbose || matches!(result.command.as_str(), "-store" | "-dump"),
        "-v requires -store or -dump",
    )?;
    usage(
        (result.password.is_none() && result.password_file.is_none())
            || matches!(result.command.as_str(), "-importpfx" | "-exportpfx"),
        "Password options require a PFX command",
    )?;
    usage(
        !result.force
            || result.command == "-addstore"
            || result.command == "-exportpfx"
            || (result.command == "-store" && count == 3),
        "-f is supported only for -addstore and output-file replacement",
    )?;
    usage(
        !result.native_write
            || (result.scope == CERT_SYSTEM_STORE_LOCAL_MACHINE
                && matches!(result.command.as_str(), "-addstore" | "-delstore")
                && result
                    .args
                    .first()
                    .is_some_and(|value| value.eq_ignore_ascii_case("ROOT"))),
        "--allow-native-write requires computer ROOT -addstore or -delstore",
    )?;
    usage(
        !(result.scope == CERT_SYSTEM_STORE_LOCAL_MACHINE
            && matches!(result.command.as_str(), "-addstore" | "-delstore")
            && result
                .args
                .first()
                .is_some_and(|value| value.eq_ignore_ascii_case("ROOT")))
            || result.native_write,
        "Computer ROOT changes require --allow-native-write (and OS permission)",
    )?;
    usage(
        !(result.command == "-exportpfx"
            && result
                .password
                .as_ref()
                .is_some_and(|value| value.is_empty())),
        "PFX export requires a nonempty password",
    )?;
    Ok(result)
}

fn api<T>(success: bool, value: T, operation: &str) -> Result<T, String> {
    if success {
        Ok(value)
    } else {
        let message = unsafe { CStr::from_ptr(SysCertGetLastErrorMessage()) }.to_string_lossy();
        Err(format!(
            "{operation} failed (0x{:x}): {message}",
            GetLastError()
        ))
    }
}

fn wide(value: &str) -> Vec<WCHAR> {
    value.encode_utf16().chain([0]).collect()
}

fn configure(options: &Options) -> Result<(), String> {
    let configuration = SYS_CERT_STORE_CONFIGURATION {
        cbSize: std::mem::size_of::<SYS_CERT_STORE_CONFIGURATION>() as DWORD,
        userStoreDirectory: options
            .user_directory
            .as_ref()
            .map_or(ptr::null(), |value| value.as_ptr()),
        machineStoreDirectory: options
            .machine_directory
            .as_ref()
            .map_or(ptr::null(), |value| value.as_ptr()),
        systemRoot: options
            .system_root
            .as_ref()
            .map_or(ptr::null(), |value| value.as_ptr()),
    };
    api(
        // SAFETY: the configuration and all optional C strings remain live
        // for the synchronous call.
        unsafe { SysCertConfigureSystemStores(&configuration) } != FALSE,
        (),
        "Configure store paths",
    )
}

struct Store(HCERTSTORE);
impl Drop for Store {
    fn drop(&mut self) {
        if !self.0.is_null() {
            CertCloseStore(self.0, 0);
        }
    }
}

struct CertificateContext(*const CERT_CONTEXT);
impl Drop for CertificateContext {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this wrapper owns one live context reference.
            unsafe { CertFreeCertificateContext(self.0) };
        }
    }
}

struct CertificateChain(*const CERT_CHAIN_CONTEXT);
impl Drop for CertificateChain {
    fn drop(&mut self) {
        // SAFETY: this wrapper owns one live chain allocation.
        unsafe { CertFreeCertificateChain(self.0) };
    }
}

struct Entry {
    context: CertificateContext,
    certificate: NativeCertificate,
    index: usize,
    origin: DWORD,
}

fn open_store(options: &Options, name: &str, write: bool) -> Result<Store, String> {
    if write
        && options.scope == CERT_SYSTEM_STORE_LOCAL_MACHINE
        && name.eq_ignore_ascii_case("ROOT")
        && !options.native_write
    {
        return Err(
            "Computer ROOT changes require --allow-native-write (and OS permission)".into(),
        );
    }
    let name = CString::new(name).map_err(|_| "Store name contains NUL")?;
    let flags = options.scope
        | if write { 0 } else { CERT_STORE_READONLY_FLAG }
        | if options.native_write {
            SYS_CERT_STORE_NATIVE_WRITE_FLAG
        } else {
            0
        };
    // SAFETY: the provider constant is valid and `name` is a live terminated
    // C string for the synchronous call.
    let handle = unsafe {
        CertOpenStore(
            PROVIDER_SYSTEM_A as LPCSTR,
            0,
            0,
            flags,
            name.as_ptr().cast(),
        )
    };
    api(!handle.is_null(), Store(handle), "Open store")
}

fn entries(store: &Store) -> Result<Vec<Entry>, String> {
    let mut result = Vec::new();
    let mut cursor = ptr::null();
    loop {
        // SAFETY: the store is live and `cursor` is null or the preceding
        // enumeration result, which this call consumes.
        cursor = unsafe { CertEnumCertificatesInStore(store.0, cursor) };
        if cursor.is_null() {
            if GetLastError() == CRYPT_E_NOT_FOUND {
                break;
            }
            return api(false, result, "Enumerate certificates");
        }
        // SAFETY: `cursor` is live until the next enumeration call.
        let retained = unsafe { CertDuplicateCertificateContext(cursor) };
        api(!retained.is_null(), (), "Retain certificate")?;
        let public = unsafe { &*retained };
        let der = unsafe {
            std::slice::from_raw_parts(public.pbCertEncoded, public.cbCertEncoded as usize)
        };
        let certificate = NativeCertificate::from_der(der).map_err(|error| error.message)?;
        let mut origin = 0;
        api(
            // SAFETY: `retained` is live and `origin` is writable.
            unsafe { SysCertGetCertificateStoreLocation(retained, &mut origin) } != FALSE,
            (),
            "Get certificate location",
        )?;
        result.push(Entry {
            context: CertificateContext(retained),
            certificate,
            index: result.len(),
            origin,
        });
    }
    Ok(result)
}

fn hex_bytes(value: &[u8]) -> String {
    hex::encode(value)
}

fn certificate_name(context: *const CERT_CONTEXT, issuer: bool) -> Result<String, String> {
    let flags = if issuer { CERT_NAME_ISSUER_FLAG } else { 0 };
    // SAFETY: `context` is supplied by a live entry and null output requests
    // the required size.
    let size = unsafe {
        CertGetNameStringA(
            context,
            CERT_NAME_RDN_TYPE,
            flags,
            ptr::null(),
            ptr::null_mut(),
            0,
        )
    };
    api(size != 0, (), "Size certificate name")?;
    let mut output = vec![libc::c_char::default(); size as usize];
    api(
        // SAFETY: `context` is live and `output` is writable for `size`
        // elements.
        unsafe {
            CertGetNameStringA(
                context,
                CERT_NAME_RDN_TYPE,
                flags,
                ptr::null(),
                output.as_mut_ptr(),
                size,
            )
        } != 0,
        (),
        "Format certificate name",
    )?;
    Ok(unsafe { CStr::from_ptr(output.as_ptr()) }
        .to_string_lossy()
        .into_owned())
}

fn certificate_pem(certificate: &NativeCertificate) -> Result<Vec<u8>, String> {
    let der = certificate.to_der();
    let mut size = 0;
    api(
        // SAFETY: `der` is readable for its reported length and null output
        // requests the required size.
        unsafe {
            CryptBinaryToStringA(
                der.as_ptr(),
                der.len() as DWORD,
                CRYPT_STRING_BASE64HEADER,
                ptr::null_mut(),
                &mut size,
            )
        } != FALSE,
        (),
        "Size certificate PEM",
    )?;
    let mut output = vec![0u8; size as usize];
    api(
        // SAFETY: `der` is readable and `output` is writable for the size
        // returned by the preceding call.
        unsafe {
            CryptBinaryToStringA(
                der.as_ptr(),
                der.len() as DWORD,
                CRYPT_STRING_BASE64HEADER,
                output.as_mut_ptr().cast(),
                &mut size,
            )
        } != FALSE,
        (),
        "Encode certificate PEM",
    )?;
    output.truncate(size.saturating_sub(1) as usize);
    Ok(output)
}

fn show(
    context: *const CERT_CONTEXT,
    certificate: &NativeCertificate,
    index: usize,
    verbose: bool,
    origin: Option<(DWORD, DWORD)>,
) -> Result<(), String> {
    println!(
        "================ Certificate {index} ================\nSerial Number: {}\nIssuer: {}\n NotBefore: {}\n NotAfter: {}\nSubject: {}\nCert Hash(sha1): {}\nCert Hash(sha256): {}",
        certificate.serial_hex().map_err(|error| error.message)?,
        certificate_name(context, true)?,
        certificate
            .not_before_text()
            .map_err(|error| error.message)?,
        certificate
            .not_after_text()
            .map_err(|error| error.message)?,
        certificate_name(context, false)?,
        hex_bytes(&certificate.sha1_fingerprint()),
        hex_bytes(&certificate.sha256_fingerprint()),
    );
    if let Some((origin, scope)) = origin {
        print!(
            "Location: {}",
            if origin == CERT_SYSTEM_STORE_CURRENT_USER {
                "CurrentUser"
            } else {
                "LocalMachine"
            }
        );
        if origin != scope {
            print!(" (inherited, read-only)");
        }
        println!();
    }
    if verbose {
        print!(
            "{}",
            String::from_utf8_lossy(&certificate_pem(certificate)?)
        );
    }
    Ok(())
}

fn read_file(path: &Path) -> Result<Vec<u8>, String> {
    let data = fs::read(path).map_err(|_| format!("Cannot open input file: {}", path.display()))?;
    if data.is_empty() || data.len() > i32::MAX as usize {
        return Err(format!(
            "Input must contain 1..INT_MAX bytes: {}",
            path.display()
        ));
    }
    Ok(data)
}

fn pkcs7_certificates(data: &[u8]) -> Result<Vec<NativeCertificate>, String> {
    let mut data = data.to_vec();
    let blob = CRYPT_DATA_BLOB {
        cbData: data.len() as DWORD,
        pbData: data.as_mut_ptr(),
    };
    // SAFETY: the blob describes the live `data` buffer for the synchronous
    // open operation.
    let store = Store(unsafe {
        CertOpenStore(
            PROVIDER_PKCS7 as LPCSTR,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0,
            CERT_STORE_READONLY_FLAG,
            (&blob as *const CRYPT_DATA_BLOB).cast(),
        )
    });
    api(!store.0.is_null(), (), "Open PKCS#7 certificate store")?;
    let mut result = Vec::new();
    let mut cursor = ptr::null();
    loop {
        // SAFETY: the store is live and `cursor` is null or the preceding
        // enumeration result, which this call consumes.
        cursor = unsafe { CertEnumCertificatesInStore(store.0, cursor) };
        if cursor.is_null() {
            if GetLastError() == CRYPT_E_NOT_FOUND {
                break;
            }
            return api(false, result, "Enumerate PKCS#7 certificates");
        }
        let public = unsafe { &*cursor };
        let der = unsafe {
            std::slice::from_raw_parts(public.pbCertEncoded, public.cbCertEncoded as usize)
        };
        result.push(NativeCertificate::from_der(der).map_err(|error| error.message)?);
    }
    Ok(result)
}

fn decode_pem(block: &str) -> Result<Vec<u8>, String> {
    let block = CString::new(block).map_err(|_| "PEM block contains NUL")?;
    let mut size = 0;
    api(
        // SAFETY: `block` is a live terminated C string and null output
        // requests the decoded size.
        unsafe {
            CryptStringToBinaryA(
                block.as_ptr(),
                0,
                CRYPT_STRING_ANY,
                ptr::null_mut(),
                &mut size,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        } != FALSE,
        (),
        "Size decoded PEM",
    )?;
    let mut output = vec![0u8; size as usize];
    api(
        // SAFETY: `block` remains live and `output` is writable for the size
        // returned by the preceding call.
        unsafe {
            CryptStringToBinaryA(
                block.as_ptr(),
                0,
                CRYPT_STRING_ANY,
                output.as_mut_ptr(),
                &mut size,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        } != FALSE,
        (),
        "Decode PEM",
    )?;
    output.truncate(size as usize);
    Ok(output)
}

fn certificates(data: &[u8]) -> Result<Vec<NativeCertificate>, String> {
    let text = std::str::from_utf8(data).ok();
    if text.is_some_and(|value| value.trim_start().starts_with("-----BEGIN ")) {
        let mut remainder = text.unwrap().trim_start();
        let mut result = Vec::new();
        while !remainder.is_empty() {
            let (end_marker, pkcs7) = if remainder.starts_with("-----BEGIN CERTIFICATE-----") {
                ("-----END CERTIFICATE-----", false)
            } else if remainder.starts_with("-----BEGIN PKCS7-----") {
                ("-----END PKCS7-----", true)
            } else {
                return Err("Unsupported PEM block; expected CERTIFICATE or PKCS7".into());
            };
            let end = remainder.find(end_marker).ok_or("Truncated PEM block")? + end_marker.len();
            let block = &remainder[..end];
            if pkcs7 {
                let der = decode_pem(block)?;
                result.extend(pkcs7_certificates(&der)?);
            } else {
                result.push(
                    NativeCertificate::from_der(&decode_pem(block)?)
                        .map_err(|_| "Invalid PEM certificate")?,
                );
            }
            remainder = remainder[end..].trim_start();
        }
        return Ok(result);
    }
    if let Ok(certificate) = NativeCertificate::from_der(data) {
        return Ok(vec![certificate]);
    }
    pkcs7_certificates(data)
        .map_err(|_| "Input is not a complete PEM/DER certificate or PKCS#7 container".into())
}

fn normalized_hex(value: &str) -> Option<String> {
    let value = lower(value).replace([':', ' '], "");
    value
        .bytes()
        .all(|byte| byte.is_ascii_hexdigit())
        .then_some(value)
}

fn normalized_serial(value: &str) -> Option<String> {
    let value = normalized_hex(value)?;
    Some(value.trim_start_matches('0').to_owned())
        .map(|value| if value.is_empty() { "0".into() } else { value })
}

fn matches(entry: &Entry, selector: &str) -> Result<bool, Usage> {
    if selector == "*" {
        return Ok(true);
    }
    let (kind, token) = selector
        .split_once(':')
        .map_or(("", selector), |(prefix, token)| {
            let prefix = lower(prefix);
            if matches!(
                prefix.as_str(),
                "index" | "serial" | "sha1" | "sha256" | "subject"
            ) {
                (Box::leak(prefix.into_boxed_str()) as &str, token)
            } else {
                ("", selector)
            }
        });
    usage(!token.is_empty(), "Empty certificate selector")?;
    if (kind.is_empty() || kind == "index") && token.parse::<usize>().ok() == Some(entry.index) {
        return Ok(true);
    }
    let digits = normalized_hex(token);
    if (kind.is_empty() || kind == "serial")
        && digits.is_some()
        && normalized_serial(token)
            == normalized_serial(
                &entry
                    .certificate
                    .serial_hex()
                    .map_err(|error| Usage(error.message))?,
            )
    {
        return Ok(true);
    }
    if (kind.is_empty() || kind == "sha1")
        && digits.as_deref() == Some(&hex_bytes(&entry.certificate.sha1_fingerprint())[..])
    {
        return Ok(true);
    }
    if (kind.is_empty() || kind == "sha256")
        && digits.as_deref() == Some(&hex_bytes(&entry.certificate.sha256_fingerprint())[..])
    {
        return Ok(true);
    }
    Ok((kind.is_empty() || kind == "subject")
        && lower(&certificate_name(entry.context.0, false).map_err(Usage)?).contains(&lower(token)))
}

fn write_file(path: &Path, data: &[u8], force: bool) -> Result<(), String> {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err("Output must be a regular file, not a symlink".into());
        }
        if !force {
            return Err("Output already exists; use -f to replace it".into());
        }
    }
    let directory = path.parent().unwrap_or_else(|| Path::new("."));
    let temporary = directory.join(format!(
        ".certutil-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    let mut pending = PendingOutput::new(temporary.clone());
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(|error| error.to_string())?;
    output.write_all(data).map_err(|error| error.to_string())?;
    output.sync_all().map_err(|error| error.to_string())?;
    drop(output);
    if force {
        fs::rename(&temporary, path).map_err(|error| error.to_string())?;
    } else {
        fs::hard_link(&temporary, path).map_err(|error| error.to_string())?;
        fs::remove_file(&temporary).map_err(|error| error.to_string())?;
    }
    pending.commit();
    Ok(())
}

struct PendingOutput {
    path: Option<PathBuf>,
}

impl PendingOutput {
    fn new(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    fn commit(&mut self) {
        self.path = None;
    }
}

impl Drop for PendingOutput {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            let _ = fs::remove_file(path);
        }
    }
}

struct TerminalEchoGuard {
    original: libc::termios,
}

impl TerminalEchoGuard {
    fn disable() -> Result<Self, String> {
        let mut original = MaybeUninit::uninit();
        if unsafe { libc::tcgetattr(libc::STDIN_FILENO, original.as_mut_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let original = unsafe { original.assume_init() };
        let mut hidden = original;
        hidden.c_lflag &= !libc::ECHO;
        if unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSAFLUSH, &hidden) } != 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        Ok(Self { original })
    }
}

impl Drop for TerminalEchoGuard {
    fn drop(&mut self) {
        unsafe {
            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &self.original);
        }
    }
}

fn password(options: &Options, exporting: bool) -> Result<Zeroizing<String>, String> {
    let value = if let Some(value) = &options.password {
        eprintln!(
            "CertUtil: warning: -p passwords are visible in process arguments; prefer --password-file or a terminal prompt."
        );
        Zeroizing::new(value.as_str().to_owned())
    } else if let Some(path) = &options.password_file {
        let metadata = fs::symlink_metadata(path).map_err(|_| "Cannot open password file")?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.permissions().mode() & 0o077 != 0
            || metadata.len() > 4096
        {
            return Err(
                "Password file must be private, owned by this user, and at most 4096 bytes".into(),
            );
        }
        let bytes = Zeroizing::new(fs::read(path).map_err(|_| "Cannot read password file")?);
        let mut value = Zeroizing::new(
            std::str::from_utf8(&bytes)
                .map_err(|_| "Password is not valid UTF-8")?
                .to_owned(),
        );
        if value.ends_with('\n') {
            value.pop();
            if value.ends_with('\r') {
                value.pop();
            }
        }
        value
    } else {
        if !std::io::stdin().is_terminal() {
            return Err("A PFX password is required: use --password-file or -p when not running on a terminal".into());
        }
        eprint!("PFX password: ");
        std::io::stderr()
            .flush()
            .map_err(|error| error.to_string())?;
        let echo = TerminalEchoGuard::disable()?;
        let mut value = Zeroizing::new(String::new());
        let read = std::io::stdin()
            .read_line(&mut value)
            .map_err(|error| error.to_string());
        drop(echo);
        eprintln!();
        read?;
        while value.ends_with(['\r', '\n']) {
            value.pop();
        }
        value
    };
    if value.contains('\0') {
        return Err("Password must not contain NUL bytes".into());
    }
    if exporting && value.is_empty() {
        return Err("PFX export requires a nonempty password".into());
    }
    Ok(value)
}

fn self_signed(certificate: &NativeCertificate) -> bool {
    certificate.self_signed().unwrap_or(false)
}

fn chain(
    options: &Options,
    name_value: &str,
    source: &[Entry],
    leaf: &NativeCertificate,
    no_chain: bool,
    no_root: bool,
) -> Result<Vec<NativeCertificate>, String> {
    if no_chain || self_signed(leaf) {
        return Ok(Vec::new());
    }
    // SAFETY: the memory provider accepts a null provider parameter.
    let candidates =
        Store(unsafe { CertOpenStore(PROVIDER_MEMORY as LPCSTR, 0, 0, 0, ptr::null()) });
    api(
        !candidates.0.is_null(),
        (),
        "Create certificate-chain store",
    )?;
    for entry in source {
        api(
            // SAFETY: the store and source context are live; no returned
            // context is requested.
            unsafe {
                CertAddCertificateContextToStore(
                    candidates.0,
                    entry.context.0,
                    CERT_STORE_ADD_ALWAYS,
                    ptr::null_mut(),
                )
            } != FALSE,
            (),
            "Add certificate-chain candidate",
        )?;
    }
    for extra in ["CA", "ROOT"] {
        if name_value.eq_ignore_ascii_case(extra) {
            continue;
        }
        for entry in entries(&open_store(options, extra, false)?)? {
            api(
                // SAFETY: the store and source context are live; no returned
                // context is requested.
                unsafe {
                    CertAddCertificateContextToStore(
                        candidates.0,
                        entry.context.0,
                        CERT_STORE_ADD_ALWAYS,
                        ptr::null_mut(),
                    )
                } != FALSE,
                (),
                "Add system certificate-chain candidate",
            )?;
        }
    }
    let leaf_context = source
        .iter()
        .find(|entry| entry.certificate.sha256_fingerprint() == leaf.sha256_fingerprint())
        .ok_or("Selected certificate context is unavailable")?;
    let parameters = CERT_CHAIN_PARA {
        cbSize: std::mem::size_of::<CERT_CHAIN_PARA>() as DWORD,
        ..CERT_CHAIN_PARA::default()
    };
    let mut raw_chain = ptr::null();
    api(
        // SAFETY: the context, store, parameters, and output slot remain live
        // for the synchronous chain build.
        unsafe {
            CertGetCertificateChain(
                ptr::null_mut(),
                leaf_context.context.0,
                ptr::null(),
                candidates.0,
                &parameters,
                0,
                ptr::null_mut(),
                &mut raw_chain,
            )
        } != FALSE,
        (),
        "Build certificate chain",
    )?;
    let chain = CertificateChain(raw_chain);
    let policy_parameters = CERT_CHAIN_POLICY_PARA {
        cbSize: std::mem::size_of::<CERT_CHAIN_POLICY_PARA>() as DWORD,
        ..CERT_CHAIN_POLICY_PARA::default()
    };
    let mut policy_status = CERT_CHAIN_POLICY_STATUS {
        cbSize: std::mem::size_of::<CERT_CHAIN_POLICY_STATUS>() as DWORD,
        ..CERT_CHAIN_POLICY_STATUS::default()
    };
    api(
        // SAFETY: the chain and initialized policy input/output structures are
        // live for the synchronous call.
        unsafe {
            CertVerifyCertificateChainPolicy(
                CERT_CHAIN_POLICY_BASE as LPCSTR,
                chain.0,
                &policy_parameters,
                &mut policy_status,
            )
        } != FALSE,
        (),
        "Verify certificate-chain policy",
    )?;
    if policy_status.dwError != ERROR_SUCCESS {
        return Err(format!(
            "Certificate-chain policy failed (0x{:x})",
            policy_status.dwError
        ));
    }
    let public = unsafe { &*chain.0 };
    if public.cChain != 1 || public.rgpChain.is_null() {
        return Err("Certificate-chain result is malformed".into());
    }
    let simple = unsafe { &**public.rgpChain };
    let mut result = Vec::new();
    for index in 1..simple.cElement as usize {
        let element = unsafe { &**simple.rgpElement.add(index) };
        let context = unsafe { &*element.pCertContext };
        let der = unsafe {
            std::slice::from_raw_parts(context.pbCertEncoded, context.cbCertEncoded as usize)
        };
        let issuer = NativeCertificate::from_der(der).map_err(|error| error.message)?;
        if no_root && index + 1 == simple.cElement as usize && self_signed(&issuer) {
            continue;
        }
        result.push(issuer);
    }
    Ok(result)
}

unsafe extern "system" fn print_store(
    name: *const std::ffi::c_void,
    _: DWORD,
    _: *const CERT_SYSTEM_STORE_INFO,
    _: *const std::ffi::c_void,
    _: *mut std::ffi::c_void,
) -> BOOL {
    let mut cursor = name.cast::<WCHAR>();
    let mut units = Vec::new();
    while unsafe { *cursor } != 0 {
        units.push(unsafe { *cursor });
        cursor = unsafe { cursor.add(1) };
    }
    println!("{}", String::from_utf16_lossy(&units));
    TRUE
}

fn execute(mut options: Options) -> Result<(), String> {
    configure(&options)?;
    match options.command.as_str() {
        "-enumstore" => {
            api(
                // SAFETY: the callback has the required ABI and does not
                // retain the names supplied during enumeration.
                unsafe {
                    CertEnumSystemStore(
                        options.scope,
                        ptr::null_mut(),
                        ptr::null_mut(),
                        Some(print_store),
                    )
                } != FALSE,
                (),
                "Enumerate stores",
            )?;
        }
        "-dump" => {
            for (index, certificate) in certificates(&read_file(Path::new(&options.args[0]))?)?
                .iter()
                .enumerate()
            {
                let der = certificate.to_der();
                // SAFETY: `der` is readable for its reported length.
                let context = CertificateContext(unsafe {
                    CertCreateCertificateContext(
                        X509_ASN_ENCODING,
                        der.as_ptr(),
                        der.len() as DWORD,
                    )
                });
                api(!context.0.is_null(), (), "Create certificate context")?;
                show(context.0, certificate, index, options.verbose, None)?;
            }
        }
        "-addstore" => {
            let parsed = certificates(&read_file(Path::new(&options.args[1]))?)?;
            let store = open_store(&options, &options.args[0], true)?;
            for certificate in parsed {
                let der = certificate.to_der();
                // SAFETY: `der` is readable for its reported length.
                let context = unsafe {
                    CertCreateCertificateContext(
                        X509_ASN_ENCODING,
                        der.as_ptr(),
                        der.len() as DWORD,
                    )
                };
                api(!context.is_null(), (), "Validate certificate")?;
                let disposition = if options.force {
                    CERT_STORE_ADD_REPLACE_EXISTING
                } else {
                    CERT_STORE_ADD_NEW
                };
                // SAFETY: the store and context are live; no returned context
                // is requested.
                let added = unsafe {
                    CertAddCertificateContextToStore(store.0, context, disposition, ptr::null_mut())
                };
                // SAFETY: this is the live reference returned by creation.
                unsafe { CertFreeCertificateContext(context) };
                api(
                    added != FALSE,
                    (),
                    "Add certificate (earlier additions, if any, remain)",
                )?;
                println!("Certificate added to {}.", options.args[0]);
            }
        }
        "-importpfx" => {
            let name = if options.args.len() == 2 {
                options.args[0].clone()
            } else {
                "MY".into()
            };
            if name.eq_ignore_ascii_case("ROOT") && options.scope == CERT_SYSTEM_STORE_LOCAL_MACHINE
            {
                return Err("Computer ROOT does not store private keys; use -addstore for public trust anchors".into());
            }
            let secret = password(&options, false)?;
            let wide_secret = Zeroizing::new(wide(&secret));
            let mut input = Zeroizing::new(read_file(Path::new(options.args.last().unwrap()))?);
            let blob = CRYPT_DATA_BLOB {
                cbData: input.len() as DWORD,
                pbData: input.as_mut_ptr(),
            };
            let store = open_store(&options, &name, true)?;
            let flags = if options.scope == CERT_SYSTEM_STORE_CURRENT_USER {
                CRYPT_USER_KEYSET
            } else {
                CRYPT_MACHINE_KEYSET
            };
            api(
                // SAFETY: the store, PFX blob, and terminated password remain
                // live for the synchronous import.
                unsafe { SysCertImportPfxToStore(store.0, &blob, wide_secret.as_ptr(), flags) }
                    != FALSE,
                (),
                "Import PFX",
            )?;
            println!("PFX imported into {name}.");
        }
        _ => {
            let exporting = options.command == "-exportpfx";
            let mut no_chain = false;
            let mut no_root = false;
            if exporting && options.args.len() >= 3 {
                let modifier = lower(options.args.last().unwrap());
                if matches!(modifier.as_str(), "nochain" | "noroot") {
                    no_chain = modifier == "nochain";
                    no_root = modifier == "noroot";
                    options.args.pop();
                }
            }
            if exporting && !(options.args.len() == 2 || options.args.len() == 3) {
                return Err("Unsupported PFX export modifier or arguments".into());
            }
            let store_name = if exporting {
                if options.args.len() == 3 {
                    options.args[0].clone()
                } else {
                    "MY".into()
                }
            } else if options.args.is_empty() {
                "CA".into()
            } else {
                options.args[0].clone()
            };
            let selector = if exporting {
                options.args[options.args.len() - 2].clone()
            } else if options.args.len() >= 2 {
                options.args[1].clone()
            } else {
                "*".into()
            };
            let store = open_store(&options, &store_name, options.command == "-delstore")?;
            let contents = entries(&store)?;
            let mut selected = Vec::new();
            for (index, entry) in contents.iter().enumerate() {
                if matches(entry, &selector).map_err(|error| error.0)? {
                    selected.push(index);
                }
            }
            let all = options.command == "-store" && options.args.len() < 2;
            if selected.is_empty() && !all {
                return Err("No certificate matches the selector".into());
            }
            if matches!(options.command.as_str(), "-delstore" | "-exportpfx") && selected.len() != 1
            {
                return Err("Ambiguous certificate selector; use a hash or explicit index".into());
            }
            if options.command == "-delstore" {
                let entry = &contents[selected[0]];
                if entry.origin != options.scope {
                    return Err("Inherited certificates cannot be deleted from a user view; open the computer store explicitly".into());
                }
                // SAFETY: the selected entry owns a live context reference.
                let retained = unsafe { CertDuplicateCertificateContext(entry.context.0) };
                api(
                    // SAFETY: `retained` is an independently owned live
                    // reference consumed by this call.
                    unsafe { CertDeleteCertificateFromStore(retained) } != FALSE,
                    (),
                    "Delete certificate",
                )?;
                println!("Certificate deleted from {store_name}.");
            } else if exporting {
                let entry = &contents[selected[0]];
                let issuers = chain(
                    &options,
                    &store_name,
                    &contents,
                    &entry.certificate,
                    no_chain,
                    no_root,
                )?;
                // SAFETY: the memory provider accepts a null provider
                // parameter.
                let export_store = Store(unsafe {
                    CertOpenStore(PROVIDER_MEMORY as LPCSTR, 0, 0, 0, ptr::null())
                });
                api(!export_store.0.is_null(), (), "Create PFX export store")?;
                api(
                    // SAFETY: the store and leaf context are live; no returned
                    // context is requested.
                    unsafe {
                        CertAddCertificateContextToStore(
                            export_store.0,
                            entry.context.0,
                            CERT_STORE_ADD_ALWAYS,
                            ptr::null_mut(),
                        )
                    } != FALSE,
                    (),
                    "Add PFX leaf certificate",
                )?;
                for issuer in &issuers {
                    let der = issuer.to_der();
                    // SAFETY: `der` is readable for its reported length.
                    let context = CertificateContext(unsafe {
                        CertCreateCertificateContext(
                            X509_ASN_ENCODING,
                            der.as_ptr(),
                            der.len() as DWORD,
                        )
                    });
                    api(!context.0.is_null(), (), "Create PFX issuer context")?;
                    api(
                        // SAFETY: the store and issuer context are live; no
                        // returned context is requested.
                        unsafe {
                            CertAddCertificateContextToStore(
                                export_store.0,
                                context.0,
                                CERT_STORE_ADD_ALWAYS,
                                ptr::null_mut(),
                            )
                        } != FALSE,
                        (),
                        "Add PFX issuer certificate",
                    )?;
                }
                let secret = password(&options, true)?;
                let wide_secret = Zeroizing::new(wide(&secret));
                let encoded = (|| {
                    let mut blob = CRYPT_DATA_BLOB::default();
                    api(
                        // SAFETY: the store, output blob, and terminated
                        // password are live; a null output buffer requests size.
                        unsafe {
                            PFXExportCertStoreEx(
                                export_store.0,
                                &mut blob,
                                wide_secret.as_ptr(),
                                ptr::null_mut(),
                                EXPORT_PRIVATE_KEYS,
                            )
                        } != FALSE,
                        (),
                        "Size PFX export",
                    )?;
                    let mut encoded = Zeroizing::new(vec![0u8; blob.cbData as usize]);
                    blob.pbData = encoded.as_mut_ptr();
                    api(
                        // SAFETY: the blob now describes the writable
                        // `encoded` buffer and the other inputs remain live.
                        unsafe {
                            PFXExportCertStoreEx(
                                export_store.0,
                                &mut blob,
                                wide_secret.as_ptr(),
                                ptr::null_mut(),
                                EXPORT_PRIVATE_KEYS,
                            )
                        } != FALSE,
                        (),
                        "Export PFX",
                    )?;
                    Ok::<_, String>(encoded)
                })();
                let encoded = encoded?;
                write_file(
                    Path::new(options.args.last().unwrap()),
                    &encoded,
                    options.force,
                )?;
                println!(
                    "Encrypted PFX exported ({} certificates).",
                    1 + issuers.len()
                );
            } else {
                for index in &selected {
                    let entry = &contents[*index];
                    show(
                        entry.context.0,
                        &entry.certificate,
                        entry.index,
                        options.verbose,
                        Some((entry.origin, options.scope)),
                    )?;
                }
                if options.args.len() == 3 {
                    let format = options.format.as_deref().unwrap_or("der");
                    let data = if format == "der" {
                        if selected.len() != 1 {
                            return Err("DER output requires exactly one certificate; use --format pem or pkcs7 for multiple matches".into());
                        }
                        contents[selected[0]].certificate.to_der()
                    } else if format == "pem" {
                        let mut output = Vec::new();
                        for index in &selected {
                            output.extend(certificate_pem(&contents[*index].certificate)?);
                        }
                        output
                    } else {
                        // SAFETY: the memory provider accepts a null provider
                        // parameter.
                        let memory = Store(unsafe {
                            CertOpenStore(PROVIDER_MEMORY as LPCSTR, 0, 0, 0, ptr::null())
                        });
                        api(!memory.0.is_null(), (), "Create export store")?;
                        for index in &selected {
                            api(
                                // SAFETY: the store and selected context are
                                // live; no returned context is requested.
                                unsafe {
                                    CertAddCertificateContextToStore(
                                        memory.0,
                                        contents[*index].context.0,
                                        CERT_STORE_ADD_ALWAYS,
                                        ptr::null_mut(),
                                    )
                                } != FALSE,
                                (),
                                "Build export store",
                            )?;
                        }
                        let mut blob = CRYPT_DATA_BLOB::default();
                        api(
                            // SAFETY: the store and writable blob are live;
                            // null blob data requests the output size.
                            unsafe {
                                CertSaveStore(
                                    memory.0,
                                    PKCS_7_ASN_ENCODING,
                                    CERT_STORE_SAVE_AS_PKCS7,
                                    CERT_STORE_SAVE_TO_MEMORY,
                                    (&mut blob as *mut CRYPT_DATA_BLOB).cast(),
                                    0,
                                )
                            } != FALSE,
                            (),
                            "Size PKCS#7",
                        )?;
                        let mut output = vec![0u8; blob.cbData as usize];
                        blob.pbData = output.as_mut_ptr();
                        api(
                            // SAFETY: the blob describes the writable `output`
                            // buffer and the store remains live.
                            unsafe {
                                CertSaveStore(
                                    memory.0,
                                    PKCS_7_ASN_ENCODING,
                                    CERT_STORE_SAVE_AS_PKCS7,
                                    CERT_STORE_SAVE_TO_MEMORY,
                                    (&mut blob as *mut CRYPT_DATA_BLOB).cast(),
                                    0,
                                )
                            } != FALSE,
                            (),
                            "Export PKCS#7",
                        )?;
                        output
                    };
                    write_file(Path::new(&options.args[2]), &data, options.force)?;
                }
                println!("{} certificate(s).", selected.len());
            }
        }
    }
    Ok(())
}

pub fn run() {
    let status = match parse_options() {
        Ok(options) if options.help => {
            print!("{HELP}");
            if std::io::stdout().flush().is_ok() {
                0
            } else {
                1
            }
        }
        Ok(options) => match execute(options) {
            Ok(()) => 0,
            Err(error) => {
                eprintln!("CertUtil: {error}");
                1
            }
        },
        Err(error) => {
            eprintln!("CertUtil: {}", error.0);
            2
        }
    };
    std::process::exit(status);
}

#[cfg(test)]
mod tests {
    use super::PendingOutput;
    use std::fs;

    #[test]
    fn pending_output_removes_uncommitted_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(".certutil-test");
        fs::write(&path, b"sensitive").unwrap();

        drop(PendingOutput::new(path.clone()));

        assert!(!path.exists());
    }

    #[test]
    fn pending_output_preserves_committed_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(".certutil-test");
        fs::write(&path, b"complete").unwrap();
        let mut pending = PendingOutput::new(path.clone());

        pending.commit();
        drop(pending);

        assert_eq!(fs::read(path).unwrap(), b"complete");
    }
}
