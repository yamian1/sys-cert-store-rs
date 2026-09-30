use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkcs7::Pkcs7;
use openssl::pkcs12::Pkcs12;
use openssl::pkey::{PKey, Private};
use openssl::stack::Stack;
use openssl::x509::{X509, X509Ref};
use std::collections::{BTreeMap, HashSet};
use std::ffi::{CStr, CString};
use std::fs::{self, OpenOptions};
use std::io::{IsTerminal, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::ptr;
use sys_cert_store::ffi::*;
use sys_cert_store::*;
use zeroize::Zeroize;

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
    password: Option<String>,
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
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
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
            result.password = Some(value()?);
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
        !(result.command == "-exportpfx" && result.password.as_deref() == Some("")),
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
    value
        .chars()
        .map(|character| character as WCHAR)
        .chain([0])
        .collect()
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
        SysCertConfigureSystemStores(&configuration) != FALSE,
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

struct Certificate(*const CERT_CONTEXT);
impl Drop for Certificate {
    fn drop(&mut self) {
        if !self.0.is_null() {
            CertFreeCertificateContext(self.0);
        }
    }
}

struct Entry {
    context: Certificate,
    certificate: X509,
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
    let handle = CertOpenStore(
        PROVIDER_SYSTEM_A as LPCSTR,
        0,
        0,
        flags,
        name.as_ptr().cast(),
    );
    api(!handle.is_null(), Store(handle), "Open store")
}

fn entries(store: &Store) -> Result<Vec<Entry>, String> {
    let mut result = Vec::new();
    let mut cursor = ptr::null();
    loop {
        cursor = CertEnumCertificatesInStore(store.0, cursor);
        if cursor.is_null() {
            if GetLastError() == CRYPT_E_NOT_FOUND {
                break;
            }
            return api(false, result, "Enumerate certificates");
        }
        let retained = CertDuplicateCertificateContext(cursor);
        api(!retained.is_null(), (), "Retain certificate")?;
        let public = unsafe { &*retained };
        let der = unsafe {
            std::slice::from_raw_parts(public.pbCertEncoded, public.cbCertEncoded as usize)
        };
        let certificate = X509::from_der(der).map_err(|error| error.to_string())?;
        let mut origin = 0;
        api(
            SysCertGetCertificateStoreLocation(retained, &mut origin) != FALSE,
            (),
            "Get certificate location",
        )?;
        result.push(Entry {
            context: Certificate(retained),
            certificate,
            index: result.len(),
            origin,
        });
    }
    Ok(result)
}

fn name(certificate_name: &openssl::x509::X509NameRef) -> String {
    certificate_name
        .entries()
        .map(|entry| {
            let key = entry.object().nid().short_name().unwrap_or("OID");
            let value = entry
                .data()
                .to_string()
                .unwrap_or_else(|_| "<invalid>".into());
            format!("{key}={value}")
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn hex_bytes(value: &[u8]) -> String {
    hex::encode(value)
}

fn serial(certificate: &X509Ref) -> String {
    certificate
        .serial_number()
        .to_bn()
        .and_then(|value| value.to_hex_str())
        .map(|value| value.to_string().to_ascii_lowercase())
        .unwrap_or_default()
}

fn fingerprint(certificate: &X509Ref, digest: MessageDigest) -> Result<String, String> {
    Ok(hex_bytes(
        certificate
            .digest(digest)
            .map_err(|error| error.to_string())?
            .as_ref(),
    ))
}

fn show(
    certificate: &X509Ref,
    index: usize,
    verbose: bool,
    origin: Option<(DWORD, DWORD)>,
) -> Result<(), String> {
    println!(
        "================ Certificate {index} ================\nSerial Number: {}\nIssuer: {}\n NotBefore: {}\n NotAfter: {}\nSubject: {}\nCert Hash(sha1): {}\nCert Hash(sha256): {}",
        serial(certificate),
        name(certificate.issuer_name()),
        certificate.not_before(),
        certificate.not_after(),
        name(certificate.subject_name()),
        fingerprint(certificate, MessageDigest::sha1())?,
        fingerprint(certificate, MessageDigest::sha256())?,
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
            String::from_utf8_lossy(&certificate.to_pem().map_err(|error| error.to_string())?)
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

fn certificates(data: &[u8]) -> Result<Vec<X509>, String> {
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
                let container =
                    Pkcs7::from_pem(block.as_bytes()).map_err(|_| "Invalid PEM PKCS#7")?;
                let signed = container
                    .signed()
                    .ok_or("Only signed-data PKCS#7 certificate containers are supported")?;
                let values = signed
                    .certificates()
                    .ok_or("PKCS#7 contains no certificates")?;
                result.extend(values.iter().map(|value| value.to_owned()));
            } else {
                result
                    .push(X509::from_pem(block.as_bytes()).map_err(|_| "Invalid PEM certificate")?);
            }
            remainder = remainder[end..].trim_start();
        }
        return Ok(result);
    }
    if let Ok(certificate) = X509::from_der(data)
        && certificate.to_der().map_err(|error| error.to_string())? == data
    {
        return Ok(vec![certificate]);
    }
    let container = Pkcs7::from_der(data)
        .map_err(|_| "Input is not a complete PEM/DER certificate or PKCS#7 container")?;
    let signed = container
        .signed()
        .ok_or("Only signed-data PKCS#7 certificate containers are supported")?;
    let values = signed
        .certificates()
        .ok_or("PKCS#7 contains no certificates")?;
    Ok(values.iter().map(|value| value.to_owned()).collect())
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
        && normalized_serial(token) == normalized_serial(&serial(&entry.certificate))
    {
        return Ok(true);
    }
    if (kind.is_empty() || kind == "sha1")
        && digits.as_deref()
            == Some(&fingerprint(&entry.certificate, MessageDigest::sha1()).map_err(Usage)?[..])
    {
        return Ok(true);
    }
    if (kind.is_empty() || kind == "sha256")
        && digits.as_deref()
            == Some(&fingerprint(&entry.certificate, MessageDigest::sha256()).map_err(Usage)?[..])
    {
        return Ok(true);
    }
    Ok((kind.is_empty() || kind == "subject")
        && lower(&name(entry.certificate.subject_name())).contains(&lower(token)))
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
    Ok(())
}

fn password(options: &Options, exporting: bool) -> Result<String, String> {
    let value = if let Some(value) = &options.password {
        eprintln!(
            "CertUtil: warning: -p passwords are visible in process arguments; prefer --password-file or a terminal prompt."
        );
        value.clone()
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
        let mut value = String::from_utf8(fs::read(path).map_err(|_| "Cannot read password file")?)
            .map_err(|_| "Password is not valid UTF-8")?;
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
        let mut value = String::new();
        std::io::stdin()
            .read_line(&mut value)
            .map_err(|error| error.to_string())?;
        value.trim_end_matches(['\r', '\n']).to_owned()
    };
    if value.contains('\0') {
        return Err("Password must not contain NUL bytes".into());
    }
    if exporting && value.is_empty() {
        return Err("PFX export requires a nonempty password".into());
    }
    Ok(value)
}

fn key_for(context: *const CERT_CONTEXT) -> Result<PKey<Private>, String> {
    let mut size = 0;
    api(
        SysCertGetCertificateFilePath(context, TRUE, ptr::null_mut(), &mut size) != FALSE,
        (),
        "Access certificate private key",
    )?;
    let mut path = vec![0i8; size as usize];
    api(
        SysCertGetCertificateFilePath(context, TRUE, path.as_mut_ptr(), &mut size) != FALSE,
        (),
        "Get private-key path",
    )?;
    let path = unsafe { CStr::from_ptr(path.as_ptr()) }.to_string_lossy();
    let metadata =
        fs::symlink_metadata(path.as_ref()).map_err(|_| "Cannot open private-key file")?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.nlink() != 1
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err("Unsafe private-key file ownership or permissions".into());
    }
    PKey::private_key_from_pem(&fs::read(path.as_ref()).map_err(|error| error.to_string())?)
        .map_err(|error| error.to_string())
}

fn self_signed(certificate: &X509Ref) -> bool {
    name(certificate.issuer_name()) == name(certificate.subject_name())
        && certificate
            .public_key()
            .and_then(|key| certificate.verify(&key))
            .unwrap_or(false)
}

fn chain(
    options: &Options,
    name_value: &str,
    source: &[Entry],
    leaf: &X509Ref,
    no_chain: bool,
    no_root: bool,
) -> Result<Vec<X509>, String> {
    if no_chain || self_signed(leaf) {
        return Ok(Vec::new());
    }
    let mut candidates = Vec::new();
    for extra in ["CA", "ROOT"] {
        if name_value.eq_ignore_ascii_case(extra) {
            continue;
        }
        candidates.extend(entries(&open_store(options, extra, false)?)?);
    }
    let mut seen = HashSet::from([fingerprint(leaf, MessageDigest::sha256())?]);
    let mut current = leaf.to_owned();
    let mut result = Vec::new();
    while !self_signed(&current) {
        let mut issuers = BTreeMap::new();
        for entry in source.iter().chain(candidates.iter()) {
            let issuer_key = entry
                .certificate
                .public_key()
                .map_err(|error| error.to_string())?;
            if entry.certificate.issued(&current) == openssl::x509::X509VerifyResult::OK
                && current.verify(&issuer_key).unwrap_or(false)
            {
                issuers.insert(
                    fingerprint(&entry.certificate, MessageDigest::sha256())?,
                    entry.certificate.clone(),
                );
            }
        }
        if issuers.len() != 1 {
            return Err("Cannot build an unambiguous complete offline issuer chain; use NoChain for a leaf-only export".into());
        }
        let (hash, issuer) = issuers.pop_first().unwrap();
        if !seen.insert(hash) {
            return Err("Cycle in certificate issuer chain".into());
        }
        if no_root && self_signed(&issuer) {
            break;
        }
        current = issuer.clone();
        result.push(issuer);
    }
    Ok(result)
}

unsafe extern "C" fn print_store(
    name: *const std::ffi::c_void,
    _: DWORD,
    _: *mut CERT_SYSTEM_STORE_INFO,
    _: *mut std::ffi::c_void,
    _: *mut std::ffi::c_void,
) -> BOOL {
    let mut cursor = name.cast::<WCHAR>();
    let mut value = String::new();
    while unsafe { *cursor } != 0 {
        if let Some(character) = char::from_u32(unsafe { *cursor } as u32) {
            value.push(character);
        }
        cursor = unsafe { cursor.add(1) };
    }
    println!("{value}");
    TRUE
}

fn execute(mut options: Options) -> Result<(), String> {
    configure(&options)?;
    match options.command.as_str() {
        "-enumstore" => {
            api(
                CertEnumSystemStore(
                    options.scope,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    Some(print_store),
                ) != FALSE,
                (),
                "Enumerate stores",
            )?;
        }
        "-dump" => {
            for (index, certificate) in certificates(&read_file(Path::new(&options.args[0]))?)?
                .iter()
                .enumerate()
            {
                show(certificate, index, options.verbose, None)?;
            }
        }
        "-addstore" => {
            let parsed = certificates(&read_file(Path::new(&options.args[1]))?)?;
            let store = open_store(&options, &options.args[0], true)?;
            for certificate in parsed {
                let der = certificate.to_der().map_err(|error| error.to_string())?;
                let context = CertCreateCertificateContext(
                    X509_ASN_ENCODING,
                    der.as_ptr(),
                    der.len() as DWORD,
                );
                api(!context.is_null(), (), "Validate certificate")?;
                let disposition = if options.force {
                    CERT_STORE_ADD_REPLACE_EXISTING
                } else {
                    CERT_STORE_ADD_NEW
                };
                let added = CertAddCertificateContextToStore(
                    store.0,
                    context,
                    disposition,
                    ptr::null_mut(),
                );
                CertFreeCertificateContext(context);
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
            let mut secret = password(&options, false)?;
            let wide_secret = wide(&secret);
            let mut input = read_file(Path::new(options.args.last().unwrap()))?;
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
                SysCertImportPfxToStore(store.0, &blob, wide_secret.as_ptr(), flags) != FALSE,
                (),
                "Import PFX",
            )?;
            secret.zeroize();
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
                let retained = CertDuplicateCertificateContext(entry.context.0);
                api(
                    CertDeleteCertificateFromStore(retained) != FALSE,
                    (),
                    "Delete certificate",
                )?;
                println!("Certificate deleted from {store_name}.");
            } else if exporting {
                let entry = &contents[selected[0]];
                let key = key_for(entry.context.0)?;
                if !entry
                    .certificate
                    .public_key()
                    .map_err(|error| error.to_string())?
                    .public_eq(&key)
                {
                    return Err("Private key does not match certificate".into());
                }
                let issuers = chain(
                    &options,
                    &store_name,
                    &contents,
                    &entry.certificate,
                    no_chain,
                    no_root,
                )?;
                let mut stack = Stack::new().map_err(|error| error.to_string())?;
                for issuer in &issuers {
                    stack
                        .push(issuer.clone())
                        .map_err(|error| error.to_string())?;
                }
                let mut secret = password(&options, true)?;
                let mut builder = Pkcs12::builder();
                builder
                    .pkey(&key)
                    .cert(&entry.certificate)
                    .ca(stack)
                    .key_algorithm(Nid::AES_256_CBC)
                    .cert_algorithm(Nid::AES_256_CBC);
                let pfx = builder.build2(&secret).map_err(|error| error.to_string())?;
                write_file(
                    Path::new(options.args.last().unwrap()),
                    &pfx.to_der().map_err(|error| error.to_string())?,
                    options.force,
                )?;
                secret.zeroize();
                println!(
                    "Encrypted PFX exported ({} certificates).",
                    1 + issuers.len()
                );
            } else {
                for index in &selected {
                    let entry = &contents[*index];
                    show(
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
                        contents[selected[0]]
                            .certificate
                            .to_der()
                            .map_err(|error| error.to_string())?
                    } else if format == "pem" {
                        let mut output = Vec::new();
                        for index in &selected {
                            output.extend(
                                contents[*index]
                                    .certificate
                                    .to_pem()
                                    .map_err(|error| error.to_string())?,
                            );
                        }
                        output
                    } else {
                        let memory = Store(CertOpenStore(
                            PROVIDER_MEMORY as LPCSTR,
                            0,
                            0,
                            0,
                            ptr::null(),
                        ));
                        api(!memory.0.is_null(), (), "Create export store")?;
                        for index in &selected {
                            api(
                                CertAddCertificateContextToStore(
                                    memory.0,
                                    contents[*index].context.0,
                                    CERT_STORE_ADD_ALWAYS,
                                    ptr::null_mut(),
                                ) != FALSE,
                                (),
                                "Build export store",
                            )?;
                        }
                        let mut blob = CRYPT_DATA_BLOB::default();
                        api(
                            CertSaveStore(
                                memory.0,
                                PKCS_7_ASN_ENCODING,
                                CERT_STORE_SAVE_AS_PKCS7,
                                CERT_STORE_SAVE_TO_MEMORY,
                                (&mut blob as *mut CRYPT_DATA_BLOB).cast(),
                                0,
                            ) != FALSE,
                            (),
                            "Size PKCS#7",
                        )?;
                        let mut output = vec![0u8; blob.cbData as usize];
                        blob.pbData = output.as_mut_ptr();
                        api(
                            CertSaveStore(
                                memory.0,
                                PKCS_7_ASN_ENCODING,
                                CERT_STORE_SAVE_AS_PKCS7,
                                CERT_STORE_SAVE_TO_MEMORY,
                                (&mut blob as *mut CRYPT_DATA_BLOB).cast(),
                                0,
                            ) != FALSE,
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

fn main() {
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
