use crate::api_types::*;
use crate::cert::Certificate;
use crate::error::{ApiError, require};
use crate::native::{native_layout, read_native};
use crate::store::{SystemPaths, store_name, user_data_directory};
use openssl::asn1::Asn1Time;
use openssl::x509::{X509, X509Crl};
use rusqlite::{Connection, OpenFlags};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::{CStr, CString, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::fd::{FromRawFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

struct Account {
    uid: libc::uid_t,
    gid: libc::gid_t,
    name: String,
    home: PathBuf,
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

struct FileDescriptor(RawFd);

impl Drop for FileDescriptor {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.0);
        }
    }
}

impl FileDescriptor {
    fn raw(&self) -> RawFd {
        self.0
    }
}

struct SourceCertificate {
    certificate: Certificate,
    openssl: X509,
}

struct Work {
    certificate: usize,
    issuer: usize,
    url: String,
}

fn os_error(code: DWORD, message: impl Into<String>) -> ApiError {
    let error = std::io::Error::last_os_error();
    ApiError::new(code, format!("{}: {}", message.into(), error))
}

fn path_cstring(path: &Path) -> Result<CString, ApiError> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| ApiError::new(E_INVALIDARG, "A filesystem path contains a NUL byte"))
}

fn lookup_account(
    mut lookup: impl FnMut(
        *mut libc::passwd,
        *mut libc::c_char,
        usize,
        *mut *mut libc::passwd,
    ) -> libc::c_int,
    description: &str,
) -> Result<Account, ApiError> {
    let suggested = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    let mut buffer = vec![
        0u8;
        if suggested > 0 {
            suggested as usize
        } else {
            16_384
        }
    ];
    loop {
        let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result = std::ptr::null_mut();
        let error = lookup(
            &mut entry,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        );
        if error == libc::ERANGE {
            require(
                buffer.len() <= 1 << 20,
                ERROR_NOT_ENOUGH_MEMORY,
                "The account database entry is too large",
            )?;
            buffer.resize(buffer.len() * 2, 0);
            continue;
        }
        require(error == 0 && !result.is_null(), E_INVALIDARG, description)?;
        require(
            !entry.pw_name.is_null() && !entry.pw_dir.is_null(),
            ERROR_INVALID_DATA,
            "The target account has incomplete account data",
        )?;
        let name = unsafe { CStr::from_ptr(entry.pw_name) }
            .to_string_lossy()
            .into_owned();
        let home_bytes = unsafe { CStr::from_ptr(entry.pw_dir) }.to_bytes().to_vec();
        require(
            !home_bytes.is_empty(),
            ERROR_INVALID_DATA,
            "The target account has no home directory",
        )?;
        let home = PathBuf::from(OsString::from_vec(home_bytes));
        require(
            home.is_absolute(),
            ERROR_INVALID_DATA,
            "The target account home directory is not absolute",
        )?;
        return Ok(Account {
            uid: entry.pw_uid,
            gid: entry.pw_gid,
            name,
            home,
        });
    }
}

fn account_by_name(name: &CStr) -> Result<Account, ApiError> {
    require(
        !name.to_bytes().is_empty(),
        E_INVALIDARG,
        "The user name must not be empty",
    )?;
    require(
        std::str::from_utf8(name.to_bytes()).is_ok(),
        E_INVALIDARG,
        "The user name is not valid UTF-8",
    )?;
    lookup_account(
        |entry, buffer, size, result| unsafe {
            libc::getpwnam_r(name.as_ptr(), entry, buffer, size, result)
        },
        "The requested Linux account does not exist",
    )
}

fn account_by_uid(uid: libc::uid_t) -> Result<Account, ApiError> {
    lookup_account(
        |entry, buffer, size, result| unsafe { libc::getpwuid_r(uid, entry, buffer, size, result) },
        "A discovered process user does not have a Linux account",
    )
}

fn process_uid(status_path: &Path) -> Result<libc::uid_t, ApiError> {
    let status = fs::read_to_string(status_path)
        .map_err(|_| ApiError::new(ERROR_ACCESS_DENIED, "Cannot inspect a process owner"))?;
    for line in status.lines() {
        let Some(values) = line.strip_prefix("Uid:") else {
            continue;
        };
        let mut values = values.split_whitespace();
        let _real = values
            .next()
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or_else(|| {
                ApiError::new(ERROR_INVALID_DATA, "A process has an invalid Uid status")
            })?;
        let effective = values
            .next()
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or_else(|| {
                ApiError::new(ERROR_INVALID_DATA, "A process has an invalid Uid status")
            })?;
        require(
            effective <= libc::uid_t::MAX as u64,
            ERROR_INVALID_DATA,
            "A process UID is out of range",
        )?;
        return Ok(effective as libc::uid_t);
    }
    Err(ApiError::new(
        ERROR_INVALID_DATA,
        "A process status has no Uid field",
    ))
}

fn dotnet_process_accounts(failures: &mut FailureSummary) -> Result<Vec<Account>, ApiError> {
    let directory = fs::read_dir("/proc")
        .map_err(|_| ApiError::new(ERROR_ACCESS_DENIED, "Cannot enumerate /proc"))?;
    let mut users = BTreeSet::new();
    for entry in directory {
        let entry = match entry {
            Ok(value) => value,
            Err(error) => {
                failures.add(error.to_string());
                continue;
            }
        };
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if name.is_empty() || !name.bytes().all(|value| value.is_ascii_digit()) {
            continue;
        }
        let base = entry.path();
        let maps = match fs::read_to_string(base.join("maps")) {
            Ok(value) => value,
            Err(_) => continue,
        };
        if !maps.lines().any(|line| line.contains("libcoreclr.so")) {
            continue;
        }
        match process_uid(&base.join("status")) {
            Ok(uid) => {
                users.insert(uid);
            }
            Err(error) => failures.add(error.message),
        }
    }
    let effective = unsafe { libc::geteuid() };
    let mut result = Vec::new();
    for uid in users {
        match account_by_uid(uid) {
            Ok(account) if effective != 0 && account.uid != effective => {
                failures
                    .add("Root privileges are required to populate another user's .NET CRL cache");
            }
            Ok(account) => result.push(account),
            Err(error) => failures.add(error.message),
        }
    }
    Ok(result)
}

fn safe_metadata(
    metadata: &fs::Metadata,
    owner: libc::uid_t,
    shared: bool,
    directory: bool,
    description: &str,
) -> Result<(), ApiError> {
    let owner_ok = metadata.uid() == owner || (shared && metadata.uid() == 0);
    let mode_mask = if shared { 0o022 } else { 0o077 };
    require(
        owner_ok
            && (directory || metadata.nlink() == 1)
            && metadata.mode() & mode_mask == 0
            && if directory {
                metadata.is_dir()
            } else {
                metadata.is_file()
            },
        ERROR_ACCESS_DENIED,
        description,
    )
}

fn store_database_path(directory: &Path, name: &str) -> Result<Option<PathBuf>, ApiError> {
    let exact = directory.join(format!("{name}.db"));
    if exact.exists() {
        return Ok(Some(exact));
    }
    if !directory.exists() {
        return Ok(None);
    }
    let mut matches = Vec::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_symlink()
            || !file_type.is_file()
            || entry.path().extension().and_then(|value| value.to_str()) != Some("db")
        {
            continue;
        }
        let path = entry.path();
        let Some(stem) = path.file_stem().and_then(|value| value.to_str()) else {
            continue;
        };
        if store_name(stem.to_owned())? == name {
            matches.push(path);
        }
    }
    require(
        matches.len() <= 1,
        ERROR_INVALID_DATA,
        "Multiple metadata files map to the same system-store name",
    )?;
    Ok(matches.pop())
}

fn read_store_certificates(
    directory: &Path,
    name: &str,
    owner: libc::uid_t,
    shared: bool,
) -> Result<Vec<Vec<u8>>, ApiError> {
    let Some(database_path) = store_database_path(directory, name)? else {
        return Ok(Vec::new());
    };
    let directory_metadata = fs::symlink_metadata(directory)?;
    require(
        !directory_metadata.file_type().is_symlink(),
        ERROR_ACCESS_DENIED,
        "A certificate-store directory must not be a symbolic link",
    )?;
    safe_metadata(
        &directory_metadata,
        owner,
        shared,
        true,
        "A certificate-store directory has unsafe ownership or permissions",
    )?;
    let database_metadata = fs::symlink_metadata(&database_path)?;
    require(
        !database_metadata.file_type().is_symlink(),
        ERROR_ACCESS_DENIED,
        "A certificate-store database must not be a symbolic link",
    )?;
    safe_metadata(
        &database_metadata,
        owner,
        shared,
        false,
        "A certificate-store database has unsafe ownership or permissions",
    )?;
    let connection = Connection::open_with_flags(
        &database_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    let application: i64 =
        connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
    let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    require(
        application == 1_396_921_137 && version == 2,
        ERROR_INVALID_DATA,
        "Not a supported sys-cert-store database",
    )?;
    let objects = PathBuf::from(format!("{}.objects", database_path.display()));
    let mut statement = connection.prepare("SELECT object FROM certificates ORDER BY id")?;
    let values = statement.query_map([], |row| row.get::<_, String>(0))?;
    let mut result = Vec::new();
    for value in values {
        let object = value?;
        require(
            object.len() == 32
                && object
                    .bytes()
                    .all(|value| value.is_ascii_hexdigit() && !value.is_ascii_uppercase()),
            ERROR_INVALID_DATA,
            "Invalid object reference in metadata",
        )?;
        let object_directory = objects.join(object);
        let metadata = fs::symlink_metadata(&object_directory)?;
        require(
            !metadata.file_type().is_symlink(),
            ERROR_ACCESS_DENIED,
            "A certificate object directory must not be a symbolic link",
        )?;
        safe_metadata(
            &metadata,
            owner,
            shared,
            true,
            "A certificate object directory has unsafe ownership or permissions",
        )?;
        let certificate_path = object_directory.join("certificate.pem");
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&certificate_path)?;
        safe_metadata(
            &file.metadata()?,
            owner,
            shared,
            false,
            "A certificate object file has unsafe ownership or permissions",
        )?;
        let mut pem = Vec::new();
        file.read_to_end(&mut pem)?;
        result.push(Certificate::from_pem(&pem)?.to_der());
    }
    Ok(result)
}

fn append_unique(
    output: &mut Vec<Vec<u8>>,
    seen: &mut BTreeSet<Vec<u8>>,
    values: impl IntoIterator<Item = Vec<u8>>,
) {
    for value in values {
        let digest = Sha256::digest(&value).to_vec();
        if seen.insert(digest) {
            output.push(value);
        }
    }
}

fn source_certificates(
    paths: &SystemPaths,
    computer: bool,
    user_directory: &Path,
    user_owner: libc::uid_t,
) -> Result<Vec<SourceCertificate>, ApiError> {
    let effective = unsafe { libc::geteuid() };
    let mut encoded = Vec::new();
    let mut seen = BTreeSet::new();
    if computer {
        for name in ["MY", "CA"] {
            append_unique(
                &mut encoded,
                &mut seen,
                read_store_certificates(&paths.machine, name, effective, true)?,
            );
        }
    } else {
        for name in ["MY", "CA", "ROOT"] {
            append_unique(
                &mut encoded,
                &mut seen,
                read_store_certificates(user_directory, name, user_owner, false)?,
            );
        }
        append_unique(
            &mut encoded,
            &mut seen,
            read_store_certificates(&paths.machine, "CA", effective, true)?,
        );
    }
    append_unique(
        &mut encoded,
        &mut seen,
        read_native(&native_layout(Some(&paths.root))?)?,
    );
    encoded
        .into_iter()
        .map(|der| {
            Ok(SourceCertificate {
                certificate: Certificate::from_der(&der)?,
                openssl: X509::from_der(&der)?,
            })
        })
        .collect()
}

fn find_issuer(certificate: &X509, certificates: &[SourceCertificate]) -> Option<usize> {
    for (index, candidate) in certificates.iter().enumerate() {
        if candidate.openssl.issued(certificate) != openssl::x509::X509VerifyResult::OK {
            continue;
        }
        let Ok(key) = candidate.openssl.public_key() else {
            continue;
        };
        if certificate.verify(&key).unwrap_or(false) {
            return Some(index);
        }
    }
    None
}

fn parse_crl(bytes: &[u8], url: &str) -> Result<X509Crl, ApiError> {
    require(
        !bytes.is_empty(),
        ERROR_INVALID_DATA,
        format!("The CRL response is empty: {url}"),
    )?;
    if let Ok(crl) = X509Crl::from_der(bytes)
        && crl.to_der()?.len() == bytes.len()
    {
        return Ok(crl);
    }
    X509Crl::from_pem(bytes).map_err(|_| {
        ApiError::new(
            ERROR_INVALID_DATA,
            format!("The downloaded object is not a CRL: {url}"),
        )
    })
}

fn download_crl(url: &str) -> Result<X509Crl, ApiError> {
    let config = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(10)))
        .build();
    let agent = ureq::Agent::new_with_config(config);
    let mut response = agent.get(url).call().map_err(|error| {
        ApiError::new(
            ERROR_GEN_FAILURE,
            format!("Cannot download CRL from {url}: {error}"),
        )
    })?;
    let bytes = response
        .body_mut()
        .with_config()
        .limit(100 * 1024 * 1024)
        .read_to_vec()
        .map_err(|error| {
            ApiError::new(
                ERROR_GEN_FAILURE,
                format!("Cannot read CRL response from {url}: {error}"),
            )
        })?;
    parse_crl(&bytes, url)
}

fn validate_crl(crl: &X509Crl, issuer: &X509, url: &str) -> Result<(), ApiError> {
    require(
        crl.issuer_name().try_cmp(issuer.subject_name())? == Ordering::Equal,
        ERROR_INVALID_DATA,
        format!("The CRL issuer does not match its certificate: {url}"),
    )?;
    let key = issuer.public_key()?;
    require(
        crl.verify(&key)?,
        ERROR_INVALID_DATA,
        format!("The CRL signature is invalid: {url}"),
    )?;
    let now = Asn1Time::days_from_now(0)?;
    require(
        crl.last_update().compare(&now)? != Ordering::Greater,
        ERROR_INVALID_DATA,
        format!("The CRL lastUpdate is in the future: {url}"),
    )?;
    let next = crl.next_update().ok_or_else(|| {
        ApiError::new(
            ERROR_INVALID_DATA,
            format!("The CRL is expired or has no nextUpdate: {url}"),
        )
    })?;
    require(
        next.compare(&now)? == Ordering::Greater,
        ERROR_INVALID_DATA,
        format!("The CRL is expired or has no nextUpdate: {url}"),
    )
}

fn cache_name(certificate: &X509, url: &str) -> String {
    let mut utf16 = Vec::with_capacity(url.len() * 2);
    for byte in url.bytes() {
        utf16.push(byte);
        utf16.push(0);
    }
    let digest = Sha256::digest(&utf16);
    let url_hash = u32::from_le_bytes([digest[0], digest[1], digest[2], digest[3]]);
    format!(
        "{:08x}.{:08x}.crl",
        certificate.issuer_name_hash(),
        url_hash
    )
}

fn fstat(file: RawFd) -> Result<libc::stat, ApiError> {
    let mut status: libc::stat = unsafe { std::mem::zeroed() };
    require(
        unsafe { libc::fstat(file, &mut status) } == 0,
        ERROR_GEN_FAILURE,
        "Cannot inspect a .NET CRL cache path",
    )?;
    Ok(status)
}

fn open_directory(path: &Path, owner: libc::uid_t) -> Result<FileDescriptor, ApiError> {
    let path = path_cstring(path)?;
    let descriptor = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if descriptor < 0 {
        return Err(os_error(
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::PermissionDenied {
                ERROR_ACCESS_DENIED
            } else {
                ERROR_FILE_NOT_FOUND
            },
            "Cannot open the target account home directory",
        ));
    }
    let result = FileDescriptor(descriptor);
    let status = fstat(result.raw())?;
    require(
        status.st_mode & libc::S_IFMT == libc::S_IFDIR && status.st_uid == owner,
        ERROR_ACCESS_DENIED,
        "The target account must own its home directory",
    )?;
    Ok(result)
}

fn ensure_directory(
    parent: RawFd,
    name: &CStr,
    account: &Account,
    cache_directory: bool,
) -> Result<FileDescriptor, ApiError> {
    let created = if unsafe { libc::mkdirat(parent, name.as_ptr(), 0o700) } == 0 {
        true
    } else {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EEXIST) {
            return Err(ApiError::new(
                if error.kind() == std::io::ErrorKind::PermissionDenied {
                    ERROR_ACCESS_DENIED
                } else {
                    ERROR_GEN_FAILURE
                },
                format!("Cannot create the .NET CRL cache directory: {error}"),
            ));
        }
        false
    };
    let descriptor = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if descriptor < 0 {
        return Err(os_error(
            ERROR_ACCESS_DENIED,
            "A .NET CRL cache path component is not a safe directory",
        ));
    }
    let result = FileDescriptor(descriptor);
    if created
        && unsafe { libc::geteuid() } == 0
        && unsafe { libc::fchown(result.raw(), account.uid, account.gid) } != 0
    {
        return Err(os_error(
            ERROR_ACCESS_DENIED,
            "Cannot assign the .NET CRL cache directory to its user",
        ));
    }
    let status = fstat(result.raw())?;
    require(
        status.st_mode & libc::S_IFMT == libc::S_IFDIR
            && status.st_uid == account.uid
            && status.st_mode & 0o022 == 0,
        ERROR_ACCESS_DENIED,
        "A .NET CRL cache path component has unsafe ownership or permissions",
    )?;
    if cache_directory && unsafe { libc::fchmod(result.raw(), 0o700) } != 0 {
        return Err(os_error(
            ERROR_ACCESS_DENIED,
            "Cannot secure the .NET CRL cache directory",
        ));
    }
    Ok(result)
}

fn cache_directory(account: &Account, home: &Path) -> Result<FileDescriptor, ApiError> {
    let mut current = open_directory(home, account.uid)?;
    for (name, cache) in [
        (c".dotnet", false),
        (c"corefx", false),
        (c"cryptography", false),
        (c"crls", true),
    ] {
        current = ensure_directory(current.raw(), name, account, cache)?;
    }
    Ok(current)
}

fn cached_crl_is_fresh(
    directory: RawFd,
    account: &Account,
    name: &CStr,
    issuer: &X509,
    url: &str,
) -> Result<bool, ApiError> {
    let descriptor = unsafe {
        libc::openat(
            directory,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if descriptor < 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENOENT) {
            return Ok(false);
        }
        return Err(ApiError::new(
            if error.kind() == std::io::ErrorKind::PermissionDenied {
                ERROR_ACCESS_DENIED
            } else {
                ERROR_GEN_FAILURE
            },
            format!("Cannot inspect a .NET CRL cache file: {error}"),
        ));
    }
    let file = FileDescriptor(descriptor);
    let status = fstat(file.raw())?;
    require(
        status.st_mode & libc::S_IFMT == libc::S_IFREG
            && status.st_uid == account.uid
            && status.st_nlink == 1
            && status.st_mode & 0o077 == 0,
        ERROR_ACCESS_DENIED,
        "A .NET CRL cache file has unsafe ownership or permissions",
    )?;
    let duplicate = unsafe { libc::dup(file.raw()) };
    if duplicate < 0 {
        return Err(os_error(
            ERROR_GEN_FAILURE,
            "Cannot open a .NET CRL cache file",
        ));
    }
    let mut input = unsafe { File::from_raw_fd(duplicate) };
    let mut pem = Vec::new();
    input.read_to_end(&mut pem)?;
    let Ok(crl) = X509Crl::from_pem(&pem) else {
        return Ok(false);
    };
    match validate_crl(&crl, issuer, url) {
        Ok(()) => Ok(true),
        Err(error) if error.code == ERROR_INVALID_DATA => Ok(false),
        Err(error) => Err(error),
    }
}

fn write_all(file: RawFd, mut data: &[u8]) -> Result<(), ApiError> {
    while !data.is_empty() {
        let written = unsafe { libc::write(file, data.as_ptr().cast(), data.len()) };
        if written < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        if written <= 0 {
            return Err(os_error(
                ERROR_GEN_FAILURE,
                "Cannot write a .NET CRL cache file",
            ));
        }
        data = &data[written as usize..];
    }
    Ok(())
}

fn write_cache_file(
    directory: RawFd,
    account: &Account,
    name: &CStr,
    crl: &X509Crl,
) -> Result<(), ApiError> {
    let pem = crl.to_pem()?;
    let temporary = CString::new(format!(
        ".{}.tmp-{}-{}",
        name.to_string_lossy(),
        std::process::id(),
        rand::random::<u64>()
    ))
    .unwrap();
    let descriptor = unsafe {
        libc::openat(
            directory,
            temporary.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )
    };
    if descriptor < 0 {
        return Err(os_error(
            ERROR_ACCESS_DENIED,
            "Cannot create a temporary .NET CRL cache file",
        ));
    }
    let file = FileDescriptor(descriptor);
    let mut installed = false;
    let result: Result<(), ApiError> = (|| {
        if unsafe { libc::fchmod(file.raw(), 0o600) } != 0 {
            return Err(os_error(
                ERROR_ACCESS_DENIED,
                "Cannot secure a .NET CRL cache file",
            ));
        }
        if unsafe { libc::geteuid() } == 0
            && unsafe { libc::fchown(file.raw(), account.uid, account.gid) } != 0
        {
            return Err(os_error(
                ERROR_ACCESS_DENIED,
                "Cannot assign a .NET CRL cache file to its user",
            ));
        }
        write_all(file.raw(), &pem)?;
        if unsafe { libc::fsync(file.raw()) } != 0 {
            return Err(os_error(
                ERROR_GEN_FAILURE,
                "Cannot flush a .NET CRL cache file",
            ));
        }
        if unsafe { libc::renameat(directory, temporary.as_ptr(), directory, name.as_ptr()) } != 0 {
            return Err(os_error(
                ERROR_GEN_FAILURE,
                "Cannot install a .NET CRL cache file",
            ));
        }
        installed = true;
        if unsafe { libc::fsync(directory) } != 0 {
            return Err(os_error(
                ERROR_GEN_FAILURE,
                "Cannot flush the .NET CRL cache directory",
            ));
        }
        Ok(())
    })();
    if !installed {
        unsafe {
            libc::unlinkat(directory, temporary.as_ptr(), 0);
        }
    }
    result
}

fn target_home(account: &Account, explicit_user: bool) -> Result<PathBuf, ApiError> {
    if explicit_user
        && account.uid == unsafe { libc::geteuid() }
        && let Some(home) = env::var_os("HOME")
    {
        let home = PathBuf::from(home);
        require(home.is_absolute(), E_INVALIDARG, "HOME must be absolute")?;
        return Ok(home);
    }
    Ok(account.home.clone())
}

pub fn populate(user_name: Option<&CStr>, paths: &SystemPaths) -> Result<(), ApiError> {
    let mut failures = FailureSummary::default();
    let explicit_user = user_name.is_some();
    let accounts;
    let user_directory;
    if let Some(user_name) = user_name {
        let account = account_by_name(user_name)?;
        let effective = unsafe { libc::geteuid() };
        require(
            effective == 0 || account.uid == effective,
            ERROR_ACCESS_DENIED,
            "Root privileges are required to populate another user's .NET CRL cache",
        )?;
        user_directory = if account.uid == effective {
            user_data_directory(paths)?
        } else {
            account.home.join(".local/share/sys-cert-store")
        };
        accounts = vec![account];
    } else {
        accounts = dotnet_process_accounts(&mut failures)?;
        user_directory = PathBuf::new();
    }
    if accounts.is_empty() {
        if failures.count == 0 {
            return Ok(());
        }
        return Err(ApiError::new(
            ERROR_GEN_FAILURE,
            format!(
                "No .NET process account could be targeted. First failure: {}",
                failures.first
            ),
        ));
    }

    let certificates = source_certificates(
        paths,
        !explicit_user,
        &user_directory,
        if explicit_user {
            accounts[0].uid
        } else {
            unsafe { libc::geteuid() }
        },
    )?;
    let mut work = Vec::new();
    let mut seen = BTreeSet::new();
    for (certificate_index, certificate) in certificates.iter().enumerate() {
        for url in certificate.certificate.crl_distribution_points()? {
            let Some(issuer_index) = find_issuer(&certificate.openssl, &certificates) else {
                failures.add(format!(
                    "Cannot find the issuer for CRL distribution point {url}"
                ));
                continue;
            };
            let mut key = certificates[issuer_index].certificate.sha256_fingerprint();
            key.push(0);
            key.extend_from_slice(url.as_bytes());
            if seen.insert(key) {
                work.push(Work {
                    certificate: certificate_index,
                    issuer: issuer_index,
                    url,
                });
            }
        }
    }

    let mut cache_directories = BTreeMap::new();
    for account in &accounts {
        match target_home(account, explicit_user).and_then(|home| cache_directory(account, &home)) {
            Ok(directory) => {
                cache_directories.insert(account.uid, directory);
            }
            Err(error) => failures.add(format!("{}: {}", account.name, error.message)),
        }
    }
    if cache_directories.is_empty() {
        return Err(ApiError::new(
            ERROR_GEN_FAILURE,
            format!(
                "No .NET CRL cache directory could be opened. First failure: {}",
                failures.first
            ),
        ));
    }

    let mut cached = 0usize;
    for item in work {
        let result: Result<(), ApiError> = (|| {
            let name = CString::new(cache_name(
                &certificates[item.certificate].openssl,
                &item.url,
            ))
            .unwrap();
            let issuer = &certificates[item.issuer].openssl;
            let mut stale_accounts = Vec::new();
            for account in &accounts {
                let Some(directory) = cache_directories.get(&account.uid) else {
                    continue;
                };
                if cached_crl_is_fresh(directory.raw(), account, &name, issuer, &item.url)? {
                    cached += 1;
                } else {
                    stale_accounts.push(account);
                }
            }
            if stale_accounts.is_empty() {
                return Ok(());
            }
            let crl = download_crl(&item.url)?;
            validate_crl(&crl, issuer, &item.url)?;
            for account in stale_accounts {
                let Some(directory) = cache_directories.get(&account.uid) else {
                    continue;
                };
                match write_cache_file(directory.raw(), account, &name, &crl) {
                    Ok(()) => cached += 1,
                    Err(error) => failures.add(format!("{}: {}", account.name, error.message)),
                }
            }
            Ok(())
        })();
        if let Err(error) = result {
            failures.add(error.message);
        }
    }
    if failures.count != 0 {
        return Err(ApiError::new(
            ERROR_GEN_FAILURE,
            format!(
                "Cached {cached} CRL entr{}; {} operation{} failed. First failure: {}",
                if cached == 1 { "y" } else { "ies" },
                failures.count,
                if failures.count == 1 { "" } else { "s" },
                failures.first
            ),
        ));
    }
    Ok(())
}
