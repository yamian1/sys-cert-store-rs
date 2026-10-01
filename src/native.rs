use crate::cert::Certificate;
use crate::error::{ApiError, require};
use crate::ffi::*;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use walkdir::WalkDir;

#[derive(Clone, Debug)]
pub struct NativeLayout {
    pub root: PathBuf,
    pub bundle: PathBuf,
    pub anchors: PathBuf,
    pub staging: PathBuf,
    pub updater: PathBuf,
    pub debian: bool,
}

fn read_file(path: &Path) -> Result<Vec<u8>, ApiError> {
    fs::read(path).map_err(|error| {
        ApiError::new(
            if error.kind() == std::io::ErrorKind::PermissionDenied {
                ERROR_ACCESS_DENIED
            } else {
                ERROR_FILE_NOT_FOUND
            },
            "Cannot open native trust file",
        )
    })
}

fn os_value(value: &str) -> &str {
    if value.len() >= 2
        && ((value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\'')))
    {
        &value[1..value.len() - 1]
    } else {
        value
    }
}

pub fn native_layout(root: Option<&Path>) -> Result<NativeLayout, ApiError> {
    let root = root.unwrap_or_else(|| Path::new("/"));
    require(
        root.is_absolute(),
        E_INVALIDARG,
        "Native root must be absolute",
    )?;
    let root = fs::canonicalize(root)?;
    let release = String::from_utf8(read_file(&root.join("etc/os-release"))?)
        .map_err(|_| ApiError::new(ERROR_INVALID_DATA, "Invalid /etc/os-release"))?;
    let mut family = HashSet::new();
    for line in release.lines() {
        if let Some(value) = line.strip_prefix("ID=") {
            family.insert(os_value(value).to_owned());
        }
        if let Some(value) = line.strip_prefix("ID_LIKE=") {
            family.extend(os_value(value).split_whitespace().map(str::to_owned));
        }
    }
    let debian = family
        .iter()
        .any(|value| matches!(value.as_str(), "ubuntu" | "debian"));
    let rpm = family.iter().any(|value| {
        matches!(
            value.as_str(),
            "rhel" | "fedora" | "centos" | "rocky" | "almalinux" | "mariner" | "azurelinux"
        )
    });
    require(
        debian || rpm,
        ERROR_NOT_SUPPORTED,
        "Unsupported distro; expected Ubuntu/Debian, Red Hat family, Mariner or Azure Linux",
    )?;
    if debian {
        Ok(NativeLayout {
            bundle: root.join("etc/ssl/certs/ca-certificates.crt"),
            anchors: root.join("usr/local/share/ca-certificates"),
            staging: root.join("usr/local/share/.sys-cert-store-staging"),
            updater: root.join("usr/sbin/update-ca-certificates"),
            root,
            debian: true,
        })
    } else {
        Ok(NativeLayout {
            bundle: root.join("etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem"),
            anchors: root.join("etc/pki/ca-trust/source/anchors"),
            staging: root.join("etc/pki/.sys-cert-store-staging"),
            updater: root.join("usr/bin/update-ca-trust"),
            root,
            debian: false,
        })
    }
}

pub fn read_native(layout: &NativeLayout) -> Result<Vec<Vec<u8>>, ApiError> {
    let text = String::from_utf8(read_file(&layout.bundle)?)
        .map_err(|_| ApiError::new(ERROR_INVALID_DATA, "Native trust bundle is not UTF-8 PEM"))?;
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let mut offset = 0;
    let mut result = Vec::new();
    let mut seen = HashSet::new();
    while offset < text.len() {
        let remainder = &text[offset..];
        let start = remainder.find(BEGIN).map(|value| offset + value);
        let tail_end = start.unwrap_or(text.len());
        for line in text[offset..tail_end].lines() {
            let trimmed = line.trim();
            require(
                trimmed.is_empty() || trimmed.starts_with('#'),
                ERROR_INVALID_DATA,
                "Unexpected data in native PEM trust bundle",
            )?;
        }
        let Some(start) = start else { break };
        let stop = text[start + BEGIN.len()..]
            .find(END)
            .map(|value| start + BEGIN.len() + value)
            .ok_or_else(|| {
                ApiError::new(
                    ERROR_INVALID_DATA,
                    "Truncated certificate in native trust bundle",
                )
            })?;
        let end = stop + END.len();
        let certificate = Certificate::from_pem(&text.as_bytes()[start..end]).map_err(|_| {
            ApiError::new(
                ERROR_INVALID_DATA,
                "Invalid certificate in native trust bundle",
            )
        })?;
        let der = certificate.to_der();
        if seen.insert(der.clone()) {
            result.push(der);
        }
        offset = end;
    }
    Ok(result)
}

fn anchor_name(certificate: &Certificate) -> Result<String, ApiError> {
    Ok(format!(
        "sys-cert-store-{}.crt",
        hex::encode(Sha256::digest(certificate.to_der()))
    ))
}

fn blocklist_directory(layout: &NativeLayout) -> PathBuf {
    let source = layout.root.join("etc/pki/ca-trust/source");
    if !source.join("blocklist").exists() && source.join("blacklist").exists() {
        source.join("blacklist")
    } else {
        source.join("blocklist")
    }
}

fn mutation_check(certificate: &Certificate) -> Result<(), ApiError> {
    require(
        unsafe { libc::getuid() == libc::geteuid() && libc::getgid() == libc::getegid() },
        ERROR_ACCESS_DENIED,
        "Trust updates are disabled in set-ID processes",
    )?;
    require(
        certificate.is_ca()?,
        E_INVALIDARG,
        "Only CA certificates can be installed as trust anchors",
    )
}

fn run_updater(layout: &NativeLayout) -> Result<(), ApiError> {
    let status = Command::new(&layout.updater)
        .arg(if layout.debian { "--fresh" } else { "extract" })
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LC_ALL", "C")
        .status()
        .map_err(|_| ApiError::new(ERROR_GEN_FAILURE, "Cannot start distro trust updater"))?;
    require(
        status.success(),
        ERROR_GEN_FAILURE,
        "Distro trust updater failed; inspect its stderr",
    )
}

#[derive(Clone)]
struct Change {
    path: PathBuf,
    before: Option<Vec<u8>>,
    after: Option<Vec<u8>>,
    mode: u32,
}

fn change(path: PathBuf, after: Option<Vec<u8>>) -> Result<Change, ApiError> {
    let before = if path.exists() {
        let metadata = fs::symlink_metadata(&path)?;
        require(
            metadata.is_file() && !metadata.file_type().is_symlink() && metadata.nlink() == 1,
            ERROR_ACCESS_DENIED,
            "Trust source must be a regular non-symlink file",
        )?;
        Some(fs::read(&path)?)
    } else {
        None
    };
    let mode = fs::metadata(&path)
        .map(|value| value.permissions().mode() & 0o777)
        .unwrap_or(0o644);
    Ok(Change {
        path,
        before,
        after,
        mode,
    })
}

fn write_replacement(path: &Path, data: &[u8], mode: u32) -> Result<(), ApiError> {
    let parent = path
        .parent()
        .ok_or_else(|| ApiError::new(ERROR_INVALID_PARAMETER, "Trust path has no parent"))?;
    fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(".sys-cert-store-{}.new", std::process::id()));
    fs::write(&temporary, data)?;
    fs::set_permissions(&temporary, fs::Permissions::from_mode(mode))?;
    fs::rename(&temporary, path)?;
    Ok(())
}

fn apply_changes(
    layout: &NativeLayout,
    changes: Vec<Change>,
    certificate: &Certificate,
    installed: bool,
) -> Result<(), ApiError> {
    require(
        !changes.is_empty(),
        CRYPT_E_NOT_FOUND,
        "No active root source to remove",
    )?;
    fs::create_dir_all(&layout.staging)?;
    fs::set_permissions(&layout.staging, fs::Permissions::from_mode(0o700))?;
    let journal = layout.staging.join("pending-update");
    require(
        !journal.exists(),
        ERROR_BUSY,
        "A pending native trust recovery journal already exists",
    )?;
    let manifest = changes
        .iter()
        .enumerate()
        .map(|(index, item)| {
            format!(
                "{index}.rollback\t{}\t{}\n",
                if item.before.is_some() {
                    "restore"
                } else {
                    "remove"
                },
                item.path.display()
            )
        })
        .collect::<String>();
    fs::write(&journal, manifest)?;
    fs::set_permissions(&journal, fs::Permissions::from_mode(0o600))?;
    let mut applied = 0usize;
    let operation = (|| -> Result<(), ApiError> {
        for item in &changes {
            let current = if item.path.exists() {
                Some(fs::read(&item.path)?)
            } else {
                None
            };
            require(
                current == item.before,
                ERROR_BUSY,
                "Trust source changed concurrently; retry after resynchronizing",
            )?;
            if let Some(after) = &item.after {
                write_replacement(&item.path, after, item.mode)?;
            } else if item.path.exists() {
                fs::remove_file(&item.path)?;
            }
            applied += 1;
        }
        run_updater(layout)?;
        let expected = certificate.to_der();
        let present = read_native(layout)?.iter().any(|value| value == &expected);
        require(
            present == installed,
            ERROR_GEN_FAILURE,
            "Distro updater did not produce the requested active trust state; inspect other trust/distrust sources",
        )
    })();
    if let Err(original) = operation {
        for item in changes[..applied].iter().rev() {
            if let Some(before) = &item.before {
                write_replacement(&item.path, before, item.mode)?;
            } else if item.path.exists() {
                fs::remove_file(&item.path)?;
            }
        }
        let regeneration = if applied > 0 {
            run_updater(layout)
        } else {
            Ok(())
        };
        let _ = fs::remove_file(&journal);
        if regeneration.is_err() {
            return Err(ApiError::new(
                ERROR_GEN_FAILURE,
                "Source changes rolled back, but trust bundle regeneration failed; run the distro updater manually",
            ));
        }
        return Err(ApiError::new(
            ERROR_GEN_FAILURE,
            format!("Trust update rolled back: {}", original.message),
        ));
    }
    fs::remove_file(&journal)?;
    Ok(())
}

fn pem_certificates(data: &[u8]) -> Result<Vec<Certificate>, ApiError> {
    const BEGIN: &[u8] = b"-----BEGIN CERTIFICATE-----";
    const END: &[u8] = b"-----END CERTIFICATE-----";
    let mut result = Vec::new();
    let mut offset = 0;
    while let Some(relative_start) = data[offset..]
        .windows(BEGIN.len())
        .position(|value| value == BEGIN)
    {
        let start = offset + relative_start;
        let body = start + BEGIN.len();
        let relative_end = data[body..]
            .windows(END.len())
            .position(|value| value == END)
            .ok_or_else(|| ApiError::new(ERROR_INVALID_DATA, "Truncated certificate PEM"))?;
        let end = body + relative_end + END.len();
        result.push(Certificate::from_pem(&data[start..end])?);
        offset = end;
    }
    require(
        !result.is_empty(),
        ERROR_INVALID_DATA,
        "Invalid trust source",
    )?;
    Ok(result)
}

fn contains_certificate(path: &Path, expected: &[u8]) -> Result<bool, ApiError> {
    let text = fs::read(path)?;
    let marker = b"-----BEGIN CERTIFICATE-----";
    if !text.windows(marker.len()).any(|value| value == marker) {
        return Ok(false);
    }
    let certificates = pem_certificates(&text)?;
    if certificates[0].to_der() != expected {
        return Ok(false);
    }
    require(
        certificates.len() == 1,
        ERROR_NOT_SUPPORTED,
        "Cannot remove an individual certificate from a multi-certificate local source",
    )?;
    Ok(true)
}

pub fn update_anchor(
    certificate: &Certificate,
    install: bool,
    layout: &NativeLayout,
) -> Result<(), ApiError> {
    mutation_check(certificate)?;
    if !install {
        return remove_trusted_certificate(certificate, layout);
    }
    let addition = change(
        layout.anchors.join(anchor_name(certificate)?),
        Some(certificate.to_pem()),
    )?;
    require(
        addition.before.is_none(),
        CRYPT_E_EXISTS,
        "Local trust anchor already exists",
    )?;
    let mut changes = vec![addition];
    if !layout.debian {
        let blocked = change(
            blocklist_directory(layout).join(anchor_name(certificate)?),
            None,
        )?;
        if blocked.before.is_some() {
            changes.push(blocked);
        }
    }
    apply_changes(layout, changes, certificate, true)
}

pub fn remove_trusted_certificate(
    certificate: &Certificate,
    layout: &NativeLayout,
) -> Result<(), ApiError> {
    mutation_check(certificate)?;
    let expected = certificate.to_der();
    let mut changes = Vec::new();
    if layout.anchors.exists() {
        for entry in WalkDir::new(&layout.anchors).follow_links(false) {
            let entry =
                entry.map_err(|error| ApiError::new(ERROR_GEN_FAILURE, error.to_string()))?;
            if !entry.file_type().is_file() || entry.path_is_symlink() {
                continue;
            }
            if layout.debian
                && entry.path().extension().and_then(|value| value.to_str()) != Some("crt")
            {
                continue;
            }
            if contains_certificate(entry.path(), &expected)? {
                changes.push(change(entry.path().to_owned(), None)?);
            }
        }
    }
    if layout.debian {
        let config = layout.root.join("etc/ca-certificates.conf");
        if config.exists() {
            let input = String::from_utf8(fs::read(&config)?)
                .map_err(|_| ApiError::new(ERROR_INVALID_DATA, "Invalid ca-certificates.conf"))?;
            let mut output = String::new();
            let mut modified = false;
            for mut line in input.lines().map(str::to_owned) {
                if !line.is_empty() && !line.starts_with('#') && !line.starts_with('!') {
                    let relative = PathBuf::from(&line);
                    require(
                        !relative.is_absolute() && !line.contains(".."),
                        ERROR_INVALID_DATA,
                        "Unsafe path in ca-certificates.conf",
                    )?;
                    let source = layout
                        .root
                        .join("usr/share/ca-certificates")
                        .join(&relative);
                    if source.exists() && contains_certificate(&source, &expected)? {
                        line.insert(0, '!');
                        modified = true;
                    }
                }
                output.push_str(&line);
                output.push('\n');
            }
            if modified {
                changes.push(change(config, Some(output.into_bytes()))?);
            }
        }
    } else {
        let directory = blocklist_directory(layout);
        fs::create_dir_all(&directory)?;
        let blocked = change(
            directory.join(anchor_name(certificate)?),
            Some(certificate.to_pem()),
        )?;
        if let Some(before) = &blocked.before {
            require(
                Some(before) == blocked.after.as_ref(),
                ERROR_ACCESS_DENIED,
                "Unexpected root blocklist contents",
            )?;
        } else {
            changes.push(blocked);
        }
    }
    apply_changes(layout, changes, certificate, false)
}
