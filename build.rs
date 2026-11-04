use std::env;
use std::path::Path;

fn link_bundled_archive(variable: &str) {
    let value = env::var(variable)
        .unwrap_or_else(|_| panic!("{variable} is required when SCS_BUNDLED_CRYPTO is set"));
    let archive = Path::new(&value);
    let directory = archive
        .parent()
        .filter(|directory| !directory.as_os_str().is_empty())
        .unwrap_or_else(|| panic!("{variable} must include an archive directory"));
    let filename = archive
        .file_name()
        .and_then(|filename| filename.to_str())
        .unwrap_or_else(|| panic!("{variable} must name a UTF-8 archive file"));

    println!("cargo:rustc-link-search=native={}", directory.display());
    println!("cargo:rustc-link-lib=static:+bundle,+verbatim={filename}");
}

fn main() {
    println!("cargo:rustc-check-cfg=cfg(scs_bundled_crypto)");
    for variable in [
        "SCS_BUNDLED_CRYPTO",
        "SCS_CRYPTO_ARCHIVE",
        "SCS_SCOSSL_ARCHIVE",
        "SCS_SYMCRYPT_RUNTIME_ARCHIVE",
        "SCS_SYMCRYPT_POSIX_ARCHIVE",
        "SCS_SYMCRYPT_COMMON_ARCHIVE",
        "SCS_SYMCRYPT_MLKEM_ARCHIVE",
        "SCS_JITTER_ARCHIVE",
        "SCS_OPENSSL_ARCHIVE",
    ] {
        println!("cargo:rerun-if-env-changed={variable}");
    }

    if env::var_os("SCS_BUNDLED_CRYPTO").is_none() {
        return;
    }

    println!("cargo:rustc-cfg=scs_bundled_crypto");
    for variable in [
        "SCS_CRYPTO_ARCHIVE",
        "SCS_SCOSSL_ARCHIVE",
        "SCS_SYMCRYPT_RUNTIME_ARCHIVE",
        "SCS_SYMCRYPT_POSIX_ARCHIVE",
        "SCS_SYMCRYPT_COMMON_ARCHIVE",
        "SCS_SYMCRYPT_MLKEM_ARCHIVE",
        "SCS_JITTER_ARCHIVE",
        "SCS_OPENSSL_ARCHIVE",
    ] {
        link_bundled_archive(variable);
    }
    println!("cargo:rustc-link-arg=-Wl,--exclude-libs,ALL");
    println!("cargo:rustc-link-arg=-Wl,-z,noexecstack");
    println!("cargo:rustc-link-lib=dylib=stdc++");
    println!("cargo:rustc-link-lib=dylib=atomic");
    println!("cargo:rustc-link-lib=dylib=dl");
    println!("cargo:rustc-link-lib=dylib=pthread");
}
