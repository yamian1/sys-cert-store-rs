use std::env;

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
    println!("cargo:rustc-link-arg=-Wl,--start-group");
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
        let archive = env::var(variable)
            .unwrap_or_else(|_| panic!("{variable} is required when SCS_BUNDLED_CRYPTO is set"));
        println!("cargo:rustc-link-arg={archive}");
    }
    println!("cargo:rustc-link-arg=-Wl,--end-group");
    println!("cargo:rustc-link-arg=-Wl,--exclude-libs,ALL");
    println!("cargo:rustc-link-arg=-Wl,-z,noexecstack");
    println!("cargo:rustc-link-lib=dylib=stdc++");
    println!("cargo:rustc-link-lib=dylib=atomic");
    println!("cargo:rustc-link-lib=dylib=dl");
    println!("cargo:rustc-link-lib=dylib=pthread");
}
