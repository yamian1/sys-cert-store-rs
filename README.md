# sys-cert-store-rs

`sys-cert-store-rs` is a Rust library and command-line tool for managing
certificate stores on Linux through a Win32-shaped API.

It provides:

- Persistent `MY`, `CA`, `ROOT`, and custom certificate stores
- Current-user and local-machine store scopes
- Certificate enumeration, search, add, replace, and delete operations
- Certificate properties and store properties
- PKCS#7 import and export
- PKCS#12/PFX import and export, including private keys and certificate chains
- Offline certificate-chain construction and base-policy validation
- PEM, DER, and base64 conversion
- Native Linux trust-store integration
- ML-DSA and composite ML-DSA certificate support
- .NET CRL-cache preloading
- A `certutil`-style Linux command-line interface

The supported public surfaces are the Rust crate and the `certutil`
executable. The crate is an `rlib`; it does not expose a C ABI or install C/C++
headers.

## Use the Rust crate

Clone the repository beside your application and add it as a path dependency:

```toml
[dependencies]
sys-cert-store = { path = "../sys-cert-store-rs" }
```

The API uses familiar CryptoAPI names and data structures. The following
example opens the current scope's `ROOT` store and counts its certificates:

```rust
use std::ptr;
use sys_cert_store::api_types::{CRYPT_E_NOT_FOUND, FALSE, WCHAR};
use sys_cert_store::{
    CertCloseStore, CertEnumCertificatesInStore, CertOpenSystemStoreW,
    GetLastError,
};

fn main() {
    let mut store_name: Vec<WCHAR> = "ROOT".chars().map(|ch| ch as WCHAR).collect();
    store_name.push(0);

    let store = CertOpenSystemStoreW(0, store_name.as_ptr());
    assert!(!store.is_null(), "open failed: 0x{:x}", GetLastError());

    let mut count = 0;
    let mut certificate = ptr::null();
    loop {
        certificate = CertEnumCertificatesInStore(store, certificate);
        if certificate.is_null() {
            break;
        }
        count += 1;
    }

    assert_eq!(GetLastError(), CRYPT_E_NOT_FOUND);
    assert_ne!(CertCloseStore(store, 0), FALSE);
    println!("{count} certificates");
}
```

Run the complete example with:

```sh
cargo run --example list_certificates
```

The crate exposes operations for:

- Opening memory, system, and PKCS#7 stores
- Creating, duplicating, enumerating, finding, and freeing certificate contexts
- Reading and writing certificate and store properties
- Importing and exporting PFX data
- Saving stores as PKCS#7
- Building and validating certificate chains
- Updating native trust anchors
- Locating persisted certificate files
- Populating the .NET CRL cache

The API is intentionally low level and uses handles, pointers, explicit
lifetimes, two-call output-buffer patterns, and `GetLastError`-style error
reporting. Call `SysCertGetLastErrorMessage` for the diagnostic message
associated with the current thread's last error.

## Use `certutil`

Build and run the CLI:

```sh
cargo build --bin certutil
./target/debug/certutil --help
```

Common operations:

```sh
# List available stores.
certutil -enumstore

# List certificates in the current user's MY store.
certutil -user -store MY

# Import a PEM, DER, or PKCS#7 certificate container.
certutil -user -addstore CA certificates.p7b

# Import a PFX and all certificates it contains into MY.
certutil -user --password-file password.txt -importPFX MY identity.pfx

# Export a certificate, private key, and chain.
certutil -user --password-file password.txt \
    -exportPFX MY sha256:<certificate-hash> identity.pfx

# Export only the end-entity certificate and private key.
certutil -user --password-file password.txt \
    -exportPFX MY sha256:<certificate-hash> identity.pfx NoChain

# Display a certificate or PKCS#7 file.
certutil -dump certificates.p7b
```

The default scope is the local machine. Use `-user` for the current user's
stores. Writing the machine `ROOT` store requires operating-system permission
and the explicit `--allow-native-write` option.

Run `certutil --help` for certificate selectors, output formats, relocated
store directories, and all supported options.

## Store behavior

`MY`, `CA`, and custom stores use persistent metadata and object storage.
`ROOT` integrates with the native Linux trust configuration. User and machine
scopes are independent.

PFX import adds the certificates contained in the PFX to the selected store.
The certificate carrying the private key retains that key association. PFX
export can include the complete chain, omit the root with `NoRoot`, or export
only the selected certificate with `NoChain`.

The chain APIs currently build complete, unambiguous offline chains from the
available stores. Network retrieval and unsupported CryptoAPI chain options
return an explicit error rather than silently changing behavior.

## Post-quantum certificates

The canonical CMake build includes the pinned cryptographic stack required for:

- `ML-DSA-44`
- `ML-DSA-65`
- `ML-DSA-87`
- `MLDSA44-ECDSA-P256-SHA256`
- `MLDSA65-ECDSA-P256-SHA512`
- `MLDSA65-ECDSA-P384-SHA512`
- `MLDSA87-ECDSA-P384-SHA512`

OpenSSL is used only when an ML-DSA or composite ML-DSA operation requires the
bundled provider. Classical certificate parsing, verification, persistence,
PKCS#7 handling, and PKCS#12 handling use Rust implementations.

## Build and test

For regular Rust development:

```sh
cargo build
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
```

Direct Cargo builds use the system OpenSSL and are suitable for store and
classical-certificate development. They do not guarantee ML-DSA support.

For a release build with the pinned PQC-capable crypto stack:

```sh
git submodule update --init third_party/openssl third_party/scossl third_party/symcrypt
git -C third_party/symcrypt submodule update --init 3rdparty/jitterentropy-library

cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

The release `certutil` executable is written to:

```text
build/cargo-target/release/certutil
```

The release checks run the Rust tests and verify that the shipped executables
use the statically linked crypto stack.

## .NET CRL-cache preloading

`SysCertPopulateDotNetCrlCache` discovers HTTP CRL distribution points from
the selected account's `MY`, `CA`, and `ROOT` stores, validates downloaded
CRLs, and writes them to the cache layout used by .NET on Linux.

The operation validates issuer matching, signatures, and validity periods. It
uses restrictive directory and file permissions, atomic writes, and reports
partial failures instead of silently producing an incomplete cache.

## Appendix A: cryptographic dependency architecture

```text
Rust application                    certutil
       |                               |
       +---------------+---------------+
                       |
                       v
              sys-cert-store crate
                       |
          +------------+-----------------------------+
          |                                          |
          v                                          v
 Rust-native classical path                   PQC signature path
          |                                          |
          +-- X.509 parsing                          +-- openssl crate
          +-- classical signature verification       |      |
          +-- PKCS#8 key handling                    |      v
          +-- PKCS#7/CMS containers                  +-- openssl-sys
          +-- PKCS#12/PFX containers                        |
          +-- hashing and encoding                          v
          |                                       static OpenSSL
          |                                              |
          |                              +---------------+---------------+
          |                              |                               |
          |                              v                               v
          |                       default provider          built-in symcryptprovider
          |                                                      |
          |                                                      v
          |                                             patched SCOSSL
          |                                                      |
          |                                                      v
          |                                        C SymCrypt static libraries
          |                                                      |
          |                                                      v
          |                                                jitterentropy
          |
          +-- SQLite-backed certificate-store persistence
          +-- native Linux trust-store integration
```

The bundled provider is initialized through this small native boundary:

```text
sys-cert-store::crypto::initialize()
    |
    v
src/crypto.cpp
    |
    +-- initializes static OpenSSL
    +-- registers the built-in SCOSSL symcryptprovider
    +-- loads the default and SymCrypt providers
    +-- selects the SymCrypt provider when an algorithm is available
```

Classical certificate operations remain on the Rust-native path. ML-DSA and
composite ML-DSA operations use OpenSSL, the built-in SCOSSL provider, and C
SymCrypt because those signature algorithms are not currently exposed by
SymCRust.

SymCRust is present in the pinned SymCrypt source tree but is not linked into
this crate:

```text
SymCRust
    +-- exposes ML-KEM and supporting primitives
    +-- does not expose ML-DSA or composite ML-DSA
    +-- therefore is not part of the runtime dependency graph
```
