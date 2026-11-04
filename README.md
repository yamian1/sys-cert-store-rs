# sys-cert-store-rs

`sys-cert-store-rs` is a multi-platform Rust library that exposes a
Win32-shaped certificate-store API.

- On Windows, standard CryptoAPI calls pass directly through to the operating
  system.
- On Linux, the crate provides persistent certificate stores, native trust
  integration, PFX and PKCS#7 handling, chain operations, and PQC support.
- The `certutil` command-line tool is currently available on Linux.

It provides:

- Persistent `MY`, `CA`, `ROOT`, and custom certificate stores
- Current-user and local-machine store scopes
- Certificate enumeration, search, add, replace, and delete operations
- Certificate properties and store properties
- PKCS#7 import and export
- PKCS#12/PFX import and export, including private keys and certificate chains
- Offline certificate-chain construction and base-policy validation
- PEM, DER, and base64 conversion
- Native trust-store integration on Linux
- ML-DSA and composite ML-DSA certificate support
- .NET CRL-cache preloading
- A `certutil`-style command-line interface on Linux

The supported public surfaces are the Rust crate and the `certutil`
executable. The crate is an `rlib`; it does not expose a C ABI or install C/C++
headers.

## Use the Rust crate

Clone the repository beside your application and add it as a path dependency:

```toml
[dependencies]
sys-cert-store = { path = "../sys-cert-store-rs" }
```

The safe API owns stores, certificate contexts, and chains and releases them
exactly once. The following example opens the current scope's `ROOT` store and
counts its certificates:

```rust
use sys_cert_store::safe::CertificateStore;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let store = CertificateStore::open_system("ROOT")?;
    println!("{} certificates", store.certificates()?.len());
    Ok(())
}
```

Run the complete example with:

```sh
cargo run --example list_certificates
```

The `safe` module initially covers:

- Opening system certificate stores
- Enumerating certificates into independently owned context handles
- Creating and duplicating certificate contexts
- Building certificate chains
- Automatically closing stores and releasing contexts and chains

The crate also exposes raw CryptoAPI-compatible operations for:

- Opening memory, system, and PKCS#7 stores
- Creating, duplicating, enumerating, finding, and freeing certificate contexts
- Reading and writing certificate and store properties
- Importing and exporting PFX data
- Saving stores as PKCS#7
- Building and validating certificate chains
- Updating native trust anchors on Linux
- Locating persisted certificate files on Linux
- Populating the .NET CRL cache on Linux

## Raw compatibility API

The Win32-shaped functions at the crate root are intentionally low level and
use handles, pointers, explicit lifetimes, two-call output-buffer patterns,
and `GetLastError`-style error reporting. Functions whose correctness depends
on caller-provided pointer, lifetime, or ownership guarantees are `unsafe fn`.
Each such function documents its requirements in a `# Safety` section.

Prefer `sys_cert_store::safe` for ordinary application code. Use the raw
surface only when implementing compatibility behavior that the safe module
does not yet cover, and keep each unsafe block narrow enough to state why its
pointers and owned handles satisfy the documented contract.

On Windows, the standard `Cert*`, `Crypt*`, and PFX calls preserve native
CryptoAPI behavior, handles, and last-error values. The Linux-specific
`SysCert*` extensions return `ERROR_CALL_NOT_IMPLEMENTED` on Windows.
`SysCertGetLastErrorMessage` is one of those Linux-specific extensions.

### Migrating from 0.1.x

Version 0.2.0 is a source-breaking safety correction. Raw function names,
arguments, return values, and platform behavior are unchanged, but calls that
depend on caller-enforced memory or ownership invariants now require an
explicit unsafe block.

- Replace manual store close guards with `safe::CertificateStore`.
- Replace create/duplicate/free context pairs with
  `safe::CertificateContextHandle`.
- Replace build/free chain pairs with `safe::CertificateChainHandle`.
- For remaining raw calls, satisfy and document the function's `# Safety`
  contract rather than broadly marking an entire operation unsafe.
- `cert::Context` is now internal and cannot be named or mutated by external
  callers.

## Use `certutil` on Linux

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

## Linux store behavior

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

## Post-quantum certificates on Linux

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

For regular Rust development on either platform:

```sh
cargo build
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
```

Windows builds use the operating system's CryptoAPI and do not build the Linux
OpenSSL, SQLite, SCOSSL, or SymCrypt dependency stack.

Direct Linux Cargo builds use the system OpenSSL and are suitable for store and
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
Rust application
       |
       v
sys-cert-store crate
       |
       +-- Windows --> native Win32 CryptoAPI
       |
       +-- Linux ------------------------+-----------------------------+
                                        |                             |
                                        v                             v
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
