# sys-cert-store-rs

A Rust library and command-line tool for Linux certificate stores managed
through a Win32-shaped Rust API. The crate provides persistent stores
(MY/CA/ROOT), user and machine scoping, native trust integration, PKCS#7 and
PKCS#12 handling, post-quantum certificates, .NET CRL-cache preloading, and a
`certutil`-style CLI.

The supported public surfaces are the Rust crate and the `certutil` executable.


## Release build

```sh
git submodule update --init third_party/openssl third_party/scossl third_party/symcrypt
git -C third_party/symcrypt submodule update --init 3rdparty/jitterentropy-library
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
cmake --install build
```

The CMake build is the canonical release build. It assembles the pinned
cryptographic stack and then builds every Rust target:

- OpenSSL 3.5.8, built statically
- patched SymCrypt-OpenSSL/SCOSSL with its provider built into the binaries
- C SymCrypt for the provider's native cryptographic operations
- hidden crypto symbols and no dynamic OpenSSL, SCOSSL, or SymCrypt dependency

Rust-native crates handle X.509 parsing and classical signature verification,
PKCS#8 key parsing and public-key derivation, PKCS#12 import/export, PKCS#7/CMS
certificate containers, hashing, persistence, native-trust integration, and
the CLI. OpenSSL is selected only after an ML-DSA or composite ML-DSA OID is
detected; its built-in `symcryptprovider` then supplies those operations
through patched SCOSSL and C SymCrypt. SymCRust is not used because its current
public surface does not implement ML-DSA or the required composite algorithms.

Supported PQC signature algorithms are:

- `ML-DSA-44`, `ML-DSA-65`, and `ML-DSA-87`
- `MLDSA44-ECDSA-P256-SHA256`
- `MLDSA65-ECDSA-P256-SHA512`
- `MLDSA65-ECDSA-P384-SHA512`
- `MLDSA87-ECDSA-P384-SHA512`

## Rust development build

```sh
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
```

To run the certificate-listing example:

```sh
cargo run --example list_certificates
```

Direct Cargo builds use the system OpenSSL and are intended for fast
development of non-PQC store behavior. They do not provide the pinned provider
or guarantee ML-DSA support. SQLite remains statically bundled in both build
paths.

The implementation targets native Linux. Rust tests exercise store behavior,
`certutil`, pure and composite ML-DSA, and .NET CRL caching. The release checks
also verify that shipped executables neither depend dynamically on crypto
libraries nor export their symbols.

`SysCertPopulateDotNetCrlCache` preloads the private CRL cache used by .NET on
Linux. With a UTF-8 user name, it discovers HTTP CRL distribution points from
that user's `MY`, `CA`, and `ROOT` views and writes validated PEM CRLs below
`.dotnet/corefx/cryptography/crls`. The current user follows `HOME`, matching
.NET; another user follows that account's home-directory record. The caller
must be root or the selected user.

Passing a null user-name pointer scans `/proc/*/maps` for processes that have loaded
`libcoreclr.so`, deduplicates their effective UIDs, discovers CDPs from the
computer `MY`, `CA`, and `ROOT` stores, and populates each discovered account's
cache. Restricted `/proc` visibility is reported rather than silently producing
an incomplete result. Downloads use HTTP, require a matching issuer and valid
CRL signature, reject future or expired CRLs, and reproduce .NET's
`<issuer-hash>.<URL-hash>.crl` name. Cache directories are `0700`, files are
`0600`, writes are atomic, and root assigns ownership to the target account.
Processing is best effort: successful independent entries remain cached while
failures are aggregated into the library's error state.
