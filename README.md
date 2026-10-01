# sys-cert-store-rs

A Rust implementation of the Linux `sys-cert-store` API. It preserves the
existing project's C ABI, Win32-shaped certificate-store surface, persistent
SQLite/object layout, system-store scoping, native trust integration, and
`certutil` command-line behavior.

The public headers are source-compatible with the C++ implementation. CMake
builds the Rust `cdylib` as `libsys_cert_store.so`, installs it as
`libsys-cert-store.so`, and exposes the installed
`sys-cert-store::sys-cert-store` target.

## Release and compatibility build

```sh
git submodule update --init third_party/openssl third_party/scossl third_party/symcrypt
git -C third_party/symcrypt submodule update --init 3rdparty/jitterentropy-library
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
cmake --install build
```

The CMake build is the canonical build. It uses the same pinned cryptographic
stack as the C++ implementation:

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

Direct Cargo builds use the system OpenSSL and are intended for fast
development of non-PQC store behavior. They do not provide the pinned provider
or guarantee ML-DSA support. SQLite remains statically bundled in both build
paths.

The implementation targets native Linux. The compatibility suite exercises the
original C ABI behavior, `certutil`, pure and composite ML-DSA, and verifies
that release binaries neither depend dynamically on crypto libraries nor
export their symbols.
