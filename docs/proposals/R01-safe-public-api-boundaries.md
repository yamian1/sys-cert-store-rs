# R01: Enforce Memory-Safety Boundaries in the Public API

- **Status:** Implemented
- **Severity addressed:** High
- **Category:** Idiomatic Rust and community-adopted patterns
- **Affected platforms:** Linux and Windows
- **Target release:** 0.2.0

## Summary

The crate's Win32-shaped API currently exposes safe Rust functions whose
correctness depends on caller-provided pointer, lifetime, aliasing, handle, or
ownership guarantees. Several functions dereference raw pointers, create
slices from caller-controlled addresses, pass pointers to native APIs, or
reconstruct owned allocations. Those operations cannot be soundly exposed as
safe Rust.

The Linux implementation also publicly exposes the internal `Context` type and
fields that participate in self-referential pointer invariants. Safe external
code can mutate those fields and invalidate pointers later used by safe
methods.

This proposal makes the low-level API accurately unsafe, makes `Context`
implementation-only, removes safe methods that read through mutable raw
metadata, and adds a small set of safe owning wrappers for common operations.
It does not replace the Win32-compatible surface or introduce a broad new
certificate framework.

## Problem

Examples of the current unsound boundary include:

- `CertCreateCertificateContext` creates a slice from an arbitrary address and
  length.
- Windows forwarding functions pass arbitrary pointers to CryptoAPI from safe
  Rust.
- `CertFreeCertificateChain` reconstructs a `Box` from a caller-provided
  pointer without requiring allocation provenance, uniqueness, or one-time
  consumption.
- `Context.info` and related fields can be changed through safe Rust even
  though they contain pointers into allocations owned by the same `Context`.
- `Context::issuer_der` and `Context::serial_le` create slices from those
  mutable pointer fields.

Null checks establish only that an address is nonzero. They do not establish
validity, alignment, initialized length, lifetime, aliasing, allocation
provenance, or ownership. `catch_unwind` contains Rust panics but cannot
contain undefined behavior.

The crate is currently an `rlib` and does not export a C ABI. Changing a Rust
function from `fn` to `unsafe fn` therefore preserves its arguments, return
type, and platform behavior, but intentionally breaks safe Rust call sites
that did not acknowledge the required contract.

## Goals

1. Make it impossible for safe external Rust code to violate the raw API's
   memory-safety and ownership preconditions.
2. Keep the existing Win32-shaped names and behavior for low-level consumers.
3. Apply equivalent contracts to the Linux implementation and Windows
   forwarding implementation.
4. Prevent safe mutation of internal pointer-bearing `Context` state.
5. Provide small safe wrappers for the most common ownership patterns.
6. Keep unsafe blocks narrow, documented, and reviewable.

## Non-goals

- Redesigning the complete API around a new certificate object model.
- Making every function unsafe merely because it has a Win32 name.
- Treating invalid flags, unsupported algorithms, or ordinary API errors as
  memory-safety concerns.
- Validating arbitrary addresses at runtime; Rust cannot generally do so.
- Preserving source compatibility with currently unsound safe calls.
- Changing native CryptoAPI behavior or the Linux compatibility semantics.

## Proposed design

### 1. Classify the raw API by caller-enforced invariants

A public function becomes `unsafe fn` when any permitted execution path
requires the caller to guarantee one or more of the following:

- a pointer is valid and aligned for a read or write;
- a pointer references at least the documented number of initialized bytes;
- a string pointer is terminated and readable;
- an output pointer is writable for the requested size;
- a typed pointer points to a live value of that type;
- a context or chain pointer was produced by the corresponding API and remains
  live;
- an operation consumes a unique owned reference or allocation exactly once;
- overlapping input and output memory is prohibited;
- a callback or provider-specific `void *` parameter remains valid for the
  required duration;
- a native API imposes an equivalent memory-safety precondition.

Returning a raw pointer is not, by itself, a reason to make a function unsafe.
Functions such as `GetLastError`, `SetLastError`, and
`SysCertGetLastErrorMessage` can remain safe because invoking them does not
require the caller to provide valid memory.

Opaque handle-only functions may remain safe when both backends treat every
bit pattern as either a valid handle or a normal invalid-handle error and do
not dereference the value. They must be marked unsafe if the corresponding
native contract requires more.

The expected unsafe groups are:

| Group | Representative functions | Required contract |
|---|---|---|
| Input strings and byte ranges | `CryptStringToBinaryA`, `CryptBinaryToStringA`, `CertOpenSystemStoreA/W`, `CertCreateCertificateContext` | Readable terminated string or readable range for the stated length |
| Typed input and output structures | `CertNameToStrA`, `CertGetNameStringA`, `CertGetCertificateContextProperty`, `CertSetCertificateContextProperty` | Live typed values and writable output storage |
| Provider-dependent pointers | `CertOpenStore`, `CertFindCertificateInStore`, `CertControlStore`, `CertSaveStore` | The pointer has the type, size, lifetime, and mutability required by the selected provider or operation |
| Context ownership | `CertDuplicateCertificateContext`, `CertFreeCertificateContext`, `CertDeleteCertificateFromStore`, enumeration and add functions | Pointer identifies a live context from this API; consuming operations receive an owned live reference exactly once |
| Chain ownership | `CertGetCertificateChain`, `CertVerifyCertificateChainPolicy`, `CertFreeCertificateChain` | Live input contexts and structures; returned chain is freed exactly once by the matching backend |
| PFX and extension APIs | `PFXImportCertStore`, `PFXExportCertStoreEx`, `SysCertImportPfxToStore`, trust and path extensions | Live blobs, strings, contexts, option structures, and output buffers |
| Enumeration callbacks | `CertEnumSystemStore`, `CertEnumSystemStoreLocation` | Callback, callback context, and callback-visible data remain valid for the call |

The implementation change must inventory every public backend function rather
than limiting the fix to the examples named in R01.

### 2. Add precise `# Safety` contracts

Every public `unsafe fn` must have a rustdoc `# Safety` section. Contracts must
describe the actual operation rather than use a generic "pointers must be
valid" statement.

For example:

```rust
/// Releases one certificate-chain allocation.
///
/// # Safety
///
/// `chain` must be null or be the live pointer returned through
/// `CertGetCertificateChain` by this crate on the current platform. A non-null
/// pointer must not have been freed previously, and no code may access the
/// chain after this call.
pub unsafe fn CertFreeCertificateChain(chain: *const CERT_CHAIN_CONTEXT) {
    // The unsafe operation remains in an explicit, narrow block.
}
```

Contracts should explicitly cover these API-specific rules:

- A zero-length byte range may use a null pointer only where the implementation
  already supports that convention.
- Two-call output-buffer APIs require the size pointer on both calls and
  require the data buffer to cover the supplied capacity on the second call.
- Enumeration APIs may consume or release the previous context according to
  CryptoAPI semantics; callers must not use a consumed reference afterward.
- Duplicate operations create an additional owned reference that must be
  released independently.
- Delete and free operations consume ownership exactly once.
- Provider-specific `void *` values must match the provider selected by the
  other arguments.
- Linux-created contexts and chains must be released by the Linux backend;
  Windows-native contexts and chains must be released by CryptoAPI.
- Callback state must outlive the synchronous enumeration call and satisfy any
  aliasing requirements caused by callback mutation.

Making a function `unsafe fn` does not make its implementation implicitly
trusted. The crate should deny `unsafe_op_in_unsafe_fn`, retaining explicit
unsafe blocks around each dereference, slice construction, ownership
reconstruction, and native call.

### 3. Seal `Context` and its pointer-bearing invariants

`Context` is an implementation detail and should become `pub(crate)`. Its
invariant-bearing fields must be private:

- `public`
- `info`
- `der`
- `buffers`
- `strings`
- `extensions`

No public or crate-visible API should return mutable references to these
fields. Construction should remain centralized in `Context::new`, which must
finish allocating backing storage before publishing the raw
`CERT_CONTEXT` pointer.

Operational metadata that does not participate in raw-pointer stability may
initially remain `pub(crate)` to keep the change focused, although accessors
are preferred where they express ownership transitions.

The following invariant should be documented next to `Context`:

> Once a `Context` is published, the allocations referenced by
> `CERT_CONTEXT`, `CERT_INFO`, blobs, strings, and extension arrays remain at
> stable addresses and are not replaced or resized until the context is
> destroyed.

`Context::public_ptr` may remain crate-private and return only a shared raw
pointer. No `public_mut`, `info_mut`, or mutable DER accessor should be added.

### 4. Stop deriving safe values from pointer-bearing metadata

`Context::issuer_der` and `Context::serial_le` must not construct slices from
`CERT_INFO` pointer fields.

During construction, cache the canonical identity values in ordinary owned
fields:

```rust
issuer_der: Vec<u8>,
serial_le: Vec<u8>,
```

The public `CERT_INFO` blobs may point into the same stable backing storage,
but identity comparison should read the owned fields directly. This keeps
`same_identity` safe even if the raw representation changes internally.

Where another internal operation needs data represented by a `CERT_INFO`
field, prefer the parsed `Certificate` or an owned canonical field. A raw
pointer should be read only at a narrowly documented unsafe boundary where the
data genuinely comes from an external caller.

### 5. Add thin safe ownership wrappers

The raw Win32-shaped functions remain available at their existing paths as
the compatibility layer. A small `safe` module should cover common operations
without attempting to wrap the entire API:

- `CertificateStore`
  - owns an `HCERTSTORE`;
  - closes it in `Drop`;
  - provides safe constructors that accept Rust strings or explicit store
    options.
- `CertificateContextHandle`
  - owns one context reference;
  - creates a context from `&[u8]`;
  - duplicates through `Clone` or an explicit `try_clone`;
  - frees its reference in `Drop`;
  - exposes `as_ptr` for advanced raw calls.
- `CertificateChainHandle`
  - owns one chain returned by chain construction;
  - frees it in `Drop`;
  - exposes read-only traversal methods or `as_ptr`.

Safe constructors convert slices and strings to raw pointer/length pairs
inside short unsafe blocks. `Drop` implementations encode the one-time release
rule. Constructors return an error when the raw API reports failure, so safe
callers do not need to use `GetLastError` directly for the covered operations.

Store enumeration has nontrivial previous-context consumption semantics. It
should receive a dedicated iterator only if that iterator can encode those
rules clearly; it is not required for the initial R01 fix.

### 6. Migrate repository call sites

Call sites fall into two categories:

1. `certutil`, examples, and ordinary tests should use the safe wrappers where
   the wrapper expresses the complete operation.
2. Compatibility tests that intentionally exercise the raw Win32-shaped API
   should call it from explicit unsafe blocks with short safety comments
   explaining pointer provenance and lifetime.

The README's primary Rust example should use the safe API. A separate
"Raw compatibility API" section should explain that the Win32-shaped surface
is unsafe for the same reason direct FFI is unsafe.

### 7. Release as a source-breaking safety correction

The change should be released as version `0.2.0`.

There should be no deprecation period that leaves unsound safe entry points in
place. Existing names remain available, but affected calls require an unsafe
block. The migration guide should show:

- wrapping raw calls in unsafe only when the caller can state the contract;
- replacing manual create/free pairs with `CertificateContextHandle`;
- replacing manual chain/free pairs with `CertificateChainHandle`;
- replacing manual store close guards with `CertificateStore`;
- removing all external uses of `cert::Context`.

## Implementation sequence

1. **Lock down internal invariants**
   - make `Context` crate-private;
   - privatize pointer-bearing fields;
   - add narrow internal accessors;
   - cache issuer DER and little-endian serial values;
   - remove safe slice construction from `CERT_INFO` pointers.

2. **Correct the raw API boundary**
   - inventory both backend modules;
   - mark only functions with caller-enforced memory or ownership contracts as
     unsafe;
   - add function-specific `# Safety` documentation;
   - keep explicit unsafe blocks in each implementation.

3. **Add minimal safe wrappers**
   - add store, context, and chain owning types;
   - implement `Drop` and duplication semantics;
   - expose slice- and string-based constructors.

4. **Migrate and document**
   - update `certutil`, examples, tests, and README;
   - keep raw compatibility tests explicit about safety;
   - add a 0.2.0 migration section.

5. **Add regression enforcement**
   - deny `unsafe_op_in_unsafe_fn`;
   - deny or explicitly enable Clippy's
     `not_unsafe_ptr_arg_deref` lint for the library;
   - deny `clippy::missing_safety_doc`;
   - add compile-fail coverage proving affected raw calls require unsafe;
   - run Miri over the safe wrapper ownership tests where supported.

## Validation plan

The implementation is complete when:

- safe external Rust cannot name or mutate `Context`;
- no safe public function dereferences, reads through, writes through, or
  consumes ownership from a caller-provided raw pointer;
- every public unsafe function has a precise `# Safety` contract;
- invalid raw pointers are not used as runtime test cases because invoking
  them would itself violate the contract;
- safe wrapper tests cover construction, duplication, enumeration handoff
  where implemented, chain ownership, and exactly-once destruction;
- Linux compatibility tests still pass;
- Windows native-store and forwarding tests still pass;
- both service examples build and preserve their current behavior;
- strict Clippy passes on both targets with the new lints enabled;
- the canonical Linux CMake/CTest release build passes.

## Trade-offs and risks

- **Source break:** Existing raw callers must add unsafe blocks or migrate to
  wrappers. This is intentional and should be called out prominently in the
  0.2.0 release notes.
- **Unsafe-block volume:** Compatibility tests and low-level code will gain
  unsafe blocks. Requiring a local safety explanation makes the existing
  obligations visible rather than creating new risk.
- **Wrapper scope:** A minimal wrapper set will not make every operation
  ergonomic. Expanding it should be driven by concrete use cases and should
  not delay closing the soundness hole.
- **Cross-platform contracts:** Linux owns some allocations that Windows
  delegates to CryptoAPI. Documentation must state backend-matching provenance
  without pretending the allocation mechanisms are identical.
- **Internal churn:** Privatizing `Context` fields requires accessors in store,
  chain, CRL-cache, and `certutil` code. Accessors should preserve current
  behavior and must not expose mutable access to pointer-bearing storage.

## Decision

Adopt the proposal as a focused 0.2.0 safety correction: make raw
caller-preconditioned operations unsafe, seal `Context`, eliminate safe reads
through mutable raw metadata, and provide only the small RAII layer needed for
common ownership patterns.
