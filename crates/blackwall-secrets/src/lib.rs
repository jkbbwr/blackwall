//! Zero-secret-in-guest cryptography, `memfd_secret(0)` storage, and per-VM
//! secret brokering table for Blackwall.
//!
//! # Capabilities
//! 1. **HPKE X25519 `seal1_` Offline Sealing & Opening (RFC 9180):**
//!    `DHKEM(X25519, HKDF-SHA256)` + `HKDF-SHA256` + `ChaCha20Poly1305`, binding
//!    canonicalized [`SealBinding`] (`allow_hosts`, `allow_path_templates`,
//!    `policy_tag`, `exp_unix_sec`) into HPKE AEAD AAD.
//! 2. **Protected In-Memory Storage ([`SecretBytes`]):**
//!    Backed on Linux by `memfd_secret(0)` + `ftruncate` + `mmap` + `mlock` with
//!    clean fallback to `mlock`'d zeroized heap memory when `memfd_secret` is
//!    unavailable, zeroizing before release on `Drop`, and redacting `Debug`.
//! 3. **Ephemeral Secret Intake & Per-VM Placeholder Minting ([`VmSecretTable`]):**
//!    Opens both `sealed = "seal1_..."` and `ephemeral = "..."` [`SecretSpec`]s
//!    from `blackwall-policy`, mints 256-bit random SDK-shaped placeholders, and
//!    performs constant-time placeholder verification for `blackwall-proxy`.

pub mod error;
pub mod hpke_seal;
pub mod mem;
pub mod table;

pub use error::{Result, SecretError};
pub use hpke_seal::{
    current_unix_sec, inspect_sealed_binding, open_sealed, open_sealed_with_binding, seal_secret,
    HostKeyPair, HostPrivateKey, HostPublicKey, OpenedSecret, SealBinding, SEAL1_PREFIX,
};
pub use mem::SecretBytes;
pub use table::{constant_time_eq, mint_placeholder, VmSecretTable, PLACEHOLDER_ENTROPY_BYTES};
