//! HPKE X25519 (`seal1_`) offline sealing and opening (RFC 9180).
//!
//! Ciphersuite:
//! - KEM: `DHKEM(X25519, HKDF-SHA256)` (`X25519HkdfSha256`)
//! - KDF: `HKDF-SHA256` (`HkdfSha256`)
//! - AEAD: `ChaCha20Poly1305`
//!
//! Every `seal1_` envelope binds a canonicalized [`SealBinding`] (`allow_hosts`,
//! `allow_path_templates`, `policy_tag`, `exp_unix_sec`) into the HPKE AEAD
//! Additional Authenticated Data (AAD), so any tampering with hosts, path
//! templates, policy tag, or expiration causes AEAD decryption to fail.

use crate::error::{Result, SecretError};
use crate::mem::SecretBytes;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Wire prefix for Blackwall v1 HPKE-sealed secrets.
pub const SEAL1_PREFIX: &str = "seal1_";

const ENVELOPE_VERSION: u8 = 1;
const HPKE_SEAL1_INFO: &[u8] = b"blackwall-secrets-seal1-v1";
const AAD_DOMAIN_PREFIX: &[u8] = b"blackwall-seal1-aad-v1\0";

const PUBKEY_PEM_HEADER: &str = "-----BEGIN BLACKWALL HPKE PUBLIC KEY-----";
const PUBKEY_PEM_FOOTER: &str = "-----END BLACKWALL HPKE PUBLIC KEY-----";
const PRIVKEY_PEM_HEADER: &str = "-----BEGIN BLACKWALL HPKE PRIVATE KEY-----";
const PRIVKEY_PEM_FOOTER: &str = "-----END BLACKWALL HPKE PRIVATE KEY-----";

type Kem = X25519HkdfSha256;
type Kdf = HkdfSha256;
type Aead = ChaCha20Poly1305;

/// X25519 HPKE public key used to seal secrets offline for a Blackwall host.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostPublicKey {
    bytes: [u8; 32],
}

impl HostPublicKey {
    /// Construct from a 32-byte raw X25519 public key.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| SecretError::InvalidKey(format!("expected 32-byte public key, got {}", bytes.len())))?;
        // Validate with HPKE KEM deserializer.
        let _ = <Kem as KemTrait>::PublicKey::from_bytes(&arr)
            .map_err(|e| SecretError::InvalidKey(format!("invalid X25519 public key: {e:?}")))?;
        Ok(Self { bytes: arr })
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.bytes
    }

    pub fn to_base64(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.bytes)
    }

    pub fn from_base64(encoded: &str) -> Result<Self> {
        let trimmed = encoded.trim();
        let raw = URL_SAFE_NO_PAD
            .decode(trimmed)
            .or_else(|_| STANDARD.decode(trimmed))?;
        Self::from_bytes(&raw)
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.bytes)
    }

    pub fn from_hex(encoded: &str) -> Result<Self> {
        let raw = hex::decode(encoded.trim())?;
        Self::from_bytes(&raw)
    }

    pub fn to_pem(&self) -> String {
        let b64 = STANDARD.encode(self.bytes);
        format!("{PUBKEY_PEM_HEADER}\n{b64}\n{PUBKEY_PEM_FOOTER}\n")
    }

    pub fn from_pem(pem: &str) -> Result<Self> {
        let body = extract_pem_body(pem, PUBKEY_PEM_HEADER, PUBKEY_PEM_FOOTER)?;
        let raw = STANDARD.decode(body)?;
        Self::from_bytes(&raw)
    }

    fn to_hpke(&self) -> Result<<Kem as KemTrait>::PublicKey> {
        <Kem as KemTrait>::PublicKey::from_bytes(&self.bytes)
            .map_err(|e| SecretError::InvalidKey(format!("invalid X25519 public key: {e:?}")))
    }
}

impl fmt::Debug for HostPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HostPublicKey({})", self.to_base64())
    }
}

/// X25519 HPKE private key with automatic zeroization on drop and redacted `Debug`.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct HostPrivateKey {
    bytes: [u8; 32],
}

impl HostPrivateKey {
    /// Construct from a 32-byte raw X25519 private key.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| SecretError::InvalidKey(format!("expected 32-byte private key, got {}", bytes.len())))?;
        let _ = <Kem as KemTrait>::PrivateKey::from_bytes(&arr)
            .map_err(|e| SecretError::InvalidKey(format!("invalid X25519 private key: {e:?}")))?;
        Ok(Self { bytes: arr })
    }

    pub fn to_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.bytes)
    }

    pub fn to_base64(&self) -> Zeroizing<String> {
        Zeroizing::new(URL_SAFE_NO_PAD.encode(self.bytes))
    }

    pub fn from_base64(encoded: &str) -> Result<Self> {
        let trimmed = encoded.trim();
        let raw = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(trimmed)
                .or_else(|_| STANDARD.decode(trimmed))?,
        );
        Self::from_bytes(&raw)
    }

    pub fn to_hex(&self) -> Zeroizing<String> {
        Zeroizing::new(hex::encode(self.bytes))
    }

    pub fn from_hex(encoded: &str) -> Result<Self> {
        let raw = Zeroizing::new(hex::decode(encoded.trim())?);
        Self::from_bytes(&raw)
    }

    pub fn to_pem(&self) -> Zeroizing<String> {
        let b64 = Zeroizing::new(STANDARD.encode(self.bytes));
        Zeroizing::new(format!(
            "{PRIVKEY_PEM_HEADER}\n{}\n{PRIVKEY_PEM_FOOTER}\n",
            b64.as_str()
        ))
    }

    pub fn from_pem(pem: &str) -> Result<Self> {
        let body = Zeroizing::new(extract_pem_body(pem, PRIVKEY_PEM_HEADER, PRIVKEY_PEM_FOOTER)?);
        let raw = Zeroizing::new(STANDARD.decode(body.as_str())?);
        Self::from_bytes(&raw)
    }

    fn to_hpke(&self) -> Result<<Kem as KemTrait>::PrivateKey> {
        <Kem as KemTrait>::PrivateKey::from_bytes(&self.bytes)
            .map_err(|e| SecretError::InvalidKey(format!("invalid X25519 private key: {e:?}")))
    }
}

impl fmt::Debug for HostPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HostPrivateKey(<redacted>)")
    }
}

/// Host X25519 HPKE keypair used to seal (`public`) and open (`private`) `seal1_` secrets.
///
/// The private key is zeroized on drop and redacted from `Debug` output.
#[derive(Clone)]
pub struct HostKeyPair {
    public: HostPublicKey,
    private: HostPrivateKey,
}

impl HostKeyPair {
    /// Generate a fresh X25519 HPKE keypair from OS cryptographic randomness.
    pub fn generate() -> Self {
        let (sk, pk) = Kem::gen_keypair();
        let mut sk_raw = sk.to_bytes();
        let pk_raw = pk.to_bytes();

        let mut sk_arr = [0u8; 32];
        sk_arr.copy_from_slice(sk_raw.as_slice());
        sk_raw.as_mut_slice().zeroize();

        let mut pk_arr = [0u8; 32];
        pk_arr.copy_from_slice(pk_raw.as_slice());

        Self {
            public: HostPublicKey { bytes: pk_arr },
            private: HostPrivateKey { bytes: sk_arr },
        }
    }

    /// Reconstruct a keypair from an existing private key by deriving its public key.
    pub fn from_private_key(private: HostPrivateKey) -> Result<Self> {
        let sk = private.to_hpke()?;
        let pk = Kem::sk_to_pk(&sk);
        let pk_raw = pk.to_bytes();
        let public = HostPublicKey::from_bytes(pk_raw.as_slice())?;
        Ok(Self { public, private })
    }

    pub fn from_private_pem(pem: &str) -> Result<Self> {
        Self::from_private_key(HostPrivateKey::from_pem(pem)?)
    }

    pub fn from_private_base64(encoded: &str) -> Result<Self> {
        Self::from_private_key(HostPrivateKey::from_base64(encoded)?)
    }

    pub fn from_private_hex(encoded: &str) -> Result<Self> {
        Self::from_private_key(HostPrivateKey::from_hex(encoded)?)
    }

    /// Load a PEM-encoded host private key from `path`, or generate and save a
    /// new keypair with `0600` permissions if `path` does not exist.
    pub fn load_or_generate(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if path.exists() {
            let pem = Zeroizing::new(fs::read_to_string(path)?);
            return Self::from_private_pem(&pem);
        }

        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }

        let kp = Self::generate();
        let pem = kp.private_key().to_pem();

        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(path)?;
            file.write_all(pem.as_bytes())?;
            file.sync_all()?;
        }
        #[cfg(not(unix))]
        {
            fs::write(path, pem.as_bytes())?;
        }

        Ok(kp)
    }

    pub fn public_key(&self) -> &HostPublicKey {
        &self.public
    }

    pub fn private_key(&self) -> &HostPrivateKey {
        &self.private
    }

    /// Convenience wrapper around [`seal_secret`] using this keypair's public key.
    pub fn seal(&self, plaintext: &[u8], binding: &SealBinding) -> Result<String> {
        seal_secret(&self.public, plaintext, binding)
    }

    /// Convenience wrapper around [`open_sealed`] using this keypair.
    pub fn open(&self, sealed: &str, now_unix_sec: u64) -> Result<OpenedSecret> {
        open_sealed(self, sealed, now_unix_sec)
    }

    /// Convenience wrapper around [`open_sealed_with_binding`] using this keypair.
    pub fn open_with_binding(
        &self,
        sealed: &str,
        expected: &SealBinding,
        now_unix_sec: u64,
    ) -> Result<SecretBytes> {
        open_sealed_with_binding(self, sealed, expected, now_unix_sec)
    }
}

impl fmt::Debug for HostKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HostKeyPair")
            .field("public", &self.public)
            .field("private", &self.private)
            .finish()
    }
}

/// Authenticated policy binding attached as HPKE AEAD AAD to every `seal1_` secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealBinding {
    pub allow_hosts: Vec<String>,
    pub allow_path_templates: Vec<String>,
    pub policy_tag: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp_unix_sec: Option<u64>,
}

impl SealBinding {
    /// Return a canonically normalized copy (lowercased, trimmed, sorted,
    /// deduplicated hosts; sorted, deduplicated path templates).
    pub fn normalized(&self) -> Self {
        let mut allow_hosts: Vec<String> = self
            .allow_hosts
            .iter()
            .map(|h| h.trim().to_ascii_lowercase())
            .filter(|h| !h.is_empty())
            .collect();
        allow_hosts.sort();
        allow_hosts.dedup();

        let mut allow_path_templates: Vec<String> = self
            .allow_path_templates
            .iter()
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty())
            .collect();
        allow_path_templates.sort();
        allow_path_templates.dedup();

        Self {
            allow_hosts,
            allow_path_templates,
            policy_tag: self.policy_tag.clone(),
            exp_unix_sec: self.exp_unix_sec,
        }
    }

    /// Serialize this binding into canonical AAD bytes for HPKE AEAD binding.
    ///
    /// Uses a domain prefix plus deterministic JSON serialization with fixed
    /// field order (`allow_hosts`, `allow_path_templates`, `policy_tag`,
    /// `exp_unix_sec`).
    pub fn canonical_aad(&self) -> Result<Vec<u8>> {
        let norm = self.normalized();
        norm.exact_aad_bytes()
    }

    /// Serialize the exact current struct fields into AAD bytes without
    /// normalizing, so any wire-level mutation to the envelope's embedded
    /// `binding` fails AEAD authentication.
    fn exact_aad_bytes(&self) -> Result<Vec<u8>> {
        let json = serde_json::to_vec(self)?;
        let mut aad = Vec::with_capacity(AAD_DOMAIN_PREFIX.len() + json.len());
        aad.extend_from_slice(AAD_DOMAIN_PREFIX);
        aad.extend_from_slice(&json);
        Ok(aad)
    }

    /// Check whether this binding has expired as of `now_unix_sec`.
    pub fn check_expiration(&self, now_unix_sec: u64) -> Result<()> {
        if let Some(exp) = self.exp_unix_sec {
            if now_unix_sec >= exp {
                return Err(SecretError::Expired {
                    exp_unix_sec: exp,
                    now_unix_sec,
                });
            }
        }
        Ok(())
    }

    /// Returns `true` if `host` (case-insensitive) is permitted by `allow_hosts`.
    pub fn allows_host(&self, host: &str) -> bool {
        let needle = host.trim().to_ascii_lowercase();
        if needle.is_empty() {
            return false;
        }
        self.allow_hosts
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(&needle))
    }

    /// Returns `true` if `path` is permitted by at least one entry in
    /// `allow_path_templates`.
    ///
    /// Rejects path traversal (`..` segments). Supports:
    /// - `"*"` or `"/*"` wildcard
    /// - Trailing `'*'` prefix templates (e.g. `"/repos/my-org/*"`)
    /// - Exact or path-segment-aligned prefix templates (e.g. `"/repos/my-org/my-repo/"`
    ///   allows `"/repos/my-org/my-repo/pulls"`, while `"/repos/my-org"` does NOT
    ///   match `"/repos/my-org-evil"`).
    pub fn allows_path(&self, path: &str) -> bool {
        if path.is_empty() || path.split('/').any(|seg| seg == "..") {
            return false;
        }
        self.allow_path_templates
            .iter()
            .any(|tpl| path_matches_template(path, tpl))
    }

    /// Validate that this binding permits the requested `host`, optional HTTP
    /// `path_prefixes`, optional `policy_tag`, and is not expired.
    pub fn validate_usage(
        &self,
        hosts: &[&str],
        path_prefixes: &[&str],
        expected_policy_tag: Option<&str>,
        now_unix_sec: u64,
    ) -> Result<()> {
        self.check_expiration(now_unix_sec)?;

        if let Some(expected_tag) = expected_policy_tag {
            if self.policy_tag != expected_tag {
                return Err(SecretError::BindingMismatch(format!(
                    "policy_tag mismatch: binding has '{}', expected '{}'",
                    self.policy_tag, expected_tag
                )));
            }
        }

        for &host in hosts {
            if !self.allows_host(host) {
                return Err(SecretError::BindingMismatch(format!(
                    "host '{host}' is not allowed by sealed binding {:?}",
                    self.allow_hosts
                )));
            }
        }

        for &prefix in path_prefixes {
            if !self.allows_path(prefix) {
                return Err(SecretError::BindingMismatch(format!(
                    "path '{prefix}' is not allowed by sealed binding {:?}",
                    self.allow_path_templates
                )));
            }
        }

        Ok(())
    }
}

fn path_matches_template(path: &str, template: &str) -> bool {
    if template.is_empty() {
        return false;
    }
    if template == "*" {
        return true;
    }
    if let Some(prefix) = template.strip_suffix('*') {
        return path.starts_with(prefix);
    }
    if path == template {
        return true;
    }
    if path.starts_with(template) {
        if template.ends_with('/') {
            return true;
        }
        return path.as_bytes().get(template.len()) == Some(&b'/');
    }
    false
}

/// Decrypted secret returned by [`open_sealed`] along with its AEAD-authenticated [`SealBinding`].
#[derive(Debug)]
pub struct OpenedSecret {
    pub secret: SecretBytes,
    pub binding: SealBinding,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SealEnvelopeV1 {
    v: u8,
    enc: String,
    ct: String,
    binding: SealBinding,
}

/// Seal `plaintext` offline to `recipient_pk` with `binding` authenticated as
/// HPKE AEAD AAD, producing a `"seal1_<base64url>"` string suitable for checked-in
/// profile TOML files.
pub fn seal_secret(
    recipient_pk: &HostPublicKey,
    plaintext: &[u8],
    binding: &SealBinding,
) -> Result<String> {
    let pk = recipient_pk.to_hpke()?;
    let normalized_binding = binding.normalized();
    let aad = normalized_binding.exact_aad_bytes()?;

    let (encapped_key, ciphertext) = hpke::single_shot_seal::<Aead, Kdf, Kem>(
        &OpModeS::Base,
        &pk,
        HPKE_SEAL1_INFO,
        plaintext,
        &aad,
    )
    .map_err(|e| SecretError::HpkeError(format!("{e:?}")))?;

    let envelope = SealEnvelopeV1 {
        v: ENVELOPE_VERSION,
        enc: URL_SAFE_NO_PAD.encode(encapped_key.to_bytes().as_slice()),
        ct: URL_SAFE_NO_PAD.encode(&ciphertext),
        binding: normalized_binding,
    };

    let envelope_json = serde_json::to_vec(&envelope)?;
    Ok(format!(
        "{SEAL1_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(&envelope_json)
    ))
}

/// Parse, authenticate, decrypt, and expiration-check a `"seal1_..."` secret
/// using `keypair`, storing the plaintext directly in [`SecretBytes`].
///
/// The envelope's embedded [`SealBinding`] is authenticated as HPKE AEAD AAD;
/// any modification to the envelope's `binding` fails decryption.
pub fn open_sealed(
    keypair: &HostKeyPair,
    sealed: &str,
    now_unix_sec: u64,
) -> Result<OpenedSecret> {
    let envelope = decode_envelope(sealed)?;
    let aad = envelope.binding.exact_aad_bytes()?;
    let secret = decrypt_envelope(keypair, &envelope, &aad)?;
    envelope.binding.check_expiration(now_unix_sec)?;
    Ok(OpenedSecret {
        secret,
        binding: envelope.binding,
    })
}

/// Open a `"seal1_..."` secret while authenticating against a caller-supplied
/// expected [`SealBinding`] directly in the HPKE AEAD AAD.
///
/// Any mismatch in `allow_hosts`, `allow_path_templates`, `policy_tag`, or
/// `exp_unix_sec` causes AEAD decryption to fail with [`SecretError::DecryptionFailed`].
pub fn open_sealed_with_binding(
    keypair: &HostKeyPair,
    sealed: &str,
    expected: &SealBinding,
    now_unix_sec: u64,
) -> Result<SecretBytes> {
    let envelope = decode_envelope(sealed)?;
    let expected_aad = expected.canonical_aad()?;
    let secret = decrypt_envelope(keypair, &envelope, &expected_aad)?;
    expected.check_expiration(now_unix_sec)?;
    Ok(secret)
}

/// Inspect the unauthenticated [`SealBinding`] metadata carried inside a
/// `"seal1_..."` envelope (useful for CLI diagnostics before opening).
///
/// **Security note:** Do not make authorization decisions from this metadata
/// until [`open_sealed`] has authenticated it via HPKE AEAD.
pub fn inspect_sealed_binding(sealed: &str) -> Result<SealBinding> {
    Ok(decode_envelope(sealed)?.binding)
}

/// Current wall-clock time in seconds since the Unix epoch.
pub fn current_unix_sec() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn decode_envelope(sealed: &str) -> Result<SealEnvelopeV1> {
    let payload = sealed.strip_prefix(SEAL1_PREFIX).ok_or_else(|| {
        SecretError::InvalidSealedFormat(format!("sealed secret must start with '{SEAL1_PREFIX}'"))
    })?;
    if payload.is_empty() {
        return Err(SecretError::InvalidSealedFormat(
            "empty sealed secret payload".into(),
        ));
    }
    let raw = URL_SAFE_NO_PAD.decode(payload)?;
    let envelope: SealEnvelopeV1 = serde_json::from_slice(&raw)?;
    if envelope.v != ENVELOPE_VERSION {
        return Err(SecretError::UnsupportedSealVersion(envelope.v));
    }
    Ok(envelope)
}

fn decrypt_envelope(
    keypair: &HostKeyPair,
    envelope: &SealEnvelopeV1,
    aad: &[u8],
) -> Result<SecretBytes> {
    let sk = keypair.private.to_hpke()?;
    let enc_bytes = URL_SAFE_NO_PAD.decode(&envelope.enc)?;
    let encapped_key = <Kem as KemTrait>::EncappedKey::from_bytes(&enc_bytes).map_err(|_| {
        SecretError::InvalidSealedFormat("invalid HPKE encapsulated key".into())
    })?;
    let ct_bytes = URL_SAFE_NO_PAD.decode(&envelope.ct)?;

    let plaintext = hpke::single_shot_open::<Aead, Kdf, Kem>(
        &OpModeR::Base,
        &sk,
        &encapped_key,
        HPKE_SEAL1_INFO,
        &ct_bytes,
        aad,
    )
    .map_err(|_| SecretError::DecryptionFailed)?;

    Ok(SecretBytes::from_vec(plaintext))
}

fn extract_pem_body(pem: &str, header: &str, footer: &str) -> Result<String> {
    let mut lines = pem.lines().map(str::trim).filter(|l| !l.is_empty());
    let first = lines
        .next()
        .ok_or_else(|| SecretError::InvalidKey("empty PEM input".into()))?;
    if first != header {
        return Err(SecretError::InvalidKey(format!(
            "unexpected PEM header '{first}', expected '{header}'"
        )));
    }
    let mut body = String::new();
    let mut found_footer = false;
    for line in lines {
        if line == footer {
            found_footer = true;
            break;
        }
        body.push_str(line);
    }
    if !found_footer || body.is_empty() {
        return Err(SecretError::InvalidKey(format!(
            "missing PEM footer '{footer}' or empty key body"
        )));
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_binding(exp: Option<u64>) -> SealBinding {
        SealBinding {
            allow_hosts: vec!["api.github.com".into(), "github.com".into()],
            allow_path_templates: vec![
                "/repos/my-org/my-repo/".into(),
                "/my-org/my-repo.git/".into(),
            ],
            policy_tag: "prod-repo-agent".into(),
            exp_unix_sec: exp,
        }
    }

    fn tamper_envelope(sealed: &str, mutate: impl FnOnce(&mut SealEnvelopeV1)) -> String {
        let mut env = decode_envelope(sealed).unwrap();
        mutate(&mut env);
        let json = serde_json::to_vec(&env).unwrap();
        format!("{SEAL1_PREFIX}{}", URL_SAFE_NO_PAD.encode(json))
    }

    #[test]
    fn keypair_serialization_round_trips_and_redacts_debug() {
        let kp = HostKeyPair::generate();

        // Public key round trips
        assert_eq!(
            HostPublicKey::from_base64(&kp.public_key().to_base64()).unwrap(),
            *kp.public_key()
        );
        assert_eq!(
            HostPublicKey::from_hex(&kp.public_key().to_hex()).unwrap(),
            *kp.public_key()
        );
        assert_eq!(
            HostPublicKey::from_pem(&kp.public_key().to_pem()).unwrap(),
            *kp.public_key()
        );

        // Private key round trips & public key derivation
        let kp_from_pem = HostKeyPair::from_private_pem(&kp.private_key().to_pem()).unwrap();
        assert_eq!(kp_from_pem.public_key(), kp.public_key());

        let kp_from_b64 = HostKeyPair::from_private_base64(&kp.private_key().to_base64()).unwrap();
        assert_eq!(kp_from_b64.public_key(), kp.public_key());

        let kp_from_hex = HostKeyPair::from_private_hex(&kp.private_key().to_hex()).unwrap();
        assert_eq!(kp_from_hex.public_key(), kp.public_key());

        // Redacted Debug
        let priv_dbg = format!("{:?}", kp.private_key());
        assert_eq!(priv_dbg, "HostPrivateKey(<redacted>)");
        let kp_dbg = format!("{kp:?}");
        assert!(kp_dbg.contains("HostPrivateKey(<redacted>)"));
        assert!(!kp_dbg.contains(kp.private_key().to_hex().as_str()));
    }

    #[test]
    fn keypair_load_or_generate_persists_with_0600() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("host.key");
        let kp1 = HostKeyPair::load_or_generate(&key_path).unwrap();
        let kp2 = HostKeyPair::load_or_generate(&key_path).unwrap();
        assert_eq!(kp1.public_key(), kp2.public_key());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn seal1_round_trip_and_wrong_key_fails() {
        let kp = HostKeyPair::generate();
        let other_kp = HostKeyPair::generate();
        let binding = sample_binding(Some(2_000_000_000));

        let sealed = seal_secret(kp.public_key(), b"ghp_super_secret_real_token", &binding).unwrap();
        assert!(sealed.starts_with(SEAL1_PREFIX));

        let opened = open_sealed(&kp, &sealed, 1_700_000_000).unwrap();
        assert_eq!(opened.secret.as_bytes(), b"ghp_super_secret_real_token");
        assert_eq!(opened.binding, binding.normalized());

        // Expected binding open succeeds even with unsorted/uppercase host input
        let unsorted_expected = SealBinding {
            allow_hosts: vec!["GITHUB.COM".into(), "api.github.com".into()],
            allow_path_templates: vec![
                "/my-org/my-repo.git/".into(),
                "/repos/my-org/my-repo/".into(),
            ],
            policy_tag: "prod-repo-agent".into(),
            exp_unix_sec: Some(2_000_000_000),
        };
        let opened_direct =
            open_sealed_with_binding(&kp, &sealed, &unsorted_expected, 1_700_000_000).unwrap();
        assert_eq!(opened_direct.as_bytes(), b"ghp_super_secret_real_token");

        // Wrong host key fails AEAD decryption
        let err = open_sealed(&other_kp, &sealed, 1_700_000_000).unwrap_err();
        assert!(matches!(err, SecretError::DecryptionFailed));
    }

    #[test]
    fn aad_binding_tampering_fails_decryption() {
        let kp = HostKeyPair::generate();
        let binding = sample_binding(Some(2_000_000_000));
        let sealed = seal_secret(kp.public_key(), b"sk-ant-real-key", &binding).unwrap();

        // 1. Tamper embedded allow_hosts in envelope
        let tampered_host = tamper_envelope(&sealed, |env| {
            env.binding.allow_hosts.push("evil.example.com".into());
        });
        assert!(matches!(
            open_sealed(&kp, &tampered_host, 1_700_000_000),
            Err(SecretError::DecryptionFailed)
        ));

        // 2. Tamper embedded allow_path_templates in envelope
        let tampered_path = tamper_envelope(&sealed, |env| {
            env.binding.allow_path_templates = vec!["/*".into()];
        });
        assert!(matches!(
            open_sealed(&kp, &tampered_path, 1_700_000_000),
            Err(SecretError::DecryptionFailed)
        ));

        // 3. Tamper embedded policy_tag in envelope
        let tampered_tag = tamper_envelope(&sealed, |env| {
            env.binding.policy_tag = "other-tag".into();
        });
        assert!(matches!(
            open_sealed(&kp, &tampered_tag, 1_700_000_000),
            Err(SecretError::DecryptionFailed)
        ));

        // 4. Tamper embedded exp_unix_sec in envelope (attempting to extend or strip expiry)
        let tampered_exp = tamper_envelope(&sealed, |env| {
            env.binding.exp_unix_sec = Some(9_999_999_999);
        });
        assert!(matches!(
            open_sealed(&kp, &tampered_exp, 1_700_000_000),
            Err(SecretError::DecryptionFailed)
        ));

        let stripped_exp = tamper_envelope(&sealed, |env| {
            env.binding.exp_unix_sec = None;
        });
        assert!(matches!(
            open_sealed(&kp, &stripped_exp, 1_700_000_000),
            Err(SecretError::DecryptionFailed)
        ));

        // 4b. Tamper ciphertext and encapsulated key bytes
        let tampered_ct = tamper_envelope(&sealed, |env| {
            let mut raw = URL_SAFE_NO_PAD.decode(&env.ct).unwrap();
            raw[0] ^= 0x01;
            env.ct = URL_SAFE_NO_PAD.encode(raw);
        });
        assert!(matches!(
            open_sealed(&kp, &tampered_ct, 1_700_000_000),
            Err(SecretError::DecryptionFailed)
        ));

        let tampered_enc = tamper_envelope(&sealed, |env| {
            let mut raw = URL_SAFE_NO_PAD.decode(&env.enc).unwrap();
            raw[0] ^= 0x80;
            env.enc = URL_SAFE_NO_PAD.encode(raw);
        });
        assert!(matches!(
            open_sealed(&kp, &tampered_enc, 1_700_000_000),
            Err(SecretError::DecryptionFailed)
        ));

        // 4c. Unsupported envelope version and malformed prefix
        let bad_ver = tamper_envelope(&sealed, |env| {
            env.v = 2;
        });
        assert!(matches!(
            open_sealed(&kp, &bad_ver, 1_700_000_000),
            Err(SecretError::UnsupportedSealVersion(2))
        ));
        assert!(matches!(
            open_sealed(&kp, "not_a_seal1_token", 1_700_000_000),
            Err(SecretError::InvalidSealedFormat(_))
        ));

        // inspect_sealed_binding returns normalized binding metadata
        assert_eq!(inspect_sealed_binding(&sealed).unwrap(), binding.normalized());

        // 5. Caller-supplied wrong expected binding fails AEAD decryption
        let mut wrong_host = binding.clone();
        wrong_host.allow_hosts = vec!["evil.example.com".into()];
        assert!(matches!(
            open_sealed_with_binding(&kp, &sealed, &wrong_host, 1_700_000_000),
            Err(SecretError::DecryptionFailed)
        ));

        let mut wrong_path = binding.clone();
        wrong_path.allow_path_templates = vec!["/repos/other-org/".into()];
        assert!(matches!(
            open_sealed_with_binding(&kp, &sealed, &wrong_path, 1_700_000_000),
            Err(SecretError::DecryptionFailed)
        ));

        let mut wrong_tag = binding.clone();
        wrong_tag.policy_tag = "staging".into();
        assert!(matches!(
            open_sealed_with_binding(&kp, &sealed, &wrong_tag, 1_700_000_000),
            Err(SecretError::DecryptionFailed)
        ));
    }

    #[test]
    fn expired_sealed_secret_is_rejected() {
        let kp = HostKeyPair::generate();
        let binding = sample_binding(Some(1_700_000_100));
        let sealed = seal_secret(kp.public_key(), b"expiring-secret", &binding).unwrap();

        // Still valid 1 second before expiry
        assert!(open_sealed(&kp, &sealed, 1_700_000_099).is_ok());

        // Rejected at exact expiry timestamp and after
        assert!(matches!(
            open_sealed(&kp, &sealed, 1_700_000_100),
            Err(SecretError::Expired {
                exp_unix_sec: 1_700_000_100,
                now_unix_sec: 1_700_000_100
            })
        ));
        assert!(matches!(
            open_sealed(&kp, &sealed, 1_700_000_500),
            Err(SecretError::Expired { .. })
        ));
    }

    #[test]
    fn path_template_matching_blocks_prefix_confusion_and_traversal() {
        let binding = SealBinding {
            allow_hosts: vec!["api.github.com".into()],
            allow_path_templates: vec![
                "/repos/my-org/my-repo".into(),
                "/orgs/acme/*".into(),
            ],
            policy_tag: "test".into(),
            exp_unix_sec: None,
        };

        assert!(binding.allows_path("/repos/my-org/my-repo"));
        assert!(binding.allows_path("/repos/my-org/my-repo/pulls"));
        assert!(!binding.allows_path("/repos/my-org/my-repo-evil/pulls"));
        assert!(!binding.allows_path("/repos/my-org/my-repo/../other-repo"));
        assert!(binding.allows_path("/orgs/acme/members"));
        assert!(!binding.allows_path("/orgs/other/members"));
    }
}
