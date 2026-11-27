use thiserror::Error;

/// Errors produced by `blackwall-secrets` key management, HPKE sealing/opening,
/// and per-VM secret table verification.
#[derive(Debug, Error)]
pub enum SecretError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("hex decode error: {0}")]
    Hex(#[from] hex::FromHexError),

    #[error("invalid UTF-8 in secret value: {0}")]
    InvalidUtf8(#[from] std::str::Utf8Error),

    #[error("invalid HPKE key material: {0}")]
    InvalidKey(String),

    #[error("invalid sealed secret format: {0}")]
    InvalidSealedFormat(String),

    #[error("unsupported sealed secret envelope version: {0}")]
    UnsupportedSealVersion(u8),

    #[error("HPKE operation failed: {0}")]
    HpkeError(String),

    #[error("sealed secret AEAD decryption or binding authentication failed")]
    DecryptionFailed,

    #[error("sealed secret expired at unix timestamp {exp_unix_sec} (current: {now_unix_sec})")]
    Expired {
        exp_unix_sec: u64,
        now_unix_sec: u64,
    },

    #[error("sealed secret binding rejected: {0}")]
    BindingMismatch(String),

    #[error("host HPKE keypair required to open sealed secret '{0}'")]
    MissingHostKey(String),

    #[error("secret '{0}' must specify exactly one of `sealed` or `ephemeral`")]
    InvalidSecretSource(String),

    #[error("unknown secret '{0}'")]
    SecretNotFound(String),

    #[error("guest placeholder mismatch for secret '{0}'")]
    PlaceholderMismatch(String),
}

pub type Result<T> = std::result::Result<T, SecretError>;
