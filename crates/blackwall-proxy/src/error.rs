use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("protocol error: {0}")]
    Proto(#[from] blackwall_proto::ProtoError),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("TLS / certificate error: {0}")]
    Tls(String),
    #[error("policy rejected request: {0}")]
    PolicyRejected(String),
    #[error("authentication failed: {0}")]
    AuthFailed(String),
    #[error("postgres wire protocol error: {0}")]
    Postgres(String),
    #[error("jail / sandbox setup error: {0}")]
    Jail(String),
    #[error("configuration error: {0}")]
    Config(String),
}

pub type Result<T> = std::result::Result<T, ProxyError>;
