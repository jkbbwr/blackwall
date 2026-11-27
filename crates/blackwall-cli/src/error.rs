//! Error types for `blackwall-cli`.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CliError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("HTTP error: {0}")]
    Http(#[from] http::Error),
    #[error("Hyper error: {0}")]
    Hyper(#[from] hyper::Error),
    #[error("WebSocket error: {0}")]
    WebSocket(#[from] tokio_tungstenite::tungstenite::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("policy error: {0}")]
    Policy(#[from] blackwall_policy::PolicyError),
    #[error("secret error: {0}")]
    Secret(#[from] blackwall_secrets::SecretError),
    #[error("OCI image error: {0}")]
    Oci(#[from] blackwall_oci::OciError),
    #[error("unpacker error: {0}")]
    Unpacker(#[from] blackwall_unpacker::UnpackerError),
    #[error("daemon socket connection failed at '{socket}': {source}")]
    SocketConnect {
        socket: String,
        #[source]
        source: std::io::Error,
    },
    #[error("daemon API error (HTTP {status}): {message}")]
    Api { status: u16, message: String },
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    #[error("stream error ({code}): {message}")]
    StreamError { code: String, message: String },
    #[error("{0}")]
    Message(String),
}

pub type Result<T> = std::result::Result<T, CliError>;
