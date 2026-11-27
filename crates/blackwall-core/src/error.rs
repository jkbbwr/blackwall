//! Error types for `blackwall-core`.

use blackwall_proto::CtrlErrorCode;
use std::net::IpAddr;
use thiserror::Error;

/// Unified error type returned by `blackwall-core` operations.
#[derive(Debug, Error)]
pub enum CoreError {
    #[error("policy error: {0}")]
    Policy(#[from] blackwall_policy::PolicyError),

    #[error("secret error: {0}")]
    Secret(#[from] blackwall_secrets::SecretError),

    #[error("OCI image error: {0}")]
    Oci(#[from] blackwall_oci::OciError),

    #[error("unpacker rejected download: {0}")]
    Unpacker(#[from] blackwall_unpacker::UnpackerError),

    #[error("VMM error: {0}")]
    Vmm(#[from] blackwall_vmm::VmmError),

    #[error("proxy error: {0}")]
    Proxy(#[from] blackwall_proxy::ProxyError),

    #[error("wire protocol error: {0}")]
    Proto(#[from] blackwall_proto::ProtoError),

    #[error("audit error: {0}")]
    Audit(#[from] blackwall_audit::AuditError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("sandbox '{0}' not found")]
    SandboxNotFound(String),

    #[error("sandbox '{0}' is not running")]
    SandboxNotRunning(String),

    #[error("image '{0}' not found")]
    ImageNotFound(String),

    #[error("image '{0}' is currently in use by an active sandbox")]
    ImageInUse(String),

    #[error("DNS resolution failed for host '{host}': {reason}")]
    DnsResolution { host: String, reason: String },

    #[error("resolved IP {ip} for host '{host}' is forbidden: {reason}")]
    ForbiddenResolvedIp {
        host: String,
        ip: IpAddr,
        reason: String,
    },

    #[error("guest session error ({code:?}): {message}")]
    GuestError {
        code: CtrlErrorCode,
        message: String,
    },

    #[error("Port 1002 session closed: {0}")]
    SessionClosed(String),

    #[error("policy violation: {0}")]
    PolicyViolation(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("invalid request: {0}")]
    InvalidRequest(String),

    #[error("internal error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, CoreError>;
