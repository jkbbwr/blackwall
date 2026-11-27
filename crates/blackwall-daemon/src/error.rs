//! Error types and HTTP JSON error mapping for `blackwall-daemon`.

use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use blackwall_core::{CoreError, CtrlErrorCode};
use blackwall_policy::PolicyError;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;
use thiserror::Error;

/// Top-level daemon startup and runtime errors.
#[derive(Debug, Error)]
pub enum DaemonError {
    #[error("core error: {0}")]
    Core(#[from] CoreError),

    #[error("socket path '{0}' already exists and is not a Unix domain socket")]
    SocketPathNotSocket(PathBuf),

    #[error("failed to bind Unix socket at '{path}': {source}")]
    SocketBind {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to set socket permissions on '{path}': {source}")]
    SocketPermissions {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("refusing to bind --http-listen to non-loopback address '{0}' without --allow-non-loopback-http")]
    NonLoopbackHttpDisallowed(SocketAddr),

    #[error("refusing to bind --preview-listen to non-loopback address '{0}' without --allow-non-loopback-http")]
    NonLoopbackPreviewDisallowed(SocketAddr),

    #[error("failed to bind HTTP listener at '{addr}': {source}")]
    HttpBind {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to bind preview HTTP listener at '{addr}': {source}")]
    PreviewBind {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },

    #[error("cannot derive default --preview-listen port from '{0}': port + 1 overflows u16; pass --preview-listen explicitly")]
    PreviewPortOverflow(SocketAddr),

    #[error("invalid HTTP control-plane auth token: {0}")]
    InvalidHttpToken(&'static str),

    #[error("failed to write HTTP auth token file '{path}': {source}")]
    TokenFileWrite {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("invalid UI directory '{0}': path does not exist or is not a directory")]
    InvalidUiDir(PathBuf),

    #[error("HTTP server error: {0}")]
    Serve(#[from] std::io::Error),
}

/// Structured JSON error response returned by all daemon HTTP endpoints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiErrorBody {
    pub code: String,
    pub message: String,
}

/// HTTP-level API error returned by Axum route handlers.
#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
}

impl ApiError {
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_request", message)
    }

    pub fn unsupported_media_type(message: impl Into<String>) -> Self {
        Self::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_media_type",
            message,
        )
    }
}

impl From<JsonRejection> for ApiError {
    fn from(rej: JsonRejection) -> Self {
        Self::new(rej.status(), "invalid_json", rej.body_text())
    }
}

impl From<QueryRejection> for ApiError {
    fn from(rej: QueryRejection) -> Self {
        Self::new(rej.status(), "invalid_query", rej.body_text())
    }
}

impl From<CoreError> for ApiError {
    fn from(err: CoreError) -> Self {
        match err {
            CoreError::SandboxNotFound(id) => Self::new(
                StatusCode::NOT_FOUND,
                "sandbox_not_found",
                format!("sandbox '{id}' not found"),
            ),
            CoreError::SandboxNotRunning(id) => Self::new(
                StatusCode::CONFLICT,
                "sandbox_not_running",
                format!("sandbox '{id}' is not running"),
            ),
            CoreError::ImageNotFound(hash) => Self::new(
                StatusCode::NOT_FOUND,
                "image_not_found",
                format!("image '{hash}' not found"),
            ),
            CoreError::ImageInUse(hash) => Self::new(
                StatusCode::CONFLICT,
                "image_in_use",
                format!("image '{hash}' is currently in use by an active sandbox"),
            ),
            CoreError::Policy(PolicyError::UnknownProfile(name)) => Self::new(
                StatusCode::NOT_FOUND,
                "profile_not_found",
                format!("unknown profile '{name}'"),
            ),
            CoreError::Policy(PolicyError::LockedPolicyViolation(msg)) => Self::new(
                StatusCode::FORBIDDEN,
                "locked_policy_violation",
                msg,
            ),
            CoreError::Policy(PolicyError::InvalidValue(msg))
                if msg.starts_with("ingress port ") =>
            {
                Self::new(StatusCode::FORBIDDEN, "ingress_port_denied", msg)
            }
            CoreError::Policy(other) => Self::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "policy_error",
                other.to_string(),
            ),
            CoreError::PolicyViolation(msg) => {
                Self::new(StatusCode::FORBIDDEN, "policy_violation", msg)
            }
            CoreError::NotFound(msg) => Self::new(StatusCode::NOT_FOUND, "not_found", msg),
            CoreError::InvalidRequest(msg) => Self::bad_request(msg),
            CoreError::Unpacker(other) => Self::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "unpacker_rejected",
                other.to_string(),
            ),
            CoreError::Secret(other) => {
                Self::new(StatusCode::BAD_REQUEST, "secret_error", other.to_string())
            }
            CoreError::ForbiddenResolvedIp { host, ip, reason } => Self::new(
                StatusCode::FORBIDDEN,
                "forbidden_resolved_ip",
                format!("resolved IP {ip} for host '{host}' is forbidden: {reason}"),
            ),
            CoreError::DnsResolution { host, reason } => Self::new(
                StatusCode::BAD_GATEWAY,
                "dns_resolution_failed",
                format!("DNS resolution failed for host '{host}': {reason}"),
            ),
            CoreError::GuestError { code, message } => {
                let (status, err_code) = match code {
                    CtrlErrorCode::NotFound => (StatusCode::NOT_FOUND, "not_found"),
                    CtrlErrorCode::InvalidRequest => (StatusCode::BAD_REQUEST, "invalid_request"),
                    CtrlErrorCode::PathViolation => (StatusCode::BAD_REQUEST, "path_violation"),
                    CtrlErrorCode::PermissionDenied => (StatusCode::FORBIDDEN, "permission_denied"),
                    CtrlErrorCode::LimitExceeded => {
                        (StatusCode::UNPROCESSABLE_ENTITY, "limit_exceeded")
                    }
                    CtrlErrorCode::Timeout => (StatusCode::GATEWAY_TIMEOUT, "timeout"),
                    CtrlErrorCode::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "guest_error"),
                };
                Self::new(status, err_code, message)
            }
            CoreError::SessionClosed(msg) => {
                Self::new(StatusCode::SERVICE_UNAVAILABLE, "session_closed", msg)
            }
            CoreError::Oci(other) => {
                let msg = other.to_string();
                if msg.starts_with("invalid image specification:") {
                    Self::new(StatusCode::BAD_REQUEST, "invalid_image_spec", msg)
                } else {
                    Self::new(StatusCode::INTERNAL_SERVER_ERROR, "oci_error", msg)
                }
            }
            CoreError::Vmm(other) => Self::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "vmm_error",
                other.to_string(),
            ),
            CoreError::Proxy(other) => Self::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "proxy_error",
                other.to_string(),
            ),
            CoreError::Proto(other) => Self::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "protocol_error",
                other.to_string(),
            ),
            CoreError::Audit(other) => Self::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "audit_error",
                other.to_string(),
            ),
            CoreError::Io(other) => Self::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "io_error",
                other.to_string(),
            ),
            CoreError::Internal(msg) => {
                Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal_error", msg)
            }
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = ApiErrorBody {
            code: self.code.to_string(),
            message: self.message,
        };
        (self.status, Json(body)).into_response()
    }
}
