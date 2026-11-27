//! Safe static file hosting with SPA fallback for `--ui-dir`.
//!
//! Security invariants:
//! - Strictly rejects any raw or percent-encoded `..`, `\`, or NUL byte traversal.
//! - Canonicalizes every resolved file path and verifies it stays strictly inside `root`.
//! - Never falls back to `index.html` for unknown `/v1/*` API paths (returns JSON 404).

use crate::error::{ApiError, DaemonError};
use axum::body::Body;
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::http::{HeaderValue, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Canonicalized root directory for static UI assets.
#[derive(Debug, Clone)]
pub struct StaticUiDir {
    root: PathBuf,
}

impl StaticUiDir {
    /// Validate and canonicalize `dir`.
    pub fn new(dir: &Path) -> Result<Self, DaemonError> {
        if !dir.is_dir() {
            return Err(DaemonError::InvalidUiDir(dir.to_path_buf()));
        }
        let root = fs::canonicalize(dir).map_err(|_| DaemonError::InvalidUiDir(dir.to_path_buf()))?;
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}

/// Serve a static asset from `ui` with SPA fallback to `index.html`.
pub async fn serve_static_ui(ui: Arc<StaticUiDir>, method: Method, uri: Uri) -> Response {
    let raw_path = uri.path();

    // Never shadow unknown API endpoints with index.html.
    if raw_path == "/v1" || raw_path.starts_with("/v1/") {
        return ApiError::new(
            StatusCode::NOT_FOUND,
            "not_found",
            format!("unknown API endpoint '{raw_path}'"),
        )
        .into_response();
    }

    if method != Method::GET && method != Method::HEAD {
        return ApiError::new(
            StatusCode::METHOD_NOT_ALLOWED,
            "method_not_allowed",
            "only GET and HEAD are allowed for static UI assets",
        )
        .into_response();
    }

    let rel_segments = match sanitize_request_path(raw_path) {
        Ok(segs) => segs,
        Err(msg) => {
            return ApiError::new(StatusCode::FORBIDDEN, "path_traversal_denied", msg)
                .into_response();
        }
    };

    let mut candidate = ui.root.clone();
    for seg in &rel_segments {
        candidate.push(seg);
    }

    // Try exact file first, then `<dir>/index.html`, then SPA fallback `<root>/index.html`.
    let target_file = match resolve_confined_file(&ui.root, &candidate).await {
        Ok(Some(file)) => file,
        Ok(None) => {
            let dir_index = candidate.join("index.html");
            match resolve_confined_file(&ui.root, &dir_index).await {
                Ok(Some(file)) => file,
                Ok(None) => {
                    let spa_index = ui.root.join("index.html");
                    match resolve_confined_file(&ui.root, &spa_index).await {
                        Ok(Some(file)) => file,
                        Ok(None) => {
                            return ApiError::new(
                                StatusCode::NOT_FOUND,
                                "not_found",
                                "static UI asset not found",
                            )
                            .into_response();
                        }
                        Err(()) => {
                            return ApiError::new(
                                StatusCode::FORBIDDEN,
                                "path_traversal_denied",
                                "resolved index.html escapes UI root",
                            )
                            .into_response();
                        }
                    }
                }
                Err(()) => {
                    return ApiError::new(
                        StatusCode::FORBIDDEN,
                        "path_traversal_denied",
                        "resolved path escapes UI root",
                    )
                    .into_response();
                }
            }
        }
        Err(()) => {
            return ApiError::new(
                StatusCode::FORBIDDEN,
                "path_traversal_denied",
                "resolved path escapes UI root",
            )
            .into_response();
        }
    };

    let bytes = match tokio::fs::read(&target_file).await {
        Ok(b) => b,
        Err(_) => {
            return ApiError::new(
                StatusCode::NOT_FOUND,
                "not_found",
                "failed to read static UI asset",
            )
            .into_response();
        }
    };

    let content_type = mime_for_path(&target_file);
    let cache_control = if content_type.starts_with("text/html") {
        "no-cache"
    } else {
        "public, max-age=3600"
    };

    let body = if method == Method::HEAD {
        Body::empty()
    } else {
        Body::from(bytes)
    };

    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, HeaderValue::from_static(content_type))
        .header(CACHE_CONTROL, HeaderValue::from_static(cache_control))
        .header("x-content-type-options", HeaderValue::from_static("nosniff"))
        .body(body)
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

async fn resolve_confined_file(root: &Path, candidate: &Path) -> Result<Option<PathBuf>, ()> {
    let Ok(meta) = tokio::fs::metadata(candidate).await else {
        return Ok(None);
    };
    if !meta.is_file() {
        return Ok(None);
    }
    let Ok(canonical) = tokio::fs::canonicalize(candidate).await else {
        return Ok(None);
    };
    if !canonical.starts_with(root) {
        return Err(());
    }
    Ok(Some(canonical))
}

fn sanitize_request_path(raw_path: &str) -> Result<Vec<String>, &'static str> {
    if raw_path.contains('\\') || raw_path.contains('\0') {
        return Err("invalid path separator or NUL byte");
    }
    // Check raw segments first before decoding.
    for seg in raw_path.split('/') {
        if seg == ".." {
            return Err("parent directory traversal ('..') is forbidden");
        }
    }

    let decoded = percent_decode(raw_path)?;
    if decoded.contains('\\') || decoded.contains('\0') {
        return Err("encoded backslash or NUL byte is forbidden");
    }

    let mut out = Vec::new();
    for seg in decoded.split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." {
            return Err("parent directory traversal ('..') is forbidden");
        }
        out.push(seg.to_string());
    }
    Ok(out)
}

fn percent_decode(input: &str) -> Result<String, &'static str> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err("malformed percent-encoding in path");
            }
            let hi = hex_val(bytes[i + 1]).ok_or("malformed percent-encoding in path")?;
            let lo = hex_val(bytes[i + 2]).ok_or("malformed percent-encoding in path")?;
            out.push((hi << 4) | lo);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| "invalid UTF-8 in path")
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn mime_for_path(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase())
        .as_deref()
    {
        Some("html" | "htm") => "text/html; charset=utf-8",
        Some("js" | "mjs") => "application/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("ico") => "image/x-icon",
        Some("webp") => "image/webp",
        Some("json" | "map") => "application/json; charset=utf-8",
        Some("woff2") => "font/woff2",
        Some("woff") => "font/woff",
        Some("ttf") => "font/ttf",
        Some("wasm") => "application/wasm",
        Some("txt") => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}
