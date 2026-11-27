//! HTTP control-plane authentication, DNS rebinding protection, CSRF checks,
//! and isolated preview origin security headers.
//!
//! Security invariants:
//! - Applied ONLY to the TCP `--http-listen` router (never UDS, never preview).
//! - Validates `Host` against the bound loopback host:port to defeat DNS rebinding.
//! - Enforces `Origin` and `Sec-Fetch-Site` on mutating methods and WebSocket upgrades
//!   to block cross-origin/cross-site CSRF (including from the isolated preview origin).
//! - Uses constant-time token comparison (`ct_eq`) for Bearer, `bw_session` cookie,
//!   and `?token=` authentication.

use crate::auth::{CallerContext, PrincipalRole};
use crate::error::{ApiError, DaemonError};
use axum::extract::rejection::JsonRejection;
use axum::extract::{Extension, Request, State};
use axum::http::header::{
    AUTHORIZATION, CACHE_CONTROL, COOKIE, HOST, LOCATION, ORIGIN, SET_COOKIE, UPGRADE,
};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use blackwall_core::SandboxManager;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs::{self, DirBuilder, OpenOptions, Permissions};
use std::io::Write;
use std::net::SocketAddr;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;

/// Session cookie name issued by `--http-listen` on token bootstrap / login.
pub const SESSION_COOKIE_NAME: &str = "bw_session";

/// Filename written with `0600` permissions next to the UDS socket.
pub const TOKEN_FILE_NAME: &str = "blackwall-http.token";

/// Configuration shared by the HTTP control-plane security middleware and auth routes.
#[derive(Clone)]
pub struct HttpSecurityConfig {
    http_addr: SocketAddr,
    preview_origin: String,
    token: Arc<String>,
}

impl fmt::Debug for HttpSecurityConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpSecurityConfig")
            .field("http_addr", &self.http_addr)
            .field("preview_origin", &self.preview_origin)
            .field("token", &"<redacted>")
            .finish()
    }
}

impl HttpSecurityConfig {
    pub fn new(http_addr: SocketAddr, preview_origin: String, token: String) -> Self {
        Self {
            http_addr,
            preview_origin,
            token: Arc::new(token),
        }
    }

    pub fn http_addr(&self) -> SocketAddr {
        self.http_addr
    }

    pub fn preview_origin(&self) -> &str {
        &self.preview_origin
    }

    pub fn token(&self) -> &str {
        self.token.as_str()
    }
}

/// Generate a cryptographically random 32-byte (64-hex-char) HTTP control-plane token.
pub fn generate_http_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Validate a user-supplied HTTP control-plane token so it is non-empty and safe
/// to embed in HTTP `Set-Cookie` and `Authorization` headers.
pub fn validate_http_token(token: &str) -> Result<(), DaemonError> {
    if token.is_empty() {
        return Err(DaemonError::InvalidHttpToken("token must not be empty"));
    }
    if token
        .bytes()
        .any(|b| !b.is_ascii_graphic() || b == b';' || b == b',' || b == b'"' || b == b'\\')
    {
        return Err(DaemonError::InvalidHttpToken(
            "token must contain only printable ASCII characters without whitespace, quotes, commas, semicolons, or backslashes",
        ));
    }
    Ok(())
}

/// Persist the active HTTP auth token with strict `0600` permissions.
pub fn write_token_file(path: &Path, token: &str) -> Result<(), DaemonError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)
                .map_err(|source| DaemonError::TokenFileWrite {
                    path: path.to_path_buf(),
                    source,
                })?;
            fs::set_permissions(parent, Permissions::from_mode(0o700)).map_err(|source| {
                DaemonError::TokenFileWrite {
                    path: parent.to_path_buf(),
                    source,
                }
            })?;
        }
    }

    // Refuse to follow pre-existing symlinks at the token file path.
    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            fs::remove_file(path).map_err(|source| DaemonError::TokenFileWrite {
                path: path.to_path_buf(),
                source,
            })?;
        }
    }

    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|source| DaemonError::TokenFileWrite {
            path: path.to_path_buf(),
            source,
        })?;

    file.write_all(token.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|source| DaemonError::TokenFileWrite {
            path: path.to_path_buf(),
            source,
        })?;

    fs::set_permissions(path, Permissions::from_mode(0o600)).map_err(|source| {
        DaemonError::TokenFileWrite {
            path: path.to_path_buf(),
            source,
        }
    })?;

    Ok(())
}

/// Remove the per-boot HTTP token file on daemon shutdown if it exists as a regular file.
pub fn cleanup_token_file(path: &Path) {
    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_file() {
            let _ = fs::remove_file(path);
        }
    }
}

/// Constant-time byte-slice equality check (runtime depends only on `expected.len()`).
pub fn ct_eq(provided: &[u8], expected: &[u8]) -> bool {
    let mut diff: usize = provided.len() ^ expected.len();
    for (i, &exp_byte) in expected.iter().enumerate() {
        let prov_byte = provided.get(i).copied().unwrap_or(0);
        diff |= usize::from(prov_byte ^ exp_byte);
    }
    std::hint::black_box(diff) == 0
}

fn build_session_cookie(token: &str) -> HeaderValue {
    let cookie = format!("{SESSION_COOKIE_NAME}={token}; HttpOnly; SameSite=Strict; Path=/");
    HeaderValue::from_str(&cookie)
        .expect("validated HTTP token must produce a valid Set-Cookie header")
}

/// Validate that the request carries exactly one `Host` header matching the bound loopback
/// host+port (`127.0.0.1:<port>`, `localhost:<port>`, `[::1]:<port>`, case-insensitive).
pub fn is_valid_host(headers: &HeaderMap, bound_addr: SocketAddr) -> bool {
    let mut host_iter = headers.get_all(HOST).iter();
    let Some(first) = host_iter.next() else {
        return false;
    };
    if host_iter.next().is_some() {
        return false;
    }
    let Ok(raw_host) = first.to_str() else {
        return false;
    };
    let host = raw_host.trim();
    if host.is_empty() {
        return false;
    }

    let port = bound_addr.port();
    let allowed_with_port = [
        format!("127.0.0.1:{port}"),
        format!("localhost:{port}"),
        format!("[::1]:{port}"),
    ];
    if allowed_with_port
        .iter()
        .any(|candidate| host.eq_ignore_ascii_case(candidate))
    {
        return true;
    }

    if !bound_addr.ip().is_unspecified() && host.eq_ignore_ascii_case(&bound_addr.to_string()) {
        return true;
    }

    if port == 80 {
        if host.eq_ignore_ascii_case("127.0.0.1")
            || host.eq_ignore_ascii_case("localhost")
            || host.eq_ignore_ascii_case("[::1]")
        {
            return true;
        }
        if !bound_addr.ip().is_unspecified() {
            let ip_host = match bound_addr.ip() {
                std::net::IpAddr::V4(v4) => v4.to_string(),
                std::net::IpAddr::V6(v6) => format!("[{v6}]"),
            };
            if host.eq_ignore_ascii_case(&ip_host) {
                return true;
            }
        }
    }

    false
}

/// Validate that an optional `Origin` header matches the control-plane origin.
pub fn validate_origin(headers: &HeaderMap, bound_addr: SocketAddr) -> Result<(), &'static str> {
    let mut origin_iter = headers.get_all(ORIGIN).iter();
    let Some(first) = origin_iter.next() else {
        return Ok(());
    };
    if origin_iter.next().is_some() {
        return Err("multiple Origin headers are forbidden");
    }
    let Ok(raw_origin) = first.to_str() else {
        return Err("malformed Origin header");
    };
    let origin = raw_origin.trim();

    let port = bound_addr.port();
    let allowed = [
        format!("http://127.0.0.1:{port}"),
        format!("http://localhost:{port}"),
        format!("http://[::1]:{port}"),
    ];
    if allowed
        .iter()
        .any(|candidate| origin.eq_ignore_ascii_case(candidate))
    {
        return Ok(());
    }

    if !bound_addr.ip().is_unspecified()
        && origin.eq_ignore_ascii_case(&format!("http://{bound_addr}"))
    {
        return Ok(());
    }

    if port == 80
        && (origin.eq_ignore_ascii_case("http://127.0.0.1")
            || origin.eq_ignore_ascii_case("http://localhost")
            || origin.eq_ignore_ascii_case("http://[::1]"))
    {
        return Ok(());
    }

    Err("cross-origin request to HTTP control plane is forbidden")
}

/// Validate that an optional `Sec-Fetch-Site` header is `"same-origin"` or `"none"`.
pub fn validate_sec_fetch_site(headers: &HeaderMap) -> Result<(), &'static str> {
    let sec_fetch_site = HeaderName::from_static("sec-fetch-site");
    let mut iter = headers.get_all(&sec_fetch_site).iter();
    let Some(first) = iter.next() else {
        return Ok(());
    };
    if iter.next().is_some() {
        return Err("multiple Sec-Fetch-Site headers are forbidden");
    }
    let Ok(raw) = first.to_str() else {
        return Err("malformed Sec-Fetch-Site header");
    };
    let val = raw.trim();
    if val.eq_ignore_ascii_case("same-origin") || val.eq_ignore_ascii_case("none") {
        Ok(())
    } else {
        Err("cross-site request to HTTP control plane is forbidden")
    }
}

fn is_mutating_or_upgrade(method: &Method, headers: &HeaderMap) -> bool {
    matches!(
        *method,
        Method::POST | Method::PUT | Method::DELETE | Method::PATCH
    ) || headers.contains_key(UPGRADE)
}

fn extract_bearer_token(headers: &HeaderMap) -> Option<&str> {
    let raw = headers.get(AUTHORIZATION)?.to_str().ok()?.trim();
    let (scheme, rest) = raw.split_once(char::is_whitespace)?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = rest.trim();
    (!token.is_empty()).then_some(token)
}

fn has_valid_session_cookie(headers: &HeaderMap, expected_token: &str) -> bool {
    let expected = expected_token.as_bytes();
    let mut matched = false;
    for val in headers.get_all(COOKIE) {
        let Ok(raw) = val.to_str() else {
            continue;
        };
        for pair in raw.split(';') {
            let trimmed = pair.trim();
            if let Some((name, value)) = trimmed.split_once('=') {
                if name.trim() == SESSION_COOKIE_NAME && ct_eq(value.trim().as_bytes(), expected) {
                    matched = true;
                }
            }
        }
    }
    matched
}

fn percent_decode_query_component(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                if i + 2 >= bytes.len() {
                    return None;
                }
                let hi = hex_nibble(bytes[i + 1])?;
                let lo = hex_nibble(bytes[i + 2])?;
                out.push((hi << 4) | lo);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            other => {
                out.push(other);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Extract a query parameter value from a URI query string, if present.
pub fn extract_query_param(query: Option<&str>, target_key: &str) -> Option<String> {
    let query = query?;
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (raw_key, raw_val) = match pair.split_once('=') {
            Some((k, v)) => (k, v),
            None => (pair, ""),
        };
        if raw_key == target_key {
            return percent_decode_query_component(raw_val);
        }
    }
    None
}

/// Check authentication via `Authorization: Bearer` header or `bw_session` cookie.
pub fn is_authenticated_header_or_cookie(headers: &HeaderMap, expected_token: &str) -> bool {
    if let Some(bearer) = extract_bearer_token(headers) {
        if ct_eq(bearer.as_bytes(), expected_token.as_bytes()) {
            return true;
        }
    }
    has_valid_session_cookie(headers, expected_token)
}

/// Check authentication via Bearer header, `bw_session` cookie, or `?token=` query parameter.
pub fn is_authenticated(headers: &HeaderMap, uri: &Uri, expected_token: &str) -> bool {
    if is_authenticated_header_or_cookie(headers, expected_token) {
        return true;
    }
    if let Some(q_token) = extract_query_param(uri.query(), "token") {
        if ct_eq(q_token.as_bytes(), expected_token.as_bytes()) {
            return true;
        }
    }
    false
}

/// Strip `bw_session` from a `Cookie` header value before forwarding to a guest preview app.
pub fn strip_session_cookie_header(raw: &str) -> Option<String> {
    let kept: Vec<&str> = raw
        .split(';')
        .map(str::trim)
        .filter(|pair| {
            if pair.is_empty() {
                return false;
            }
            match pair.split_once('=') {
                Some((name, _)) => name.trim() != SESSION_COOKIE_NAME,
                None => true,
            }
        })
        .collect();
    if kept.is_empty() {
        None
    } else {
        Some(kept.join("; "))
    }
}

/// Middleware protecting the `--http-listen` control-plane router.
pub async fn http_security_middleware(
    State(cfg): State<HttpSecurityConfig>,
    req: Request,
    next: Next,
) -> Response {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers();

    // 1. DNS rebinding protection: strictly validate `Host` header.
    if !is_valid_host(headers, cfg.http_addr) {
        return ApiError::new(
            StatusCode::FORBIDDEN,
            "invalid_host",
            format!(
                "Host header must match loopback control-plane address on port {}",
                cfg.http_addr.port()
            ),
        )
        .into_response();
    }

    // 2. CSRF / cross-origin protection for mutating methods (and WebSocket upgrades).
    if is_mutating_or_upgrade(&method, headers) {
        if let Err(msg) = validate_origin(headers, cfg.http_addr) {
            return ApiError::new(StatusCode::FORBIDDEN, "cross_origin_forbidden", msg)
                .into_response();
        }
        if let Err(msg) = validate_sec_fetch_site(headers) {
            return ApiError::new(StatusCode::FORBIDDEN, "cross_site_forbidden", msg)
                .into_response();
        }
    }

    // 3a. Token bootstrap on `GET /?token=<TOKEN>`: set HttpOnly SameSite=Strict cookie
    //     and redirect 302 to `/` so the token is stripped from browser URL/history immediately.
    let path = uri.path();
    if method == Method::GET && path == "/" {
        if let Some(q_token) = extract_query_param(uri.query(), "token") {
            if ct_eq(q_token.as_bytes(), cfg.token().as_bytes()) {
                return Response::builder()
                    .status(StatusCode::FOUND)
                    .header(LOCATION, HeaderValue::from_static("/"))
                    .header(SET_COOKIE, build_session_cookie(cfg.token()))
                    .header(CACHE_CONTROL, HeaderValue::from_static("no-store"))
                    .header("referrer-policy", HeaderValue::from_static("no-referrer"))
                    .body(axum::body::Body::empty())
                    .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
            } else {
                let mut resp = ApiError::new(
                    StatusCode::UNAUTHORIZED,
                    "unauthorized",
                    "invalid authentication token",
                )
                .into_response();
                resp.headers_mut()
                    .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
                return resp;
            }
        }
    }

    // 3b. Enforce auth on all `/v1/*` routes except `GET /v1/auth/status` and `POST /v1/auth/login`.
    let is_v1_route = path == "/v1" || path.starts_with("/v1/");
    let is_auth_exempt = (method == Method::GET && path == "/v1/auth/status")
        || (method == Method::POST && path == "/v1/auth/login");

    if is_v1_route && !is_auth_exempt && !is_authenticated(headers, &uri, cfg.token()) {
        let mut resp = ApiError::new(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "HTTP control-plane authentication required",
        )
        .into_response();
        resp.headers_mut()
            .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
        return resp;
    }

    next.run(req).await
}

/// Combined state for `/v1/auth/status` and `/v1/auth/login` endpoints.
#[derive(Clone)]
pub struct AuthState {
    pub security: HttpSecurityConfig,
    pub manager: Arc<SandboxManager>,
}

/// Response payload for `GET /v1/auth/status` and `POST /v1/auth/login`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthStatusResponse {
    pub authenticated: bool,
    pub preview_origin: String,
    pub role: PrincipalRole,
    pub readonly_profiles: bool,
    pub require_locked_profiles: bool,
    pub has_policy_ceiling: bool,
    pub allow_image_build: bool,
}

/// Request payload for `POST /v1/auth/login`.
#[derive(Debug, Deserialize)]
pub struct AuthLoginRequest {
    pub token: String,
}

/// `GET /v1/auth/status`: reports whether the caller has a valid session cookie or Bearer token,
/// advertises the isolated preview origin URL, and surfaces the caller's role and active
/// operator lockdown flags.
pub async fn auth_status(
    State(state): State<AuthState>,
    Extension(caller): Extension<CallerContext>,
    headers: HeaderMap,
) -> Response {
    let authenticated = is_authenticated_header_or_cookie(&headers, state.security.token());
    let lockdown = state.manager.lockdown_status();
    let body = AuthStatusResponse {
        authenticated,
        preview_origin: state.security.preview_origin().to_string(),
        role: caller.role,
        readonly_profiles: lockdown.readonly_profiles,
        require_locked_profiles: lockdown.require_locked_profiles,
        has_policy_ceiling: lockdown.has_policy_ceiling,
        allow_image_build: lockdown.allow_image_build,
    };
    let mut resp = (StatusCode::OK, Json(body)).into_response();
    resp.headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

/// `POST /v1/auth/login`: validates the submitted token in constant time and sets
/// the `HttpOnly; SameSite=Strict` `bw_session` cookie.
pub async fn auth_login(
    State(state): State<AuthState>,
    Extension(caller): Extension<CallerContext>,
    payload: Result<Json<AuthLoginRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(req) = payload?;
    if !ct_eq(req.token.as_bytes(), state.security.token().as_bytes()) {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "invalid authentication token",
        ));
    }

    let lockdown = state.manager.lockdown_status();
    let body = AuthStatusResponse {
        authenticated: true,
        preview_origin: state.security.preview_origin().to_string(),
        role: caller.role,
        readonly_profiles: lockdown.readonly_profiles,
        require_locked_profiles: lockdown.require_locked_profiles,
        has_policy_ceiling: lockdown.has_policy_ceiling,
        allow_image_build: lockdown.allow_image_build,
    };
    let mut resp = (StatusCode::OK, Json(body)).into_response();
    resp.headers_mut()
        .insert(SET_COOKIE, build_session_cookie(state.security.token()));
    resp.headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(resp)
}

/// Middleware attached to the isolated preview router (`--preview-listen`) to enforce
/// defensive response headers on all guest-served content.
pub async fn preview_security_headers_middleware(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let headers = resp.headers_mut();
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        HeaderName::from_static("origin-agent-cluster"),
        HeaderValue::from_static("?1"),
    );
    resp
}
