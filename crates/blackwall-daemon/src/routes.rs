//! HTTP/1.1 + JSON + NDJSON + WebSocket route handlers matching `docs/API.md`.

use crate::auth::{attach_default_operator_context, CallerContext, Capability};
use crate::error::ApiError;
use crate::http_security::{
    auth_login, auth_status, http_security_middleware, preview_security_headers_middleware,
    strip_session_cookie_header, AuthState, HttpSecurityConfig,
};
use crate::static_ui::{serve_static_ui, StaticUiDir};
use axum::body::Body;
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{DefaultBodyLimit, Extension, Path, Query, Request, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE, COOKIE, HOST, SET_COOKIE};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, delete, get, post, put};
use axum::{Json, Router};
use blackwall_core::{
    AuditEvent, CoreError, DownloadFormat, ExecRequest, ExecStreamEvent, HostServiceSpec,
    ImageSpec, ProfileDraft, PtyEvent, PtyHandle, PtyOpenParams, SandboxManager, SignalKind,
    TcpTunnelEvent, TcpTunnelHandle, UploadKind,
};
use blackwall_policy::PolicyError;
use bytes::Bytes;
use futures_util::{stream, SinkExt, StreamExt};
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_stream::wrappers::UnboundedReceiverStream;

/// Maximum upload body size accepted by `PUT /v1/sandboxes/{id}/files` (512 MiB).
pub const MAX_UPLOAD_BODY_BYTES: usize = 512 * 1024 * 1024;
const PREVIEW_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const PREVIEW_RESPONSE_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Clone)]
struct AppState {
    manager: Arc<SandboxManager>,
}

/// Construct the complete `blackwall-daemon` Axum router backed by `manager` for the `0600` UDS.
///
/// Serves all control-plane routes AND `/v1/sandboxes/{id}/proxy/{port}*` with no HTTP token
/// requirement (protected by kernel `0600` Unix socket permissions).
pub fn build_router(manager: Arc<SandboxManager>) -> Router {
    build_router_with_ui(manager, None)
}

/// Construct the UDS `blackwall-daemon` Axum router with optional static UI hosting.
pub fn build_router_with_ui(
    manager: Arc<SandboxManager>,
    ui_dir: Option<Arc<StaticUiDir>>,
) -> Router {
    let state = AppState { manager };
    let mut router = build_control_plane_base_router()
        .route("/v1/sandboxes/{id}/proxy/{port}", any(proxy_http_root))
        .route("/v1/sandboxes/{id}/proxy/{port}/", any(proxy_http_root))
        .route(
            "/v1/sandboxes/{id}/proxy/{port}/{*rest}",
            any(proxy_http_subpath),
        )
        .with_state(state);

    if let Some(ui) = ui_dir {
        router = router.fallback(move |method: Method, uri: Uri| {
            let ui = Arc::clone(&ui);
            serve_static_ui(ui, method, uri)
        });
    }

    router.layer(axum::middleware::from_fn(attach_default_operator_context))
}

/// Construct the hardened TCP HTTP control-plane router (`--http-listen`).
///
/// Security invariants:
/// - Rejects `/v1/sandboxes/{id}/proxy/{port}*` with `403 preview_origin_required` so untrusted
///   guest HTML/JS can never share an origin with the control plane.
/// - Exposes `GET /v1/auth/status` and `POST /v1/auth/login` for browser session bootstrap.
/// - Enforces strict `Host`, `Origin`/`Sec-Fetch-Site`, and Bearer/Cookie/`?token=` auth
///   middleware on all requests.
pub fn build_http_control_plane_router(
    manager: Arc<SandboxManager>,
    ui_dir: Option<Arc<StaticUiDir>>,
    security: HttpSecurityConfig,
) -> Router {
    let auth_state = AuthState {
        security: security.clone(),
        manager: Arc::clone(&manager),
    };
    let state = AppState { manager };
    let preview_origin = Arc::new(security.preview_origin().to_string());
    let reject_preview_origin_1 = Arc::clone(&preview_origin);
    let reject_preview_origin_2 = Arc::clone(&preview_origin);
    let reject_preview_origin_3 = Arc::clone(&preview_origin);

    let auth_router = Router::new()
        .route("/v1/auth/status", get(auth_status))
        .route("/v1/auth/login", post(auth_login))
        .with_state(auth_state);

    let mut router = build_control_plane_base_router()
        .with_state(state)
        .merge(auth_router)
        .route(
            "/v1/sandboxes/{id}/proxy/{port}",
            any(move || {
                let origin = Arc::clone(&reject_preview_origin_1);
                async move { preview_origin_required(&origin) }
            }),
        )
        .route(
            "/v1/sandboxes/{id}/proxy/{port}/",
            any(move || {
                let origin = Arc::clone(&reject_preview_origin_2);
                async move { preview_origin_required(&origin) }
            }),
        )
        .route(
            "/v1/sandboxes/{id}/proxy/{port}/{*rest}",
            any(move || {
                let origin = Arc::clone(&reject_preview_origin_3);
                async move { preview_origin_required(&origin) }
            }),
        );

    if let Some(ui) = ui_dir {
        router = router.fallback(move |method: Method, uri: Uri| {
            let ui = Arc::clone(&ui);
            serve_static_ui(ui, method, uri)
        });
    }

    router
        .layer(axum::middleware::from_fn(attach_default_operator_context))
        .layer(axum::middleware::from_fn_with_state(
            security,
            http_security_middleware,
        ))
}

/// Construct the isolated preview HTTP router (`--preview-listen`).
///
/// Serves:
/// 1. Subdomain-isolated previews: `http://<port>-<sandbox-id>.localhost:<preview_port>/...`
///    (and nested subdomains `<sub...>.<port>-<sandbox-id>.localhost:<preview_port>/...`),
///    giving every `(sandbox_id, port)` its own browser Same-Origin boundary (`localStorage`,
///    `IndexedDB`, `ServiceWorker`, and cookies) and serving guest apps natively at `/`.
/// 2. Path-prefix fallback: `/v1/sandboxes/{id}/proxy/{port}*` (with `Set-Cookie` `Path` scoped
///    to the sandbox prefix and `Domain=` stripped).
///
/// Serves ZERO control-plane routes and attaches `X-Content-Type-Options: nosniff`,
/// `Referrer-Policy: no-referrer`, and `Origin-Agent-Cluster: ?1`.
pub fn build_preview_router(manager: Arc<SandboxManager>) -> Router {
    let state = AppState { manager };
    Router::new()
        .route("/v1/sandboxes/{id}/proxy/{port}", any(proxy_http_root))
        .route("/v1/sandboxes/{id}/proxy/{port}/", any(proxy_http_root))
        .route(
            "/v1/sandboxes/{id}/proxy/{port}/{*rest}",
            any(proxy_http_subpath),
        )
        .fallback(any(proxy_http_subdomain_fallback))
        .with_state(state)
        .layer(axum::middleware::from_fn(
            preview_security_headers_middleware,
        ))
}

fn preview_origin_required(preview_origin: &str) -> Response {
    ApiError::new(
        StatusCode::FORBIDDEN,
        "preview_origin_required",
        format!("Sandbox HTTP previews are served on the isolated preview origin: {preview_origin}"),
    )
    .into_response()
}

fn build_control_plane_base_router() -> Router<AppState> {
    let files_router = Router::new()
        .route("/v1/sandboxes/{id}/files", put(upload_files).get(download_files))
        .layer(DefaultBodyLimit::max(MAX_UPLOAD_BODY_BYTES));

    Router::new()
        // Sandbox lifecycle
        .route("/v1/sandboxes", post(create_sandbox).get(list_sandboxes))
        .route(
            "/v1/sandboxes/{id}",
            get(get_sandbox).delete(delete_sandbox),
        )
        .route("/v1/sandboxes/{id}/keepalive", post(keepalive_sandbox))
        // Exec & background processes
        .route("/v1/sandboxes/{id}/exec", post(exec_command))
        .route("/v1/sandboxes/{id}/processes", get(list_processes))
        .route(
            "/v1/sandboxes/{id}/processes/{proc_id}/logs",
            get(process_logs),
        )
        .route(
            "/v1/sandboxes/{id}/processes/{proc_id}/signal",
            post(signal_process),
        )
        .route(
            "/v1/sandboxes/{id}/processes/{proc_id}",
            delete(delete_process),
        )
        // Filesystem listing & listening ports inspection
        .route("/v1/sandboxes/{id}/fs", get(list_dir))
        .route("/v1/sandboxes/{id}/ports", get(list_listening_ports))
        // Dynamic ingress port allowlist management
        .route(
            "/v1/sandboxes/{id}/ingress",
            get(list_ingress_ports).post(allow_ingress_port),
        )
        .route(
            "/v1/sandboxes/{id}/ingress/{port}",
            delete(close_ingress_port),
        )
        // Interactive PTY WebSocket
        .route("/v1/sandboxes/{id}/pty", get(open_pty_ws))
        // Host-to-guest TCP ingress tunnel (WebSocket)
        .route("/v1/sandboxes/{id}/tunnel/{port}", get(open_tcp_tunnel_ws))
        // Guest-to-host service bridges
        .route(
            "/v1/sandboxes/{id}/bridges",
            get(list_host_bridges).post(attach_host_bridge),
        )
        .route(
            "/v1/sandboxes/{id}/bridges/{guest_port}",
            delete(detach_host_bridge),
        )
        // Profiles, images & audit
        .route("/v1/profiles", get(list_profiles).post(create_profile))
        .route(
            "/v1/profiles/{name}",
            get(get_profile).delete(delete_profile),
        )
        .route("/v1/images", get(list_images))
        .route("/v1/images/build", post(build_image))
        .route("/v1/images/{content_hash}", delete(delete_image))
        .route("/v1/audit", get(get_audit_events))
        .route("/v1/sandboxes/{id}/audit", get(get_sandbox_audit_events))
        .merge(files_router)
}

// ---------------------------------------------------------------------------
// 2.1 Sandbox Lifecycle
// ---------------------------------------------------------------------------

async fn create_sandbox(
    State(state): State<AppState>,
    payload: Result<Json<ProfileDraft>, JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(draft) = payload?;
    // Never log `draft` because it may carry ephemeral plaintext secrets.
    let summary = state.manager.create_sandbox(draft).await?;
    Ok((StatusCode::CREATED, Json(summary)).into_response())
}

async fn list_sandboxes(State(state): State<AppState>) -> Response {
    let list = state.manager.list_sandboxes();
    (StatusCode::OK, Json(list)).into_response()
}

async fn get_sandbox(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let detail = state.manager.get_sandbox(&id).await?;
    Ok((StatusCode::OK, Json(detail)).into_response())
}

async fn delete_sandbox(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    state.manager.destroy_sandbox(&id).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn keepalive_sandbox(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let resp = state.manager.keepalive_sandbox(&id)?;
    Ok((StatusCode::OK, Json(resp)).into_response())
}

#[derive(Debug, Default, Deserialize)]
struct FsQuery {
    #[serde(default)]
    path: Option<String>,
}

async fn list_dir(
    State(state): State<AppState>,
    Path(id): Path<String>,
    query: Result<Query<FsQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    let Query(query) = query?;
    let path = query
        .path
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("/workspace");
    let entries = state.manager.list_dir(&id, path).await?;
    Ok((StatusCode::OK, Json(entries)).into_response())
}

async fn list_listening_ports(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let ports = state.manager.list_listening_ports(&id).await?;
    Ok((StatusCode::OK, Json(ports)).into_response())
}

// ---------------------------------------------------------------------------
// 2.1a Dynamic Ingress Port Allowlist
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct AllowIngressPortRequest {
    pub port: u16,
}

async fn list_ingress_ports(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let ports = state.manager.list_ingress_ports(&id)?;
    Ok((StatusCode::OK, Json(ports)).into_response())
}

async fn allow_ingress_port(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerContext>,
    Path(id): Path<String>,
    payload: Result<Json<AllowIngressPortRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    caller.require(Capability::MutateIngress)?;
    let Json(req) = payload?;
    let ports = state.manager.allow_ingress_port(&id, req.port)?;
    Ok((StatusCode::CREATED, Json(ports)).into_response())
}

async fn close_ingress_port(
    State(state): State<AppState>,
    Path((id, port)): Path<(String, u16)>,
) -> Result<StatusCode, ApiError> {
    if port == 0 {
        return Err(ApiError::bad_request("ingress port must be >= 1"));
    }
    state.manager.close_ingress_port(&id, port)?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// 2.1b Host Service Bridges (Guest -> Host Loopback / UDS Forwarding)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct AttachBridgeRequest {
    #[serde(default)]
    pub name: Option<String>,
    pub guest_port: u16,
    pub target: String,
}

async fn list_host_bridges(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let bridges = state.manager.list_host_bridges(&id)?;
    Ok((StatusCode::OK, Json(bridges)).into_response())
}

async fn attach_host_bridge(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerContext>,
    Path(id): Path<String>,
    payload: Result<Json<AttachBridgeRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    caller.require(Capability::MutateBridges)?;
    let Json(req) = payload?;
    let name = req
        .name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| format!("bridge-{}", req.guest_port));
    let spec = HostServiceSpec {
        name,
        guest_port: req.guest_port,
        target: req.target,
    };
    let attached = state.manager.attach_host_bridge(&id, spec).await?;
    Ok((StatusCode::CREATED, Json(attached)).into_response())
}

async fn detach_host_bridge(
    State(state): State<AppState>,
    Path((id, guest_port)): Path<(String, u16)>,
) -> Result<StatusCode, ApiError> {
    if guest_port == 0 {
        return Err(ApiError::bad_request("guest_port must be >= 1"));
    }
    state.manager.detach_host_bridge(&id, guest_port).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// 2.2 Command Execution & Background Processes
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
struct ExecQuery {
    #[serde(default)]
    stream: bool,
}

async fn exec_command(
    State(state): State<AppState>,
    Path(id): Path<String>,
    query: Result<Query<ExecQuery>, QueryRejection>,
    payload: Result<Json<ExecRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    let Query(query) = query?;
    let Json(req) = payload?;

    if req.background {
        let proc = state.manager.exec_background(&id, req).await?;
        return Ok((StatusCode::ACCEPTED, Json(proc)).into_response());
    }

    if query.stream {
        let rx = state.manager.exec_stream(&id, req).await?;
        return Ok(ndjson_stream_response(rx, None));
    }

    let result = state.manager.exec(&id, req).await?;
    Ok((StatusCode::OK, Json(result)).into_response())
}

async fn list_processes(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let procs = state.manager.list_processes(&id).await?;
    Ok((StatusCode::OK, Json(procs)).into_response())
}

#[derive(Debug, Default, Deserialize)]
struct LogsQuery {
    #[serde(default)]
    tail: Option<usize>,
    #[serde(default)]
    follow: bool,
}

async fn process_logs(
    State(state): State<AppState>,
    Path((id, proc_id)): Path<(String, String)>,
    query: Result<Query<LogsQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    let Query(query) = query?;
    let mut rx = state
        .manager
        .process_logs(&id, &proc_id, query.tail, query.follow)
        .await?;

    // For non-follow requests, inspect the first frame before committing HTTP 200
    // so guest-side `NotFound` errors surface as proper 404 JSON responses.
    let first = if !query.follow {
        match rx.recv().await {
            Some(ExecStreamEvent::Error { code, message }) => {
                return Err(ApiError::from(blackwall_core::CoreError::GuestError {
                    code,
                    message,
                }));
            }
            other => other,
        }
    } else {
        None
    };

    Ok(ndjson_stream_response(rx, first))
}

#[derive(Debug, Deserialize)]
struct SignalBody {
    signal: SignalKind,
}

async fn signal_process(
    State(state): State<AppState>,
    Path((id, proc_id)): Path<(String, String)>,
    payload: Result<Json<SignalBody>, JsonRejection>,
) -> Result<StatusCode, ApiError> {
    let Json(body) = payload?;
    state
        .manager
        .signal_process(&id, &proc_id, body.signal)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_process(
    State(state): State<AppState>,
    Path((id, proc_id)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    state.manager.delete_process(&id, &proc_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

fn encode_ndjson_event(ev: ExecStreamEvent) -> Result<Bytes, Infallible> {
    let mut line = serde_json::to_vec(&ev.to_ndjson_value()).unwrap_or_else(|_| b"{}".to_vec());
    line.push(b'\n');
    Ok(Bytes::from(line))
}

fn ndjson_stream_response(
    rx: mpsc::UnboundedReceiver<ExecStreamEvent>,
    first: Option<ExecStreamEvent>,
) -> Response {
    let tail_stream = UnboundedReceiverStream::new(rx).map(encode_ndjson_event);
    let body = match first {
        Some(ev) => Body::from_stream(stream::once(async move { encode_ndjson_event(ev) }).chain(tail_stream)),
        None => Body::from_stream(tail_stream),
    };

    Response::builder()
        .status(StatusCode::OK)
        .header(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-ndjson"),
        )
        .header(CACHE_CONTROL, HeaderValue::from_static("no-store"))
        .body(body)
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

// ---------------------------------------------------------------------------
// 2.3 Interactive PTY (WebSocket)
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
struct PtyQuery {
    cols: Option<u16>,
    rows: Option<u16>,
    cmd: Option<String>,
    cwd: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum PtyClientControl {
    Resize { cols: u16, rows: u16 },
}

fn parse_pty_cmd(raw: Option<String>) -> Option<Vec<String>> {
    let s = raw?;
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.starts_with('[') {
        if let Ok(parsed) = serde_json::from_str::<Vec<String>>(trimmed) {
            if !parsed.is_empty() {
                return Some(parsed);
            }
        }
    }
    let parts: Vec<String> = trimmed.split_whitespace().map(ToOwned::to_owned).collect();
    if parts.is_empty() {
        None
    } else {
        Some(parts)
    }
}

async fn open_pty_ws(
    State(state): State<AppState>,
    Path(id): Path<String>,
    query: Result<Query<PtyQuery>, QueryRejection>,
    ws: WebSocketUpgrade,
) -> Result<Response, ApiError> {
    let Query(query) = query?;
    let mut params = PtyOpenParams::default();
    if let Some(cols) = query.cols {
        if cols == 0 {
            return Err(ApiError::bad_request("pty cols must be >= 1"));
        }
        params.cols = cols;
    }
    if let Some(rows) = query.rows {
        if rows == 0 {
            return Err(ApiError::bad_request("pty rows must be >= 1"));
        }
        params.rows = rows;
    }
    params.cmd = parse_pty_cmd(query.cmd);
    params.cwd = query.cwd;

    // Open the guest PTY before upgrading so unknown sandboxes or invalid parameters
    // fail with proper HTTP 4xx JSON responses rather than an abrupt WS drop.
    let pty = state.manager.open_pty(&id, params).await?;
    Ok(ws.on_upgrade(move |socket| handle_pty_socket(socket, pty)))
}

async fn handle_pty_socket(socket: WebSocket, pty: PtyHandle) {
    let (mut ws_tx, mut ws_rx) = socket.split();
    let (pty_writer, mut pty_rx) = pty.split();

    loop {
        tokio::select! {
            biased;

            maybe_ev = pty_rx.recv() => {
                match maybe_ev {
                    Some(PtyEvent::Output(bytes)) => {
                        if ws_tx.send(Message::Binary(bytes.into())).await.is_err() {
                            break;
                        }
                    }
                    Some(PtyEvent::Exited(code)) => {
                        let exit_json = serde_json::json!({
                            "type": "exit",
                            "code": code,
                        })
                        .to_string();
                        let _ = ws_tx.send(Message::Text(exit_json.into())).await;
                        let _ = ws_tx.send(Message::Close(None)).await;
                        let _ = ws_tx.flush().await;
                        break;
                    }
                    None => {
                        let _ = ws_tx.send(Message::Close(None)).await;
                        let _ = ws_tx.flush().await;
                        break;
                    }
                }
            }

            maybe_msg = ws_rx.next() => {
                match maybe_msg {
                    Some(Ok(Message::Binary(data))) => {
                        if pty_writer.write_input(data.as_ref()).is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Text(text))) => {
                        match serde_json::from_str::<PtyClientControl>(text.as_str()) {
                            Ok(PtyClientControl::Resize { cols, rows }) => {
                                if cols > 0 && rows > 0 && pty_writer.resize(cols, rows).is_err() {
                                    break;
                                }
                            }
                            Err(err) => {
                                tracing::debug!(%err, "ignoring unrecognized PTY WS text frame");
                            }
                        }
                    }
                    Some(Ok(Message::Ping(payload))) => {
                        if ws_tx.send(Message::Pong(payload)).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Pong(_))) => {}
                    Some(Ok(Message::Close(_))) | Some(Err(_)) | None => {
                        break;
                    }
                }
            }
        }
    }

    let _ = pty_writer.close();
}

// ---------------------------------------------------------------------------
// 2.3b Host-to-Guest TCP Ingress Tunnel (WebSocket) & Direct HTTP Reverse Proxy
// ---------------------------------------------------------------------------

async fn open_tcp_tunnel_ws(
    State(state): State<AppState>,
    Path((id, port)): Path<(String, u16)>,
    ws: WebSocketUpgrade,
) -> Result<Response, ApiError> {
    if port == 0 {
        return Err(ApiError::bad_request("tunnel port must be >= 1"));
    }
    // Validate allow_ports and open guest tunnel BEFORE WebSocket upgrade so denied
    // ports return 403 Forbidden and unknown sandboxes return 404 Not Found cleanly.
    let tunnel = state.manager.open_tcp_tunnel(&id, port).await?;
    Ok(ws.on_upgrade(move |socket| handle_tcp_tunnel_socket(socket, tunnel)))
}

async fn handle_tcp_tunnel_socket(socket: WebSocket, tunnel: TcpTunnelHandle) {
    let (mut ws_tx, mut ws_rx) = socket.split();
    let (tunnel_writer, mut tunnel_rx) = tunnel.split();

    loop {
        tokio::select! {
            biased;

            maybe_ev = tunnel_rx.recv() => {
                match maybe_ev {
                    Some(TcpTunnelEvent::Data(bytes)) => {
                        if ws_tx.send(Message::Binary(bytes.into())).await.is_err() {
                            break;
                        }
                    }
                    Some(TcpTunnelEvent::Closed(_)) | None => {
                        let _ = ws_tx.send(Message::Close(None)).await;
                        let _ = ws_tx.flush().await;
                        break;
                    }
                }
            }

            maybe_msg = ws_rx.next() => {
                match maybe_msg {
                    Some(Ok(Message::Binary(data))) => {
                        if tunnel_writer.write_data(data.as_ref()).is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Ping(payload))) => {
                        if ws_tx.send(Message::Pong(payload)).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Pong(_))) => {}
                    Some(Ok(Message::Text(_))) => {}
                    Some(Ok(Message::Close(_))) | Some(Err(_)) | None => {
                        break;
                    }
                }
            }
        }
    }

    let _ = tunnel_writer.close();
}

enum SetCookieScope<'a> {
    /// Subdomain preview (`<port>-<sandbox-id>.localhost`): allow `Domain=` only when equal to or
    /// nested under `allowed_domain`, otherwise strip `Domain=` to keep the cookie host-only.
    Subdomain { allowed_domain: &'a str },
    /// Path-prefix fallback (`/v1/sandboxes/{id}/proxy/{port}/`): always strip `Domain=` and force
    /// `Path=/v1/sandboxes/{id}/proxy/{port}/`.
    PathPrefix { forced_path: &'a str },
}

/// Parse `<port>-<sandbox-id>.localhost[:port]` (or `<sub...>.<port>-<sandbox-id>.localhost[:port]`)
/// from an HTTP `Host` header, returning `(sandbox_id, guest_port, allowed_domain_root)`.
fn parse_preview_subdomain_host(host_header: &str) -> Option<(String, u16, String)> {
    let trimmed = host_header.trim();
    if trimmed.is_empty() || trimmed.starts_with('[') {
        return None;
    }
    let host_only = match trimmed.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') && p.parse::<u16>().is_ok() => h,
        _ => trimmed,
    };
    let normalized = host_only.trim_end_matches('.').to_ascii_lowercase();
    let prefix = normalized.strip_suffix(".localhost")?;
    if prefix.is_empty() {
        return None;
    }
    // Last label immediately before `.localhost` carries `<port>-<sandbox-id>`.
    let root_label = prefix.rsplit('.').next()?;
    let (port_str, sandbox_id) = root_label.split_once('-')?;
    let port: u16 = port_str.parse().ok()?;
    if port == 0 || sandbox_id.is_empty() {
        return None;
    }
    if !sandbox_id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return None;
    }
    Some((
        sandbox_id.to_string(),
        port,
        format!("{root_label}.localhost"),
    ))
}

/// Sanitize a guest `Set-Cookie` header according to `scope` to prevent cross-sandbox cookie tossing.
fn sanitize_set_cookie_header(raw: &str, scope: &SetCookieScope<'_>) -> Option<String> {
    let mut parts = raw.split(';');
    let first = parts.next()?.trim();
    if first.is_empty() {
        return None;
    }
    let mut out = vec![first.to_string()];
    let mut has_path = false;

    for attr in parts {
        let trimmed = attr.trim();
        if trimmed.is_empty() {
            continue;
        }
        let (k, v_opt) = match trimmed.split_once('=') {
            Some((k, v)) => (k.trim(), Some(v.trim())),
            None => (trimmed, None),
        };
        if k.eq_ignore_ascii_case("domain") {
            match scope {
                SetCookieScope::Subdomain { allowed_domain } => {
                    if let Some(v) = v_opt {
                        let norm = v.trim_start_matches('.').trim_end_matches('.').to_ascii_lowercase();
                        let allowed_nested = norm == *allowed_domain
                            || norm.ends_with(&format!(".{allowed_domain}"));
                        if allowed_nested {
                            out.push(format!("Domain={norm}"));
                        }
                    }
                    // Broader or invalid Domain= (e.g. `localhost`, `127.0.0.1`, other sandbox) is stripped.
                }
                SetCookieScope::PathPrefix { .. } => {
                    // Strip Domain= on shared 127.0.0.1:7701 fallback.
                }
            }
            continue;
        }
        if k.eq_ignore_ascii_case("path") {
            match scope {
                SetCookieScope::Subdomain { .. } => {
                    out.push(trimmed.to_string());
                }
                SetCookieScope::PathPrefix { forced_path } => {
                    if !has_path {
                        out.push(format!("Path={forced_path}"));
                        has_path = true;
                    }
                }
            }
            continue;
        }
        out.push(trimmed.to_string());
    }

    if let SetCookieScope::PathPrefix { forced_path } = scope {
        if !has_path {
            out.push(format!("Path={forced_path}"));
        }
    }

    Some(out.join("; "))
}

async fn proxy_http_subdomain_fallback(
    State(state): State<AppState>,
    req: Request,
) -> Result<Response, ApiError> {
    let host_str = req
        .headers()
        .get(HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let Some((sandbox_id, port, allowed_domain)) = parse_preview_subdomain_host(host_str) else {
        return Ok(StatusCode::NOT_FOUND.into_response());
    };
    proxy_http_inner(
        &state,
        &sandbox_id,
        port,
        None,
        Some(allowed_domain),
        req,
    )
    .await
}

async fn proxy_http_root(
    State(state): State<AppState>,
    Path((id, port)): Path<(String, u16)>,
    req: Request,
) -> Result<Response, ApiError> {
    proxy_http_inner(&state, &id, port, None, None, req).await
}

async fn proxy_http_subpath(
    State(state): State<AppState>,
    Path((id, port, rest)): Path<(String, u16, String)>,
    req: Request,
) -> Result<Response, ApiError> {
    proxy_http_inner(&state, &id, port, Some(rest), None, req).await
}

async fn proxy_http_inner(
    state: &AppState,
    id: &str,
    port: u16,
    rest: Option<String>,
    subdomain_root: Option<String>,
    req: Request,
) -> Result<Response, ApiError> {
    if port == 0 {
        return Err(ApiError::bad_request("proxy port must be >= 1"));
    }

    let tunnel = state.manager.open_tcp_tunnel(id, port).await?;
    let stream = tunnel.into_stream();

    let (parts, body) = req.into_parts();
    let prefix = format!("/v1/sandboxes/{id}/proxy/{port}");
    let stripped_path = if subdomain_root.is_some() {
        let p = parts.uri.path();
        if p.is_empty() {
            "/".to_string()
        } else {
            p.to_string()
        }
    } else {
        match parts.uri.path().strip_prefix(&prefix) {
            Some("") | Some("/") => "/".to_string(),
            Some(tail) if tail.starts_with('/') => tail.to_string(),
            Some(tail) => format!("/{tail}"),
            None => match rest {
                Some(r) if !r.is_empty() => {
                    if r.starts_with('/') {
                        r
                    } else {
                        format!("/{r}")
                    }
                }
                _ => "/".to_string(),
            },
        }
    };
    let target_uri_str = match parts.uri.query() {
        Some(q) if !q.is_empty() => format!("{stripped_path}?{q}"),
        _ => stripped_path,
    };
    let target_uri: Uri = target_uri_str
        .parse()
        .map_err(|e| ApiError::bad_request(format!("invalid proxy target URI: {e}")))?;

    let io = TokioIo::new(stream);
    let (mut sender, conn) = timeout(
        PREVIEW_HANDSHAKE_TIMEOUT,
        hyper::client::conn::http1::handshake(io),
    )
    .await
    .map_err(|_| {
        ApiError::new(
            StatusCode::GATEWAY_TIMEOUT,
            "proxy_handshake_timeout",
            "timed out waiting for guest HTTP handshake",
        )
    })?
    .map_err(|e| {
        ApiError::new(
            StatusCode::BAD_GATEWAY,
            "proxy_handshake_failed",
            format!("guest HTTP handshake failed: {e}"),
        )
    })?;
    tokio::spawn(async move {
        if let Err(err) = conn.await {
            tracing::debug!(%err, "guest HTTP reverse-proxy connection closed");
        }
    });

    let mut upstream_req_builder = hyper::Request::builder()
        .method(parts.method)
        .uri(target_uri);

    if let Some(headers_mut) = upstream_req_builder.headers_mut() {
        for (name, value) in &parts.headers {
            if is_hop_by_hop_header(name) || *name == HOST {
                continue;
            }
            if *name == COOKIE {
                if let Ok(raw) = value.to_str() {
                    if let Some(sanitized) = strip_session_cookie_header(raw) {
                        if let Ok(sanitized_val) = HeaderValue::from_str(&sanitized) {
                            headers_mut.append(COOKIE, sanitized_val);
                        }
                    }
                }
                continue;
            }
            headers_mut.append(name.clone(), value.clone());
        }
        if let Ok(host_val) = HeaderValue::from_str(&format!("127.0.0.1:{port}")) {
            headers_mut.insert(HOST, host_val);
        }
    }

    let upstream_req = upstream_req_builder
        .body(body)
        .map_err(|e| ApiError::bad_request(format!("failed to build proxied request: {e}")))?;

    let upstream_resp = timeout(PREVIEW_RESPONSE_TIMEOUT, sender.send_request(upstream_req))
        .await
        .map_err(|_| {
            ApiError::new(
                StatusCode::GATEWAY_TIMEOUT,
                "proxy_upstream_timeout",
                "timed out waiting for guest HTTP response",
            )
        })?
        .map_err(|e| {
            ApiError::new(
                StatusCode::BAD_GATEWAY,
                "proxy_upstream_error",
                format!("guest HTTP proxy request failed: {e}"),
            )
        })?;

    let forced_path = format!("{prefix}/");
    let cookie_scope = match subdomain_root.as_deref() {
        Some(allowed_domain) => SetCookieScope::Subdomain { allowed_domain },
        None => SetCookieScope::PathPrefix {
            forced_path: &forced_path,
        },
    };

    let (resp_parts, resp_body) = upstream_resp.into_parts();
    let mut out_builder = Response::builder().status(resp_parts.status);
    if let Some(headers_mut) = out_builder.headers_mut() {
        for (name, value) in &resp_parts.headers {
            if is_hop_by_hop_header(name) {
                continue;
            }
            if *name == SET_COOKIE {
                if let Ok(raw) = value.to_str() {
                    if let Some(sanitized) = sanitize_set_cookie_header(raw, &cookie_scope) {
                        if let Ok(sanitized_val) = HeaderValue::from_str(&sanitized) {
                            headers_mut.append(SET_COOKIE, sanitized_val);
                        }
                    }
                }
                continue;
            }
            headers_mut.append(name.clone(), value.clone());
        }
    }

    let response = out_builder
        .body(Body::new(resp_body))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
    Ok(response)
}

fn is_hop_by_hop_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
    )
}

// ---------------------------------------------------------------------------
// 2.4 File I/O (Upload / Download)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct UploadQuery {
    path: String,
}

fn parse_upload_kind(headers: &HeaderMap) -> Result<UploadKind, ApiError> {
    let Some(raw) = headers.get(CONTENT_TYPE) else {
        return Ok(UploadKind::Raw);
    };
    let ct = raw
        .to_str()
        .map_err(|_| ApiError::unsupported_media_type("invalid Content-Type header"))?;
    let mime = ct.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    match mime.as_str() {
        "" | "application/octet-stream" => Ok(UploadKind::Raw),
        "application/x-tar" => Ok(UploadKind::Tar),
        "application/gzip" | "application/x-gzip" => Ok(UploadKind::TarGz),
        other => Err(ApiError::unsupported_media_type(format!(
            "unsupported upload Content-Type '{other}'; expected application/octet-stream, application/x-tar, or application/gzip"
        ))),
    }
}

async fn upload_files(
    State(state): State<AppState>,
    Path(id): Path<String>,
    query: Result<Query<UploadQuery>, QueryRejection>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let Query(query) = query?;
    if query.path.trim().is_empty() {
        return Err(ApiError::bad_request("query parameter 'path' must not be empty"));
    }
    let kind = parse_upload_kind(&headers)?;
    let res = state
        .manager
        .upload_files(&id, &query.path, kind, &body)
        .await?;
    Ok((StatusCode::OK, Json(res)).into_response())
}

#[derive(Debug, Deserialize)]
struct DownloadQuery {
    path: String,
    #[serde(default)]
    format: Option<String>,
}

fn parse_download_format(raw: Option<&str>) -> Result<DownloadFormat, ApiError> {
    match raw.map(|s| s.trim().to_ascii_lowercase()).as_deref() {
        None | Some("raw") => Ok(DownloadFormat::Raw),
        Some("tar.gz") => Ok(DownloadFormat::TarGz),
        Some(other) => Err(ApiError::bad_request(format!(
            "unsupported download format '{other}'; expected 'raw' or 'tar.gz'"
        ))),
    }
}

async fn download_files(
    State(state): State<AppState>,
    Path(id): Path<String>,
    query: Result<Query<DownloadQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    let Query(query) = query?;
    if query.path.trim().is_empty() {
        return Err(ApiError::bad_request("query parameter 'path' must not be empty"));
    }
    let format = parse_download_format(query.format.as_deref())?;
    let (data, meta) = state
        .manager
        .download_files_with_meta(&id, &query.path, format)
        .await?;

    let content_type = match format {
        DownloadFormat::Raw => HeaderValue::from_static("application/octet-stream"),
        DownloadFormat::TarGz => HeaderValue::from_static("application/gzip"),
    };

    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, content_type)
        .header(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if let Ok(v) = HeaderValue::from_str(&meta.sandbox_id) {
        builder = builder.header("x-blackwall-sandbox-id", v);
    }
    if let Ok(v) = HeaderValue::from_str(&meta.bytes.to_string()) {
        builder = builder.header("x-blackwall-bytes", v);
    }
    if let Ok(v) = HeaderValue::from_str(&meta.files.to_string()) {
        builder = builder.header("x-blackwall-files", v);
    }
    if let Ok(v) = HeaderValue::from_str(&meta.dirs.to_string()) {
        builder = builder.header("x-blackwall-dirs", v);
    }
    if let Ok(v) = HeaderValue::from_str(&meta.duration_ms.to_string()) {
        builder = builder.header("x-blackwall-duration-ms", v);
    }
    if let Ok(v) = HeaderValue::from_str(&meta.sha256) {
        builder = builder.header("x-blackwall-sha256", v);
    }

    let response = builder
        .body(Body::from(data))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
    Ok(response)
}

// ---------------------------------------------------------------------------
// 2.5 Profiles & Images
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct CreateProfileRequest {
    pub name: String,
    #[serde(default)]
    pub toml: Option<String>,
    #[serde(default)]
    pub draft: Option<ProfileDraft>,
}

#[derive(Debug, Deserialize)]
pub struct BuildImageRequest {
    #[serde(default)]
    pub oci_ref: Option<String>,
    #[serde(default)]
    pub profile: Option<String>,
}

async fn list_profiles(State(state): State<AppState>) -> Response {
    let profiles = state.manager.list_profiles();
    (StatusCode::OK, Json(profiles)).into_response()
}

async fn create_profile(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerContext>,
    payload: Result<Json<CreateProfileRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    caller.require(Capability::MutateProfiles)?;
    let Json(req) = payload?;
    // Never log `req` because invalid requests may attempt to submit plaintext secrets.
    let spec = state
        .manager
        .create_profile(&req.name, req.toml.as_deref(), req.draft)
        .map_err(|err| match err {
            CoreError::Policy(PolicyError::LockedPolicyViolation(msg)) => ApiError::new(
                StatusCode::FORBIDDEN,
                "locked_policy_violation",
                msg,
            ),
            CoreError::Policy(policy_err) => ApiError::bad_request(policy_err.to_string()),
            other => ApiError::from(other),
        })?;
    Ok((StatusCode::CREATED, Json(spec)).into_response())
}

async fn get_profile(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Response, ApiError> {
    let spec = state.manager.get_profile(&name)?;
    Ok((StatusCode::OK, Json(spec)).into_response())
}

async fn delete_profile(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerContext>,
    Path(name): Path<String>,
) -> Result<StatusCode, ApiError> {
    caller.require(Capability::MutateProfiles)?;
    state.manager.delete_profile(&name)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_images(State(state): State<AppState>) -> Result<Response, ApiError> {
    let images = state.manager.list_images()?;
    Ok((StatusCode::OK, Json(images)).into_response())
}

async fn build_image(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerContext>,
    payload: Result<Json<BuildImageRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    caller.require(Capability::BuildImages)?;
    state.manager.check_image_build_allowed()?;
    let Json(req) = payload?;
    let oci_ref = req
        .oci_ref
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned);
    let profile = req
        .profile
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned);

    let image_spec = match (oci_ref, profile) {
        (Some(_), Some(_)) => {
            return Err(ApiError::bad_request(
                "specify either 'oci_ref' or 'profile', not both",
            ));
        }
        (None, None) => {
            return Err(ApiError::bad_request(
                "must specify either 'oci_ref' or 'profile'",
            ));
        }
        (Some(reference), None) => ImageSpec {
            image_ref: Some(reference),
            base: None,
            packages: Vec::new(),
            run: Vec::new(),
        },
        (None, Some(profile_name)) => {
            let resolved = state.manager.get_profile(&profile_name)?;
            resolved.image
        }
    };

    let manager = Arc::clone(&state.manager);
    let built = tokio::task::spawn_blocking(move || manager.build_image(&image_spec))
        .await
        .map_err(|e| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("image build task panicked: {e}"),
            )
        })??;

    Ok((StatusCode::OK, Json(built)).into_response())
}

async fn delete_image(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerContext>,
    Path(content_hash): Path<String>,
) -> Result<StatusCode, ApiError> {
    caller.require(Capability::DeleteImages)?;
    state.manager.delete_image(&content_hash)?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// 2.6 Audit Event Query & Live Streaming
// ---------------------------------------------------------------------------

const DEFAULT_AUDIT_LIMIT: usize = 200;
const MAX_AUDIT_LIMIT: usize = 2000;

#[derive(Debug, Default, Deserialize)]
struct AuditQuery {
    #[serde(default)]
    sandbox_id: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    follow: bool,
}

#[derive(Debug, Default, Deserialize)]
struct SandboxAuditQuery {
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    follow: bool,
}

async fn get_audit_events(
    State(state): State<AppState>,
    query: Result<Query<AuditQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    let Query(query) = query?;
    let sandbox_id = query.sandbox_id.filter(|s| !s.trim().is_empty());
    Ok(audit_events_response(
        &state.manager,
        sandbox_id,
        query.limit,
        query.follow,
    ))
}

async fn get_sandbox_audit_events(
    State(state): State<AppState>,
    Path(id): Path<String>,
    query: Result<Query<SandboxAuditQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    let Query(query) = query?;
    Ok(audit_events_response(
        &state.manager,
        Some(id),
        query.limit,
        query.follow,
    ))
}

fn encode_audit_ndjson(ev: &AuditEvent) -> Result<Bytes, Infallible> {
    let mut line = serde_json::to_vec(ev).unwrap_or_else(|_| b"{}".to_vec());
    line.push(b'\n');
    Ok(Bytes::from(line))
}

fn audit_events_response(
    manager: &SandboxManager,
    sandbox_id: Option<String>,
    limit: Option<usize>,
    follow: bool,
) -> Response {
    let limit = limit.unwrap_or(DEFAULT_AUDIT_LIMIT).min(MAX_AUDIT_LIMIT);

    if !follow {
        let events = manager.recent_audit_events(sandbox_id.as_deref(), limit);
        return (StatusCode::OK, Json(events)).into_response();
    }

    let (recent, rx) = manager.recent_and_subscribe_audit(sandbox_id.as_deref(), limit);
    let initial_chunks: Vec<Result<Bytes, Infallible>> =
        recent.iter().map(encode_audit_ndjson).collect();
    let initial_stream = stream::iter(initial_chunks);

    let live_stream = stream::unfold((rx, sandbox_id), |(mut rx, filter_id)| async move {
        loop {
            match rx.recv().await {
                Ok(ev) => {
                    if let Some(ref target_id) = filter_id {
                        if ev.sandbox_id != *target_id {
                            continue;
                        }
                    }
                    return Some((encode_audit_ndjson(&ev), (rx, filter_id)));
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
            }
        }
    });

    let body = Body::from_stream(initial_stream.chain(live_stream));
    Response::builder()
        .status(StatusCode::OK)
        .header(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-ndjson"),
        )
        .header(CACHE_CONTROL, HeaderValue::from_static("no-store"))
        .body(body)
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_preview_subdomain_hosts_and_rejects_non_preview_hosts() {
        assert_eq!(
            parse_preview_subdomain_host("3000-bw-fed6f0f2a47c.localhost:7701"),
            Some((
                "bw-fed6f0f2a47c".into(),
                3000,
                "3000-bw-fed6f0f2a47c.localhost".into()
            ))
        );
        assert_eq!(
            parse_preview_subdomain_host("app.api.5173-bw-abc123.localhost:7701"),
            Some((
                "bw-abc123".into(),
                5173,
                "5173-bw-abc123.localhost".into()
            ))
        );
        assert_eq!(parse_preview_subdomain_host("127.0.0.1:7701"), None);
        assert_eq!(parse_preview_subdomain_host("localhost:7701"), None);
        assert_eq!(parse_preview_subdomain_host("0-bw-abc123.localhost:7701"), None);
        assert_eq!(parse_preview_subdomain_host("3000-bw-abc123.evil.com:7701"), None);
    }

    #[test]
    fn sanitizes_set_cookie_for_subdomain_and_path_prefix_scopes() {
        let sub_scope = SetCookieScope::Subdomain {
            allowed_domain: "3000-bw-aaa.localhost",
        };
        // Strips broader Domain=localhost and Domain=127.0.0.1 (making cookie host-only)
        assert_eq!(
            sanitize_set_cookie_header("sid=1; Domain=localhost; Path=/; HttpOnly", &sub_scope)
                .as_deref(),
            Some("sid=1; Path=/; HttpOnly")
        );
        assert_eq!(
            sanitize_set_cookie_header("sid=1; Domain=.localhost; Path=/", &sub_scope).as_deref(),
            Some("sid=1; Path=/")
        );
        assert_eq!(
            sanitize_set_cookie_header("sid=1; Domain=127.0.0.1; Path=/", &sub_scope).as_deref(),
            Some("sid=1; Path=/")
        );
        assert_eq!(
            sanitize_set_cookie_header("sid=1; Domain=3000-bw-bbb.localhost; Path=/", &sub_scope)
                .as_deref(),
            Some("sid=1; Path=/")
        );
        // Preserves Domain= matching or nested under this exact sandbox preview subdomain
        assert_eq!(
            sanitize_set_cookie_header("sid=1; Domain=3000-bw-aaa.localhost; Path=/", &sub_scope)
                .as_deref(),
            Some("sid=1; Domain=3000-bw-aaa.localhost; Path=/")
        );
        assert_eq!(
            sanitize_set_cookie_header(
                "sid=1; Domain=app.3000-bw-aaa.localhost; Path=/",
                &sub_scope
            )
            .as_deref(),
            Some("sid=1; Domain=app.3000-bw-aaa.localhost; Path=/")
        );

        // PathPrefix fallback strips Domain= and forces Path=/v1/sandboxes/{id}/proxy/{port}/
        let path_scope = SetCookieScope::PathPrefix {
            forced_path: "/v1/sandboxes/bw-aaa/proxy/3000/",
        };
        assert_eq!(
            sanitize_set_cookie_header("sid=1; Domain=127.0.0.1; Path=/; HttpOnly", &path_scope)
                .as_deref(),
            Some("sid=1; Path=/v1/sandboxes/bw-aaa/proxy/3000/; HttpOnly")
        );
        assert_eq!(
            sanitize_set_cookie_header("sid=1; HttpOnly", &path_scope).as_deref(),
            Some("sid=1; HttpOnly; Path=/v1/sandboxes/bw-aaa/proxy/3000/")
        );
    }
}
