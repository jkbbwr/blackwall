//! `blackwall-daemon` — Rootless `0600` Unix Domain Socket HTTP/1.1 + JSON + NDJSON + WebSocket server.
//!
//! Exposes the full interactive sandbox API specified in `docs/API.md` on top of
//! [`blackwall_core::SandboxManager`]. Designed as both a library (for clean in-process
//! integration testing) and a standalone rootless daemon binary.

pub mod auth;
pub mod error;
pub mod http_security;
pub mod routes;
pub mod socket;
pub mod static_ui;

pub use auth::{attach_default_operator_context, CallerContext, Capability, PrincipalRole};
pub use error::{ApiError, ApiErrorBody, DaemonError};
pub use http_security::{
    ct_eq, generate_http_token, AuthState, AuthStatusResponse, HttpSecurityConfig,
    SESSION_COOKIE_NAME, TOKEN_FILE_NAME,
};
pub use routes::{
    build_http_control_plane_router, build_preview_router, build_router, build_router_with_ui,
    AttachBridgeRequest, BuildImageRequest, CreateProfileRequest, MAX_UPLOAD_BODY_BYTES,
};
pub use socket::{bind_unix_socket, cleanup_socket, default_socket_path};
pub use static_ui::StaticUiDir;

use blackwall_core::SandboxManager;
use http_security::{cleanup_token_file, validate_http_token, write_token_file};
use std::future::Future;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::net::{TcpListener, UnixListener};
use tokio::sync::watch;

/// Optional loopback HTTP control-plane + isolated preview listener + static UI hosting configuration.
#[derive(Debug, Clone)]
pub struct HttpOptions {
    pub listen_addr: SocketAddr,
    /// Optional isolated preview HTTP listen address. When `None`, defaults to the same IP
    /// as `listen_addr` with `port + 1` (e.g. `127.0.0.1:7700` -> `127.0.0.1:7701`).
    pub preview_listen: Option<SocketAddr>,
    pub allow_non_loopback: bool,
    pub ui_dir: Option<PathBuf>,
    /// Optional HTTP control-plane authentication token. When `None`, a cryptographically
    /// random 32-byte (64-hex-char) token is generated on startup.
    pub http_token: Option<String>,
}

struct BoundHttpListeners {
    http_listener: TcpListener,
    http_addr: SocketAddr,
    preview_listener: TcpListener,
    preview_addr: SocketAddr,
    preview_origin: String,
    token: String,
    token_path: PathBuf,
    ui_dir: Option<Arc<StaticUiDir>>,
}

/// A bound, `0600`-hardened daemon Unix socket listener paired with its [`SandboxManager`]
/// and an optional loopback HTTP control plane + isolated preview origin listener.
///
/// Separating [`BoundDaemon::bind`] from [`BoundDaemon::serve`] guarantees the socket
/// exists and has `0600` permissions before clients connect.
pub struct BoundDaemon {
    listener: UnixListener,
    socket_path: PathBuf,
    manager: Arc<SandboxManager>,
    http: Option<BoundHttpListeners>,
}

fn bind_tcp_listener(
    addr: SocketAddr,
    map_err: impl Fn(SocketAddr, std::io::Error) -> DaemonError,
) -> Result<(TcpListener, SocketAddr), DaemonError> {
    let std_listener = std::net::TcpListener::bind(addr).map_err(|e| map_err(addr, e))?;
    std_listener
        .set_nonblocking(true)
        .map_err(|e| map_err(addr, e))?;
    let local_addr = std_listener.local_addr().map_err(|e| map_err(addr, e))?;
    let tcp_listener = TcpListener::from_std(std_listener).map_err(|e| map_err(addr, e))?;
    Ok((tcp_listener, local_addr))
}

impl BoundDaemon {
    /// Bind a rootless `0600` Unix domain socket at `socket_path`.
    pub fn bind(
        manager: Arc<SandboxManager>,
        socket_path: impl Into<PathBuf>,
    ) -> Result<Self, DaemonError> {
        let socket_path = socket_path.into();
        let listener = bind_unix_socket(&socket_path)?;
        manager.add_forbidden_bridge_unix_path(&socket_path);
        Ok(Self {
            listener,
            socket_path,
            manager,
            http: None,
        })
    }

    /// Attach an optional HTTP control-plane listener + isolated preview origin listener
    /// (both loopback-only unless `allow_non_loopback` is true) and optional static UI directory.
    pub fn with_http(mut self, opts: HttpOptions) -> Result<Self, DaemonError> {
        if !opts.listen_addr.ip().is_loopback() && !opts.allow_non_loopback {
            return Err(DaemonError::NonLoopbackHttpDisallowed(opts.listen_addr));
        }
        if let Some(preview_addr) = opts.preview_listen {
            if !preview_addr.ip().is_loopback() && !opts.allow_non_loopback {
                return Err(DaemonError::NonLoopbackPreviewDisallowed(preview_addr));
            }
        }

        let token = match opts.http_token {
            Some(tok) => {
                validate_http_token(&tok)?;
                tok
            }
            None => generate_http_token(),
        };

        let ui_dir = match opts.ui_dir {
            Some(dir) => Some(Arc::new(StaticUiDir::new(&dir)?)),
            None => None,
        };

        let (http_listener, http_addr) =
            bind_tcp_listener(opts.listen_addr, |addr, source| DaemonError::HttpBind {
                addr,
                source,
            })?;

        let (preview_listener, preview_addr) = match opts.preview_listen {
            Some(addr) => bind_tcp_listener(addr, |addr, source| DaemonError::PreviewBind {
                addr,
                source,
            })?,
            None => {
                if opts.listen_addr.port() == 0 {
                    // When binding an ephemeral HTTP port (e.g. `127.0.0.1:0` in tests),
                    // prefer `port + 1` and fall back to an ephemeral port on the same IP if busy.
                    let preferred = http_addr
                        .port()
                        .checked_add(1)
                        .map(|p| SocketAddr::new(http_addr.ip(), p));
                    match preferred.and_then(|addr| {
                        bind_tcp_listener(addr, |addr, source| DaemonError::PreviewBind {
                            addr,
                            source,
                        })
                        .ok()
                    }) {
                        Some(bound) => bound,
                        None => bind_tcp_listener(
                            SocketAddr::new(http_addr.ip(), 0),
                            |addr, source| DaemonError::PreviewBind { addr, source },
                        )?,
                    }
                } else {
                    let preview_port = http_addr
                        .port()
                        .checked_add(1)
                        .ok_or(DaemonError::PreviewPortOverflow(http_addr))?;
                    let default_preview_addr = SocketAddr::new(http_addr.ip(), preview_port);
                    bind_tcp_listener(default_preview_addr, |addr, source| {
                        DaemonError::PreviewBind { addr, source }
                    })?
                }
            }
        };

        let preview_origin = format!("http://{preview_addr}");
        let token_path = self
            .socket_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
            .join(TOKEN_FILE_NAME);
        write_token_file(&token_path, &token)?;

        self.manager.add_forbidden_bridge_port(http_addr.port());
        self.manager.add_forbidden_bridge_port(preview_addr.port());

        self.http = Some(BoundHttpListeners {
            http_listener,
            http_addr,
            preview_listener,
            preview_addr,
            preview_origin,
            token,
            token_path,
            ui_dir,
        });
        Ok(self)
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    pub fn http_addr(&self) -> Option<SocketAddr> {
        self.http.as_ref().map(|h| h.http_addr)
    }

    pub fn preview_addr(&self) -> Option<SocketAddr> {
        self.http.as_ref().map(|h| h.preview_addr)
    }

    pub fn preview_origin(&self) -> Option<&str> {
        self.http.as_ref().map(|h| h.preview_origin.as_str())
    }

    pub fn http_token(&self) -> Option<&str> {
        self.http.as_ref().map(|h| h.token.as_str())
    }

    pub fn http_token_path(&self) -> Option<&Path> {
        self.http.as_ref().map(|h| h.token_path.as_path())
    }

    pub fn manager(&self) -> &Arc<SandboxManager> {
        &self.manager
    }

    /// Run the HTTP/1.1 + WebSocket server until `shutdown` resolves, then destroy
    /// all active sandboxes and unlink the Unix socket file (and HTTP token file) cleanly.
    pub async fn serve<F>(self, shutdown: F) -> Result<(), DaemonError>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let uds_app = build_router(Arc::clone(&self.manager));
        tracing::info!(socket = %self.socket_path.display(), "blackwall-daemon listening");

        let token_path_to_cleanup = self.http.as_ref().map(|h| h.token_path.clone());

        let serve_res = if let Some(http_cfg) = self.http {
            let security = HttpSecurityConfig::new(
                http_cfg.http_addr,
                http_cfg.preview_origin.clone(),
                http_cfg.token.clone(),
            );
            let http_app = build_http_control_plane_router(
                Arc::clone(&self.manager),
                http_cfg.ui_dir.clone(),
                security,
            );
            let preview_app = build_preview_router(Arc::clone(&self.manager));

            tracing::info!(
                http_addr = %http_cfg.http_addr,
                preview_origin = %http_cfg.preview_origin,
                token_file = %http_cfg.token_path.display(),
                ui_dir = ?http_cfg.ui_dir.as_ref().map(|u| u.root()),
                "blackwall-daemon HTTP control plane active"
            );
            tracing::info!(
                "Open dashboard: http://{}/?token={}",
                http_cfg.http_addr,
                http_cfg.token
            );

            let (stop_tx, mut stop_rx_uds) = watch::channel(false);
            let mut stop_rx_http = stop_rx_uds.clone();
            let mut stop_rx_preview = stop_rx_uds.clone();

            tokio::spawn(async move {
                shutdown.await;
                let _ = stop_tx.send(true);
            });

            let uds_fut = axum::serve(self.listener, uds_app).with_graceful_shutdown(async move {
                let _ = stop_rx_uds.wait_for(|v| *v).await;
            });
            let http_fut =
                axum::serve(http_cfg.http_listener, http_app).with_graceful_shutdown(async move {
                    let _ = stop_rx_http.wait_for(|v| *v).await;
                });
            let preview_fut = axum::serve(http_cfg.preview_listener, preview_app)
                .with_graceful_shutdown(async move {
                    let _ = stop_rx_preview.wait_for(|v| *v).await;
                });

            let (uds_res, http_res, preview_res) = tokio::join!(uds_fut, http_fut, preview_fut);
            uds_res.and(http_res).and(preview_res)
        } else {
            axum::serve(self.listener, uds_app)
                .with_graceful_shutdown(shutdown)
                .await
        };

        tracing::info!("blackwall-daemon shutting down; destroying all active sandboxes");
        self.manager.destroy_all().await;
        cleanup_socket(&self.socket_path);
        if let Some(token_path) = token_path_to_cleanup {
            cleanup_token_file(&token_path);
        }

        serve_res.map_err(DaemonError::Serve)
    }
}

/// Convenience wrapper binding `socket_path` with `0600` permissions and serving until `shutdown`.
pub async fn serve_unix<F>(
    manager: Arc<SandboxManager>,
    socket_path: impl Into<PathBuf>,
    shutdown: F,
) -> Result<(), DaemonError>
where
    F: Future<Output = ()> + Send + 'static,
{
    let daemon = BoundDaemon::bind(manager, socket_path)?;
    daemon.serve(shutdown).await
}

/// Future resolving upon `SIGINT` (Ctrl-C) or `SIGTERM` for graceful daemon shutdown.
pub async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sigterm) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sigterm.recv().await;
        } else {
            std::future::pending::<()>().await;
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            tracing::info!("received SIGINT");
        }
        _ = terminate => {
            tracing::info!("received SIGTERM");
        }
    }
}
