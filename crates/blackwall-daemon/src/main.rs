//! Rootless `blackwall-daemon` binary entrypoint.

use blackwall_core::{CoreConfig, JsonlAuditSink, NoopAuditSink, PolicyCeiling, SandboxManager};
use blackwall_daemon::{default_socket_path, shutdown_signal, BoundDaemon, HttpOptions};
use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(
    name = "blackwall-daemon",
    version,
    about = "Rootless 0600 Unix domain socket API daemon for Blackwall sandboxes"
)]
struct Cli {
    /// Unix domain socket path (default: $XDG_RUNTIME_DIR/blackwall.sock or /tmp/blackwall-<uid>.sock).
    #[arg(long, env = "BLACKWALL_SOCKET")]
    socket: Option<PathBuf>,

    /// Directory containing *.toml profile definitions.
    #[arg(long, env = "BLACKWALL_PROFILE_DIR")]
    profile_dir: Option<PathBuf>,

    /// Directory storing content-addressed erofs + dm-verity base images.
    #[arg(long, env = "BLACKWALL_IMAGE_CACHE_DIR")]
    image_cache_dir: Option<PathBuf>,

    /// Path to the host X25519 HPKE private key used to open seal1_ secrets.
    #[arg(long, env = "BLACKWALL_HOST_KEY")]
    host_key: Option<PathBuf>,

    /// Path to hardened vmlinux-lo guest kernel.
    #[arg(long, env = "BLACKWALL_KERNEL_LO")]
    kernel_lo: Option<PathBuf>,

    /// Path to hardened vmlinux-noinet guest kernel.
    #[arg(long, env = "BLACKWALL_KERNEL_NOINET")]
    kernel_noinet: Option<PathBuf>,

    /// Path to guest initramfs containing blackwall-init and blackwall-netbridge.
    #[arg(long, env = "BLACKWALL_INITRAMFS")]
    initramfs: Option<PathBuf>,

    /// Runtime scratch directory for per-VM sockets and metadata.
    #[arg(long, env = "BLACKWALL_RUNTIME_DIR")]
    runtime_dir: Option<PathBuf>,

    /// Optional JSONL file path for structured audit events.
    #[arg(long, env = "BLACKWALL_AUDIT_LOG")]
    audit_log: Option<PathBuf>,

    /// Optional loopback HTTP listen address (e.g. 127.0.0.1:7700) serving /v1/* + static UI.
    #[arg(long, env = "BLACKWALL_HTTP_LISTEN")]
    http_listen: Option<SocketAddr>,

    /// Optional isolated loopback preview HTTP listen address serving ONLY /v1/sandboxes/{id}/proxy/{port}*
    /// (defaults to --http-listen IP with port + 1, e.g. 127.0.0.1:7701).
    #[arg(long, env = "BLACKWALL_PREVIEW_LISTEN")]
    preview_listen: Option<SocketAddr>,

    /// Optional HTTP control-plane authentication token (random 32-byte hex token generated on startup if omitted).
    #[arg(long, env = "BLACKWALL_HTTP_TOKEN")]
    http_token: Option<String>,

    /// Explicitly allow binding --http-listen (and --preview-listen) to a non-loopback address.
    #[arg(long, env = "BLACKWALL_ALLOW_NON_LOOPBACK_HTTP", default_value_t = false)]
    allow_non_loopback_http: bool,

    /// Optional static UI dist directory served when --http-listen is active (defaults to ./ui/dist if present).
    #[arg(long, env = "BLACKWALL_UI_DIR")]
    ui_dir: Option<PathBuf>,

    /// Disable profile creation and deletion via the daemon API.
    #[arg(long, env = "BLACKWALL_READONLY_PROFILES", default_value_t = false)]
    readonly_profiles: bool,

    /// Require every sandbox creation request to extend a registered policy.locked = true profile.
    #[arg(long, env = "BLACKWALL_REQUIRE_LOCKED_PROFILES", default_value_t = false)]
    require_locked_profiles: bool,

    /// Path to a TOML PolicyCeiling file enforcing operator hard upper bounds on all sandboxes,
    /// profiles, host bridges, and image builds.
    #[arg(long, env = "BLACKWALL_POLICY_CEILING")]
    policy_ceiling: Option<PathBuf>,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("blackwall_daemon=info,blackwall_core=info")),
        )
        .init();

    let cli = Cli::parse();
    let socket_path = cli.socket.unwrap_or_else(default_socket_path);

    let mut cfg = CoreConfig::default();
    if let Some(dir) = cli.profile_dir {
        cfg.profile_dir = dir;
    }
    if let Some(dir) = cli.image_cache_dir {
        cfg.image_cache_dir = dir;
    }
    if let Some(key) = cli.host_key {
        cfg.host_key_path = key;
    }
    if let Some(k) = cli.kernel_lo {
        cfg.kernel_lo_path = k;
    }
    if let Some(k) = cli.kernel_noinet {
        cfg.kernel_noinet_path = k;
    }
    if let Some(initramfs) = cli.initramfs {
        cfg.initramfs_path = initramfs;
    }
    if let Some(run_dir) = cli.runtime_dir {
        cfg.runtime_dir = run_dir;
    }
    cfg.readonly_profiles = cli.readonly_profiles;
    cfg.require_locked_profiles = cli.require_locked_profiles;
    if let Some(ceiling_path) = cli.policy_ceiling {
        match PolicyCeiling::from_file(&ceiling_path) {
            Ok(ceiling) => {
                tracing::info!(
                    policy_ceiling = %ceiling_path.display(),
                    "loaded operator policy ceiling"
                );
                cfg.policy_ceiling = Some(ceiling);
            }
            Err(err) => {
                eprintln!(
                    "blackwall-daemon: failed to load policy ceiling '{}': {err}",
                    ceiling_path.display()
                );
                std::process::exit(1);
            }
        }
    }
    if cfg.readonly_profiles || cfg.require_locked_profiles || cfg.policy_ceiling.is_some() {
        tracing::info!(
            readonly_profiles = cfg.readonly_profiles,
            require_locked_profiles = cfg.require_locked_profiles,
            has_policy_ceiling = cfg.policy_ceiling.is_some(),
            "operator lockdown controls active"
        );
    }
    if let Some(audit_path) = cli.audit_log {
        match JsonlAuditSink::open_append(&audit_path) {
            Ok(sink) => cfg.audit_sink = Arc::new(sink),
            Err(err) => {
                eprintln!(
                    "blackwall-daemon: failed to open audit log '{}': {err}",
                    audit_path.display()
                );
                std::process::exit(1);
            }
        }
    } else {
        cfg.audit_sink = Arc::new(NoopAuditSink);
    }

    // Self-protection: prevent sandboxes from bridging back into blackwall-daemon's own
    // control UDS socket or HTTP control/preview ports.
    cfg.forbidden_bridge_unix_paths.push(socket_path.clone());
    if let Some(listen_addr) = cli.http_listen {
        if listen_addr.port() != 0 {
            cfg.forbidden_bridge_ports.push(listen_addr.port());
        }
        if let Some(preview_addr) = cli.preview_listen {
            if preview_addr.port() != 0 {
                cfg.forbidden_bridge_ports.push(preview_addr.port());
            }
        } else if let Some(preview_port) = listen_addr.port().checked_add(1) {
            if listen_addr.port() != 0 {
                cfg.forbidden_bridge_ports.push(preview_port);
            }
        }
    }

    let manager = match SandboxManager::new(cfg) {
        Ok(m) => Arc::new(m),
        Err(err) => {
            eprintln!("blackwall-daemon: failed to initialize SandboxManager: {err}");
            std::process::exit(1);
        }
    };

    let mut daemon = match BoundDaemon::bind(manager, socket_path) {
        Ok(d) => d,
        Err(err) => {
            eprintln!("blackwall-daemon: {err}");
            std::process::exit(1);
        }
    };

    if let Some(listen_addr) = cli.http_listen {
        let ui_dir = cli.ui_dir.or_else(|| {
            let default_dir = PathBuf::from("./ui/dist");
            default_dir.is_dir().then_some(default_dir)
        });
        daemon = match daemon.with_http(HttpOptions {
            listen_addr,
            preview_listen: cli.preview_listen,
            allow_non_loopback: cli.allow_non_loopback_http,
            ui_dir,
            http_token: cli.http_token,
        }) {
            Ok(d) => d,
            Err(err) => {
                eprintln!("blackwall-daemon: {err}");
                std::process::exit(1);
            }
        };
    } else if cli.preview_listen.is_some() {
        eprintln!("blackwall-daemon: --preview-listen requires --http-listen");
        std::process::exit(1);
    }

    if let Err(err) = daemon.serve(shutdown_signal()).await {
        eprintln!("blackwall-daemon: server error: {err}");
        std::process::exit(1);
    }
}
