//! Rootless `0600` Unix domain socket creation, permission hardening, and cleanup.

use crate::error::DaemonError;
use std::fs::{self, DirBuilder, Permissions};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tokio::net::UnixListener;

/// Serializes process-global `umask(2)` mutations across concurrent socket binds
/// (important when multiple in-process test daemons start concurrently).
static UMASK_LOCK: Mutex<()> = Mutex::new(());

/// RAII guard that restores the previous process `umask` when dropped.
struct UmaskGuard(libc::mode_t);

impl UmaskGuard {
    fn set(new_mask: libc::mode_t) -> Self {
        // SAFETY: `libc::umask` is always safe to call; serialized by `UMASK_LOCK`.
        let prev = unsafe { libc::umask(new_mask) };
        Self(prev)
    }
}

impl Drop for UmaskGuard {
    fn drop(&mut self) {
        // SAFETY: Restores the previous process umask while `UMASK_LOCK` is held.
        unsafe {
            libc::umask(self.0);
        }
    }
}

/// Resolve the default rootless daemon Unix socket path:
/// 1. `$BLACKWALL_SOCKET` (if set and non-empty)
/// 2. `$XDG_RUNTIME_DIR/blackwall.sock` (if set and non-empty)
/// 3. `/tmp/blackwall-<uid>.sock`
pub fn default_socket_path() -> PathBuf {
    if let Some(env_sock) = std::env::var_os("BLACKWALL_SOCKET") {
        if !env_sock.is_empty() {
            return PathBuf::from(env_sock);
        }
    }
    if let Some(runtime_dir) = std::env::var_os("XDG_RUNTIME_DIR") {
        if !runtime_dir.is_empty() {
            return PathBuf::from(runtime_dir).join("blackwall.sock");
        }
    }
    // SAFETY: `geteuid` has no preconditions and cannot fail.
    let uid = unsafe { libc::geteuid() };
    PathBuf::from(format!("/tmp/blackwall-{uid}.sock"))
}

/// Bind a rootless Unix domain socket at `path` with strict `0600` permissions.
///
/// Security invariants:
/// - Missing parent directories are created with mode `0700`.
/// - Existing stale Unix sockets at `path` are unlinked prior to bind; non-socket
///   paths fail closed without deleting arbitrary files.
/// - `umask(0o177)` is held around `bind(2)` so the socket is created atomically as
///   `0600` with zero world-readable/world-writable race window, followed by an
///   explicit `chmod(0o600)`.
pub fn bind_unix_socket(path: &Path) -> Result<UnixListener, DaemonError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)
                .map_err(|source| DaemonError::SocketBind {
                    path: path.to_path_buf(),
                    source,
                })?;
            fs::set_permissions(parent, Permissions::from_mode(0o700)).map_err(|source| {
                DaemonError::SocketPermissions {
                    path: parent.to_path_buf(),
                    source,
                }
            })?;
        }
    }

    match fs::symlink_metadata(path) {
        Ok(meta) => {
            if !meta.file_type().is_socket() {
                return Err(DaemonError::SocketPathNotSocket(path.to_path_buf()));
            }
            fs::remove_file(path).map_err(|source| DaemonError::SocketBind {
                path: path.to_path_buf(),
                source,
            })?;
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(DaemonError::SocketBind {
                path: path.to_path_buf(),
                source,
            });
        }
    }

    let listener = {
        let _lock = UMASK_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _umask = UmaskGuard::set(0o177);
        UnixListener::bind(path).map_err(|source| DaemonError::SocketBind {
            path: path.to_path_buf(),
            source,
        })?
    };

    fs::set_permissions(path, Permissions::from_mode(0o600)).map_err(|source| {
        DaemonError::SocketPermissions {
            path: path.to_path_buf(),
            source,
        }
    })?;

    Ok(listener)
}

/// Remove the daemon Unix socket file on shutdown if it still exists as a socket.
pub fn cleanup_socket(path: &Path) {
    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_socket() {
            let _ = fs::remove_file(path);
        }
    }
}
