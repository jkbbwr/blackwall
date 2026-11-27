//! Unified VMM backend abstraction and host-initiated hybrid `vsock` handshake.
//!
//! Platform-specific VMM drivers (such as `blackwall-vmm-linux` for rootless
//! `cloud-hypervisor` on Linux KVM) implement [`VmmBackend`] and [`VmInstance`].
//!
//! Host-initiated `vsock` bootstrap ([`connect_vsock_port`] and
//! [`perform_host_handshake`]) connects to guest listeners on:
//! - Port `1002` (`CTRL_SESSION`, bidirectional control / exec / PTY / files)
//! - Port `1001` (`AUDIT_UNI`, half-closed `SHUT_WR` for strict guest -> host flow)
//! - Port `1000` (`NET_MUX`, optional bidirectional network multiplexer)
//!
//! Immediately after establishing these channels, the host `unlink()`s the
//! ephemeral `vsock.sock` socket path so no additional host connections can be
//! opened to the jailed VMM.

pub mod handshake;

pub use handshake::{connect_vsock_port, perform_host_handshake, HandshakeConfig};

use blackwall_audit::AuditSink;
use std::fmt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;

/// Errors returned by VMM backends, pre-exec jails, and `vsock` handshakes.
#[derive(Debug, Error)]
pub enum VmmError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("protocol error: {0}")]
    Proto(#[from] blackwall_proto::ProtoError),

    #[error("invalid VM launch configuration: {0}")]
    InvalidConfig(String),

    #[error("host VMM prerequisite missing: {0}")]
    PrereqFailed(String),

    #[error("VMM jail setup failed: {0}")]
    JailFailed(String),

    #[error("VMM launch failed: {0}")]
    LaunchFailed(String),

    #[error("vsock handshake timed out on port {port} after {timeout:?}: {last_error}")]
    HandshakeTimeout {
        port: u32,
        timeout: Duration,
        last_error: String,
    },

    #[error("vsock handshake protocol error on port {port}: {detail}")]
    HandshakeProtocol { port: u32, detail: String },

    #[error("vsock channels have already been taken from this VM instance")]
    ChannelsAlreadyTaken,

    #[error("VMM process error: {0}")]
    ProcessError(String),
}

pub type Result<T> = std::result::Result<T, VmmError>;

/// Platform-agnostic configuration for launching a Blackwall microVM.
#[derive(Clone)]
pub struct VmLaunchConfig {
    pub sandbox_id: String,
    pub kernel_path: PathBuf,
    pub initramfs_path: PathBuf,
    pub vda_erofs_path: PathBuf,
    pub vcpus: u32,
    pub memory_mib: u64,
    pub workspace_mib: u64,
    pub enable_net_mux: bool,
    pub audit_sink: Arc<dyn AuditSink>,
}

impl fmt::Debug for VmLaunchConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VmLaunchConfig")
            .field("sandbox_id", &self.sandbox_id)
            .field("kernel_path", &self.kernel_path)
            .field("initramfs_path", &self.initramfs_path)
            .field("vda_erofs_path", &self.vda_erofs_path)
            .field("vcpus", &self.vcpus)
            .field("memory_mib", &self.memory_mib)
            .field("workspace_mib", &self.workspace_mib)
            .field("enable_net_mux", &self.enable_net_mux)
            .field("audit_sink", &"<dyn AuditSink>")
            .finish()
    }
}

impl VmLaunchConfig {
    /// Validate basic structural invariants before attempting a VM launch.
    pub fn validate(&self) -> Result<()> {
        if self.sandbox_id.trim().is_empty() {
            return Err(VmmError::InvalidConfig(
                "sandbox_id must not be empty".into(),
            ));
        }
        if self.sandbox_id.contains('/') || self.sandbox_id.contains('\0') {
            return Err(VmmError::InvalidConfig(
                "sandbox_id contains illegal path characters".into(),
            ));
        }
        if self.vcpus == 0 {
            return Err(VmmError::InvalidConfig("vcpus must be >= 1".into()));
        }
        if self.memory_mib < 64 {
            return Err(VmmError::InvalidConfig(
                "memory_mib must be >= 64 MiB".into(),
            ));
        }
        if self.workspace_mib == 0 {
            return Err(VmmError::InvalidConfig(
                "workspace_mib must be >= 1 MiB".into(),
            ));
        }
        if self.kernel_path.as_os_str().is_empty() {
            return Err(VmmError::InvalidConfig("kernel_path must not be empty".into()));
        }
        if self.initramfs_path.as_os_str().is_empty() {
            return Err(VmmError::InvalidConfig(
                "initramfs_path must not be empty".into(),
            ));
        }
        if self.vda_erofs_path.as_os_str().is_empty() {
            return Err(VmmError::InvalidConfig(
                "vda_erofs_path must not be empty".into(),
            ));
        }
        Ok(())
    }
}

/// Persistent host-initiated `vsock` channels established during early guest boot.
#[derive(Debug)]
pub struct VsockChannels {
    /// Port `1000` (`NET_MUX`): bidirectional multiplexed network stream handed to `blackwall-proxy`.
    /// `None` when `enable_net_mux == false` (`network.mode = "loopback"` or `"none"`).
    pub net_mux: Option<UnixStream>,
    /// Port `1001` (`AUDIT_UNI`): strictly unidirectional guest -> host audit stream.
    /// Half-closed via `shutdown(Shutdown::Write)` immediately after handshake.
    pub audit_uni: UnixStream,
    /// Port `1002` (`CTRL_SESSION`): bidirectional control, exec, PTY, and file transfer channel.
    pub ctrl_session: UnixStream,
}

/// Exit details observed when a VM process terminates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmExitStatus {
    pub code: Option<i32>,
    pub signal: Option<i32>,
    pub fatal: bool,
    pub detail: Option<String>,
}

impl VmExitStatus {
    /// Returns `true` when the VMM exited cleanly with code `0` and no fatal trap.
    pub fn success(&self) -> bool {
        !self.fatal && self.code == Some(0) && self.signal.is_none()
    }
}

/// Handle to a running microVM instance.
pub trait VmInstance: Send + Sync {
    /// Unique sandbox identifier.
    fn id(&self) -> &str;

    /// Host OS process ID of the VMM process.
    fn pid(&self) -> u32;

    /// Take ownership of the handshaked `vsock` channels (callable once).
    fn take_channels(&self) -> Result<VsockChannels>;

    /// Returns `true` if the VMM process is still running.
    fn is_alive(&self) -> bool;

    /// Forcibly terminate the VMM process and reap its resources.
    fn kill(&self) -> Result<()>;

    /// Block until the VMM process exits and return its exit status.
    fn wait(&self) -> Result<VmExitStatus>;
}

/// Unified backend interface implemented by platform-specific VMM drivers.
pub trait VmmBackend: Send + Sync {
    /// Human-readable backend name (e.g., `"linux-cloud-hypervisor"`).
    fn name(&self) -> &'static str;

    /// Launch a jailed microVM and complete the host-initiated `vsock` handshake.
    fn launch(&self, config: VmLaunchConfig) -> Result<Box<dyn VmInstance>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use blackwall_audit::NoopAuditSink;

    fn sample_config() -> VmLaunchConfig {
        VmLaunchConfig {
            sandbox_id: "sb-test-1".into(),
            kernel_path: PathBuf::from("/boot/vmlinux-lo"),
            initramfs_path: PathBuf::from("/boot/initramfs.cpio.gz"),
            vda_erofs_path: PathBuf::from("/images/debian.erofs"),
            vcpus: 2,
            memory_mib: 512,
            workspace_mib: 256,
            enable_net_mux: false,
            audit_sink: Arc::new(NoopAuditSink),
        }
    }

    #[test]
    fn launch_config_validation() {
        let cfg = sample_config();
        assert!(cfg.validate().is_ok());

        let mut bad = cfg.clone();
        bad.sandbox_id = String::new();
        assert!(matches!(bad.validate(), Err(VmmError::InvalidConfig(_))));

        let mut bad = cfg.clone();
        bad.sandbox_id = "../escape".into();
        assert!(matches!(bad.validate(), Err(VmmError::InvalidConfig(_))));

        let mut bad = cfg.clone();
        bad.vcpus = 0;
        assert!(matches!(bad.validate(), Err(VmmError::InvalidConfig(_))));

        let mut bad = cfg.clone();
        bad.memory_mib = 16;
        assert!(matches!(bad.validate(), Err(VmmError::InvalidConfig(_))));

        let mut bad = cfg;
        bad.workspace_mib = 0;
        assert!(matches!(bad.validate(), Err(VmmError::InvalidConfig(_))));
    }
}
