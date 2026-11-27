//! In-process mock [`VmmBackend`] backed by real `blackwall-init` Port 1002
//! sessions over Unix `socketpair`s.
//!
//! Enables both `blackwall-core` and `blackwall-daemon` to execute full multi-turn
//! end-to-end sandbox tests (create -> upload -> sync/streaming exec -> background
//! processes + logs + signal -> PTY -> download through `blackwall-unpacker` ->
//! idle/wall timeout reaping -> destroy) without requiring KVM or `cloud-hypervisor`.

use blackwall_init::session::{serve_session, SessionOptions};
use blackwall_proto::{write_audit_frame, GuestAuditFrame};
use blackwall_vmm::{
    Result as VmmResult, VmExitStatus, VmInstance, VmLaunchConfig, VmmBackend, VmmError,
    VsockChannels,
};
use std::collections::HashMap;
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use tempfile::TempDir;

/// Custom Port 1002 server hook for fault-injection tests (e.g., simulating a
/// compromised guest sending malicious `.tar.gz` bytes over Port 1002).
pub type CustomCtrlResponder =
    Arc<dyn Fn(String, UnixStream, PathBuf) + Send + Sync>;

/// In-process [`VmmBackend`] that spawns `blackwall_init::session::serve_session`
/// over real Unix `socketpair`s (plus a real half-closed Port 1001 audit pipe and
/// optional Port 1000 `net_mux` pair).
#[derive(Clone)]
pub struct MockSessionVmmBackend {
    next_pid: Arc<AtomicU32>,
    custom_ctrl: Option<CustomCtrlResponder>,
    guest_net_streams: Arc<Mutex<HashMap<String, UnixStream>>>,
    guest_audit_streams: Arc<Mutex<HashMap<String, UnixStream>>>,
}

impl Default for MockSessionVmmBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl MockSessionVmmBackend {
    /// Create a mock VMM backend running real `blackwall_init::session::serve_session`.
    pub fn new() -> Self {
        Self {
            next_pid: Arc::new(AtomicU32::new(40_000)),
            custom_ctrl: None,
            guest_net_streams: Arc::new(Mutex::new(HashMap::new())),
            guest_audit_streams: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Create a mock VMM backend with a custom Port 1002 server closure for fault injection.
    pub fn with_custom_ctrl_responder(responder: CustomCtrlResponder) -> Self {
        Self {
            custom_ctrl: Some(responder),
            ..Self::new()
        }
    }

    /// Take the guest side of Port 1000 (`NET_MUX`) for an egress sandbox (for proxy E2E tests).
    pub fn take_guest_net_stream(&self, sandbox_id: &str) -> Option<UnixStream> {
        self.guest_net_streams
            .lock()
            .ok()
            .and_then(|mut g| g.remove(sandbox_id))
    }

    /// Emit a synthetic guest [`GuestAuditFrame`] on Port 1001 for `sandbox_id`.
    pub fn emit_guest_audit_frame(&self, sandbox_id: &str, frame: &GuestAuditFrame) -> bool {
        let Ok(mut guard) = self.guest_audit_streams.lock() else {
            return false;
        };
        let Some(stream) = guard.get_mut(sandbox_id) else {
            return false;
        };
        write_audit_frame(stream, frame).is_ok()
    }
}

struct MockVmInstance {
    sandbox_id: String,
    pid: u32,
    alive: Arc<AtomicBool>,
    channels: Mutex<Option<VsockChannels>>,
    guest_ctrl_shutdown: Mutex<Option<UnixStream>>,
    guest_audit_streams: Arc<Mutex<HashMap<String, UnixStream>>>,
    guest_net_streams: Arc<Mutex<HashMap<String, UnixStream>>>,
    session_thread: Mutex<Option<thread::JoinHandle<()>>>,
    _workspace_dir: TempDir,
}

impl VmInstance for MockVmInstance {
    fn id(&self) -> &str {
        &self.sandbox_id
    }

    fn pid(&self) -> u32 {
        self.pid
    }

    fn take_channels(&self) -> VmmResult<VsockChannels> {
        let mut guard = self
            .channels
            .lock()
            .map_err(|_| VmmError::ProcessError("channels lock poisoned".into()))?;
        guard.take().ok_or(VmmError::ChannelsAlreadyTaken)
    }

    fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Acquire)
    }

    fn kill(&self) -> VmmResult<()> {
        self.alive.store(false, Ordering::Release);
        if let Ok(mut guard) = self.guest_ctrl_shutdown.lock() {
            if let Some(s) = guard.take() {
                let _ = s.shutdown(Shutdown::Both);
            }
        }
        if let Ok(mut guard) = self.guest_audit_streams.lock() {
            guard.remove(&self.sandbox_id);
        }
        if let Ok(mut guard) = self.guest_net_streams.lock() {
            guard.remove(&self.sandbox_id);
        }
        if let Ok(mut guard) = self.session_thread.lock() {
            if let Some(handle) = guard.take() {
                let _ = handle.join();
            }
        }
        Ok(())
    }

    fn wait(&self) -> VmmResult<VmExitStatus> {
        if let Ok(mut guard) = self.session_thread.lock() {
            if let Some(handle) = guard.take() {
                let _ = handle.join();
            }
        }
        self.alive.store(false, Ordering::Release);
        Ok(VmExitStatus {
            code: Some(0),
            signal: None,
            fatal: false,
            detail: None,
        })
    }
}

impl Drop for MockVmInstance {
    fn drop(&mut self) {
        let _ = self.kill();
    }
}

impl VmmBackend for MockSessionVmmBackend {
    fn name(&self) -> &'static str {
        "mock-in-process-session"
    }

    fn launch(&self, config: VmLaunchConfig) -> VmmResult<Box<dyn VmInstance>> {
        let workspace_dir = TempDir::new()?;
        let ws_path = workspace_dir.path().to_path_buf();

        // Port 1002: CTRL_SESSION
        let (ctrl_host, ctrl_guest) = UnixStream::pair()?;
        let ctrl_guest_shutdown = ctrl_guest.try_clone()?;

        // Port 1001: AUDIT_UNI (enforce SHUT_WR on host side matching real handshake)
        let (audit_host, mut audit_guest) = UnixStream::pair()?;
        audit_host.shutdown(Shutdown::Write)?;

        // Send a realistic guest boot telemetry frame on Port 1001 immediately.
        let _ = write_audit_frame(
            &mut audit_guest,
            &GuestAuditFrame {
                timestamp_ns: 1,
                source: "blackwall-init".into(),
                kind: "mock_guest_boot".into(),
                payload: serde_json::json!({
                    "sandbox_id": config.sandbox_id,
                    "workspace": "/workspace",
                }),
            },
        );
        if let Ok(mut guard) = self.guest_audit_streams.lock() {
            guard.insert(config.sandbox_id.clone(), audit_guest);
        }

        // Port 1000: optional NET_MUX
        let net_mux = if config.enable_net_mux {
            let (net_host, net_guest) = UnixStream::pair()?;
            if let Ok(mut guard) = self.guest_net_streams.lock() {
                guard.insert(config.sandbox_id.clone(), net_guest);
            }
            Some(net_host)
        } else {
            None
        };

        let alive = Arc::new(AtomicBool::new(true));
        let alive_thread = Arc::clone(&alive);
        let sandbox_id = config.sandbox_id.clone();
        let custom_ctrl = self.custom_ctrl.clone();

        let session_thread = thread::Builder::new()
            .name(format!("bw-mock-init-{sandbox_id}"))
            .spawn(move || {
                if let Some(custom) = custom_ctrl {
                    custom(sandbox_id, ctrl_guest, ws_path);
                } else if let Ok(rx) = ctrl_guest.try_clone() {
                    let _ = serve_session(rx, ctrl_guest, SessionOptions::for_testing(ws_path));
                }
                alive_thread.store(false, Ordering::Release);
            })?;

        let pid = self.next_pid.fetch_add(1, Ordering::Relaxed);
        Ok(Box::new(MockVmInstance {
            sandbox_id: config.sandbox_id,
            pid,
            alive,
            channels: Mutex::new(Some(VsockChannels {
                net_mux,
                audit_uni: audit_host,
                ctrl_session: ctrl_host,
            })),
            guest_ctrl_shutdown: Mutex::new(Some(ctrl_guest_shutdown)),
            guest_audit_streams: Arc::clone(&self.guest_audit_streams),
            guest_net_streams: Arc::clone(&self.guest_net_streams),
            session_thread: Mutex::new(Some(session_thread)),
            _workspace_dir: workspace_dir,
        }))
    }
}
