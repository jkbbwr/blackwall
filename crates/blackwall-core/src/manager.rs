//! Sandbox runtime orchestrator, lifecycle manager, and TTL/idle reaper.

use crate::audit_hub::AuditHub;
use crate::dns::{resolve_allowlisted_hosts_with, DnsResolveOptions, DnsResolver, SystemDnsResolver};
use crate::error::{CoreError, Result};
use crate::proxy_runtime::{ProxyLaunchMode, VmProxyHandle};
use crate::secrets_bridge::VmSecretTableBridge;
use crate::session_client::{
    BackgroundProcess, ExecRequest, ExecResult, ExecStreamEvent, PtyHandle, PtyOpenParams,
    SessionClient, TcpTunnelHandle, UploadResult,
};
use blackwall_audit::{
    drain_port1001_stream, AuditEvent, AuditEventKind, AuditOrigin, AuditSink, NoopAuditSink,
    TransferDirection,
};
use blackwall_oci::{image_content_hash, BuiltImage, ImageBuilder};
use blackwall_policy::{
    validate_host_service, validate_profile_name, ComputeSpec, ExportSpec, HostServiceSpec,
    ImageSpec, IngressSpec, NetworkMode, PolicyCeiling, PolicyError, ProfileDraft, ProfileRegistry,
    SandboxSpec,
};
use blackwall_proto::{
    BootConfig, CtrlErrorCode, DmVerityConfig, DownloadFormat, ProcessInfo, SignalKind, UploadKind,
};
use blackwall_proxy::EphemeralCa;
use blackwall_secrets::{
    current_unix_sec, HostKeyPair, HostPublicKey, SealBinding, VmSecretTable,
};
use blackwall_unpacker::{unpack_raw_to_dir, unpack_to_dir, UnpackSummary};
use blackwall_vmm::{VmInstance, VmLaunchConfig, VmmBackend};
use blackwall_vmm_linux::LinuxVmmBackend;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::io::{Cursor, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::thread;
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, mpsc, watch};
use uuid::Uuid;

/// Configuration for [`SandboxManager`].
#[derive(Clone)]
pub struct CoreConfig {
    pub profile_dir: PathBuf,
    pub image_cache_dir: PathBuf,
    pub host_key_path: PathBuf,
    pub kernel_lo_path: PathBuf,
    pub kernel_noinet_path: PathBuf,
    pub initramfs_path: PathBuf,
    pub runtime_dir: PathBuf,
    pub audit_sink: Arc<dyn AuditSink>,
    /// Polling interval for the background idle/wall-time reaper task.
    pub reaper_interval: Duration,
    /// IP filtering options for out-of-process DNS resolution (strict by default).
    pub dns_options: DnsResolveOptions,
    /// When `true` (used with mock/in-process VMM backends in tests), allows creating
    /// sandboxes even when an OCI `vda.erofs` image is not cached/built on host disk.
    pub allow_unbuilt_images_for_mock: bool,
    /// Controls whether per-VM egress proxies spawn as dedicated jailed `pasta` + `blackwall-proxy`
    /// child processes (`Auto` by default) or run in-process (`InProcess` in mock unit tests).
    pub proxy_launch_mode: ProxyLaunchMode,
    /// Loopback TCP ports that host service bridges are forbidden from targeting
    /// (e.g., `blackwall-daemon`'s own HTTP control-plane and preview ports).
    pub forbidden_bridge_ports: Vec<u16>,
    /// Host Unix domain socket paths that host service bridges are forbidden from targeting
    /// (e.g., `blackwall-daemon`'s own `0600` control socket).
    pub forbidden_bridge_unix_paths: Vec<PathBuf>,
    /// When `true`, disables profile creation and deletion via the API (`--readonly-profiles`).
    pub readonly_profiles: bool,
    /// When `true`, requires every `create_sandbox` request to extend a registered
    /// `policy.locked = true` profile (`--require-locked-profiles`).
    pub require_locked_profiles: bool,
    /// Optional operator-enforced hard policy ceiling applied to all sandboxes, profiles,
    /// bridges, and image builds (`--policy-ceiling <file.toml>`).
    pub policy_ceiling: Option<PolicyCeiling>,
}

/// Validate a [`HostServiceSpec`] against policy syntax rules and daemon self-protection lists.
///
/// Rejects:
/// - Invalid names, ports, or non-loopback / traversal targets (`CoreError::Policy`)
/// - Loopback TCP targets whose port is in `cfg.forbidden_bridge_ports` (`CoreError::PolicyViolation`)
/// - `unix://` targets matching (lexically or after canonicalization) any path in
///   `cfg.forbidden_bridge_unix_paths` (`CoreError::PolicyViolation`)
pub fn validate_bridge_target_against_config(
    svc: &HostServiceSpec,
    cfg: &CoreConfig,
) -> Result<()> {
    validate_bridge_target_against_lists(
        svc,
        &cfg.forbidden_bridge_ports,
        &cfg.forbidden_bridge_unix_paths,
    )
}

fn validate_bridge_target_against_lists(
    svc: &HostServiceSpec,
    forbidden_ports: &[u16],
    forbidden_unix_paths: &[PathBuf],
) -> Result<()> {
    validate_host_service(svc)?;

    if let Some(raw_path) = svc.target.strip_prefix("unix://") {
        let target_path = Path::new(raw_path);
        let target_lex = lexical_normalize_path(target_path);
        let target_canon = canonical_or_normalized_path(target_path);
        for forbidden in forbidden_unix_paths {
            let forb_lex = lexical_normalize_path(forbidden);
            let forb_canon = canonical_or_normalized_path(forbidden);
            if target_lex == forb_lex || target_canon == forb_canon {
                return Err(CoreError::PolicyViolation(format!(
                    "host service bridge '{}' cannot target forbidden daemon Unix socket '{}'",
                    svc.name, svc.target
                )));
            }
        }
        return Ok(());
    }

    if let Ok(addr) = svc.target.parse::<SocketAddr>() {
        if forbidden_ports.contains(&addr.port()) {
            return Err(CoreError::PolicyViolation(format!(
                "host service bridge '{}' cannot target forbidden daemon port {}",
                svc.name,
                addr.port()
            )));
        }
    }

    Ok(())
}

fn lexical_normalize_path(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            std::path::Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn canonical_or_normalized_path(path: &Path) -> PathBuf {
    if let Ok(canon) = fs::canonicalize(path) {
        return canon;
    }
    if let (Some(parent), Some(name)) = (path.parent(), path.file_name()) {
        if let Ok(canon_parent) = fs::canonicalize(parent) {
            return canon_parent.join(name);
        }
    }
    lexical_normalize_path(path)
}

impl Default for CoreConfig {
    fn default() -> Self {
        let config_root = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
            .unwrap_or_else(|| PathBuf::from("/tmp"));
        let cache_root = std::env::var_os("XDG_CACHE_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))
            .unwrap_or_else(|| PathBuf::from("/tmp"));
        let runtime_root = std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);

        let bw_cfg = config_root.join("blackwall");
        let bw_cache = cache_root.join("blackwall");
        let bw_run = runtime_root.join("blackwall");

        Self {
            profile_dir: bw_cfg.join("profiles"),
            image_cache_dir: bw_cache.join("images"),
            host_key_path: bw_cfg.join("host.key"),
            kernel_lo_path: bw_cache.join("kernel/vmlinux-lo"),
            kernel_noinet_path: bw_cache.join("kernel/vmlinux-noinet"),
            initramfs_path: bw_cache.join("kernel/initramfs.cpio.gz"),
            runtime_dir: bw_run,
            audit_sink: Arc::new(NoopAuditSink),
            reaper_interval: Duration::from_secs(1),
            dns_options: DnsResolveOptions::strict(),
            allow_unbuilt_images_for_mock: false,
            proxy_launch_mode: ProxyLaunchMode::Auto,
            forbidden_bridge_ports: Vec::new(),
            forbidden_bridge_unix_paths: Vec::new(),
            readonly_profiles: false,
            require_locked_profiles: false,
            policy_ceiling: None,
        }
    }
}

impl CoreConfig {
    /// Build a self-contained [`CoreConfig`] rooted under `dir` for tests / embedded runs.
    pub fn for_testing(dir: impl AsRef<Path>, audit_sink: Arc<dyn AuditSink>) -> Self {
        let root = dir.as_ref();
        Self {
            profile_dir: root.join("profiles"),
            image_cache_dir: root.join("images"),
            host_key_path: root.join("host.key"),
            kernel_lo_path: root.join("vmlinux-lo"),
            kernel_noinet_path: root.join("vmlinux-noinet"),
            initramfs_path: root.join("initramfs.cpio.gz"),
            runtime_dir: root.join("run"),
            audit_sink,
            reaper_interval: Duration::from_millis(25),
            dns_options: DnsResolveOptions::strict(),
            allow_unbuilt_images_for_mock: true,
            proxy_launch_mode: ProxyLaunchMode::InProcess,
            forbidden_bridge_ports: Vec::new(),
            forbidden_bridge_unix_paths: Vec::new(),
            readonly_profiles: false,
            require_locked_profiles: false,
            policy_ceiling: None,
        }
    }
}

/// Summary of operator-enforced lockdown controls active on a [`SandboxManager`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockdownStatus {
    pub readonly_profiles: bool,
    pub require_locked_profiles: bool,
    pub has_policy_ceiling: bool,
    pub allow_image_build: bool,
}

/// Lifecycle state of a Blackwall sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxState {
    Starting,
    Running,
    Stopping,
    Stopped,
}

/// Live runtime counters tracked across a sandbox session.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxRunStats {
    pub exec_count: u64,
    pub exec_failed_count: u64,
    pub total_exec_duration_ms: u64,
    pub background_spawned_count: u64,
    pub pty_sessions_count: u64,
    #[serde(default)]
    pub ingress_connections_count: u64,
    pub upload_count: u64,
    pub upload_bytes: u64,
    pub download_count: u64,
    pub download_bytes: u64,
    pub last_activity_at: u64,
}

/// Metadata attached to a sanitized file/archive download (`GET /v1/sandboxes/{id}/files`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DownloadMetadata {
    pub sandbox_id: String,
    pub path: String,
    pub format: DownloadFormat,
    pub bytes: u64,
    pub files: u64,
    pub dirs: u64,
    pub sha256: String,
    pub duration_ms: u64,
}

/// Directory entry returned by `GET /v1/sandboxes/{id}/fs`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsEntry {
    pub name: String,
    pub path: String,
    pub kind: String, // "dir" | "file" | "symlink" | "symlink_dir" | "other"
    pub mode: String,
    pub mtime: i64,
    pub size: u64,
    pub is_dir: bool,
}

/// Response returned by `POST /v1/sandboxes/{id}/keepalive`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeepaliveResponse {
    pub id: String,
    pub idle_deadline_at: u64,
    pub idle_remaining_sec: u64,
    pub expires_at: u64,
    pub wall_remaining_sec: u64,
}

/// Listening TCP socket entry returned by `GET /v1/sandboxes/{id}/ports`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListeningPort {
    pub port: u16,
    pub address: String,
    pub allowed: bool,
    pub proxy_url: String,
}

/// Summary metadata returned by `POST /v1/sandboxes` and `GET /v1/sandboxes`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxSummary {
    pub id: String,
    pub profile: String,
    pub state: SandboxState,
    pub image_roothash: String,
    #[serde(default)]
    pub image_content_hash: String,
    #[serde(default)]
    pub kernel_profile: String,
    #[serde(default)]
    pub vmm_backend: String,
    #[serde(default)]
    pub vmm_pid: u32,
    #[serde(default)]
    pub proxy_pid: Option<u32>,
    #[serde(default)]
    pub proxy_isolated: bool,
    #[serde(default)]
    pub boot_duration_ms: u64,
    #[serde(default)]
    pub guest_init_version: String,
    #[serde(default)]
    pub workspace_mounted: bool,
    #[serde(default)]
    pub netbridge_ready: bool,
    #[serde(default)]
    pub compute: ComputeSpec,
    pub network_mode: NetworkMode,
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
    #[serde(default)]
    pub ingress_allow_ports: Vec<u16>,
    #[serde(default)]
    pub host_services: Vec<HostServiceSpec>,
    pub created_at: u64,
    pub expires_at: u64,
    pub idle_deadline_at: u64,
    #[serde(default)]
    pub uptime_sec: u64,
    #[serde(default)]
    pub idle_remaining_sec: u64,
    #[serde(default)]
    pub wall_remaining_sec: u64,
}

/// Full sandbox inspection view returned by `GET /v1/sandboxes/{id}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxDetail {
    pub id: String,
    pub profile: String,
    pub state: SandboxState,
    pub image_roothash: String,
    #[serde(default)]
    pub image_content_hash: String,
    #[serde(default)]
    pub kernel_profile: String,
    #[serde(default)]
    pub vmm_backend: String,
    #[serde(default)]
    pub boot_duration_ms: u64,
    #[serde(default)]
    pub guest_init_version: String,
    #[serde(default)]
    pub workspace_mounted: bool,
    #[serde(default)]
    pub netbridge_ready: bool,
    pub created_at: u64,
    pub expires_at: u64,
    pub idle_deadline_at: u64,
    #[serde(default)]
    pub uptime_sec: u64,
    #[serde(default)]
    pub idle_remaining_sec: u64,
    #[serde(default)]
    pub wall_remaining_sec: u64,
    pub compute: ComputeSpec,
    pub network_mode: NetworkMode,
    pub allowed_hosts: Vec<String>,
    #[serde(default)]
    pub ingress_allow_ports: Vec<u16>,
    #[serde(default)]
    pub ingress: IngressSpec,
    #[serde(default)]
    pub host_services: Vec<HostServiceSpec>,
    #[serde(default)]
    pub pinned_dns: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub configured_secrets: Vec<String>,
    pub export: ExportSpec,
    pub processes: Vec<ProcessInfo>,
    pub vmm_pid: u32,
    #[serde(default)]
    pub proxy_pid: Option<u32>,
    #[serde(default)]
    pub proxy_isolated: bool,
    #[serde(default)]
    pub stats: SandboxRunStats,
}

struct Deadlines {
    idle_deadline_mono: Instant,
    idle_deadline_unix: u64,
    max_wall_deadline_mono: Instant,
    expires_at_unix: u64,
    idle_timeout_sec: u64,
}

impl Deadlines {
    fn new(now_unix: u64, idle_timeout_sec: u64, max_wall_time_sec: u64) -> Self {
        let now_mono = Instant::now();
        let effective_idle = idle_timeout_sec.min(max_wall_time_sec);
        Self {
            idle_deadline_mono: now_mono + Duration::from_secs(effective_idle),
            idle_deadline_unix: now_unix.saturating_add(effective_idle),
            max_wall_deadline_mono: now_mono + Duration::from_secs(max_wall_time_sec),
            expires_at_unix: now_unix.saturating_add(max_wall_time_sec),
            idle_timeout_sec,
        }
    }

    fn touch(&mut self) {
        let now_mono = Instant::now();
        let now_unix = current_unix_sec();
        let next_mono = now_mono + Duration::from_secs(self.idle_timeout_sec);
        self.idle_deadline_mono = next_mono.min(self.max_wall_deadline_mono);
        self.idle_deadline_unix = now_unix
            .saturating_add(self.idle_timeout_sec)
            .min(self.expires_at_unix);
    }

    fn expiry_reason(&self, now_mono: Instant) -> Option<&'static str> {
        if now_mono >= self.max_wall_deadline_mono {
            Some("max_wall_time_sec exceeded")
        } else if now_mono >= self.idle_deadline_mono {
            Some("idle_timeout_sec exceeded")
        } else {
            None
        }
    }
}

/// Live handle to an active Blackwall sandbox instance.
pub struct SandboxHandle {
    pub id: String,
    pub spec: SandboxSpec,
    pub image_roothash: String,
    pub image_content_hash: String,
    pub kernel_profile: String,
    pub vmm_backend_name: String,
    pub boot_duration_ms: u64,
    pub guest_init_version: String,
    pub workspace_mounted: bool,
    pub netbridge_ready: bool,
    pub pinned_dns: BTreeMap<String, Vec<String>>,
    pub created_at: u64,
    state: Mutex<SandboxState>,
    deadlines: Mutex<Deadlines>,
    stats: Mutex<SandboxRunStats>,
    session: SessionClient,
    ingress_ports: Arc<Mutex<BTreeSet<u16>>>,
    bridges: Arc<Mutex<BTreeMap<u16, HostServiceSpec>>>,
    bridge_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    vm: Mutex<Box<dyn VmInstance>>,
    proxy: Mutex<Option<VmProxyHandle>>,
    audit_thread: Mutex<Option<thread::JoinHandle<()>>>,
}

impl SandboxHandle {
    /// Refresh `idle_deadline_at` (clamped by `max_wall_time_sec`).
    pub fn touch(&self) {
        if let Ok(mut d) = self.deadlines.lock() {
            d.touch();
        }
        if let Ok(mut s) = self.stats.lock() {
            s.last_activity_at = current_unix_sec();
        }
    }

    pub fn summary(&self) -> SandboxSummary {
        let state = self
            .state
            .lock()
            .map(|g| *g)
            .unwrap_or(SandboxState::Stopped);
        let (expires_at, idle_deadline_at) = self
            .deadlines
            .lock()
            .map(|d| (d.expires_at_unix, d.idle_deadline_unix))
            .unwrap_or((self.created_at, self.created_at));
        let now = current_unix_sec();
        let (proxy_pid, proxy_isolated) = self
            .proxy
            .lock()
            .ok()
            .and_then(|g| g.as_ref().map(|p| (p.proxy_pid(), p.is_isolated())))
            .unwrap_or((None, false));
        SandboxSummary {
            id: self.id.clone(),
            profile: self.spec.name.clone(),
            state,
            image_roothash: self.image_roothash.clone(),
            image_content_hash: self.image_content_hash.clone(),
            kernel_profile: self.kernel_profile.clone(),
            vmm_backend: self.vmm_backend_name.clone(),
            vmm_pid: self.vmm_pid(),
            proxy_pid,
            proxy_isolated,
            boot_duration_ms: self.boot_duration_ms,
            guest_init_version: self.guest_init_version.clone(),
            workspace_mounted: self.workspace_mounted,
            netbridge_ready: self.netbridge_ready,
            compute: self.spec.compute.clone(),
            network_mode: self.spec.network.mode,
            allowed_hosts: self.spec.derived_dns_allow().into_iter().collect(),
            ingress_allow_ports: self.ingress_ports_snapshot(),
            host_services: self.host_services_snapshot(),
            created_at: self.created_at,
            expires_at,
            idle_deadline_at,
            uptime_sec: now.saturating_sub(self.created_at),
            idle_remaining_sec: idle_deadline_at.saturating_sub(now),
            wall_remaining_sec: expires_at.saturating_sub(now),
        }
    }

    pub fn stats_snapshot(&self) -> SandboxRunStats {
        self.stats.lock().map(|g| g.clone()).unwrap_or_default()
    }

    pub fn ingress_ports_snapshot(&self) -> Vec<u16> {
        self.ingress_ports
            .lock()
            .map(|g| g.iter().copied().collect())
            .unwrap_or_default()
    }

    pub fn host_services_snapshot(&self) -> Vec<HostServiceSpec> {
        self.bridges
            .lock()
            .map(|g| g.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Borrow the underlying Port 1002 [`SessionClient`].
    pub fn session(&self) -> &SessionClient {
        &self.session
    }

    fn vmm_pid(&self) -> u32 {
        self.vm.lock().map(|v| v.pid()).unwrap_or(0)
    }

    fn is_vm_alive(&self) -> bool {
        self.vm.lock().map(|v| v.is_alive()).unwrap_or(false)
    }

    fn set_state(&self, new_state: SandboxState) {
        if let Ok(mut g) = self.state.lock() {
            *g = new_state;
        }
    }

    fn expiry_reason(&self, now: Instant) -> Option<&'static str> {
        self.deadlines.lock().ok()?.expiry_reason(now)
    }

    async fn teardown(&self) {
        self.set_state(SandboxState::Stopping);

        // Best-effort graceful guest shutdown over Port 1002 with a short timeout.
        let _ = tokio::time::timeout(Duration::from_millis(500), self.session.shutdown()).await;

        // Abort background host-bridge accept task if still running.
        if let Ok(mut guard) = self.bridge_task.lock() {
            if let Some(task) = guard.take() {
                task.abort();
            }
        }

        // Stop per-VM proxy tasks (if egress mode).
        if let Ok(mut proxy_guard) = self.proxy.lock() {
            if let Some(mut proxy) = proxy_guard.take() {
                proxy.stop();
            }
        }

        // Terminate VMM and reclaim unlinked vdb scratch disk.
        if let Ok(vm) = self.vm.lock() {
            let _ = vm.kill();
        }

        // Join Port 1001 audit drain thread once the guest socket closes.
        let handle = self
            .audit_thread
            .lock()
            .ok()
            .and_then(|mut g| g.take());
        if let Some(h) = handle {
            let _ = tokio::task::spawn_blocking(move || {
                let _ = h.join();
            })
            .await;
        }

        self.set_state(SandboxState::Stopped);
    }
}

struct ManagerInner {
    config: CoreConfig,
    forbidden_bridge_ports: RwLock<Vec<u16>>,
    forbidden_bridge_unix_paths: RwLock<Vec<PathBuf>>,
    audit_hub: AuditHub,
    profiles: RwLock<ProfileRegistry>,
    in_memory_profiles: RwLock<BTreeMap<String, ProfileDraft>>,
    image_builder: ImageBuilder,
    host_key: HostKeyPair,
    vmm_backend: Arc<dyn VmmBackend>,
    dns_resolver: Arc<dyn DnsResolver>,
    sandboxes: RwLock<HashMap<String, Arc<SandboxHandle>>>,
}

impl ManagerInner {
    fn validate_bridge_target(&self, svc: &HostServiceSpec) -> Result<()> {
        let ports = self
            .forbidden_bridge_ports
            .read()
            .map_err(|_| CoreError::Internal("forbidden_bridge_ports lock poisoned".into()))?;
        let unix_paths = self
            .forbidden_bridge_unix_paths
            .read()
            .map_err(|_| CoreError::Internal("forbidden_bridge_unix_paths lock poisoned".into()))?;
        validate_bridge_target_against_lists(svc, &ports, &unix_paths)
    }

    fn load_current_profiles(&self) -> Result<ProfileRegistry> {
        let mut reg = ProfileRegistry::load_dir(&self.config.profile_dir)?;
        if let Ok(mem) = self.in_memory_profiles.read() {
            for (name, draft) in mem.iter() {
                reg.insert(name.clone(), draft.clone());
            }
        }
        if let Ok(mut guard) = self.profiles.write() {
            *guard = reg.clone();
        }
        Ok(reg)
    }

    fn get_handle(&self, id: &str) -> Result<Arc<SandboxHandle>> {
        let guard = self
            .sandboxes
            .read()
            .map_err(|_| CoreError::Internal("sandboxes lock poisoned".into()))?;
        guard
            .get(id)
            .cloned()
            .ok_or_else(|| CoreError::SandboxNotFound(id.to_string()))
    }

    async fn destroy_with_reason(&self, id: &str, reason: Option<&str>) -> Result<()> {
        let handle = {
            let mut guard = self
                .sandboxes
                .write()
                .map_err(|_| CoreError::Internal("sandboxes lock poisoned".into()))?;
            guard.remove(id)
        }
        .ok_or_else(|| CoreError::SandboxNotFound(id.to_string()))?;

        if let Some(reap_reason) = reason {
            self.config.audit_sink.record(AuditEvent::now(
                id,
                AuditEventKind::SandboxLifecycle {
                    phase: "reaped".into(),
                    image_roothash: Some(handle.image_roothash.clone()),
                    details: Some(reap_reason.to_string()),
                },
            ));
        }

        handle.teardown().await;

        self.config.audit_sink.record(AuditEvent::now(
            id,
            AuditEventKind::SandboxLifecycle {
                phase: "destroyed".into(),
                image_roothash: Some(handle.image_roothash.clone()),
                details: reason.map(ToOwned::to_owned),
            },
        ));

        Ok(())
    }
}

/// Top-level embeddable Blackwall sandbox orchestrator & SDK entry point.
///
/// Manages composed profiles, OCI `vda` image caching, HPKE host keys, out-of-process
/// DNS pinning, VMM lifecycle, Port 1001 audit draining, per-VM Pingora/Postgres proxies,
/// Port 1002 interactive sessions, `blackwall-unpacker` download sanitization, and
/// automatic `idle_timeout_sec` / `max_wall_time_sec` reaping.
pub struct SandboxManager {
    inner: Arc<ManagerInner>,
    reaper_shutdown_tx: Mutex<Option<watch::Sender<bool>>>,
}

impl SandboxManager {
    /// Construct a production [`SandboxManager`] backed by [`LinuxVmmBackend`] and [`SystemDnsResolver`].
    pub fn new(config: CoreConfig) -> Result<Self> {
        Self::with_backend(
            config,
            Box::new(LinuxVmmBackend::default()),
            Arc::new(SystemDnsResolver),
        )
    }

    /// Construct a [`SandboxManager`] with custom [`VmmBackend`] and [`DnsResolver`]
    /// (e.g., [`crate::mock::MockSessionVmmBackend`] + [`crate::dns::StaticDnsResolver`] in tests).
    pub fn with_backend(
        mut config: CoreConfig,
        vmm_backend: Box<dyn VmmBackend>,
        dns_resolver: Arc<dyn DnsResolver>,
    ) -> Result<Self> {
        let profiles = ProfileRegistry::load_dir(&config.profile_dir)?;
        let image_builder = ImageBuilder::new(&config.image_cache_dir);
        let host_key = HostKeyPair::load_or_generate(&config.host_key_path)?;

        let audit_hub = AuditHub::new(config.audit_sink);
        config.audit_sink = Arc::new(audit_hub.clone());

        let forbidden_ports = config.forbidden_bridge_ports.clone();
        let forbidden_unix_paths = config.forbidden_bridge_unix_paths.clone();

        let inner = Arc::new(ManagerInner {
            config,
            forbidden_bridge_ports: RwLock::new(forbidden_ports),
            forbidden_bridge_unix_paths: RwLock::new(forbidden_unix_paths),
            audit_hub,
            profiles: RwLock::new(profiles),
            in_memory_profiles: RwLock::new(BTreeMap::new()),
            image_builder,
            host_key,
            vmm_backend: Arc::from(vmm_backend),
            dns_resolver,
            sandboxes: RwLock::new(HashMap::new()),
        });

        let manager = Self {
            inner,
            reaper_shutdown_tx: Mutex::new(None),
        };
        manager.start_reaper_if_tokio_active();
        Ok(manager)
    }

    /// Explicitly start the background idle/wall-time reaper task on the current Tokio runtime.
    ///
    /// Called automatically by [`Self::new`] and [`Self::with_backend`] when invoked inside
    /// a Tokio runtime; safe to call again (idempotent).
    pub fn start_reaper(&self) {
        let Ok(mut guard) = self.reaper_shutdown_tx.lock() else {
            return;
        };
        if guard.is_some() {
            return;
        }
        let (tx, mut rx) = watch::channel(false);
        *guard = Some(tx);

        let weak: Weak<ManagerInner> = Arc::downgrade(&self.inner);
        let interval = self.inner.config.reaper_interval.max(Duration::from_millis(10));

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        let Some(inner) = weak.upgrade() else {
                            break;
                        };
                        let now = Instant::now();
                        let expired: Vec<(String, &'static str)> = {
                            let Ok(guard) = inner.sandboxes.read() else {
                                continue;
                            };
                            guard
                                .iter()
                                .filter_map(|(id, handle)| {
                                    if let Some(reason) = handle.expiry_reason(now) {
                                        Some((id.clone(), reason))
                                    } else if !handle.is_vm_alive() {
                                        Some((id.clone(), "vmm_exited"))
                                    } else {
                                        None
                                    }
                                })
                                .collect()
                        };
                        for (id, reason) in expired {
                            tracing::info!(sandbox_id = %id, %reason, "reaping sandbox");
                            let _ = inner.destroy_with_reason(&id, Some(reason)).await;
                        }
                    }
                    changed = rx.changed() => {
                        if changed.is_err() || *rx.borrow() {
                            break;
                        }
                    }
                }
            }
        });
    }

    fn start_reaper_if_tokio_active(&self) {
        if tokio::runtime::Handle::try_current().is_ok() {
            self.start_reaper();
        }
    }

    /// Borrow the active [`CoreConfig`].
    pub fn config(&self) -> &CoreConfig {
        &self.inner.config
    }

    /// Check whether image builds are allowed under the active operator [`PolicyCeiling`].
    pub fn check_image_build_allowed(&self) -> Result<()> {
        if self
            .inner
            .config
            .policy_ceiling
            .as_ref()
            .and_then(|c| c.allow_image_build)
            == Some(false)
        {
            return Err(CoreError::PolicyViolation(
                "image builds are disabled by policy ceiling".into(),
            ));
        }
        Ok(())
    }

    /// Return the active operator lockdown configuration summary.
    pub fn lockdown_status(&self) -> LockdownStatus {
        let allow_image_build = self
            .inner
            .config
            .policy_ceiling
            .as_ref()
            .and_then(|c| c.allow_image_build)
            != Some(false);
        LockdownStatus {
            readonly_profiles: self.inner.config.readonly_profiles,
            require_locked_profiles: self.inner.config.require_locked_profiles,
            has_policy_ceiling: self.inner.config.policy_ceiling.is_some(),
            allow_image_build,
        }
    }

    /// Register an additional loopback TCP port that host service bridges may never target
    /// (e.g., an ephemerally bound daemon HTTP or preview listener port).
    pub fn add_forbidden_bridge_port(&self, port: u16) {
        if port == 0 {
            return;
        }
        if let Ok(mut guard) = self.inner.forbidden_bridge_ports.write() {
            if !guard.contains(&port) {
                guard.push(port);
            }
        }
    }

    /// Register an additional host Unix domain socket path that host service bridges may never target
    /// (e.g., the daemon's own `0600` UDS control socket).
    pub fn add_forbidden_bridge_unix_path(&self, path: impl Into<PathBuf>) {
        let path = path.into();
        if path.as_os_str().is_empty() {
            return;
        }
        if let Ok(mut guard) = self.inner.forbidden_bridge_unix_paths.write() {
            if !guard.contains(&path) {
                guard.push(path);
            }
        }
    }

    /// Borrow the configured [`AuditSink`].
    pub fn audit_sink(&self) -> &Arc<dyn AuditSink> {
        &self.inner.config.audit_sink
    }

    /// Return up to `limit` recent [`AuditEvent`]s from the in-memory [`AuditHub`] ring buffer,
    /// optionally filtered to `sandbox_id`, in chronological order.
    pub fn recent_audit_events(&self, sandbox_id: Option<&str>, limit: usize) -> Vec<AuditEvent> {
        self.inner.audit_hub.recent(sandbox_id, limit)
    }

    /// Subscribe to live [`AuditEvent`]s broadcast by the [`AuditHub`].
    pub fn subscribe_audit(&self) -> broadcast::Receiver<AuditEvent> {
        self.inner.audit_hub.subscribe()
    }

    /// Atomically snapshot recent matching [`AuditEvent`]s and subscribe to subsequent
    /// live events without gaps or duplicates.
    pub fn recent_and_subscribe_audit(
        &self,
        sandbox_id: Option<&str>,
        limit: usize,
    ) -> (Vec<AuditEvent>, broadcast::Receiver<AuditEvent>) {
        self.inner.audit_hub.recent_and_subscribe(sandbox_id, limit)
    }

    /// Return the host's X25519 HPKE public key for offline `seal1_` sealing.
    pub fn host_public_key(&self) -> HostPublicKey {
        self.inner.host_key.public_key().clone()
    }

    /// Register or override an in-memory profile draft in the registry.
    pub fn register_profile(&self, name: impl Into<String>, draft: ProfileDraft) -> Result<()> {
        let name = name.into();
        {
            let mut mem = self
                .inner
                .in_memory_profiles
                .write()
                .map_err(|_| CoreError::Internal("in_memory_profiles lock poisoned".into()))?;
            mem.insert(name.clone(), draft.clone());
        }
        let mut guard = self
            .inner
            .profiles
            .write()
            .map_err(|_| CoreError::Internal("profiles lock poisoned".into()))?;
        guard.insert(name, draft);
        Ok(())
    }

    /// Reload all `*.toml` profiles from `config.profile_dir`.
    pub fn reload_profiles(&self) -> Result<()> {
        let _ = self.inner.load_current_profiles()?;
        Ok(())
    }

    /// Create and boot a new interactive sandbox from a composable [`ProfileDraft`].
    pub async fn create_sandbox(&self, draft: ProfileDraft) -> Result<SandboxSummary> {
        let boot_started = Instant::now();
        // Ensure background reaper is running if manager was constructed prior to entering Tokio.
        self.start_reaper_if_tokio_active();

        // 1. Resolve composed policy (validating ceilings, conflicts, and secret references).
        let mut spec = self
            .inner
            .load_current_profiles()?
            .resolve_api_request_with_options(&draft, self.inner.config.require_locked_profiles)?;

        if let Some(ref ceiling) = self.inner.config.policy_ceiling {
            ceiling.enforce(&spec)?;
        }

        // 1b. Validate declared host service bridges against daemon self-protection lists
        // BEFORE launching the VMM.
        for svc in &spec.host_services {
            self.inner.validate_bridge_target(svc)?;
        }

        let sandbox_id = format!("bw-{}", &Uuid::new_v4().simple().to_string()[..12]);
        let audit_sink = Arc::clone(&self.inner.config.audit_sink);

        audit_sink.record(AuditEvent::now(
            &sandbox_id,
            AuditEventKind::SandboxLifecycle {
                phase: "creating".into(),
                image_roothash: None,
                details: Some(format!(
                    "profile={} network={:?} vcpus={} mem={}MiB ws={}MiB",
                    spec.name,
                    spec.network.mode,
                    spec.compute.vcpus,
                    spec.compute.memory_mib,
                    spec.compute.workspace_mib
                )),
            },
        ));

        // 2. Open secrets (HPKE seal1_ & ephemeral) into memfd_secret + mint random placeholders.
        let (secret_table, guest_placeholders) = VmSecretTable::from_sandbox_spec(
            &mut spec,
            Some(&self.inner.host_key),
            None,
            current_unix_sec(),
        )?;
        let secret_bridge = Arc::new(VmSecretTableBridge::from_table(secret_table));

        // 3. Resolve immutable vda image & hardened kernel path.
        let image_content_hash_val = image_content_hash(&spec.image);
        let (vda_erofs_path, vda_verity, image_roothash) = self.resolve_image(&spec.image)?;
        let (kernel_path, kernel_profile) = match spec.network.mode {
            NetworkMode::None => (
                self.inner.config.kernel_noinet_path.clone(),
                "vmlinux-noinet".to_string(),
            ),
            NetworkMode::Loopback | NetworkMode::Egress => (
                self.inner.config.kernel_lo_path.clone(),
                "vmlinux-lo".to_string(),
            ),
        };

        // 4. Out-of-process DNS resolution & IP filtering (outside any proxy jail).
        let pinned_hosts = resolve_allowlisted_hosts_with(
            &spec,
            self.inner.dns_resolver.as_ref(),
            self.inner.config.dns_options,
        )?;
        let pinned_dns_meta: BTreeMap<String, Vec<String>> = pinned_hosts
            .iter()
            .map(|(h, addrs)| (h.clone(), addrs.iter().map(ToString::to_string).collect()))
            .collect();

        // 5. Generate ephemeral per-VM ECDSA P-256 MITM CA when network.mode == Egress.
        let ephemeral_ca = if spec.network.mode == NetworkMode::Egress {
            Some(Arc::new(EphemeralCa::generate(&sandbox_id)?))
        } else {
            None
        };
        let mitm_ca_pem = ephemeral_ca
            .as_ref()
            .map(|ca| ca.ca_cert_pem().to_string());

        // 6. Launch VMM (in spawn_blocking so KVM boot & vsock handshake never stall Tokio).
        let launch_cfg = VmLaunchConfig {
            sandbox_id: sandbox_id.clone(),
            kernel_path,
            initramfs_path: self.inner.config.initramfs_path.clone(),
            vda_erofs_path,
            vcpus: spec.compute.vcpus,
            memory_mib: u64::from(spec.compute.memory_mib),
            workspace_mib: u64::from(spec.compute.workspace_mib),
            enable_net_mux: spec.network.mode == NetworkMode::Egress,
            audit_sink: Arc::clone(&audit_sink),
        };
        let vmm_backend = Arc::clone(&self.inner.vmm_backend);
        let vm = tokio::task::spawn_blocking(move || vmm_backend.launch(launch_cfg))
            .await
            .map_err(|e| CoreError::Internal(format!("VMM launch task panicked: {e}")))??;

        let channels = vm.take_channels()?;

        // 7. Start Port 1001 unidirectional audit drain thread.
        let audit_sid = sandbox_id.clone();
        let audit_sink_thread = Arc::clone(&audit_sink);
        let audit_stream = channels.audit_uni;
        let audit_thread = thread::Builder::new()
            .name(format!("bw-audit-{sandbox_id}"))
            .spawn(move || {
                let _ = drain_port1001_stream(audit_stream, &audit_sid, audit_sink_thread.as_ref());
            })
            .map_err(CoreError::Io)?;

        // 8. Start per-VM Pingora + Postgres proxy if egress mode is active.
        let proxy_handle = if let Some(ca) = ephemeral_ca {
            match VmProxyHandle::start_with_mode(
                &sandbox_id,
                &spec,
                pinned_hosts,
                ca,
                secret_bridge,
                Arc::clone(&audit_sink),
                channels.net_mux,
                self.inner.config.proxy_launch_mode,
            ) {
                Ok(h) => Some(h),
                Err(err) => {
                    let _ = vm.kill();
                    return Err(err);
                }
            }
        } else {
            None
        };

        // 9. Attach Port 1002 session client, wire host-service bridge acceptor, and run BootConfigure -> BootReady.
        let session = match SessionClient::new(&sandbox_id, channels.ctrl_session) {
            Ok(s) => s,
            Err(err) => {
                drop(proxy_handle);
                let _ = vm.kill();
                return Err(err);
            }
        };

        let bridges: Arc<Mutex<BTreeMap<u16, HostServiceSpec>>> =
            Arc::new(Mutex::new(BTreeMap::new()));
        let (bridge_open_tx, bridge_open_rx) =
            mpsc::channel::<(String, u16)>(HOST_BRIDGE_OPEN_QUEUE_CAPACITY);
        session.set_host_bridge_open_tx(bridge_open_tx);
        let bridge_task = spawn_host_bridge_acceptor(
            sandbox_id.clone(),
            session.clone(),
            Arc::clone(&bridges),
            Arc::clone(&audit_sink),
            bridge_open_rx,
        );

        let boot_cfg = BootConfig {
            vda_verity,
            network_mode: spec.network.mode.into(),
            mitm_ca_pem,
            env: spec.env.clone(),
            secret_placeholders: guest_placeholders,
            workspace_mount: "/workspace".to_string(),
        };

        let boot_ready = match session.boot_configure(boot_cfg).await {
            Ok(r) => r,
            Err(err) => {
                bridge_task.abort();
                drop(proxy_handle);
                let _ = vm.kill();
                return Err(err);
            }
        };

        // 10. Bind any statically declared host service bridges inside the guest.
        for svc in &spec.host_services {
            if let Err(err) = session.host_bridge_bind(svc.guest_port).await {
                bridge_task.abort();
                drop(proxy_handle);
                let _ = vm.kill();
                return Err(err);
            }
            if let Ok(mut guard) = bridges.lock() {
                guard.insert(svc.guest_port, svc.clone());
            }
        }

        let created_at = current_unix_sec();
        let boot_duration_ms = boot_started.elapsed().as_millis() as u64;
        let deadlines = Deadlines::new(
            created_at,
            spec.compute.idle_timeout_sec,
            spec.compute.max_wall_time_sec,
        );

        let ingress_ports: Arc<Mutex<BTreeSet<u16>>> =
            Arc::new(Mutex::new(spec.ingress.allow_ports.iter().copied().collect()));

        let handle = Arc::new(SandboxHandle {
            id: sandbox_id.clone(),
            spec,
            image_roothash: image_roothash.clone(),
            image_content_hash: image_content_hash_val,
            kernel_profile,
            vmm_backend_name: self.inner.vmm_backend.name().to_string(),
            boot_duration_ms,
            guest_init_version: boot_ready.version.clone(),
            workspace_mounted: boot_ready.workspace_mounted,
            netbridge_ready: boot_ready.netbridge_ready,
            pinned_dns: pinned_dns_meta,
            created_at,
            state: Mutex::new(SandboxState::Running),
            deadlines: Mutex::new(deadlines),
            stats: Mutex::new(SandboxRunStats {
                last_activity_at: created_at,
                ..SandboxRunStats::default()
            }),
            session,
            ingress_ports,
            bridges,
            bridge_task: Mutex::new(Some(bridge_task)),
            vm: Mutex::new(vm),
            proxy: Mutex::new(proxy_handle),
            audit_thread: Mutex::new(Some(audit_thread)),
        });

        let summary = handle.summary();
        {
            let mut guard = self
                .inner
                .sandboxes
                .write()
                .map_err(|_| CoreError::Internal("sandboxes lock poisoned".into()))?;
            guard.insert(sandbox_id.clone(), handle);
        }

        audit_sink.record(AuditEvent::now(
            &sandbox_id,
            AuditEventKind::SandboxLifecycle {
                phase: "running".into(),
                image_roothash: Some(image_roothash),
                details: Some(format!(
                    "init_version={} workspace_mounted={} netbridge_ready={}",
                    boot_ready.version, boot_ready.workspace_mounted, boot_ready.netbridge_ready
                )),
            },
        ));

        Ok(summary)
    }

    fn resolve_image(
        &self,
        spec: &ImageSpec,
    ) -> Result<(PathBuf, Option<DmVerityConfig>, String)> {
        if let Some(cached) = self.inner.image_builder.lookup_cache(spec)? {
            let roothash = cached.verity.roothash_hex.clone();
            return Ok((cached.erofs_path, Some(cached.verity), roothash));
        }
        if self.inner.config.allow_unbuilt_images_for_mock {
            let hash = image_content_hash(spec);
            let placeholder_path = self.inner.config.image_cache_dir.join(format!("{hash}.erofs"));
            return Ok((placeholder_path, None, format!("mock-{hash}")));
        }
        let built = self.inner.image_builder.build(spec)?;
        let roothash = built.verity.roothash_hex.clone();
        Ok((built.erofs_path, Some(built.verity), roothash))
    }

    /// List all currently active sandboxes.
    pub fn list_sandboxes(&self) -> Vec<SandboxSummary> {
        let Ok(guard) = self.inner.sandboxes.read() else {
            return Vec::new();
        };
        let mut out: Vec<SandboxSummary> = guard.values().map(|h| h.summary()).collect();
        out.sort_by(|a, b| a.created_at.cmp(&b.created_at).then_with(|| a.id.cmp(&b.id)));
        out
    }

    /// Inspect full sandbox status, caps, timers, and active background processes.
    pub async fn get_sandbox(&self, id: &str) -> Result<SandboxDetail> {
        let handle = self.inner.get_handle(id)?;
        handle.touch();
        let summary = handle.summary();
        let processes = handle.session.list_processes().await.unwrap_or_default();
        let allowed_hosts: Vec<String> = handle.spec.derived_dns_allow().into_iter().collect();

        let configured_secrets: Vec<String> = handle.spec.secrets.keys().cloned().collect();

        Ok(SandboxDetail {
            id: summary.id,
            profile: summary.profile,
            state: summary.state,
            image_roothash: summary.image_roothash,
            image_content_hash: summary.image_content_hash,
            kernel_profile: summary.kernel_profile,
            vmm_backend: summary.vmm_backend,
            boot_duration_ms: summary.boot_duration_ms,
            guest_init_version: summary.guest_init_version,
            workspace_mounted: summary.workspace_mounted,
            netbridge_ready: summary.netbridge_ready,
            created_at: summary.created_at,
            expires_at: summary.expires_at,
            idle_deadline_at: summary.idle_deadline_at,
            uptime_sec: summary.uptime_sec,
            idle_remaining_sec: summary.idle_remaining_sec,
            wall_remaining_sec: summary.wall_remaining_sec,
            compute: handle.spec.compute.clone(),
            network_mode: handle.spec.network.mode,
            allowed_hosts,
            ingress_allow_ports: summary.ingress_allow_ports.clone(),
            ingress: IngressSpec {
                allow_ports: summary.ingress_allow_ports,
            },
            host_services: summary.host_services,
            pinned_dns: handle.pinned_dns.clone(),
            configured_secrets,
            export: handle.spec.export.clone(),
            processes,
            vmm_pid: handle.vmm_pid(),
            proxy_pid: summary.proxy_pid,
            proxy_isolated: summary.proxy_isolated,
            stats: handle.stats_snapshot(),
        })
    }

    /// Destroy a sandbox immediately, wiping encrypted `vdb`, stopping its proxy, and killing the VMM.
    pub async fn destroy_sandbox(&self, id: &str) -> Result<()> {
        self.inner.destroy_with_reason(id, None).await
    }

    /// Destroy all active sandboxes (graceful daemon shutdown).
    pub async fn destroy_all(&self) {
        let ids: Vec<String> = self
            .inner
            .sandboxes
            .read()
            .map(|g| g.keys().cloned().collect())
            .unwrap_or_default();
        for id in ids {
            let _ = self.inner.destroy_with_reason(&id, Some("manager_shutdown")).await;
        }
    }

    /// Execute a synchronous command inside sandbox `id`.
    pub async fn exec(&self, id: &str, req: ExecRequest) -> Result<ExecResult> {
        let handle = self.inner.get_handle(id)?;
        handle.touch();
        let cmd_for_audit = req.cmd.clone();
        let cwd_for_audit = req.cwd.clone();
        let res = handle.session.exec_sync(req).await?;
        if let Ok(mut st) = handle.stats.lock() {
            st.exec_count += 1;
            if !res.success {
                st.exec_failed_count += 1;
            }
            st.total_exec_duration_ms = st.total_exec_duration_ms.saturating_add(res.duration_ms);
            st.last_activity_at = current_unix_sec();
        }
        self.inner.config.audit_sink.record(AuditEvent::now(
            id,
            AuditEventKind::ExecCommand {
                cmd: cmd_for_audit,
                cwd: cwd_for_audit,
                background: false,
                exit_code: Some(res.exit_code),
                duration_ms: Some(res.duration_ms),
            },
        ));
        Ok(res)
    }

    /// Execute a command inside sandbox `id`, streaming stdout/stderr/exit events.
    pub async fn exec_stream(
        &self,
        id: &str,
        req: ExecRequest,
    ) -> Result<mpsc::UnboundedReceiver<ExecStreamEvent>> {
        let handle = self.inner.get_handle(id)?;
        handle.touch();
        if let Ok(mut st) = handle.stats.lock() {
            st.exec_count += 1;
            st.last_activity_at = current_unix_sec();
        }
        self.inner.config.audit_sink.record(AuditEvent::now(
            id,
            AuditEventKind::ExecCommand {
                cmd: req.cmd.clone(),
                cwd: req.cwd.clone(),
                background: false,
                exit_code: None,
                duration_ms: None,
            },
        ));
        handle.session.exec_stream(req).await
    }

    /// Spawn a tracked background process inside sandbox `id`.
    pub async fn exec_background(&self, id: &str, req: ExecRequest) -> Result<BackgroundProcess> {
        let handle = self.inner.get_handle(id)?;
        handle.touch();
        let cmd_for_audit = req.cmd.clone();
        let cwd_for_audit = req.cwd.clone();
        let proc = handle.session.exec_background(req).await?;
        if let Ok(mut st) = handle.stats.lock() {
            st.background_spawned_count += 1;
            st.last_activity_at = current_unix_sec();
        }
        self.inner.config.audit_sink.record(AuditEvent::now(
            id,
            AuditEventKind::ExecCommand {
                cmd: cmd_for_audit,
                cwd: cwd_for_audit,
                background: true,
                exit_code: None,
                duration_ms: None,
            },
        ));
        Ok(proc)
    }

    /// List tracked background processes in sandbox `id`.
    pub async fn list_processes(&self, id: &str) -> Result<Vec<ProcessInfo>> {
        let handle = self.inner.get_handle(id)?;
        handle.touch();
        handle.session.list_processes().await
    }

    /// Fetch or follow buffered stdout/stderr logs for a tracked background process.
    pub async fn process_logs(
        &self,
        id: &str,
        proc_id: &str,
        tail: Option<usize>,
        follow: bool,
    ) -> Result<mpsc::UnboundedReceiver<ExecStreamEvent>> {
        let handle = self.inner.get_handle(id)?;
        handle.touch();
        handle.session.process_logs(proc_id, tail, follow).await
    }

    /// Send a POSIX signal to a tracked background process group in sandbox `id`.
    pub async fn signal_process(
        &self,
        id: &str,
        proc_id: &str,
        signal: SignalKind,
    ) -> Result<()> {
        let handle = self.inner.get_handle(id)?;
        handle.touch();
        handle.session.signal_process(proc_id, signal).await
    }

    /// Kill and delete a tracked background process handle in sandbox `id`.
    pub async fn delete_process(&self, id: &str, proc_id: &str) -> Result<()> {
        let handle = self.inner.get_handle(id)?;
        handle.touch();
        handle.session.delete_process(proc_id).await
    }

    /// Attach an interactive PTY session inside sandbox `id`.
    pub async fn open_pty(&self, id: &str, params: PtyOpenParams) -> Result<PtyHandle> {
        let handle = self.inner.get_handle(id)?;
        handle.touch();
        let pty = handle.session.open_pty(params).await?;
        if let Ok(mut st) = handle.stats.lock() {
            st.pty_sessions_count += 1;
            st.last_activity_at = current_unix_sec();
        }
        Ok(pty)
    }

    /// Open a host-to-guest TCP ingress tunnel to `127.0.0.1:<guest_port>` inside sandbox `id`.
    ///
    /// Enforces `handle.ingress_ports.contains(&guest_port)` fail-closed and emits
    /// `AuditEventKind::IngressTunnel` events.
    pub async fn open_tcp_tunnel(&self, id: &str, guest_port: u16) -> Result<TcpTunnelHandle> {
        let handle = self.inner.get_handle(id)?;
        handle.touch();
        let allowed = handle
            .ingress_ports
            .lock()
            .map(|g| g.contains(&guest_port))
            .unwrap_or(false);
        if !allowed {
            self.inner.config.audit_sink.record(AuditEvent::now(
                id,
                AuditEventKind::IngressTunnel {
                    guest_port,
                    bytes_in: 0,
                    bytes_out: 0,
                    allowed: false,
                },
            ));
            return Err(CoreError::Policy(blackwall_policy::PolicyError::InvalidValue(
                format!(
                    "ingress port {guest_port} is not allowlisted for sandbox '{id}'"
                ),
            )));
        }

        let tunnel = handle
            .session
            .open_tcp_tunnel_with_audit(
                guest_port,
                Some(Arc::clone(&self.inner.config.audit_sink)),
            )
            .await?;

        if let Ok(mut st) = handle.stats.lock() {
            st.ingress_connections_count += 1;
            st.last_activity_at = current_unix_sec();
        }
        Ok(tunnel)
    }

    /// List all currently allowlisted ingress ports for sandbox `id` (sorted ascending).
    pub fn list_ingress_ports(&self, id: &str) -> Result<Vec<u16>> {
        let handle = self.inner.get_handle(id)?;
        handle.touch();
        Ok(handle.ingress_ports_snapshot())
    }

    /// Dynamically allowlist an ingress port on a running sandbox `id`.
    pub fn allow_ingress_port(&self, id: &str, port: u16) -> Result<Vec<u16>> {
        if port == 0 {
            return Err(CoreError::InvalidRequest(
                "ingress port must be >= 1".into(),
            ));
        }
        let handle = self.inner.get_handle(id)?;
        handle.touch();

        if handle.spec.network.mode == NetworkMode::None {
            return Err(CoreError::InvalidRequest(
                "cannot allow ingress ports when network.mode is 'none'".into(),
            ));
        }
        if handle.spec.policy.locked {
            return Err(CoreError::PolicyViolation(
                "cannot open new ingress ports on a locked policy sandbox".into(),
            ));
        }

        let ports = {
            let mut guard = handle
                .ingress_ports
                .lock()
                .map_err(|_| CoreError::Internal("ingress_ports lock poisoned".into()))?;
            guard.insert(port);
            guard.iter().copied().collect::<Vec<u16>>()
        };

        self.inner.config.audit_sink.record(AuditEvent::now(
            id,
            AuditEventKind::SandboxLifecycle {
                phase: "ingress_port_opened".into(),
                image_roothash: None,
                details: Some(format!("port={port}")),
            },
        ));

        Ok(ports)
    }

    /// Close (remove) an allowlisted ingress port on sandbox `id`.
    ///
    /// Always permitted even when `policy.locked == true` because narrowing exposure
    /// never expands a sandbox's attack surface.
    pub fn close_ingress_port(&self, id: &str, port: u16) -> Result<()> {
        let handle = self.inner.get_handle(id)?;
        handle.touch();

        let removed = {
            let mut guard = handle
                .ingress_ports
                .lock()
                .map_err(|_| CoreError::Internal("ingress_ports lock poisoned".into()))?;
            guard.remove(&port)
        };
        if !removed {
            return Err(CoreError::NotFound(format!(
                "ingress port {port} is not allowlisted on sandbox '{id}'"
            )));
        }

        self.inner.config.audit_sink.record(AuditEvent::now(
            id,
            AuditEventKind::SandboxLifecycle {
                phase: "ingress_port_closed".into(),
                image_roothash: None,
                details: Some(format!("port={port}")),
            },
        ));

        Ok(())
    }

    /// List all currently attached host service bridges for sandbox `id`.
    pub fn list_host_bridges(&self, id: &str) -> Result<Vec<HostServiceSpec>> {
        let handle = self.inner.get_handle(id)?;
        handle.touch();
        Ok(handle.host_services_snapshot())
    }

    /// Dynamically attach a host service bridge (`127.0.0.1:<guest_port>` -> host loopback/UDS)
    /// to a running sandbox `id`.
    pub async fn attach_host_bridge(
        &self,
        id: &str,
        svc: HostServiceSpec,
    ) -> Result<HostServiceSpec> {
        let handle = self.inner.get_handle(id)?;
        handle.touch();

        if self
            .inner
            .config
            .policy_ceiling
            .as_ref()
            .and_then(|c| c.allow_host_services)
            == Some(false)
        {
            return Err(CoreError::PolicyViolation(
                "host service bridges are disabled by policy ceiling".into(),
            ));
        }

        if handle.spec.network.mode == NetworkMode::None {
            return Err(CoreError::InvalidRequest(
                "cannot attach host bridge when network.mode is 'none'".into(),
            ));
        }
        if handle.spec.policy.locked {
            return Err(CoreError::PolicyViolation(
                "cannot attach host bridge on locked policy sandbox".into(),
            ));
        }

        self.inner.validate_bridge_target(&svc)?;

        {
            let guard = handle
                .bridges
                .lock()
                .map_err(|_| CoreError::Internal("bridges lock poisoned".into()))?;
            if guard.contains_key(&svc.guest_port) {
                return Err(CoreError::InvalidRequest(format!(
                    "guest port {} is already bound by a host bridge",
                    svc.guest_port
                )));
            }
        }

        handle.session.host_bridge_bind(svc.guest_port).await?;

        {
            let mut guard = handle
                .bridges
                .lock()
                .map_err(|_| CoreError::Internal("bridges lock poisoned".into()))?;
            guard.insert(svc.guest_port, svc.clone());
        }

        Ok(svc)
    }

    /// Detach a previously attached host service bridge on `guest_port` from sandbox `id`.
    ///
    /// Always permitted even when `policy.locked == true` because detaching an existing
    /// bridge only narrows the sandbox's access to host services.
    pub async fn detach_host_bridge(&self, id: &str, guest_port: u16) -> Result<()> {
        let handle = self.inner.get_handle(id)?;
        handle.touch();

        let removed = {
            let mut guard = handle
                .bridges
                .lock()
                .map_err(|_| CoreError::Internal("bridges lock poisoned".into()))?;
            guard.remove(&guest_port)
        };
        if removed.is_none() {
            return Err(CoreError::NotFound(format!(
                "no host bridge bound on guest port {guest_port} for sandbox '{id}'"
            )));
        }

        handle.session.host_bridge_unbind(guest_port).await?;
        Ok(())
    }

    /// Upload a raw file or tar/tar.gz archive into `/workspace` in sandbox `id`.
    pub async fn upload_files(
        &self,
        id: &str,
        path: &str,
        kind: UploadKind,
        data: &[u8],
    ) -> Result<UploadResult> {
        let handle = self.inner.get_handle(id)?;
        handle.touch();
        let res = handle.session.upload_files(path, kind, data).await?;
        if let Ok(mut st) = handle.stats.lock() {
            st.upload_count += 1;
            st.upload_bytes = st.upload_bytes.saturating_add(res.bytes_written);
            st.last_activity_at = current_unix_sec();
        }
        self.inner.config.audit_sink.record(AuditEvent::now(
            id,
            AuditEventKind::FileTransfer {
                direction: TransferDirection::Upload,
                path: path.to_string(),
                bytes: res.bytes_written,
                files: res.files_written,
            },
        ));
        Ok(res)
    }

    /// Download a file or directory from `/workspace` in sandbox `id`, returning both
    /// the sanitized bytes and full transfer/checksum metadata.
    pub async fn download_files_with_meta(
        &self,
        id: &str,
        path: &str,
        format: DownloadFormat,
    ) -> Result<(Vec<u8>, DownloadMetadata)> {
        let started = Instant::now();
        let handle = self.inner.get_handle(id)?;
        handle.touch();
        let (bytes, summary) = handle
            .session
            .download_files_with_summary(
                path,
                format,
                &handle.spec.export,
                Arc::clone(&self.inner.config.audit_sink),
            )
            .await?;

        let sha256 = hex::encode(Sha256::digest(&bytes));
        let duration_ms = started.elapsed().as_millis() as u64;
        if let Ok(mut st) = handle.stats.lock() {
            st.download_count += 1;
            st.download_bytes = st.download_bytes.saturating_add(bytes.len() as u64);
            st.last_activity_at = current_unix_sec();
        }
        self.inner.config.audit_sink.record(AuditEvent::now(
            id,
            AuditEventKind::FileTransfer {
                direction: TransferDirection::Download,
                path: path.to_string(),
                bytes: summary.bytes_written,
                files: summary.files_written,
            },
        ));

        let meta = DownloadMetadata {
            sandbox_id: id.to_string(),
            path: path.to_string(),
            format,
            bytes: bytes.len() as u64,
            files: summary.files_written,
            dirs: summary.dirs_written,
            sha256,
            duration_ms,
        };
        Ok((bytes, meta))
    }

    /// Download a file or directory from `/workspace` in sandbox `id`.
    ///
    /// **Always** pipes guest bytes through `blackwall_unpacker::sanitize_download_stream`
    /// enforcing `spec.export.max_bytes`, `spec.export.max_files`, and canonical `.tar.gz`
    /// re-packing (rejecting symlinks, hardlinks, `..`, devices, and zip-bombs).
    pub async fn download_files(
        &self,
        id: &str,
        path: &str,
        format: DownloadFormat,
    ) -> Result<Vec<u8>> {
        let (bytes, _) = self.download_files_with_meta(id, path, format).await?;
        Ok(bytes)
    }

    /// Download and safely unpack onto a host directory `dest_dir`, enforcing
    /// case/Unicode-normalized `deny_touch_globs` via `blackwall-unpacker`.
    pub async fn download_files_to_dir(
        &self,
        id: &str,
        path: &str,
        format: DownloadFormat,
        dest_dir: &Path,
    ) -> Result<UnpackSummary> {
        let handle = self.inner.get_handle(id)?;
        let sanitized = self.download_files(id, path, format).await?;
        let spec = handle.spec.export.clone();
        let dest = dest_dir.to_path_buf();
        let sandbox_id = id.to_string();
        let rel_name = Path::new(path)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("file")
            .to_string();
        let sink = Arc::clone(&self.inner.config.audit_sink);

        tokio::task::spawn_blocking(move || match format {
            DownloadFormat::TarGz => {
                unpack_to_dir(Cursor::new(sanitized), &dest, &spec, &sandbox_id, sink.as_ref())
            }
            DownloadFormat::Raw => unpack_raw_to_dir(
                Cursor::new(sanitized),
                &dest,
                &rel_name,
                &spec,
                &sandbox_id,
                sink.as_ref(),
            ),
        })
        .await
        .map_err(|e| CoreError::Internal(format!("unpack task panicked: {e}")))?
        .map_err(CoreError::from)
    }

    /// Reset `idle_deadline_at` to `min(now + idle_timeout_sec, expires_at)` and return
    /// updated deadline timers for sandbox `id`.
    pub fn keepalive_sandbox(&self, id: &str) -> Result<KeepaliveResponse> {
        let handle = self.inner.get_handle(id)?;
        handle.touch();
        let now = current_unix_sec();
        let (expires_at, idle_deadline_at) = handle
            .deadlines
            .lock()
            .map(|d| (d.expires_at_unix, d.idle_deadline_unix))
            .unwrap_or((handle.created_at, handle.created_at));
        Ok(KeepaliveResponse {
            id: handle.id.clone(),
            idle_deadline_at,
            idle_remaining_sec: idle_deadline_at.saturating_sub(now),
            expires_at,
            wall_remaining_sec: expires_at.saturating_sub(now),
        })
    }

    /// List directory entries inside sandbox `id` over Port 1002 without emitting
    /// `AuditEventKind::ExecCommand` or incrementing `stats.exec_count`.
    ///
    /// Entries are sorted with directories first (`dir` / `symlink_dir`), then alphabetically.
    pub async fn list_dir(&self, id: &str, path: &str) -> Result<Vec<FsEntry>> {
        let target_path = if path.is_empty() { "/workspace" } else { path };
        if target_path.contains('\0') {
            return Err(CoreError::InvalidRequest(
                "path must not contain NUL bytes".into(),
            ));
        }

        let handle = self.inner.get_handle(id)?;
        handle.touch();

        let req = ExecRequest::new([
            "/bin/sh",
            "-c",
            LIST_DIR_SCRIPT,
            "_",
            target_path,
        ])
        .with_cwd("/workspace")
        .with_timeout_sec(15);

        let res = handle.session.exec_sync(req).await?;
        if res.exit_code == 4 {
            return Err(CoreError::GuestError {
                code: CtrlErrorCode::PermissionDenied,
                message: res.stderr.trim().to_string(),
            });
        }
        if res.exit_code == 3 {
            return Err(CoreError::GuestError {
                code: CtrlErrorCode::NotFound,
                message: res.stderr.trim().to_string(),
            });
        }
        if res.exit_code == 2 {
            return Err(CoreError::InvalidRequest(res.stderr.trim().to_string()));
        }
        if res.exit_code != 0 {
            return Err(CoreError::GuestError {
                code: CtrlErrorCode::Internal,
                message: format!(
                    "directory listing failed (exit={}): {}",
                    res.exit_code,
                    res.stderr.trim()
                ),
            });
        }

        Ok(parse_list_dir_output(target_path, &res.stdout))
    }

    /// Inspect listening TCP sockets inside sandbox `id` by reading `/proc/net/tcp` and
    /// `/proc/net/tcp6` over Port 1002 without emitting `ExecCommand` audit events or
    /// incrementing `stats.exec_count`.
    pub async fn list_listening_ports(&self, id: &str) -> Result<Vec<ListeningPort>> {
        let handle = self.inner.get_handle(id)?;
        handle.touch();

        let req = ExecRequest::new(["/bin/sh", "-c", LIST_PORTS_SCRIPT])
            .with_cwd("/workspace")
            .with_timeout_sec(10);

        let res = handle.session.exec_sync(req).await?;
        if res.exit_code != 0 {
            return Err(CoreError::GuestError {
                code: CtrlErrorCode::Internal,
                message: format!(
                    "listening port inspection failed (exit={}): {}",
                    res.exit_code,
                    res.stderr.trim()
                ),
            });
        }

        let allow_ports = handle.ingress_ports_snapshot();
        Ok(parse_listening_ports_output(
            id,
            &res.stdout,
            &allow_ports,
        ))
    }

    /// List all available profile names (always includes `"base"`), dynamically scanning `profile_dir`.
    pub fn list_profiles(&self) -> Vec<String> {
        match self.inner.load_current_profiles() {
            Ok(reg) => reg.names(),
            Err(err) => {
                tracing::warn!(%err, "failed to scan profile_dir; returning cached profiles");
                self.inner
                    .profiles
                    .read()
                    .map(|g| g.names())
                    .unwrap_or_else(|_| vec![blackwall_policy::BASE_PROFILE_NAME.to_string()])
            }
        }
    }

    /// Resolve a named profile (dynamically scanning `profile_dir`) and return a
    /// **secret-redacted** [`SandboxSpec`].
    pub fn get_profile(&self, name: &str) -> Result<SandboxSpec> {
        let reg = self.inner.load_current_profiles()?;
        Ok(reg.resolve_named(name)?.redacted())
    }

    /// Create or update an on-disk TOML profile `<profile_dir>/<name>.toml` atomically.
    ///
    /// Strictly validates `name`, parses with file-loading rules (rejecting plaintext
    /// `ephemeral` secrets), verifies inheritance/cycles/conflicts via `ProfileRegistry`,
    /// writes atomically (temp file + rename), and returns the secret-redacted resolved spec.
    pub fn create_profile(
        &self,
        name: &str,
        toml_raw: Option<&str>,
        draft: Option<ProfileDraft>,
    ) -> Result<SandboxSpec> {
        if self.inner.config.readonly_profiles {
            return Err(CoreError::PolicyViolation(
                "profile mutations are disabled (--readonly-profiles)".into(),
            ));
        }
        validate_profile_name(name).map_err(|e| CoreError::InvalidRequest(e.to_string()))?;

        let profile_dir = &self.inner.config.profile_dir;
        if profile_dir.as_os_str().is_empty() {
            return Err(CoreError::InvalidRequest(
                "profile_dir is not configured".into(),
            ));
        }

        let toml_content = if let Some(raw) = toml_raw {
            raw.to_string()
        } else if let Some(mut d) = draft {
            if let Some(ref existing) = d.name {
                if existing != name {
                    return Err(CoreError::InvalidRequest(format!(
                        "draft name '{existing}' does not match requested profile name '{name}'"
                    )));
                }
            }
            d.version = Some(d.version.unwrap_or(1));
            d.name = Some(name.to_string());
            d.to_toml_string()?
        } else {
            return Err(CoreError::InvalidRequest(
                "must provide either 'toml' or 'draft'".into(),
            ));
        };

        // Parse using strict file-loading validation (forbids plaintext `ephemeral` secrets).
        let mut parsed = ProfileDraft::from_toml_str(&toml_content)?;
        if let Some(ref parsed_name) = parsed.name {
            if parsed_name != name {
                return Err(CoreError::InvalidRequest(format!(
                    "profile TOML name '{parsed_name}' does not match requested name '{name}'"
                )));
            }
        } else {
            parsed.name = Some(name.to_string());
        }

        // Validate full resolution (extends, cycles, conflicts, secret refs, ceilings).
        let mut candidate = self.inner.load_current_profiles()?;
        candidate.insert(name.to_string(), parsed);
        let resolved = candidate.resolve_named(name)?;

        if let Some(ref ceiling) = self.inner.config.policy_ceiling {
            ceiling.enforce(&resolved)?;
        }

        // Atomically write `<profile_dir>/<name>.toml` via temp file + rename.
        fs::create_dir_all(profile_dir)?;
        let target_path = profile_dir.join(format!("{name}.toml"));
        let mut tmp = tempfile::NamedTempFile::new_in(profile_dir)?;
        tmp.write_all(toml_content.as_bytes())?;
        tmp.flush()?;
        tmp.persist(&target_path).map_err(|e| CoreError::Io(e.error))?;

        // Ensure disk is authoritative over any prior in-memory override and refresh cache.
        if let Ok(mut mem) = self.inner.in_memory_profiles.write() {
            mem.remove(name);
        }
        let _ = self.inner.load_current_profiles();

        Ok(resolved.redacted())
    }

    /// Delete `<profile_dir>/<name>.toml` after validating `name` (rejecting `"base"`).
    pub fn delete_profile(&self, name: &str) -> Result<()> {
        if self.inner.config.readonly_profiles {
            return Err(CoreError::PolicyViolation(
                "profile mutations are disabled (--readonly-profiles)".into(),
            ));
        }
        validate_profile_name(name).map_err(|e| CoreError::InvalidRequest(e.to_string()))?;

        let profile_dir = &self.inner.config.profile_dir;
        if profile_dir.as_os_str().is_empty() {
            return Err(CoreError::InvalidRequest(
                "profile_dir is not configured".into(),
            ));
        }

        let target_path = profile_dir.join(format!("{name}.toml"));
        if !target_path.is_file() {
            return Err(CoreError::Policy(PolicyError::UnknownProfile(
                name.to_string(),
            )));
        }

        fs::remove_file(&target_path)?;
        if let Ok(mut mem) = self.inner.in_memory_profiles.write() {
            mem.remove(name);
        }
        let _ = self.inner.load_current_profiles();
        Ok(())
    }

    /// List all cached `erofs + dm-verity` base images.
    pub fn list_images(&self) -> Result<Vec<BuiltImage>> {
        Ok(self.inner.image_builder.list_cached()?)
    }

    /// Build or return a cached `erofs + dm-verity` base image for `spec`.
    pub fn build_image(&self, spec: &ImageSpec) -> Result<BuiltImage> {
        self.check_image_build_allowed()?;
        Ok(self.inner.image_builder.build(spec)?)
    }

    /// Delete a cached image directory by its 64-char lowercase hex `content_hash`.
    ///
    /// Rejects invalid hashes (`InvalidRequest`), images currently in use by any active
    /// sandbox (`ImageInUse`), and missing entries (`ImageNotFound`).
    pub fn delete_image(&self, content_hash: &str) -> Result<()> {
        if !is_valid_content_hash(content_hash) {
            return Err(CoreError::InvalidRequest(
                "content_hash must be exactly 64 lowercase hexadecimal characters".into(),
            ));
        }

        let in_use = self
            .inner
            .sandboxes
            .read()
            .map_err(|_| CoreError::Internal("sandboxes lock poisoned".into()))?
            .values()
            .any(|h| h.image_content_hash == content_hash);
        if in_use {
            return Err(CoreError::ImageInUse(content_hash.to_string()));
        }

        let entry_dir = self.inner.image_builder.cache_dir().join(content_hash);
        if !entry_dir.exists() {
            return Err(CoreError::ImageNotFound(content_hash.to_string()));
        }
        fs::remove_dir_all(&entry_dir)?;
        Ok(())
    }

    /// Seal a secret offline with this host's X25519 HPKE public key, returning `"seal1_..."`.
    pub fn seal_secret(&self, plaintext: &[u8], binding: &SealBinding) -> Result<String> {
        Ok(self.inner.host_key.seal(plaintext, binding)?)
    }
}

const HOST_BRIDGE_OPEN_QUEUE_CAPACITY: usize = 64;
const MAX_CONCURRENT_HOST_BRIDGE_STREAMS: usize = 64;

fn spawn_host_bridge_acceptor(
    sandbox_id: String,
    session: SessionClient,
    bridges: Arc<Mutex<BTreeMap<u16, HostServiceSpec>>>,
    audit_sink: Arc<dyn AuditSink>,
    mut rx: mpsc::Receiver<(String, u16)>,
) -> tokio::task::JoinHandle<()> {
    let concurrency_limit = Arc::new(tokio::sync::Semaphore::new(
        MAX_CONCURRENT_HOST_BRIDGE_STREAMS,
    ));
    tokio::spawn(async move {
        while let Some((stream_id, guest_port)) = rx.recv().await {
            let Ok(permit) = Arc::clone(&concurrency_limit).try_acquire_owned() else {
                let _ = session
                    .reject_host_bridge_stream(
                        stream_id,
                        format!(
                            "too many concurrent host bridge streams (limit={MAX_CONCURRENT_HOST_BRIDGE_STREAMS})"
                        ),
                    )
                    .await;
                audit_sink.record(
                    AuditEvent::now(
                        &sandbox_id,
                        AuditEventKind::HostServiceBridge {
                            name: "rate_limited".to_string(),
                            guest_port,
                            target: String::new(),
                            bytes_in: 0,
                            bytes_out: 0,
                            allowed: false,
                        },
                    )
                    .with_origin(AuditOrigin::Daemon),
                );
                continue;
            };
            let sid = sandbox_id.clone();
            let sess = session.clone();
            let bridges_ref = Arc::clone(&bridges);
            let sink = Arc::clone(&audit_sink);
            tokio::spawn(async move {
                let _permit = permit;
                handle_host_bridge_open(sid, sess, bridges_ref, sink, stream_id, guest_port).await;
            });
        }
    })
}

async fn handle_host_bridge_open(
    sandbox_id: String,
    session: SessionClient,
    bridges: Arc<Mutex<BTreeMap<u16, HostServiceSpec>>>,
    audit_sink: Arc<dyn AuditSink>,
    stream_id: String,
    guest_port: u16,
) {
    let svc_opt = bridges
        .lock()
        .ok()
        .and_then(|guard| guard.get(&guest_port).cloned());

    let Some(svc) = svc_opt else {
        let _ = session
            .reject_host_bridge_stream(stream_id, "guest port not bridged")
            .await;
        audit_sink.record(
            AuditEvent::now(
                &sandbox_id,
                AuditEventKind::HostServiceBridge {
                    name: "unknown".to_string(),
                    guest_port,
                    target: String::new(),
                    bytes_in: 0,
                    bytes_out: 0,
                    allowed: false,
                },
            )
            .with_origin(AuditOrigin::Daemon),
        );
        return;
    };

    if let Some(unix_path) = svc.target.strip_prefix("unix://") {
        let mut host_stream = match tokio::net::UnixStream::connect(unix_path).await {
            Ok(s) => s,
            Err(err) => {
                let _ = session
                    .reject_host_bridge_stream(stream_id, err.to_string())
                    .await;
                audit_sink.record(
                    AuditEvent::now(
                        &sandbox_id,
                        AuditEventKind::HostServiceBridge {
                            name: svc.name,
                            guest_port,
                            target: svc.target,
                            bytes_in: 0,
                            bytes_out: 0,
                            allowed: false,
                        },
                    )
                    .with_origin(AuditOrigin::Daemon),
                );
                return;
            }
        };

        let tunnel = match session.accept_host_bridge_stream(stream_id.clone()).await {
            Ok(t) => t,
            Err(err) => {
                let _ = session
                    .reject_host_bridge_stream(stream_id, err.to_string())
                    .await;
                return;
            }
        };
        let mut guest_stream = tunnel.into_stream();
        let (bytes_in, bytes_out) =
            match tokio::io::copy_bidirectional(&mut guest_stream, &mut host_stream).await {
                Ok((guest_to_host, host_to_guest)) => (host_to_guest, guest_to_host),
                Err(_) => (guest_stream.bytes_in(), guest_stream.bytes_out()),
            };
        audit_sink.record(
            AuditEvent::now(
                &sandbox_id,
                AuditEventKind::HostServiceBridge {
                    name: svc.name,
                    guest_port,
                    target: svc.target,
                    bytes_in,
                    bytes_out,
                    allowed: true,
                },
            )
            .with_origin(AuditOrigin::Daemon),
        );
    } else {
        let mut host_stream = match tokio::net::TcpStream::connect(&svc.target).await {
            Ok(s) => s,
            Err(err) => {
                let _ = session
                    .reject_host_bridge_stream(stream_id, err.to_string())
                    .await;
                audit_sink.record(
                    AuditEvent::now(
                        &sandbox_id,
                        AuditEventKind::HostServiceBridge {
                            name: svc.name,
                            guest_port,
                            target: svc.target,
                            bytes_in: 0,
                            bytes_out: 0,
                            allowed: false,
                        },
                    )
                    .with_origin(AuditOrigin::Daemon),
                );
                return;
            }
        };

        let tunnel = match session.accept_host_bridge_stream(stream_id.clone()).await {
            Ok(t) => t,
            Err(err) => {
                let _ = session
                    .reject_host_bridge_stream(stream_id, err.to_string())
                    .await;
                return;
            }
        };
        let mut guest_stream = tunnel.into_stream();
        let (bytes_in, bytes_out) =
            match tokio::io::copy_bidirectional(&mut guest_stream, &mut host_stream).await {
                Ok((guest_to_host, host_to_guest)) => (host_to_guest, guest_to_host),
                Err(_) => (guest_stream.bytes_in(), guest_stream.bytes_out()),
            };
        audit_sink.record(
            AuditEvent::now(
                &sandbox_id,
                AuditEventKind::HostServiceBridge {
                    name: svc.name,
                    guest_port,
                    target: svc.target,
                    bytes_in,
                    bytes_out,
                    allowed: true,
                },
            )
            .with_origin(AuditOrigin::Daemon),
        );
    }
}

const LIST_DIR_SCRIPT: &str = r#"dir="$1"
if [ ! -e "/workspace" ]; then
  case "$dir" in
    /workspace) dir="." ;;
    /workspace/*) dir="./${dir#/workspace/}" ;;
  esac
fi
if [ ! -e "$dir" ]; then
  printf 'path not found: %s\n' "$1" >&2
  exit 3
fi
if [ ! -d "$dir" ]; then
  printf 'not a directory: %s\n' "$1" >&2
  exit 2
fi
if [ ! -r "$dir" ] || [ ! -x "$dir" ]; then
  printf 'permission denied: %s\n' "$1" >&2
  exit 4
fi
cd "$dir" 2>/dev/null || { printf 'permission denied: %s\n' "$1" >&2; exit 4; }
for f in .[!.]* ..?* *; do
  [ -e "$f" ] || [ -L "$f" ] || continue
  if [ -L "$f" ]; then
    if [ -d "$f" ]; then t="symlink_dir"; else t="symlink"; fi
  elif [ -d "$f" ]; then
    t="dir"
  elif [ -f "$f" ]; then
    t="file"
  else
    t="other"
  fi
  st=$(stat -c '%a|%Y|%s' -- "$f" 2>/dev/null || printf -- '---|0|0')
  printf '%s|%s|%s\0' "$t" "$st" "$f"
done
"#;

const LIST_PORTS_SCRIPT: &str = r#"printf '===V4===\n'
cat /proc/net/tcp 2>/dev/null || true
printf '===V6===\n'
cat /proc/net/tcp6 2>/dev/null || true
"#;

fn join_guest_path(dir: &str, name: &str) -> String {
    let trimmed = dir.trim_end_matches('/');
    if trimmed.is_empty() {
        format!("/{name}")
    } else {
        format!("{trimmed}/{name}")
    }
}

fn parse_list_dir_output(dir: &str, stdout: &str) -> Vec<FsEntry> {
    let mut entries = Vec::new();
    for record in stdout.split('\0') {
        if record.is_empty() {
            continue;
        }
        let mut parts = record.splitn(5, '|');
        let (Some(kind), Some(mode), Some(mtime_s), Some(size_s), Some(name)) = (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        ) else {
            continue;
        };
        if name.is_empty() || name == "." || name == ".." {
            continue;
        }
        let is_dir = kind == "dir" || kind == "symlink_dir";
        entries.push(FsEntry {
            name: name.to_string(),
            path: join_guest_path(dir, name),
            kind: kind.to_string(),
            mode: mode.to_string(),
            mtime: mtime_s.parse::<i64>().unwrap_or(0),
            size: size_s.parse::<u64>().unwrap_or(0),
            is_dir,
        });
    }
    entries.sort_by(|a, b| b.is_dir.cmp(&a.is_dir).then_with(|| a.name.cmp(&b.name)));
    entries
}

fn parse_listening_ports_output(
    sandbox_id: &str,
    stdout: &str,
    allow_ports: &[u16],
) -> Vec<ListeningPort> {
    let mut port_map: BTreeMap<u16, String> = BTreeMap::new();
    let mut is_v6 = false;
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed == "===V4===" {
            is_v6 = false;
            continue;
        }
        if trimmed == "===V6===" {
            is_v6 = true;
            continue;
        }
        parse_proc_net_tcp_line(trimmed, is_v6, &mut port_map);
    }

    port_map
        .into_iter()
        .map(|(port, address)| ListeningPort {
            port,
            address,
            allowed: allow_ports.contains(&port),
            proxy_url: format!("/v1/sandboxes/{sandbox_id}/proxy/{port}/"),
        })
        .collect()
}

fn parse_proc_net_tcp_line(line: &str, is_v6: bool, out: &mut BTreeMap<u16, String>) {
    let mut cols = line.split_whitespace();
    let Some(sl) = cols.next() else {
        return;
    };
    if sl == "sl" {
        return;
    }
    let Some(local_addr) = cols.next() else {
        return;
    };
    let Some(_rem_addr) = cols.next() else {
        return;
    };
    let Some(state) = cols.next() else {
        return;
    };
    // 0A = TCP_LISTEN
    if !state.eq_ignore_ascii_case("0A") {
        return;
    }
    let Some((ip_hex, port_hex)) = local_addr.split_once(':') else {
        return;
    };
    let Ok(port) = u16::from_str_radix(port_hex, 16) else {
        return;
    };
    if port == 0 {
        return;
    }
    let addr = if is_v6 {
        decode_proc_ipv6(ip_hex)
    } else {
        decode_proc_ipv4(ip_hex)
    };
    if let Some(addr_str) = addr {
        out.entry(port).or_insert(addr_str);
    }
}

fn decode_proc_ipv4(hex_str: &str) -> Option<String> {
    if hex_str.len() != 8 {
        return None;
    }
    let val = u32::from_str_radix(hex_str, 16).ok()?;
    Some(Ipv4Addr::from(val.to_ne_bytes()).to_string())
}

fn decode_proc_ipv6(hex_str: &str) -> Option<String> {
    if hex_str.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for i in 0..4 {
        let chunk = &hex_str[i * 8..(i + 1) * 8];
        let word = u32::from_str_radix(chunk, 16).ok()?;
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&word.to_ne_bytes());
    }
    Some(Ipv6Addr::from(bytes).to_string())
}

fn is_valid_content_hash(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

impl Drop for SandboxManager {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.reaper_shutdown_tx.lock() {
            if let Some(tx) = guard.take() {
                let _ = tx.send(true);
            }
        }
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn parse_proc_net_tcp_v4_and_v6_listening_ports() {
        let sample = "\
===V4===
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345
   1: 00000000:0BB8 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12346
   2: 0100007F:9999 0100007F:1F90 01 00000000:00000000 00:00000000 00000000  1000        0 12347
===V6===
  sl  local_address                         remote_address                        st
   0: 00000000000000000000000001000000:1435 00000000000000000000000000000000:0000 0A
   1: 00000000000000000000000000000000:0BB8 00000000000000000000000000000000:0000 0A
";
        let ports = parse_listening_ports_output("bw-test123", sample, &[3000, 5173]);
        assert_eq!(ports.len(), 3);
        assert_eq!(ports[0].port, 3000);
        assert_eq!(ports[0].address, "0.0.0.0"); // v4 preferred over duplicate v6
        assert!(ports[0].allowed);
        assert_eq!(ports[0].proxy_url, "/v1/sandboxes/bw-test123/proxy/3000/");

        assert_eq!(ports[1].port, 5173);
        assert_eq!(ports[1].address, "::1");
        assert!(ports[1].allowed);
        assert_eq!(ports[1].proxy_url, "/v1/sandboxes/bw-test123/proxy/5173/");

        assert_eq!(ports[2].port, 8080);
        assert_eq!(ports[2].address, "127.0.0.1");
        assert!(!ports[2].allowed);
        assert_eq!(ports[2].proxy_url, "/v1/sandboxes/bw-test123/proxy/8080/");
    }

    #[test]
    fn parse_list_dir_sorts_dirs_first_then_alphabetical() {
        let out = "file|644|1700000000|12|b.txt\0dir|755|1700000001|4096|zdir\0file|644|1700000002|5|a.txt\0symlink_dir|777|1700000003|4|alink\0";
        let entries = parse_list_dir_output("/workspace/", out);
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["alink", "zdir", "a.txt", "b.txt"]);
        assert!(entries[0].is_dir);
        assert!(entries[1].is_dir);
        assert!(!entries[2].is_dir);
        assert_eq!(entries[2].path, "/workspace/a.txt");
    }
}
