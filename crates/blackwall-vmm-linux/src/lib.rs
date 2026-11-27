//! Rootless Linux KVM VMM backend powered by `cloud-hypervisor`.
//!
//! Implements [`blackwall_vmm::VmmBackend`] with:
//! - Strictly read-only `vda` (`O_RDONLY`) and unlinked ephemeral `vdb` (`O_TMPFILE` + `ftruncate`)
//! - Pre-`exec` 100% rootless jail (`CLONE_NEWUSER`, empty `CLONE_NEWNET`, `CLONE_NEWPID`,
//!   `CLONE_NEWNS` + `pivot_root`, Landlock, `PR_SET_DUMPABLE=0`, `PR_SET_NO_NEW_PRIVS=1`,
//!   `PR_SCHED_CORE`, and `seccomp-bpf` explicitly denying `SYS_connect`)
//! - Host-initiated hybrid `vsock` handshake for Ports 1002, 1001 (`SHUT_WR`), and 1000
//!   followed by immediate `unlink()` of `vsock.sock`
//! - Deterministic fatal exit monitoring emitting `AuditEventKind::VmmFatalExit`

pub mod jail;
pub mod monitor;
pub mod seccomp;
pub mod storage;

pub use jail::{
    apply_vmm_landlock, enable_sched_core_cookie, probe_landlock_available,
    probe_sched_core_available, EffectiveVmmPaths, JailPolicy, RootlessVmmJail, SchedCoreStatus,
};
pub use monitor::{classify_vmm_exit, detect_fatal_signature, VmmMonitorState};
pub use seccomp::{
    apply_vmm_seccomp_filter, build_vmm_seccomp_filter, build_vmm_seccomp_filter_with_deny_action,
    vmm_unconditional_allowed_syscalls,
};
pub use storage::{clear_cloexec, create_unlinked_scratch, open_vda_readonly};

use blackwall_audit::{AuditEvent, AuditEventKind};
use blackwall_vmm::{
    perform_host_handshake, HandshakeConfig, Result, VmExitStatus, VmInstance, VmLaunchConfig,
    VmmBackend, VmmError, VsockChannels,
};
use std::fs::{self, OpenOptions};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;

/// Console configuration passed to `cloud-hypervisor --console`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ConsoleMode {
    /// Virtio console piped to `cloud-hypervisor`'s stdout (requires controlling TTY).
    Tty,
    /// Disable virtio console completely.
    Off,
    /// Discard console output (`/dev/null`) — safe for headless daemon spawns.
    #[default]
    Null,
    /// Write console output to a specific file path.
    File(PathBuf),
}

impl ConsoleMode {
    pub fn to_ch_arg(&self) -> String {
        match self {
            ConsoleMode::Tty => "tty".into(),
            ConsoleMode::Off => "off".into(),
            ConsoleMode::Null => "null".into(),
            ConsoleMode::File(p) => format!("file={}", p.display()),
        }
    }
}

/// Action passed to `cloud-hypervisor --seccomp`.
///
/// Defaults to `False` because Blackwall installs its own stricter pre-`exec`
/// `seccomp-bpf` filter (explicitly denying `SYS_connect`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ChSeccompMode {
    #[default]
    False,
    True,
    Log,
    Errno,
}

impl ChSeccompMode {
    pub fn as_str(self) -> &'static str {
        match self {
            ChSeccompMode::False => "false",
            ChSeccompMode::True => "true",
            ChSeccompMode::Log => "log",
            ChSeccompMode::Errno => "errno",
        }
    }
}

/// Parameters used by [`build_ch_args`] to construct the exact `cloud-hypervisor` CLI.
#[derive(Debug, Clone)]
pub struct ChArgsConfig {
    pub kernel_path: PathBuf,
    pub initramfs_path: PathBuf,
    pub vda_disk: String,
    pub vdb_disk: String,
    pub vcpus: u32,
    pub memory_mib: u64,
    pub vsock_socket_path: PathBuf,
    pub rng_source: PathBuf,
    pub console_mode: ConsoleMode,
    pub ch_seccomp: ChSeccompMode,
    pub enable_pvpanic: bool,
}

/// Build the exact `cloud-hypervisor` CLI argument vector.
///
/// Architectural invariants enforced here:
/// - Exactly 2 virtio-blk disks: `vda` strictly `readonly=on`, `vdb` ephemeral read-write
/// - Exactly 1 `virtio-vsock` device (`cid=3`, hybrid Unix socket)
/// - `virtio-rng` backed by `/dev/urandom`
/// - Zero `virtio-net` (`--net`), zero `virtiofs` (`--fs`), zero `vhost-user`
/// - Deterministic exit on guest reset/shutdown (`--guest-reset-action exit-vmm`,
///   `--guest-shutdown-action exit-vmm`) and optional `--pvpanic`
pub fn build_ch_args(cfg: &ChArgsConfig) -> Vec<String> {
    let mut args = vec![
        "--kernel".into(),
        cfg.kernel_path.to_string_lossy().into_owned(),
        "--initramfs".into(),
        cfg.initramfs_path.to_string_lossy().into_owned(),
        "--cpus".into(),
        format!("boot={}", cfg.vcpus),
        "--memory".into(),
        format!("size={}M", cfg.memory_mib),
        "--disk".into(),
        format!("path={},readonly=on,image_type=raw", cfg.vda_disk),
        format!("path={},image_type=raw", cfg.vdb_disk),
        "--vsock".into(),
        format!("cid=3,socket={}", cfg.vsock_socket_path.display()),
        "--rng".into(),
        format!("src={}", cfg.rng_source.display()),
        "--console".into(),
        cfg.console_mode.to_ch_arg(),
        "--serial".into(),
        "off".into(),
        "--guest-reset-action".into(),
        "exit-vmm".into(),
        "--guest-shutdown-action".into(),
        "exit-vmm".into(),
        "--seccomp".into(),
        cfg.ch_seccomp.as_str().into(),
    ];

    if cfg.enable_pvpanic {
        args.push("--pvpanic".into());
    }

    args
}

/// Host Linux prerequisite diagnostic report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxVmmPrereqs {
    pub kvm_present: bool,
    pub kvm_accessible: bool,
    pub cloud_hypervisor_path: Option<PathBuf>,
    pub cloud_hypervisor_version: Option<String>,
    pub landlock_available: bool,
    pub sched_core_available: bool,
}

impl LinuxVmmPrereqs {
    /// Returns `true` when both `/dev/kvm` (read-write) and `cloud-hypervisor` are available.
    pub fn is_ready(&self) -> bool {
        self.kvm_accessible && self.cloud_hypervisor_path.is_some()
    }

    /// Return human-readable diagnostic messages for any missing prerequisites.
    pub fn missing_requirements(&self) -> Vec<String> {
        let mut missing = Vec::new();
        if !self.kvm_present {
            missing.push("/dev/kvm does not exist (KVM virtualization unavailable)".into());
        } else if !self.kvm_accessible {
            missing.push("/dev/kvm exists but is not read/write accessible by current user".into());
        }
        if self.cloud_hypervisor_path.is_none() {
            missing.push("cloud-hypervisor binary not found in PATH".into());
        }
        missing
    }
}

/// Probe host Linux KVM, `cloud-hypervisor`, Landlock, and `PR_SCHED_CORE` availability.
pub fn check_linux_vmm_prereqs() -> LinuxVmmPrereqs {
    let kvm_path = Path::new("/dev/kvm");
    let kvm_present = kvm_path.exists();
    let kvm_accessible = kvm_present
        && OpenOptions::new()
            .read(true)
            .write(true)
            .open(kvm_path)
            .is_ok();

    let cloud_hypervisor_path = find_executable_in_path("cloud-hypervisor");
    let cloud_hypervisor_version = cloud_hypervisor_path.as_ref().and_then(|bin| {
        Command::new(bin)
            .arg("--version")
            .output()
            .ok()
            .filter(|out| out.status.success())
            .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string())
            .filter(|s| !s.is_empty())
    });

    LinuxVmmPrereqs {
        kvm_present,
        kvm_accessible,
        cloud_hypervisor_path,
        cloud_hypervisor_version,
        landlock_available: probe_landlock_available(),
        sched_core_available: probe_sched_core_available(),
    }
}

fn find_executable_in_path(name: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(name);
        if is_executable_file(&candidate) {
            return Some(candidate);
        }
    }
    None
}

fn is_executable_file(path: &Path) -> bool {
    fs::metadata(path)
        .map(|m| m.is_file() && (m.permissions().mode() & 0o111) != 0)
        .unwrap_or(false)
}

/// Configuration for [`LinuxVmmBackend`].
#[derive(Debug, Clone)]
pub struct LinuxVmmConfig {
    /// Explicit path to `cloud-hypervisor` (auto-discovered via `PATH` when `None`).
    pub cloud_hypervisor_bin: Option<PathBuf>,
    /// Directory where unlinked `O_TMPFILE` scratch `vdb` files are allocated.
    pub scratch_base_dir: PathBuf,
    /// Directory where per-VM `0700` ephemeral `vsock-dir/` directories are created.
    pub runtime_base_dir: PathBuf,
    /// Host-initiated `vsock` handshake timeout and retry parameters.
    pub handshake: HandshakeConfig,
    /// Console capture mode passed to `cloud-hypervisor --console`.
    pub console_mode: ConsoleMode,
    /// Cloud Hypervisor internal `--seccomp` setting (defaults to `False` since
    /// Blackwall applies its own stricter pre-`exec` seccomp-bpf filter).
    pub ch_seccomp: ChSeccompMode,
    /// Enable `--pvpanic` for deterministic guest panic reporting.
    pub enable_pvpanic: bool,
    /// Hardening layers enforced by `RootlessVmmJail`.
    pub jail_policy: JailPolicy,
}

impl Default for LinuxVmmConfig {
    fn default() -> Self {
        let runtime_root = std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        Self {
            cloud_hypervisor_bin: None,
            scratch_base_dir: std::env::temp_dir(),
            runtime_base_dir: runtime_root.join("blackwall-vmm"),
            handshake: HandshakeConfig::default(),
            console_mode: ConsoleMode::Tty,
            ch_seccomp: ChSeccompMode::False,
            enable_pvpanic: true,
            jail_policy: JailPolicy::default(),
        }
    }
}

/// Rootless Linux KVM VMM backend launching jailed `cloud-hypervisor` instances.
#[derive(Debug, Clone, Default)]
pub struct LinuxVmmBackend {
    config: LinuxVmmConfig,
}

impl LinuxVmmBackend {
    pub fn new(config: LinuxVmmConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &LinuxVmmConfig {
        &self.config
    }

    fn resolve_ch_binary(&self) -> Result<PathBuf> {
        if let Some(ref bin) = self.config.cloud_hypervisor_bin {
            if is_executable_file(bin) {
                return Ok(bin.clone());
            }
            return Err(VmmError::PrereqFailed(format!(
                "configured cloud-hypervisor binary is not executable: {}",
                bin.display()
            )));
        }
        find_executable_in_path("cloud-hypervisor").ok_or_else(|| {
            VmmError::PrereqFailed("cloud-hypervisor binary not found in PATH".into())
        })
    }
}

/// Running rootless `cloud-hypervisor` microVM instance.
pub struct LinuxVmInstance {
    sandbox_id: String,
    pid: u32,
    child: Mutex<Child>,
    channels: Mutex<Option<VsockChannels>>,
    monitor: Arc<VmmMonitorState>,
    watcher_handles: Mutex<Vec<thread::JoinHandle<()>>>,
    vm_runtime_dir: PathBuf,
    cached_exit: Mutex<Option<VmExitStatus>>,
}

impl LinuxVmInstance {
    /// Return a snapshot of captured VMM stderr/console logs.
    pub fn captured_log(&self) -> String {
        self.monitor.captured_log()
    }

    fn join_watchers(&self) {
        if let Ok(mut guard) = self.watcher_handles.lock() {
            for handle in guard.drain(..) {
                let _ = handle.join();
            }
        }
    }

    fn cleanup_runtime_dir(&self) {
        let _ = fs::remove_dir_all(&self.vm_runtime_dir);
    }
}

impl VmInstance for LinuxVmInstance {
    fn id(&self) -> &str {
        &self.sandbox_id
    }

    fn pid(&self) -> u32 {
        self.pid
    }

    fn take_channels(&self) -> Result<VsockChannels> {
        let mut guard = self
            .channels
            .lock()
            .map_err(|_| VmmError::ProcessError("channels mutex poisoned".into()))?;
        guard.take().ok_or(VmmError::ChannelsAlreadyTaken)
    }

    fn is_alive(&self) -> bool {
        if let Ok(guard) = self.cached_exit.lock() {
            if guard.is_some() {
                return false;
            }
        }
        let Ok(mut child) = self.child.lock() else {
            return false;
        };
        match child.try_wait() {
            Ok(None) => true,
            Ok(Some(status)) => {
                let classified = self.monitor.record_exit(status);
                if let Ok(mut exit_guard) = self.cached_exit.lock() {
                    *exit_guard = Some(classified);
                }
                false
            }
            Err(_) => false,
        }
    }

    fn kill(&self) -> Result<()> {
        self.monitor.mark_host_killed();
        let mut child = self
            .child
            .lock()
            .map_err(|_| VmmError::ProcessError("child mutex poisoned".into()))?;
        match child.kill() {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::InvalidInput => {
                // Already exited.
            }
            Err(err) => return Err(VmmError::Io(err)),
        }
        let status = child.wait()?;
        drop(child);

        self.join_watchers();
        let classified = self.monitor.record_exit(status);
        if let Ok(mut exit_guard) = self.cached_exit.lock() {
            *exit_guard = Some(classified);
        }
        self.cleanup_runtime_dir();
        Ok(())
    }

    fn wait(&self) -> Result<VmExitStatus> {
        if let Ok(guard) = self.cached_exit.lock() {
            if let Some(ref existing) = *guard {
                return Ok(existing.clone());
            }
        }

        let status = {
            let mut child = self
                .child
                .lock()
                .map_err(|_| VmmError::ProcessError("child mutex poisoned".into()))?;
            child.wait()?
        };

        self.join_watchers();
        let classified = self.monitor.record_exit(status);
        if let Ok(mut exit_guard) = self.cached_exit.lock() {
            *exit_guard = Some(classified.clone());
        }
        self.cleanup_runtime_dir();
        Ok(classified)
    }
}

impl Drop for LinuxVmInstance {
    fn drop(&mut self) {
        if self.is_alive() {
            let _ = self.kill();
        } else {
            self.cleanup_runtime_dir();
        }
    }
}

impl VmmBackend for LinuxVmmBackend {
    fn name(&self) -> &'static str {
        "linux-cloud-hypervisor"
    }

    fn launch(&self, config: VmLaunchConfig) -> Result<Box<dyn VmInstance>> {
        config.validate()?;

        // Check required prerequisites before allocating per-VM state.
        let ch_binary = self.resolve_ch_binary()?;
        OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/kvm")
            .map_err(|e| VmmError::PrereqFailed(format!("/dev/kvm not accessible: {e}")))?;

        for (label, p) in [
            ("kernel", &config.kernel_path),
            ("initramfs", &config.initramfs_path),
            ("vda", &config.vda_erofs_path),
        ] {
            if !p.is_file() {
                return Err(VmmError::InvalidConfig(format!(
                    "{label} path does not exist or is not a file: {}",
                    p.display()
                )));
            }
        }

        config.audit_sink.record(AuditEvent::now(
            &config.sandbox_id,
            AuditEventKind::SandboxLifecycle {
                phase: "vmm_launching".into(),
                image_roothash: None,
                details: Some(format!(
                    "vcpus={} memory_mib={} workspace_mib={} net_mux={}",
                    config.vcpus, config.memory_mib, config.workspace_mib, config.enable_net_mux
                )),
            },
        ));

        // 1. Validate vda readability and create a private 0700 per-VM runtime dir
        //    containing vsock-dir/, pivot staging, and the ephemeral sparse vdb file
        //    (which is unlinked immediately after handshake so it has zero host links).
        let _vda_check = open_vda_readonly(&config.vda_erofs_path)?;
        drop(_vda_check);

        let vm_runtime_dir = self
            .config
            .runtime_base_dir
            .join(format!("{}-{}", config.sandbox_id, std::process::id()));
        let vsock_host_dir = vm_runtime_dir.join("vsock");
        let pivot_staging_dir = vm_runtime_dir.join("root");
        let vdb_host_path = vm_runtime_dir.join("vdb.raw");
        fs::create_dir_all(&vsock_host_dir)?;
        fs::set_permissions(&vm_runtime_dir, fs::Permissions::from_mode(0o700))?;
        fs::set_permissions(&vsock_host_dir, fs::Permissions::from_mode(0o700))?;

        {
            use std::os::unix::fs::OpenOptionsExt;
            let vdb_file = OpenOptions::new()
                .create_new(true)
                .read(true)
                .write(true)
                .mode(0o600)
                .open(&vdb_host_path)?;
            vdb_file.set_len(config.workspace_mib * 1024 * 1024)?;
        }

        // 2. Pre-compile the VMM seccomp-bpf program in the parent before fork().
        let seccomp_prog = if self.config.jail_policy.enable_seccomp {
            Some(build_vmm_seccomp_filter()?)
        } else {
            None
        };

        let jail = RootlessVmmJail {
            vsock_host_dir: vsock_host_dir.clone(),
            pivot_staging_dir,
            ch_binary,
            kernel_path: config.kernel_path.clone(),
            initramfs_path: config.initramfs_path.clone(),
            vda_path: Some(config.vda_erofs_path.clone()),
            vdb_path: Some(vdb_host_path.clone()),
            policy: self.config.jail_policy,
        };
        let eff = jail.effective_paths();

        let ch_args = build_ch_args(&ChArgsConfig {
            kernel_path: eff.kernel_path,
            initramfs_path: eff.initramfs_path,
            vda_disk: eff
                .vda_path
                .as_ref()
                .unwrap()
                .to_string_lossy()
                .into_owned(),
            vdb_disk: eff
                .vdb_path
                .as_ref()
                .unwrap()
                .to_string_lossy()
                .into_owned(),
            vcpus: config.vcpus,
            memory_mib: config.memory_mib,
            vsock_socket_path: eff.vsock_socket_path,
            rng_source: PathBuf::from(jail::JAILED_DEV_URANDOM),
            console_mode: self.config.console_mode.clone(),
            ch_seccomp: self.config.ch_seccomp,
            enable_pvpanic: self.config.enable_pvpanic,
        });

        tracing::debug!(
            sandbox_id = %config.sandbox_id,
            bin = %eff.ch_binary.display(),
            args = ?ch_args,
            "spawning jailed cloud-hypervisor"
        );

        let mut cmd = Command::new(&eff.ch_binary);
        cmd.args(&ch_args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        // SAFETY: pre_exec runs in the forked child before execve, applying the full
        // rootless jail (userns, empty netns, pivot_root with read-only vda & vdb,
        // dumpable=0, sched_core, landlock, no_new_privs, seccomp-bpf).
        unsafe {
            cmd.pre_exec(move || {
                jail.apply_pre_exec(seccomp_prog.as_ref())
                    .map_err(|e| std::io::Error::other(e.to_string()))
            });
        }

        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(err) => {
                let _ = fs::remove_dir_all(&vm_runtime_dir);
                return Err(VmmError::LaunchFailed(format!(
                    "failed to spawn cloud-hypervisor: {err}"
                )));
            }
        };

        let pid = child.id();
        let monitor = VmmMonitorState::new(config.sandbox_id.clone(), Arc::clone(&config.audit_sink));
        let mut watchers = Vec::new();
        if let Some(stdout) = child.stdout.take() {
            watchers.push(monitor.spawn_stream_watcher(stdout, "stdout"));
        }
        if let Some(stderr) = child.stderr.take() {
            watchers.push(monitor.spawn_stream_watcher(stderr, "stderr"));
        }

        // 4. Perform host-initiated hybrid vsock handshake on host-side vsock.sock,
        //    enforce SHUT_WR on Port 1001, and immediately unlink vsock.sock.
        let host_vsock_sock = vsock_host_dir.join("vsock.sock");
        let channels = match perform_host_handshake(
            &host_vsock_sock,
            config.enable_net_mux,
            &self.config.handshake,
        ) {
            Ok(ch) => {
                // Immediately unlink ephemeral scratch vdb on the host once CH has opened it
                // so it carries zero host directory entries and auto-reclaims on VMM exit.
                let _ = fs::remove_file(&vdb_host_path);
                ch
            }
            Err(err) => {
                monitor.mark_host_killed();
                let _ = child.kill();
                if let Ok(status) = child.wait() {
                    let _ = monitor.record_exit(status);
                }
                for h in watchers {
                    let _ = h.join();
                }
                let _ = fs::remove_dir_all(&vm_runtime_dir);
                let captured = monitor.captured_log();
                if captured.trim().is_empty() {
                    return Err(err);
                }
                return Err(VmmError::LaunchFailed(format!(
                    "{err}; cloud-hypervisor output:\n{}",
                    captured.trim()
                )));
            }
        };

        config.audit_sink.record(AuditEvent::now(
            &config.sandbox_id,
            AuditEventKind::SandboxLifecycle {
                phase: "vmm_ready".into(),
                image_roothash: None,
                details: Some(format!("pid={pid}")),
            },
        ));

        Ok(Box::new(LinuxVmInstance {
            sandbox_id: config.sandbox_id,
            pid,
            child: Mutex::new(child),
            channels: Mutex::new(Some(channels)),
            monitor,
            watcher_handles: Mutex::new(watchers),
            vm_runtime_dir,
            cached_exit: Mutex::new(None),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blackwall_audit::MemoryAuditSink;

    #[test]
    fn build_ch_args_enforces_two_disk_vsock_no_net_no_virtiofs() {
        let args = build_ch_args(&ChArgsConfig {
            kernel_path: PathBuf::from("/boot/vmlinux"),
            initramfs_path: PathBuf::from("/boot/initramfs"),
            vda_disk: "/disks/vda.erofs".into(),
            vdb_disk: "/disks/vdb.raw".into(),
            vcpus: 4,
            memory_mib: 2048,
            vsock_socket_path: PathBuf::from("/vsock/vsock.sock"),
            rng_source: PathBuf::from("/dev/urandom"),
            console_mode: ConsoleMode::Tty,
            ch_seccomp: ChSeccompMode::False,
            enable_pvpanic: true,
        });

        // Verify exact disk, vsock, cpu, memory, rng, console, and seccomp arguments.
        assert_eq!(
            args,
            vec![
                "--kernel",
                "/boot/vmlinux",
                "--initramfs",
                "/boot/initramfs",
                "--cpus",
                "boot=4",
                "--memory",
                "size=2048M",
                "--disk",
                "path=/disks/vda.erofs,readonly=on,image_type=raw",
                "path=/disks/vdb.raw,image_type=raw",
                "--vsock",
                "cid=3,socket=/vsock/vsock.sock",
                "--rng",
                "src=/dev/urandom",
                "--console",
                "tty",
                "--serial",
                "off",
                "--guest-reset-action",
                "exit-vmm",
                "--guest-shutdown-action",
                "exit-vmm",
                "--seccomp",
                "false",
                "--pvpanic",
            ]
        );

        // Explicitly assert forbidden host trust surfaces are absent.
        for forbidden in ["--net", "--fs", "virtio-net", "virtiofs", "vhost"] {
            assert!(
                !args.iter().any(|a| a.contains(forbidden)),
                "forbidden argument {forbidden} found in cloud-hypervisor args: {args:?}"
            );
        }
    }

    #[test]
    fn check_linux_vmm_prereqs_reports_cleanly() {
        let prereqs = check_linux_vmm_prereqs();
        if prereqs.is_ready() {
            assert!(prereqs.kvm_present);
            assert!(prereqs.kvm_accessible);
            assert!(prereqs.cloud_hypervisor_path.is_some());
            assert!(prereqs.missing_requirements().is_empty());
        } else {
            assert!(!prereqs.missing_requirements().is_empty());
        }
    }

    /// Gated live KVM boot test: checks for `cloud-hypervisor`, `/dev/kvm`, and
    /// built guest artifacts (`vmlinux-lo` / `vmlinux-noinet` + initramfs + vda).
    /// When artifacts/tools are absent, prints a clear diagnostic listing what is
    /// missing and returns cleanly without false failure.
    #[test]
    fn gated_live_kvm_boot_test() {
        let prereqs = check_linux_vmm_prereqs();
        let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap_or_else(|_| PathBuf::from("."));

        let kernel_candidates = [
            std::env::var_os("BLACKWALL_KERNEL_PATH").map(PathBuf::from),
            Some(workspace_root.join("kernel/out/vmlinux-lo")),
            Some(workspace_root.join("kernel/out/vmlinux-noinet")),
        ];
        let kernel_path = kernel_candidates
            .into_iter()
            .flatten()
            .find(|p| p.is_file());

        let initramfs_candidates = [
            std::env::var_os("BLACKWALL_INITRAMFS_PATH").map(PathBuf::from),
            Some(workspace_root.join("kernel/out/initramfs.cpio.gz")),
            Some(workspace_root.join("kernel/out/initramfs.cpio")),
        ];
        let initramfs_path = initramfs_candidates
            .into_iter()
            .flatten()
            .find(|p| p.is_file());

        let vda_candidates = [
            std::env::var_os("BLACKWALL_VDA_PATH").map(PathBuf::from),
            Some(workspace_root.join("kernel/out/vda.erofs")),
        ];
        let vda_path = vda_candidates.into_iter().flatten().find(|p| p.is_file());

        let mut missing = prereqs.missing_requirements();
        if kernel_path.is_none() {
            missing.push(
                "guest kernel artifact missing (expected BLACKWALL_KERNEL_PATH or kernel/out/vmlinux-lo / kernel/out/vmlinux-noinet)".into(),
            );
        }
        if initramfs_path.is_none() {
            missing.push(
                "guest initramfs artifact missing (expected BLACKWALL_INITRAMFS_PATH or kernel/out/initramfs.cpio.gz)".into(),
            );
        }
        if vda_path.is_none() {
            missing.push(
                "guest vda erofs image missing (expected BLACKWALL_VDA_PATH or kernel/out/vda.erofs)".into(),
            );
        }

        if !missing.is_empty() {
            eprintln!(
                "[gated_live_kvm_boot_test] SKIPPING live KVM boot — missing tools/artifacts:\n  - {}",
                missing.join("\n  - ")
            );
            return;
        }

        let sink = Arc::new(MemoryAuditSink::new());
        let backend = LinuxVmmBackend::default();
        let vm = backend
            .launch(VmLaunchConfig {
                sandbox_id: "sb-live-kvm-test".into(),
                kernel_path: kernel_path.unwrap(),
                initramfs_path: initramfs_path.unwrap(),
                vda_erofs_path: vda_path.unwrap(),
                vcpus: 1,
                memory_mib: 256,
                workspace_mib: 64,
                enable_net_mux: false,
                audit_sink: sink,
            })
            .expect("live rootless KVM boot + vsock handshake should succeed");

        assert!(vm.is_alive());
        let _channels = vm.take_channels().expect("channels available once");
        assert!(vm.take_channels().is_err());
        vm.kill().expect("clean VM teardown");
    }
}
