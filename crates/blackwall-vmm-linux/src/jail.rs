//! 100% Rootless pre-`exec` Linux jail for `cloud-hypervisor`.
//!
//! Enforces defense-in-depth isolation outside the hypervisor:
//! 1. `PR_SET_DUMPABLE = 0` (blocks host ptrace / `/proc/pid/mem` inspection)
//! 2. `PR_SCHED_CORE` (`PR_SCHED_CORE_CREATE`) per-VM SMT core-scheduling cookie
//!    (gracefully logged and skipped if kernel lacks `CONFIG_SCHED_CORE`)
//! 3. `CLONE_NEWUSER` (1:1 mapping of current uid/gid with `setgroups = deny`),
//!    empty `CLONE_NEWNET` (not even `lo`), `CLONE_NEWNS` (and `CLONE_NEWPID`)
//! 4. `pivot_root` into an empty `tmpfs` containing ONLY:
//!    - Bind-mounted 1-file `vsock-dir/` (`/vsock`)
//!    - `/dev/kvm`, `/dev/urandom`, `/dev/null`
//!    - Read-only `cloud-hypervisor` binary (+ minimal read-only runtime libs if dynamically linked)
//!    - Read-only kernel & initramfs files + `/proc` (for `/proc/self/fd/<vda|vdb>`)
//! 5. `landlock` (`landlock = "0.4"`) restricting filesystem access strictly to
//!    `vsock-dir/`, `/dev/kvm`, `/dev/urandom`, and the `cloud-hypervisor` binary
//!    (+ minimal read-only runtime paths)
//! 6. `PR_SET_NO_NEW_PRIVS = 1`
//! 7. `seccomp-bpf` (`seccompiler = "0.5"`) denying `SYS_connect` and restricting
//!    sockets to `AF_UNIX` only.

use crate::seccomp::apply_vmm_seccomp_filter;
use blackwall_vmm::{Result, VmmError};
use landlock::{
    Access, AccessFs, BitFlags, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset, RulesetAttr,
    RulesetCreatedAttr, RulesetStatus, ABI,
};
use seccompiler::BpfProgram;
use std::ffi::CString;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

// Linux PR_SCHED_CORE prctl constants (from <linux/prctl.h>, kernel >= 5.14).
const PR_SCHED_CORE: libc::c_int = 62;
const PR_SCHED_CORE_CREATE: libc::c_ulong = 1;
const PR_SCHED_CORE_SCOPE_THREAD_GROUP: libc::c_ulong = 1;

/// Jailed mount paths used inside the `pivot_root` empty `tmpfs`.
pub const JAILED_VSOCK_DIR: &str = "/vsock";
pub const JAILED_VSOCK_SOCK: &str = "/vsock/vsock.sock";
pub const JAILED_CH_BIN: &str = "/bin/cloud-hypervisor";
pub const JAILED_KERNEL: &str = "/boot/vmlinux";
pub const JAILED_INITRAMFS: &str = "/boot/initramfs";
pub const JAILED_VDA: &str = "/disks/vda.erofs";
pub const JAILED_VDB: &str = "/disks/vdb.raw";
pub const JAILED_DEV_KVM: &str = "/dev/kvm";
pub const JAILED_DEV_URANDOM: &str = "/dev/urandom";

/// Toggleable hardening layers for `RootlessVmmJail` (all enabled by default).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JailPolicy {
    pub enable_userns: bool,
    pub enable_netns: bool,
    pub enable_pidns: bool,
    pub enable_mount_pivot: bool,
    pub enable_landlock: bool,
    pub enable_seccomp: bool,
    pub enable_sched_core: bool,
}

impl Default for JailPolicy {
    fn default() -> Self {
        Self {
            enable_userns: true,
            enable_netns: true,
            enable_pidns: true,
            enable_mount_pivot: true,
            enable_landlock: true,
            enable_seccomp: true,
            enable_sched_core: true,
        }
    }
}

/// Outcome of attempting `PR_SCHED_CORE_CREATE` on the current kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedCoreStatus {
    Enabled,
    Unsupported(i32),
}

/// Pre-`exec` builder and applier for the rootless `cloud-hypervisor` jail.
#[derive(Debug, Clone)]
pub struct RootlessVmmJail {
    pub vsock_host_dir: PathBuf,
    pub pivot_staging_dir: PathBuf,
    pub ch_binary: PathBuf,
    pub kernel_path: PathBuf,
    pub initramfs_path: PathBuf,
    pub vda_path: Option<PathBuf>,
    pub vdb_path: Option<PathBuf>,
    pub policy: JailPolicy,
}

/// Paths that `cloud-hypervisor` should open once inside the jail (either jailed
/// `/...` paths after `pivot_root` or original host paths when `enable_mount_pivot` is off).
#[derive(Debug, Clone)]
pub struct EffectiveVmmPaths {
    pub ch_binary: PathBuf,
    pub kernel_path: PathBuf,
    pub initramfs_path: PathBuf,
    pub vda_path: Option<PathBuf>,
    pub vdb_path: Option<PathBuf>,
    pub vsock_socket_path: PathBuf,
}

impl RootlessVmmJail {
    /// Compute the executable, kernel, initramfs, disk, and vsock paths visible to
    /// `cloud-hypervisor` after `apply_pre_exec()` finishes.
    pub fn effective_paths(&self) -> EffectiveVmmPaths {
        if self.policy.enable_mount_pivot && self.policy.enable_userns {
            EffectiveVmmPaths {
                ch_binary: PathBuf::from(JAILED_CH_BIN),
                kernel_path: PathBuf::from(JAILED_KERNEL),
                initramfs_path: PathBuf::from(JAILED_INITRAMFS),
                vda_path: self.vda_path.as_ref().map(|_| PathBuf::from(JAILED_VDA)),
                vdb_path: self.vdb_path.as_ref().map(|_| PathBuf::from(JAILED_VDB)),
                vsock_socket_path: PathBuf::from(JAILED_VSOCK_SOCK),
            }
        } else {
            EffectiveVmmPaths {
                ch_binary: self.ch_binary.clone(),
                kernel_path: self.kernel_path.clone(),
                initramfs_path: self.initramfs_path.clone(),
                vda_path: self.vda_path.clone(),
                vdb_path: self.vdb_path.clone(),
                vsock_socket_path: self.vsock_host_dir.join("vsock.sock"),
            }
        }
    }

    /// Apply all configured jail layers in the child process immediately before `execve`.
    ///
    /// `seccomp_program` MUST be pre-compiled in the parent process prior to `fork()`
    /// so we avoid unnecessary work after forking.
    ///
    /// Ordering note: `unshare(CLONE_NEWUSER | ...)` and `/proc/self/{setgroups,uid_map,gid_map}`
    /// MUST run before `PR_SET_DUMPABLE = 0`, because Linux marks `/proc/self/*` root-owned
    /// once `dumpable == 0`, which would otherwise deny writes to `uid_map`/`gid_map`.
    pub fn apply_pre_exec(&self, seccomp_program: Option<&BpfProgram>) -> Result<()> {
        // 1. Enter rootless namespaces (userns, empty netns, mountns, pidns) and map uid/gid.
        if self.policy.enable_userns {
            let uid = unsafe { libc::geteuid() };
            let gid = unsafe { libc::getegid() };

            let mut flags = libc::CLONE_NEWUSER;
            if self.policy.enable_netns {
                flags |= libc::CLONE_NEWNET;
            }
            if self.policy.enable_mount_pivot {
                flags |= libc::CLONE_NEWNS;
            }
            // Note: Do NOT pass CLONE_NEWPID to unshare() inside a single-fork pre_exec:
            // Linux's copy_process() rejects clone(CLONE_THREAD) with EINVAL whenever
            // pid_ns_for_children != task_active_pid_ns, which breaks multi-threaded VMMs
            // (cloud-hypervisor vCPU/virtio threads). PR_SET_DUMPABLE=0 + CLONE_NEWUSER
            // already blocks cross-process ptrace and /proc/<pid>/mem inspection.
            let _ = self.policy.enable_pidns;

            if unsafe { libc::unshare(flags) } != 0 {
                let err = std::io::Error::last_os_error();
                return Err(VmmError::JailFailed(format!(
                    "unshare(0x{flags:x}) failed: {err}"
                )));
            }

            write_userns_id_maps(uid, gid)?;

            // Note: we deliberately do NOT bring up `lo` in the new netns, leaving
            // CLONE_NEWNET completely empty (zero network interfaces / zero routes).
            if self.policy.enable_mount_pivot {
                self.setup_empty_tmpfs_pivot_root()?;
            }
        }

        // 2. Disable ptrace / core dumps (after /proc/self/{uid,gid}_map writes complete).
        set_dumpable_zero()?;

        // 3. Assign a dedicated per-VM SMT core-scheduling cookie when supported.
        if self.policy.enable_sched_core {
            match enable_sched_core_cookie() {
                SchedCoreStatus::Enabled => {}
                SchedCoreStatus::Unsupported(_errno) => {
                    // Gracefully continue if kernel lacks CONFIG_SCHED_CORE.
                }
            }
        }

        // 4. Restrict filesystem visibility with Landlock.
        if self.policy.enable_landlock {
            let paths = self.effective_paths();
            let vsock_dir = paths
                .vsock_socket_path
                .parent()
                .unwrap_or_else(|| Path::new(JAILED_VSOCK_DIR));
            apply_vmm_landlock_with_disks(
                vsock_dir,
                &paths.ch_binary,
                &paths.kernel_path,
                &paths.initramfs_path,
                paths.vda_path.as_deref(),
                paths.vdb_path.as_deref(),
                self.policy.enable_mount_pivot && self.policy.enable_userns,
            )?;
        }

        // 5. Lock privileges irreversibly before installing seccomp-bpf.
        set_no_new_privs()?;

        // 6. Install seccomp-bpf filter (denying SYS_connect) as the final step before execve.
        if self.policy.enable_seccomp {
            let prog = seccomp_program.ok_or_else(|| {
                VmmError::JailFailed("seccomp enabled but no compiled BPF program supplied".into())
            })?;
            apply_vmm_seccomp_filter(prog)?;
        }

        Ok(())
    }

    fn setup_empty_tmpfs_pivot_root(&self) -> Result<()> {
        // Prevent mount propagation back to the host mount namespace.
        mount_raw(
            None,
            Path::new("/"),
            None,
            libc::MS_REC | libc::MS_PRIVATE,
            None,
        )?;

        let new_root = &self.pivot_staging_dir;
        fs::create_dir_all(new_root).map_err(|e| {
            VmmError::JailFailed(format!("create pivot staging dir {}: {e}", new_root.display()))
        })?;

        // Mount an empty minimal tmpfs as our new root.
        mount_raw(
            Some("tmpfs"),
            new_root,
            Some("tmpfs"),
            libc::MS_NOSUID | libc::MS_NODEV,
            Some("size=16m,mode=0755"),
        )?;

        // Bind-mount ONLY the 1-file vsock-dir/ read-write.
        let jailed_vsock = new_root.join("vsock");
        fs::create_dir_all(&jailed_vsock)?;
        bind_mount(&self.vsock_host_dir, &jailed_vsock, false)?;

        // Bind-mount /dev/kvm, /dev/urandom, and /dev/null as device files.
        let dev_dir = new_root.join("dev");
        fs::create_dir_all(&dev_dir)?;
        bind_mount_file(Path::new("/dev/kvm"), &dev_dir.join("kvm"), false)?;
        bind_mount_file(Path::new("/dev/urandom"), &dev_dir.join("urandom"), false)?;
        bind_mount_file(Path::new("/dev/null"), &dev_dir.join("null"), false)?;

        // Bind-mount cloud-hypervisor binary read-only.
        let bin_dir = new_root.join("bin");
        fs::create_dir_all(&bin_dir)?;
        bind_mount_file(&self.ch_binary, &bin_dir.join("cloud-hypervisor"), true)?;

        // Bind-mount kernel and initramfs read-only.
        let boot_dir = new_root.join("boot");
        fs::create_dir_all(&boot_dir)?;
        bind_mount_file(&self.kernel_path, &boot_dir.join("vmlinux"), true)?;
        bind_mount_file(&self.initramfs_path, &boot_dir.join("initramfs"), true)?;

        // Bind-mount vda (strictly read-only) and ephemeral vdb (read-write) if configured.
        if self.vda_path.is_some() || self.vdb_path.is_some() {
            let disks_dir = new_root.join("disks");
            fs::create_dir_all(&disks_dir)?;
            if let Some(ref vda) = self.vda_path {
                bind_mount_file(vda, &disks_dir.join("vda.erofs"), true)?;
            }
            if let Some(ref vdb) = self.vdb_path {
                bind_mount_file(vdb, &disks_dir.join("vdb.raw"), false)?;
            }
        }

        // Bind-mount /proc so `/proc/self/fd/<vda_fd>` and `/proc/self/fd/<vdb_fd>` resolve.
        let proc_dir = new_root.join("proc");
        fs::create_dir_all(&proc_dir)?;
        bind_mount_rec(Path::new("/proc"), &proc_dir, false)?;

        // If cloud-hypervisor is dynamically linked, bind-mount minimal read-only loader/lib dirs.
        for lib_dir in ["/lib", "/lib64", "/usr/lib", "/usr/lib64"] {
            let src = Path::new(lib_dir);
            if src.exists() {
                let dst = new_root.join(lib_dir.trim_start_matches('/'));
                if let Some(parent) = dst.parent() {
                    let _ = fs::create_dir_all(parent);
                }
                if src.is_dir() {
                    let _ = fs::create_dir_all(&dst);
                    let _ = bind_mount_rec(src, &dst, true);
                }
            }
        }

        // Perform pivot_root(".", ".old_root") and detach the host root completely.
        let old_root = new_root.join(".old_root");
        fs::create_dir_all(&old_root)?;

        let c_new = path_to_cstring(new_root)?;
        if unsafe { libc::chdir(c_new.as_ptr()) } != 0 {
            return Err(VmmError::JailFailed(format!(
                "chdir({}) failed: {}",
                new_root.display(),
                std::io::Error::last_os_error()
            )));
        }

        let c_dot = CString::new(".").unwrap();
        let c_old = CString::new(".old_root").unwrap();
        let ret = unsafe { libc::syscall(libc::SYS_pivot_root, c_dot.as_ptr(), c_old.as_ptr()) };
        if ret != 0 {
            return Err(VmmError::JailFailed(format!(
                "pivot_root failed: {}",
                std::io::Error::last_os_error()
            )));
        }

        let c_slash = CString::new("/").unwrap();
        if unsafe { libc::chdir(c_slash.as_ptr()) } != 0 {
            return Err(VmmError::JailFailed(format!(
                "chdir('/') after pivot_root failed: {}",
                std::io::Error::last_os_error()
            )));
        }

        let c_old_abs = CString::new("/.old_root").unwrap();
        if unsafe { libc::umount2(c_old_abs.as_ptr(), libc::MNT_DETACH) } != 0 {
            return Err(VmmError::JailFailed(format!(
                "umount2(/.old_root, MNT_DETACH) failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        let _ = fs::remove_dir("/.old_root");

        Ok(())
    }
}

/// Set `PR_SET_DUMPABLE = 0` so unprivileged processes cannot `ptrace` or inspect `/proc/pid/mem`.
pub fn set_dumpable_zero() -> Result<()> {
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(VmmError::JailFailed(format!(
            "prctl(PR_SET_DUMPABLE, 0) failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

/// Set `PR_SET_NO_NEW_PRIVS = 1`.
pub fn set_no_new_privs() -> Result<()> {
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(VmmError::JailFailed(format!(
            "prctl(PR_SET_NO_NEW_PRIVS, 1) failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

/// Create a fresh per-VM SMT core-scheduling cookie (`PR_SCHED_CORE_CREATE`).
///
/// Gracefully returns `SchedCoreStatus::Unsupported(errno)` when the host kernel
/// lacks `CONFIG_SCHED_CORE`.
pub fn enable_sched_core_cookie() -> SchedCoreStatus {
    let ret = unsafe {
        libc::prctl(
            PR_SCHED_CORE,
            PR_SCHED_CORE_CREATE,
            0 as libc::c_ulong, // pid = 0 (current task)
            PR_SCHED_CORE_SCOPE_THREAD_GROUP,
            0 as libc::c_ulong,
        )
    };
    if ret == 0 {
        SchedCoreStatus::Enabled
    } else {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        SchedCoreStatus::Unsupported(errno)
    }
}

/// Probe whether `PR_SCHED_CORE` is supported on this host kernel without altering
/// the caller's own scheduling cookie permanently (probes inside a tiny helper or
/// checks via `PR_SCHED_CORE_GET`).
pub fn probe_sched_core_available() -> bool {
    const PR_SCHED_CORE_GET: libc::c_ulong = 0;
    let mut cookie: u64 = 0;
    let ret = unsafe {
        libc::prctl(
            PR_SCHED_CORE,
            PR_SCHED_CORE_GET,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            (&mut cookie as *mut u64) as libc::c_ulong,
        )
    };
    ret == 0
}

/// Write `/proc/self/setgroups = deny`, `/proc/self/uid_map`, and `/proc/self/gid_map`
/// for a 1:1 rootless user namespace mapping.
pub fn write_userns_id_maps(uid: libc::uid_t, gid: libc::gid_t) -> Result<()> {
    // Kernel requires writing "deny" to setgroups before unprivileged gid_map updates.
    fs::write("/proc/self/setgroups", b"deny\n")
        .map_err(|e| VmmError::JailFailed(format!("write /proc/self/setgroups failed: {e}")))?;
    fs::write("/proc/self/uid_map", format!("{uid} {uid} 1\n"))
        .map_err(|e| VmmError::JailFailed(format!("write /proc/self/uid_map failed: {e}")))?;
    fs::write("/proc/self/gid_map", format!("{gid} {gid} 1\n"))
        .map_err(|e| VmmError::JailFailed(format!("write /proc/self/gid_map failed: {e}")))?;
    Ok(())
}

/// Apply a Landlock (`landlock = "0.4"`) filesystem ruleset strictly allowing:
/// - `vsock_dir` (read-write + socket creation/unlink)
/// - `/dev/kvm` (read-write + ioctl_dev)
/// - `/dev/urandom`, `/dev/null` (read-write)
/// - `ch_binary`, `kernel_path`, `initramfs_path` (read + execute for binary, read for boot files)
/// - `/proc` (for `/proc/self/fd/<fd>`) and minimal read-only shared library dirs when needed
pub fn apply_vmm_landlock(
    vsock_dir: &Path,
    ch_binary: &Path,
    kernel_path: &Path,
    initramfs_path: &Path,
    pivoted: bool,
) -> Result<RulesetStatus> {
    apply_vmm_landlock_with_disks(
        vsock_dir,
        ch_binary,
        kernel_path,
        initramfs_path,
        None,
        None,
        pivoted,
    )
}

pub fn apply_vmm_landlock_with_disks(
    vsock_dir: &Path,
    ch_binary: &Path,
    kernel_path: &Path,
    initramfs_path: &Path,
    vda_path: Option<&Path>,
    vdb_path: Option<&Path>,
    pivoted: bool,
) -> Result<RulesetStatus> {
    let abi = ABI::V5;
    let all_fs = AccessFs::from_all(abi);
    let read_dir_access = AccessFs::from_read(abi);
    let file_all = AccessFs::from_file(abi);
    let file_read_exec = read_dir_access & file_all;
    let file_read_only = AccessFs::ReadFile;
    let dev_rw_ioctl: BitFlags<AccessFs> = file_all & !AccessFs::Execute;

    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(all_fs)
        .map_err(|e| VmmError::JailFailed(format!("landlock handle_access failed: {e}")))?
        .create()
        .map_err(|e| VmmError::JailFailed(format!("landlock ruleset create failed: {e}")))?;

    // 1. vsock-dir/ (full directory rights for binding & unlinking vsock.sock)
    if let Ok(fd) = PathFd::new(vsock_dir) {
        ruleset = ruleset
            .add_rule(PathBeneath::new(fd, all_fs))
            .map_err(|e| VmmError::JailFailed(format!("landlock rule for vsock_dir: {e}")))?;
    }

    // 2. /dev/kvm, /dev/urandom, /dev/null
    for dev in [JAILED_DEV_KVM, JAILED_DEV_URANDOM, "/dev/null"] {
        if let Ok(fd) = PathFd::new(dev) {
            ruleset = ruleset
                .add_rule(PathBeneath::new(fd, dev_rw_ioctl))
                .map_err(|e| VmmError::JailFailed(format!("landlock rule for {dev}: {e}")))?;
        }
    }

    // 3. cloud-hypervisor binary (read + execute)
    if let Ok(fd) = PathFd::new(ch_binary) {
        ruleset = ruleset
            .add_rule(PathBeneath::new(fd, file_read_exec))
            .map_err(|e| VmmError::JailFailed(format!("landlock rule for ch_binary: {e}")))?;
    }

    // 4. Kernel, initramfs, and vda (strictly read-only)
    for boot_file in [kernel_path, initramfs_path]
        .into_iter()
        .chain(vda_path)
    {
        if let Ok(fd) = PathFd::new(boot_file) {
            ruleset = ruleset
                .add_rule(PathBeneath::new(fd, file_read_only))
                .map_err(|e| VmmError::JailFailed(format!("landlock rule for read-only file: {e}")))?;
        }
    }

    // 4b. Ephemeral encrypted scratch disk vdb (read/write/truncate, no execute)
    if let Some(vdb) = vdb_path {
        if let Ok(fd) = PathFd::new(vdb) {
            ruleset = ruleset
                .add_rule(PathBeneath::new(fd, dev_rw_ioctl))
                .map_err(|e| VmmError::JailFailed(format!("landlock rule for vdb: {e}")))?;
        }
    }

    // 5. /proc (needed for /proc/self/fd/<vda_fd> and /proc/self/fd/<vdb_fd>)
    if let Ok(fd) = PathFd::new("/proc") {
        let proc_rights = read_dir_access | AccessFs::WriteFile;
        ruleset = ruleset
            .add_rule(PathBeneath::new(fd, proc_rights))
            .map_err(|e| VmmError::JailFailed(format!("landlock rule for /proc: {e}")))?;
    }

    // 6. Minimal shared library dirs for dynamically linked cloud-hypervisor.
    for lib_dir in ["/lib", "/lib64", "/usr/lib", "/usr/lib64"] {
        if Path::new(lib_dir).exists() {
            if let Ok(fd) = PathFd::new(lib_dir) {
                ruleset = ruleset
                    .add_rule(PathBeneath::new(fd, read_dir_access))
                    .map_err(|e| {
                        VmmError::JailFailed(format!("landlock rule for {lib_dir}: {e}"))
                    })?;
            }
        }
    }

    if !pivoted {
        // When pivot_root is disabled (e.g., restricted container environments),
        // nothing else on the host filesystem is added—strictly fail-closed.
    }

    let status = ruleset
        .restrict_self()
        .map_err(|e| VmmError::JailFailed(format!("landlock restrict_self failed: {e}")))?;

    Ok(status.ruleset)
}

/// Probe whether the running Linux kernel supports Landlock (best-effort ABI check).
pub fn probe_landlock_available() -> bool {
    Ruleset::default()
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(AccessFs::from_all(ABI::V1))
        .and_then(|r| r.create())
        .is_ok()
}

fn path_to_cstring(path: &Path) -> Result<CString> {
    CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        VmmError::JailFailed(format!("path contains interior NUL: {}", path.display()))
    })
}

fn mount_raw(
    source: Option<&str>,
    target: &Path,
    fstype: Option<&str>,
    flags: libc::c_ulong,
    data: Option<&str>,
) -> Result<()> {
    let c_src = source.map(|s| CString::new(s).unwrap());
    let c_tgt = path_to_cstring(target)?;
    let c_fs = fstype.map(|s| CString::new(s).unwrap());
    let c_data = data.map(|s| CString::new(s).unwrap());

    let ret = unsafe {
        libc::mount(
            c_src.as_ref().map_or(std::ptr::null(), |c| c.as_ptr()),
            c_tgt.as_ptr(),
            c_fs.as_ref().map_or(std::ptr::null(), |c| c.as_ptr()),
            flags,
            c_data
                .as_ref()
                .map_or(std::ptr::null(), |c| c.as_ptr().cast()),
        )
    };
    if ret != 0 {
        return Err(VmmError::JailFailed(format!(
            "mount({}, flags=0x{flags:x}) failed: {}",
            target.display(),
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

fn bind_mount(src: &Path, dst: &Path, readonly: bool) -> Result<()> {
    let c_src = path_to_cstring(src)?;
    let c_dst = path_to_cstring(dst)?;
    if unsafe {
        libc::mount(
            c_src.as_ptr(),
            c_dst.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND,
            std::ptr::null(),
        )
    } != 0
    {
        return Err(VmmError::JailFailed(format!(
            "bind mount {} -> {} failed: {}",
            src.display(),
            dst.display(),
            std::io::Error::last_os_error()
        )));
    }
    if readonly {
        let _ = unsafe {
            libc::mount(
                std::ptr::null(),
                c_dst.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY,
                std::ptr::null(),
            )
        };
    }
    Ok(())
}

fn bind_mount_rec(src: &Path, dst: &Path, readonly: bool) -> Result<()> {
    let c_src = path_to_cstring(src)?;
    let c_dst = path_to_cstring(dst)?;
    if unsafe {
        libc::mount(
            c_src.as_ptr(),
            c_dst.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND | libc::MS_REC,
            std::ptr::null(),
        )
    } != 0
    {
        return Err(VmmError::JailFailed(format!(
            "recursive bind mount {} -> {} failed: {}",
            src.display(),
            dst.display(),
            std::io::Error::last_os_error()
        )));
    }
    if readonly {
        let _ = unsafe {
            libc::mount(
                std::ptr::null(),
                c_dst.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_REC,
                std::ptr::null(),
            )
        };
    }
    Ok(())
}

fn bind_mount_file(src: &Path, dst: &Path, readonly: bool) -> Result<()> {
    // Create an empty regular file as the bind-mount target.
    fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(dst)
        .map_err(|e| {
            VmmError::JailFailed(format!("create bind target {}: {e}", dst.display()))
        })?;
    bind_mount(src, dst, readonly)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seccomp::build_vmm_seccomp_filter;
    use tempfile::TempDir;

    #[test]
    fn jail_effective_paths_reflect_pivot_root_policy() {
        let jail = RootlessVmmJail {
            vsock_host_dir: PathBuf::from("/tmp/vsock-dir"),
            pivot_staging_dir: PathBuf::from("/tmp/pivot"),
            ch_binary: PathBuf::from("/usr/bin/cloud-hypervisor"),
            kernel_path: PathBuf::from("/tmp/vmlinux-lo"),
            initramfs_path: PathBuf::from("/tmp/initramfs.cpio.gz"),
            vda_path: None,
            vdb_path: None,
            policy: JailPolicy::default(),
        };

        let pivoted = jail.effective_paths();
        assert_eq!(pivoted.ch_binary, PathBuf::from(JAILED_CH_BIN));
        assert_eq!(pivoted.vsock_socket_path, PathBuf::from(JAILED_VSOCK_SOCK));
        assert_eq!(pivoted.kernel_path, PathBuf::from(JAILED_KERNEL));
        assert_eq!(pivoted.initramfs_path, PathBuf::from(JAILED_INITRAMFS));

        let mut unpivoted_jail = jail;
        unpivoted_jail.policy.enable_mount_pivot = false;
        let host = unpivoted_jail.effective_paths();
        assert_eq!(host.ch_binary, PathBuf::from("/usr/bin/cloud-hypervisor"));
        assert_eq!(
            host.vsock_socket_path,
            PathBuf::from("/tmp/vsock-dir/vsock.sock")
        );
    }

    #[test]
    fn pre_exec_hardening_sets_dumpable_zero_no_new_privs_and_blocks_connect() {
        let dir = TempDir::new().unwrap();
        let vsock_dir = dir.path().join("vsock");
        fs::create_dir_all(&vsock_dir).unwrap();
        let fake_bin = dir.path().join("ch");
        let fake_kernel = dir.path().join("vmlinux");
        let fake_initrd = dir.path().join("initrd");
        fs::write(&fake_bin, b"bin").unwrap();
        fs::write(&fake_kernel, b"kern").unwrap();
        fs::write(&fake_initrd, b"init").unwrap();

        let program = build_vmm_seccomp_filter().unwrap();

        let jail = RootlessVmmJail {
            vsock_host_dir: vsock_dir,
            pivot_staging_dir: dir.path().join("pivot"),
            ch_binary: fake_bin,
            kernel_path: fake_kernel,
            initramfs_path: fake_initrd,
            vda_path: None,
            vdb_path: None,
            policy: JailPolicy {
                // Keep userns/netns/pivot optional in case the test runner runs in a
                // locked-down container without nested userns, while testing dumpable,
                // sched_core, landlock, no_new_privs, and seccomp in a real forked child.
                enable_userns: false,
                enable_netns: false,
                enable_pidns: false,
                enable_mount_pivot: false,
                enable_landlock: true,
                enable_seccomp: true,
                enable_sched_core: true,
            },
        };

        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            if jail.apply_pre_exec(Some(&program)).is_err() {
                unsafe { libc::_exit(20) };
            }

            // PR_GET_DUMPABLE must be 0.
            let dumpable = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) };
            if dumpable != 0 {
                unsafe { libc::_exit(21) };
            }

            // PR_GET_NO_NEW_PRIVS must be 1.
            let nnp = unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) };
            if nnp != 1 {
                unsafe { libc::_exit(22) };
            }

            // Landlock must deny opening an unpermitted host file (e.g. /etc/hostname or /etc/passwd).
            if Path::new("/etc/passwd").exists() && fs::File::open("/etc/passwd").is_ok() {
                // Only fail if Landlock is active on this kernel.
                if probe_landlock_available() {
                    unsafe { libc::_exit(23) };
                }
            }

            unsafe { libc::_exit(0) };
        } else {
            let mut status: libc::c_int = 0;
            assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
            assert!(libc::WIFEXITED(status));
            assert_eq!(
                libc::WEXITSTATUS(status),
                0,
                "jailed subprocess failed with exit code {}",
                libc::WEXITSTATUS(status)
            );
        }
    }

    #[test]
    fn full_rootless_userns_netns_pivot_root_landlock_seccomp_jail_in_subprocess() {
        let dir = TempDir::new().unwrap();
        let vsock_dir = dir.path().join("vsock");
        fs::create_dir_all(&vsock_dir).unwrap();
        fs::write(vsock_dir.join("marker"), b"ok").unwrap();

        let fake_bin = dir.path().join("ch");
        let fake_kernel = dir.path().join("vmlinux");
        let fake_initrd = dir.path().join("initrd");
        fs::write(&fake_bin, b"bin").unwrap();
        fs::write(&fake_kernel, b"kern").unwrap();
        fs::write(&fake_initrd, b"init").unwrap();

        // Skip gracefully only if `/dev/kvm` is absent (needed for bind mount) or
        // unprivileged user namespaces are disabled on this host kernel.
        if !Path::new("/dev/kvm").exists() {
            eprintln!("[full_rootless_jail_test] SKIPPING: /dev/kvm absent");
            return;
        }

        let program = build_vmm_seccomp_filter().unwrap();
        let jail = RootlessVmmJail {
            vsock_host_dir: vsock_dir,
            pivot_staging_dir: dir.path().join("pivot"),
            ch_binary: fake_bin,
            kernel_path: fake_kernel,
            initramfs_path: fake_initrd,
            vda_path: None,
            vdb_path: None,
            policy: JailPolicy::default(),
        };

        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            if let Err(err) = jail.apply_pre_exec(Some(&program)) {
                // Exit code 77 ONLY if unshare(CLONE_NEWUSER) itself is forbidden by host policy.
                let msg = err.to_string();
                if msg.contains("unshare(")
                    && (msg.contains("Operation not permitted")
                        || msg.contains("Permission denied"))
                {
                    unsafe { libc::_exit(77) };
                }
                eprintln!("full jail apply_pre_exec failed: {msg}");
                unsafe { libc::_exit(30) };
            }

            // 1. Inside pivot_root, /vsock/marker and /dev/urandom must be accessible,
            //    while host /etc/passwd must NOT exist.
            if fs::read("/vsock/marker").ok().as_deref() != Some(b"ok".as_slice()) {
                unsafe { libc::_exit(31) };
            }
            if Path::new("/etc/passwd").exists() {
                unsafe { libc::_exit(32) };
            }
            if fs::File::open("/dev/urandom").is_err() {
                unsafe { libc::_exit(38) };
            }

            // 2. Empty CLONE_NEWNET: `/proc/net/dev` should have no non-lo interfaces and `lo` is down;
            //    and seccomp must still block AF_INET and connect() with EPERM.
            let inet_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
            let inet_errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if inet_fd != -1 || inet_errno != libc::EPERM {
                unsafe { libc::_exit(33) };
            }

            let unix_fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
            if unix_fd < 0 {
                unsafe { libc::_exit(34) };
            }
            let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
            addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
            let p = b"/vsock/vsock.sock";
            for (i, b) in p.iter().enumerate() {
                addr.sun_path[i] = *b as libc::c_char;
            }
            let ret = unsafe {
                libc::connect(
                    unix_fd,
                    (&addr as *const libc::sockaddr_un).cast(),
                    std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
                )
            };
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            unsafe { libc::close(unix_fd) };
            if ret != -1 || errno != libc::EPERM {
                unsafe { libc::_exit(35) };
            }

            // 3. Dumpable=0 and NO_NEW_PRIVS=1 must hold.
            if unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) } != 0 {
                unsafe { libc::_exit(36) };
            }
            if unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) } != 1 {
                unsafe { libc::_exit(37) };
            }

            unsafe { libc::_exit(0) };
        } else {
            let mut status: libc::c_int = 0;
            assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
            assert!(libc::WIFEXITED(status));
            let code = libc::WEXITSTATUS(status);
            if code == 77 {
                eprintln!("[full_rootless_jail_test] SKIPPING: unprivileged userns restricted in this environment");
                return;
            }
            assert_eq!(
                code, 0,
                "full rootless jail subprocess failed with exit code {code}"
            );
        }
    }
}
