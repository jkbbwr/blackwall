//! Rootless host jail helper for `blackwall-unpacker`.
//!
//! Applies defense-in-depth process containment before parsing untrusted guest
//! file/archive streams:
//! - `PR_SET_NO_NEW_PRIVS = 1`
//! - `PR_SET_DUMPABLE = 0`
//! - Landlock filesystem restriction strictly to `output_dir` (or no host FS if `None`)
//! - `seccomp-bpf` filter denying network socket syscalls (`socket`, `connect`, `bind`, etc.)

use crate::{Result, UnpackerError};
use std::path::Path;

/// Report describing which kernel jail layers were activated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JailStatus {
    pub no_new_privs: bool,
    pub non_dumpable: bool,
    pub landlock_enforced: bool,
    pub seccomp_enforced: bool,
}

/// Apply the rootless unpacker jail to the calling thread/process.
///
/// - `output_dir`: when `Some(dir)`, Landlock permits filesystem operations
///   strictly beneath `dir`; when `None` (pure streaming canonical re-packing),
///   Landlock denies all ambient host filesystem access.
#[cfg(target_os = "linux")]
pub fn apply_unpacker_jail(output_dir: Option<&Path>) -> Result<JailStatus> {
    use landlock::{Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus, ABI};
    use seccompiler::{BpfProgram, SeccompAction, SeccompFilter};

    // 1. PR_SET_NO_NEW_PRIVS = 1
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc != 0 {
        return Err(UnpackerError::JailError(format!(
            "prctl(PR_SET_NO_NEW_PRIVS) failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    // 2. PR_SET_DUMPABLE = 0
    let rc = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    if rc != 0 {
        return Err(UnpackerError::JailError(format!(
            "prctl(PR_SET_DUMPABLE, 0) failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    // 3. Landlock filesystem containment (best-effort across kernel ABIs)
    let abi = ABI::V5;
    let handled = AccessFs::from_all(abi);
    let mut ruleset = Ruleset::default()
        .handle_access(handled)
        .map_err(|e| UnpackerError::JailError(format!("landlock handle_access failed: {e}")))?
        .create()
        .map_err(|e| UnpackerError::JailError(format!("landlock create failed: {e}")))?;

    if let Some(dir) = output_dir {
        let fd = PathFd::new(dir).map_err(|e| {
            UnpackerError::JailError(format!(
                "landlock open output_dir '{}' failed: {e}",
                dir.display()
            ))
        })?;
        ruleset = ruleset
            .add_rule(PathBeneath::new(fd, handled))
            .map_err(|e| UnpackerError::JailError(format!("landlock add_rule failed: {e}")))?;
    }

    let ll_status = ruleset
        .restrict_self()
        .map_err(|e| UnpackerError::JailError(format!("landlock restrict_self failed: {e}")))?;
    let landlock_enforced = !matches!(ll_status.ruleset, RulesetStatus::NotEnforced);

    // 4. seccomp-bpf denying network socket and namespace/ptrace syscalls
    let denied_syscalls: Vec<(i64, Vec<seccompiler::SeccompRule>)> = vec![
        (libc::SYS_socket, vec![]),
        (libc::SYS_connect, vec![]),
        (libc::SYS_bind, vec![]),
        (libc::SYS_listen, vec![]),
        (libc::SYS_accept, vec![]),
        (libc::SYS_accept4, vec![]),
        (libc::SYS_socketpair, vec![]),
        (libc::SYS_unshare, vec![]),
        (libc::SYS_setns, vec![]),
        (libc::SYS_ptrace, vec![]),
    ];

    let target_arch = std::env::consts::ARCH.try_into().map_err(|e| {
        UnpackerError::JailError(format!("unsupported seccomp target arch: {e}"))
    })?;

    let filter: BpfProgram = SeccompFilter::new(
        denied_syscalls.into_iter().collect(),
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        target_arch,
    )
    .map_err(|e| UnpackerError::JailError(format!("seccomp filter build failed: {e}")))?
    .try_into()
    .map_err(|e| UnpackerError::JailError(format!("seccomp BPF compile failed: {e}")))?;

    seccompiler::apply_filter(&filter)
        .map_err(|e| UnpackerError::JailError(format!("seccomp apply_filter failed: {e}")))?;

    Ok(JailStatus {
        no_new_privs: true,
        non_dumpable: true,
        landlock_enforced,
        seccomp_enforced: true,
    })
}

#[cfg(not(target_os = "linux"))]
pub fn apply_unpacker_jail(_output_dir: Option<&Path>) -> Result<JailStatus> {
    Ok(JailStatus {
        no_new_privs: false,
        non_dumpable: false,
        landlock_enforced: false,
        seccomp_enforced: false,
    })
}
