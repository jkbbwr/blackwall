//! Pre-`exec` `seccomp-bpf` allowlist filter for the jailed Linux `cloud-hypervisor` VMM.
//!
//! Security invariant (per `docs/ARCHITECTURE.md` & `docs/THREAT_MODEL.md`):
//! - **`SYS_connect` is explicitly denied** (omitted from the allowlist; default mismatch
//!   action returns `EPERM` or kills the process).
//! - `SYS_socket` and `SYS_socketpair` are restricted strictly to `AF_UNIX`.
//! - `SYS_accept4`, `SYS_accept`, `SYS_bind`, `SYS_listen` are permitted for the
//!   ephemeral hybrid `vsock.sock` listener before the host `unlink()`s it.
//! - KVM (`SYS_ioctl`), memory management (`mmap`/`mprotect`/`munmap`), async I/O
//!   event loops (`epoll_*`, `eventfd2`, `futex`), vCPU threading (`clone`/`clone3`),
//!   and dynamic linker startup syscalls are permitted.
//! - Dangerous escape/privilege/debug surfaces (`ptrace`, `mount`, `unshare`, `setns`,
//!   `bpf`, `io_uring_*`, `userfaultfd`, `kexec_load`, `init_module`, etc.) are denied.

use blackwall_vmm::{Result, VmmError};
use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch,
};
use std::collections::BTreeMap;

/// Return the target architecture for compiling `seccomp-bpf` programs.
pub fn current_target_arch() -> Result<TargetArch> {
    #[cfg(target_arch = "x86_64")]
    {
        Ok(TargetArch::x86_64)
    }
    #[cfg(target_arch = "aarch64")]
    {
        Ok(TargetArch::aarch64)
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        Err(VmmError::PrereqFailed(
            "unsupported CPU architecture for seccomp-bpf".into(),
        ))
    }
}

/// Complete list of unconditionally allowed syscall numbers for `cloud-hypervisor`
/// (excluding `SYS_socket` / `SYS_socketpair` which carry explicit `AF_UNIX` rules).
///
/// Crucially, `libc::SYS_connect` is NEVER included here.
pub fn vmm_unconditional_allowed_syscalls() -> Vec<i64> {
    let mut syscalls = vec![
        // Exec & process/thread lifecycle
        libc::SYS_execve,
        libc::SYS_execveat,
        libc::SYS_brk,
        libc::SYS_set_tid_address,
        libc::SYS_set_robust_list,
        libc::SYS_rseq,
        libc::SYS_prlimit64,
        libc::SYS_getrlimit,
        libc::SYS_getrandom,
        libc::SYS_getpid,
        libc::SYS_gettid,
        libc::SYS_getuid,
        libc::SYS_geteuid,
        libc::SYS_getgid,
        libc::SYS_getegid,
        libc::SYS_uname,
        libc::SYS_sched_getaffinity,
        libc::SYS_sched_setaffinity,
        libc::SYS_sched_yield,
        libc::SYS_clone,
        libc::SYS_clone3,
        libc::SYS_futex,
        libc::SYS_exit,
        libc::SYS_exit_group,
        libc::SYS_tgkill,
        libc::SYS_tkill,
        libc::SYS_kill,
        libc::SYS_sigaltstack,
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigreturn,
        libc::SYS_rt_sigpending,
        libc::SYS_rt_sigtimedwait,
        libc::SYS_restart_syscall,
        libc::SYS_nanosleep,
        libc::SYS_clock_nanosleep,
        libc::SYS_clock_gettime,
        libc::SYS_clock_getres,
        libc::SYS_gettimeofday,
        libc::SYS_prctl,
        // Memory mapping & guest RAM management
        libc::SYS_mmap,
        libc::SYS_mprotect,
        libc::SYS_munmap,
        libc::SYS_mremap,
        libc::SYS_madvise,
        libc::SYS_mlock,
        libc::SYS_munlock,
        libc::SYS_membarrier,
        // File descriptors, virtio-blk I/O, /proc/self/fd, dynamic loader
        libc::SYS_openat,
        libc::SYS_openat2,
        libc::SYS_close,
        libc::SYS_close_range,
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_pread64,
        libc::SYS_pwrite64,
        libc::SYS_readv,
        libc::SYS_writev,
        libc::SYS_preadv,
        libc::SYS_pwritev,
        libc::SYS_preadv2,
        libc::SYS_pwritev2,
        libc::SYS_lseek,
        libc::SYS_fstat,
        libc::SYS_newfstatat,
        libc::SYS_statx,
        libc::SYS_fstatfs,
        libc::SYS_statfs,
        libc::SYS_ftruncate,
        libc::SYS_fsync,
        libc::SYS_fdatasync,
        libc::SYS_fallocate,
        libc::SYS_fcntl,
        libc::SYS_dup,
        libc::SYS_dup3,
        libc::SYS_pipe2,
        libc::SYS_readlinkat,
        libc::SYS_faccessat,
        libc::SYS_faccessat2,
        libc::SYS_getcwd,
        libc::SYS_getdents64,
        libc::SYS_unlinkat,
        libc::SYS_umask,
        libc::SYS_fchmod,
        // Event loop & timers
        libc::SYS_epoll_create1,
        libc::SYS_epoll_ctl,
        libc::SYS_epoll_pwait,
        libc::SYS_epoll_pwait2,
        libc::SYS_ppoll,
        libc::SYS_eventfd2,
        libc::SYS_timerfd_create,
        libc::SYS_timerfd_settime,
        libc::SYS_timerfd_gettime,
        libc::SYS_signalfd4,
        // KVM & device ioctls
        libc::SYS_ioctl,
        // Hybrid vsock Unix server socket operations (NO SYS_connect!)
        libc::SYS_bind,
        libc::SYS_listen,
        libc::SYS_accept,
        libc::SYS_accept4,
        libc::SYS_getsockname,
        libc::SYS_getpeername,
        libc::SYS_setsockopt,
        libc::SYS_getsockopt,
        libc::SYS_shutdown,
        libc::SYS_recvfrom,
        libc::SYS_recvmsg,
        libc::SYS_sendto,
        libc::SYS_sendmsg,
    ];

    #[cfg(target_arch = "x86_64")]
    syscalls.extend_from_slice(&[
        libc::SYS_arch_prctl,
        libc::SYS_open,
        libc::SYS_stat,
        libc::SYS_lstat,
        libc::SYS_access,
        libc::SYS_pipe,
        libc::SYS_dup2,
        libc::SYS_poll,
        libc::SYS_epoll_wait,
        libc::SYS_eventfd,
        libc::SYS_readlink,
        libc::SYS_unlink,
        libc::SYS_chmod,
        libc::SYS_fork,
    ]);

    syscalls
}

/// Build the `seccomp-bpf` allowlist filter for the jailed Linux VMM.
///
/// Any syscall not explicitly permitted — including `SYS_connect` — fails with
/// `EPERM` (`SeccompAction::Errno(libc::EPERM as u32)`).
pub fn build_vmm_seccomp_filter() -> Result<BpfProgram> {
    build_vmm_seccomp_filter_with_deny_action(SeccompAction::Errno(libc::EPERM as u32))
}

/// Build the `seccomp-bpf` allowlist filter with a caller-selected mismatch action
/// (e.g., `Errno(EPERM)` or `KillProcess`).
pub fn build_vmm_seccomp_filter_with_deny_action(
    mismatch_action: SeccompAction,
) -> Result<BpfProgram> {
    let arch = current_target_arch()?;
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();

    for syscall in vmm_unconditional_allowed_syscalls() {
        debug_assert_ne!(
            syscall,
            libc::SYS_connect,
            "SYS_connect must never be in the VMM seccomp allowlist"
        );
        rules.insert(syscall, vec![]);
    }

    // Restrict socket() and socketpair() strictly to AF_UNIX.
    let af_unix_rule = SeccompRule::new(vec![SeccompCondition::new(
        0,
        SeccompCmpArgLen::Dword,
        SeccompCmpOp::Eq,
        libc::AF_UNIX as u64,
    )
    .map_err(|e| VmmError::JailFailed(format!("failed to build AF_UNIX seccomp rule: {e}")))?])
    .map_err(|e| VmmError::JailFailed(format!("failed to build socket seccomp rule: {e}")))?;

    rules.insert(libc::SYS_socket, vec![af_unix_rule.clone()]);
    rules.insert(libc::SYS_socketpair, vec![af_unix_rule]);

    // Explicitly verify SYS_connect is not present in the compiled rule map.
    if rules.contains_key(&libc::SYS_connect) {
        return Err(VmmError::JailFailed(
            "invariant violation: SYS_connect present in VMM seccomp filter".into(),
        ));
    }

    let filter = SeccompFilter::new(rules, mismatch_action, SeccompAction::Allow, arch)
        .map_err(|e| VmmError::JailFailed(format!("failed to construct SeccompFilter: {e}")))?;

    let program: BpfProgram = filter
        .try_into()
        .map_err(|e| VmmError::JailFailed(format!("failed to compile seccomp BPF program: {e}")))?;

    Ok(program)
}

/// Install a previously compiled VMM `seccomp-bpf` filter on the current thread.
///
/// Caller MUST have already set `PR_SET_NO_NEW_PRIVS = 1`.
pub fn apply_vmm_seccomp_filter(program: &BpfProgram) -> Result<()> {
    seccompiler::apply_filter(program)
        .map_err(|e| VmmError::JailFailed(format!("seccompiler::apply_filter failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seccomp_filter_compiles_and_excludes_connect() {
        let allowed = vmm_unconditional_allowed_syscalls();
        assert!(
            !allowed.contains(&libc::SYS_connect),
            "SYS_connect must not be in VMM seccomp allowlist"
        );
        assert!(
            !allowed.contains(&libc::SYS_ptrace),
            "SYS_ptrace must not be in VMM seccomp allowlist"
        );
        assert!(
            !allowed.contains(&libc::SYS_io_uring_setup),
            "SYS_io_uring_setup must not be in VMM seccomp allowlist"
        );
        assert!(allowed.contains(&libc::SYS_accept4));
        assert!(allowed.contains(&libc::SYS_ioctl));
        assert!(allowed.contains(&libc::SYS_epoll_pwait));
        assert!(allowed.contains(&libc::SYS_clone3));

        let program = build_vmm_seccomp_filter().unwrap();
        assert!(
            !program.is_empty(),
            "compiled BPF program must contain instructions"
        );
    }

    #[test]
    fn seccomp_filter_blocks_connect_and_af_inet_in_forked_subprocess() {
        let program = build_vmm_seccomp_filter().unwrap();

        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());

        if pid == 0 {
            // Child: set NO_NEW_PRIVS, install our VMM seccomp filter, and test syscalls.
            if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
                unsafe { libc::_exit(10) };
            }
            if seccompiler::apply_filter(&program).is_err() {
                unsafe { libc::_exit(11) };
            }

            // 1. socket(AF_UNIX, SOCK_STREAM, 0) MUST succeed.
            let unix_fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
            if unix_fd < 0 {
                unsafe { libc::_exit(12) };
            }

            // 2. connect() on that AF_UNIX socket MUST be blocked with EPERM by seccomp!
            let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
            addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
            let path = b"/tmp/nonexistent-blackwall-seccomp-probe.sock";
            for (i, b) in path.iter().enumerate() {
                addr.sun_path[i] = *b as libc::c_char;
            }
            let conn_ret = unsafe {
                libc::connect(
                    unix_fd,
                    (&addr as *const libc::sockaddr_un).cast(),
                    std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
                )
            };
            let conn_errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            unsafe { libc::close(unix_fd) };
            if conn_ret != -1 || conn_errno != libc::EPERM {
                unsafe { libc::_exit(13) };
            }

            // 3. socket(AF_INET, SOCK_STREAM, 0) MUST also be blocked with EPERM!
            let inet_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
            let inet_errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if inet_fd != -1 || inet_errno != libc::EPERM {
                unsafe { libc::_exit(14) };
            }

            // 4. Allowed syscalls (getpid, eventfd2) MUST still succeed.
            let efd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC) };
            if efd < 0 {
                unsafe { libc::_exit(15) };
            }
            unsafe { libc::close(efd) };

            unsafe { libc::_exit(0) };
        } else {
            // Parent: wait for child and assert exit code 0.
            let mut status: libc::c_int = 0;
            let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
            assert_eq!(waited, pid);
            assert!(
                libc::WIFEXITED(status),
                "seccomp test child did not exit normally: status={status}"
            );
            assert_eq!(
                libc::WEXITSTATUS(status),
                0,
                "seccomp test child failed with code {}",
                libc::WEXITSTATUS(status)
            );
        }
    }
}
