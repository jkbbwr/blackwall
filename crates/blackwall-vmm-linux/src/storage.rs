//! Storage primitives for Blackwall's 2-disk Linux KVM model:
//! - `vda`: strictly read-only (`O_RDONLY`) immutable `erofs + dm-verity` rootfs
//! - `vdb`: unlinked ephemeral scratch file (`O_TMPFILE | O_RDWR | O_CLOEXEC`,
//!   mode `0600`, sized with `ftruncate`) backed by guest-encrypted `dm-crypt`
//!
//! Because `vdb` is unlinked before the VMM ever starts and the host kernel never
//! mounts it, closing the file descriptor on VM exit immediately reclaims all
//! blocks with zero host filesystem persistence.

use blackwall_vmm::{Result, VmmError};
use std::ffi::CString;
use std::fs::OpenOptions;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

const MIB: u64 = 1024 * 1024;

/// Open the immutable `vda` rootfs image strictly read-only (`O_RDONLY`).
pub fn open_vda_readonly(path: &Path) -> Result<OwnedFd> {
    let file = OpenOptions::new()
        .read(true)
        .write(false)
        .open(path)
        .map_err(|e| {
            VmmError::LaunchFailed(format!(
                "failed to open read-only vda image {}: {e}",
                path.display()
            ))
        })?;
    Ok(file.into())
}

/// Create an unlinked, `0600` read-write ephemeral scratch file of exact size
/// `workspace_mib * 1024 * 1024` bytes inside `dir`.
///
/// Primary path uses Linux `open(dir, O_TMPFILE | O_RDWR | O_CLOEXEC, 0o600)`.
/// If the underlying filesystem does not support `O_TMPFILE` (`EOPNOTSUPP`,
/// `EINVAL`, `EISDIR`, `ENOSYS`), transparently falls back to `mkstemp()` +
/// immediate `unlink()` + `O_CLOEXEC`.
pub fn create_unlinked_scratch(dir: &Path, workspace_mib: u64) -> Result<OwnedFd> {
    if workspace_mib == 0 {
        return Err(VmmError::InvalidConfig(
            "workspace_mib must be >= 1 MiB".into(),
        ));
    }
    let size_bytes = workspace_mib.checked_mul(MIB).ok_or_else(|| {
        VmmError::InvalidConfig(format!("workspace_mib overflow: {workspace_mib}"))
    })?;
    let size_off_t = libc::off_t::try_from(size_bytes).map_err(|_| {
        VmmError::InvalidConfig(format!(
            "workspace size {size_bytes} exceeds platform off_t"
        ))
    })?;

    let fd = open_tmpfile_or_fallback(dir)?;

    // Resize the unlinked sparse backing file to exact workspace capacity.
    let ret = unsafe { libc::ftruncate(fd.as_raw_fd(), size_off_t) };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        return Err(VmmError::LaunchFailed(format!(
            "ftruncate({size_bytes}) on unlinked scratch vdb failed: {err}"
        )));
    }

    Ok(fd)
}

fn open_tmpfile_or_fallback(dir: &Path) -> Result<OwnedFd> {
    let c_dir = CString::new(dir.as_os_str().as_bytes()).map_err(|_| {
        VmmError::InvalidConfig(format!(
            "scratch directory contains NUL byte: {}",
            dir.display()
        ))
    })?;

    let raw_fd = unsafe {
        libc::open(
            c_dir.as_ptr(),
            libc::O_TMPFILE | libc::O_RDWR | libc::O_CLOEXEC,
            0o600 as libc::c_uint,
        )
    };
    if raw_fd >= 0 {
        return Ok(unsafe { OwnedFd::from_raw_fd(raw_fd) });
    }

    let err = std::io::Error::last_os_error();
    let errno = err.raw_os_error().unwrap_or(0);
    if !matches!(
        errno,
        libc::EOPNOTSUPP | libc::EINVAL | libc::EISDIR | libc::ENOSYS
    ) {
        return Err(VmmError::LaunchFailed(format!(
            "open(O_TMPFILE) in {} failed: {err}",
            dir.display()
        )));
    }

    tracing::debug!(
        dir = %dir.display(),
        errno,
        "O_TMPFILE unsupported on filesystem; falling back to mkstemp + immediate unlink"
    );
    create_mkstemp_unlinked(dir)
}

fn create_mkstemp_unlinked(dir: &Path) -> Result<OwnedFd> {
    let template_path = dir.join(".blackwall-vdb-XXXXXX");
    let mut template_bytes = template_path.as_os_str().as_bytes().to_vec();
    if template_bytes.contains(&0) {
        return Err(VmmError::InvalidConfig(format!(
            "scratch directory contains NUL byte: {}",
            dir.display()
        )));
    }
    template_bytes.push(0);

    let raw_fd = unsafe { libc::mkstemp(template_bytes.as_mut_ptr() as *mut libc::c_char) };
    if raw_fd < 0 {
        let err = std::io::Error::last_os_error();
        return Err(VmmError::LaunchFailed(format!(
            "mkstemp fallback in {} failed: {err}",
            dir.display()
        )));
    }

    // Wrap immediately so any subsequent error still closes the descriptor cleanly.
    let owned = unsafe { OwnedFd::from_raw_fd(raw_fd) };

    // Immediately unlink the temporary path so it is invisible and reclaimed on close.
    let unlink_ret = unsafe { libc::unlink(template_bytes.as_ptr() as *const libc::c_char) };
    if unlink_ret != 0 {
        let err = std::io::Error::last_os_error();
        return Err(VmmError::LaunchFailed(format!(
            "immediate unlink() after mkstemp failed: {err}"
        )));
    }

    // Enforce 0600 permissions and FD_CLOEXEC consistently with the O_TMPFILE path.
    if unsafe { libc::fchmod(owned.as_raw_fd(), 0o600) } != 0 {
        let err = std::io::Error::last_os_error();
        return Err(VmmError::LaunchFailed(format!(
            "fchmod(0600) on scratch vdb failed: {err}"
        )));
    }
    if unsafe { libc::fcntl(owned.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
        let err = std::io::Error::last_os_error();
        return Err(VmmError::LaunchFailed(format!(
            "fcntl(FD_CLOEXEC) on scratch vdb failed: {err}"
        )));
    }

    Ok(owned)
}

/// Clear `FD_CLOEXEC` on `fd` inside `pre_exec` right before `execve` so the
/// child `cloud-hypervisor` process inherits it at `/proc/self/fd/<fd>`.
pub fn clear_cloexec(fd: RawFd) -> std::io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let new_flags = flags & !libc::FD_CLOEXEC;
    if unsafe { libc::fcntl(fd, libc::F_SETFD, new_flags) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn fstat_fd(fd: RawFd) -> libc::stat {
        let mut st = std::mem::MaybeUninit::<libc::stat>::zeroed();
        let ret = unsafe { libc::fstat(fd, st.as_mut_ptr()) };
        assert_eq!(ret, 0, "fstat failed: {}", std::io::Error::last_os_error());
        unsafe { st.assume_init() }
    }

    #[test]
    fn create_unlinked_scratch_has_zero_links_and_exact_size() {
        let dir = TempDir::new().unwrap();
        let workspace_mib = 16;
        let expected_size = (workspace_mib * MIB) as i64;

        let fd = create_unlinked_scratch(dir.path(), workspace_mib).unwrap();
        let st = fstat_fd(fd.as_raw_fd());

        assert_eq!(st.st_nlink, 0, "scratch vdb must have st_nlink == 0");
        assert_eq!(
            st.st_size, expected_size,
            "scratch vdb must have exact ftruncated size"
        );
        assert_eq!(
            st.st_mode & 0o777,
            0o600,
            "scratch vdb mode must be strictly 0600"
        );

        // Verify directory contains zero visible files.
        let entries: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
        assert!(entries.is_empty(), "unlinked scratch must leave no dir entry");

        // Verify FD_CLOEXEC is set in parent.
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
        assert_ne!(flags & libc::FD_CLOEXEC, 0, "FD_CLOEXEC must be set");
    }

    #[test]
    fn mkstemp_fallback_also_produces_unlinked_zero_link_fd() {
        let dir = TempDir::new().unwrap();
        let fd = create_mkstemp_unlinked(dir.path()).unwrap();
        let st = fstat_fd(fd.as_raw_fd());
        assert_eq!(st.st_nlink, 0);
        assert_eq!(st.st_mode & 0o777, 0o600);
        assert!(std::fs::read_dir(dir.path()).unwrap().next().is_none());
    }

    #[test]
    fn open_vda_readonly_enforces_rdonly_access_mode() {
        let dir = TempDir::new().unwrap();
        let vda_path = dir.path().join("rootfs.erofs");
        let mut f = std::fs::File::create(&vda_path).unwrap();
        f.write_all(b"erofs-test-bytes").unwrap();
        drop(f);

        let fd = open_vda_readonly(&vda_path).unwrap();
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
        assert_eq!(flags & libc::O_ACCMODE, libc::O_RDONLY);

        // Attempting to write to vda fd must fail with EBADF.
        let w = unsafe { libc::write(fd.as_raw_fd(), b"x".as_ptr().cast(), 1) };
        assert_eq!(w, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EBADF)
        );
    }
}
