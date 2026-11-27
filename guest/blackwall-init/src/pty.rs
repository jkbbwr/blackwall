//! Pure `libc` Unix98 PTY helper (`posix_openpt`, `grantpt`, `unlockpt`,
//! `TIOCGPTN`, `TIOCSWINSZ`, `setsid`, `TIOCSCTTY`) with async-signal-safe `fork` + `execve`.

use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};

#[cfg(target_env = "musl")]
type IoctlReq = libc::c_int;
#[cfg(not(target_env = "musl"))]
type IoctlReq = libc::c_ulong;

const TIOCGPTN: u32 = 0x8004_5430;
const TIOCSPTLCK: u32 = 0x4004_5431;

/// Privilege drop configuration applied in child processes before `exec`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrivilegeDrop {
    pub uid: u32,
    pub gid: u32,
}

pub struct PtySession {
    master: OwnedFd,
    child_pid: libc::pid_t,
}

impl PtySession {
    pub fn spawn(
        cmd: &[String],
        cwd: Option<&Path>,
        env: &BTreeMap<String, String>,
        cols: u16,
        rows: u16,
        drop_privs: Option<PrivilegeDrop>,
    ) -> io::Result<Self> {
        if cmd.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "pty command must not be empty",
            ));
        }

        // Open master PTY fd.
        let master_raw = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC) };
        if master_raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let master = unsafe { OwnedFd::from_raw_fd(master_raw) };

        // Grant/unlock PTY slave. In minimal initramfs without devpts helpers,
        // `TIOCSPTLCK(0)` unlocks directly; we call `grantpt`/`unlockpt` and fall back to ioctl.
        let mut unlock: libc::c_int = 0;
        let unlock_rc = unsafe {
            libc::ioctl(
                master.as_raw_fd(),
                TIOCSPTLCK as IoctlReq,
                &mut unlock as *mut libc::c_int,
            )
        };
        if unlock_rc < 0 {
            if unsafe { libc::grantpt(master.as_raw_fd()) } < 0 {
                return Err(io::Error::last_os_error());
            }
            if unsafe { libc::unlockpt(master.as_raw_fd()) } < 0 {
                return Err(io::Error::last_os_error());
            }
        }

        let mut pty_num: libc::c_uint = 0;
        let rc = unsafe {
            libc::ioctl(
                master.as_raw_fd(),
                TIOCGPTN as IoctlReq,
                &mut pty_num as *mut libc::c_uint,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        let slave_path = CString::new(format!("/dev/pts/{pty_num}"))
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid pts path"))?;

        set_winsize(master.as_raw_fd(), cols, rows)?;

        // Pre-allocate all C strings BEFORE fork() so the child path is async-signal-safe.
        let resolved_prog = resolve_executable(&cmd[0], env);
        let prog_c = CString::new(resolved_prog.as_os_str().as_encoded_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in program path"))?;

        let mut argv_c: Vec<CString> = Vec::with_capacity(cmd.len());
        for arg in cmd {
            argv_c.push(
                CString::new(arg.as_str())
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in argv"))?,
            );
        }
        let mut argv_ptrs: Vec<*const libc::c_char> =
            argv_c.iter().map(|s| s.as_ptr()).collect();
        argv_ptrs.push(std::ptr::null());

        let mut env_c: Vec<CString> = Vec::with_capacity(env.len() + 2);
        let mut has_term = false;
        let mut has_path = false;
        for (k, v) in env {
            if k == "TERM" {
                has_term = true;
            }
            if k == "PATH" {
                has_path = true;
            }
            env_c.push(
                CString::new(format!("{k}={v}"))
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in env"))?,
            );
        }
        if !has_term {
            env_c.push(CString::new("TERM=xterm-256color").unwrap());
        }
        if !has_path {
            env_c.push(
                CString::new("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
                    .unwrap(),
            );
        }
        let mut env_ptrs: Vec<*const libc::c_char> = env_c.iter().map(|s| s.as_ptr()).collect();
        env_ptrs.push(std::ptr::null());

        let cwd_c = match cwd {
            Some(p) => Some(
                CString::new(p.as_os_str().as_encoded_bytes())
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in cwd"))?,
            ),
            None => None,
        };

        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(io::Error::last_os_error());
        }

        if pid == 0 {
            // Child process — async-signal-safe syscalls only.
            unsafe {
                // Close master in child.
                libc::close(master.as_raw_fd());

                if libc::setsid() < 0 {
                    libc::_exit(126);
                }

                let slave_fd = libc::open(slave_path.as_ptr(), libc::O_RDWR);
                if slave_fd < 0 {
                    libc::_exit(126);
                }

                // Set controlling terminal.
                let _ = libc::ioctl(slave_fd, libc::TIOCSCTTY as IoctlReq, 0 as libc::c_int);

                if libc::dup2(slave_fd, libc::STDIN_FILENO) < 0
                    || libc::dup2(slave_fd, libc::STDOUT_FILENO) < 0
                    || libc::dup2(slave_fd, libc::STDERR_FILENO) < 0
                {
                    libc::_exit(126);
                }
                if slave_fd > 2 {
                    libc::close(slave_fd);
                }

                if let Some(ref c) = cwd_c {
                    let _ = libc::chdir(c.as_ptr());
                }

                if let Some(privs) = drop_privs {
                    if apply_privilege_drop_raw(privs) != 0 {
                        libc::_exit(126);
                    }
                }

                libc::execve(prog_c.as_ptr(), argv_ptrs.as_ptr(), env_ptrs.as_ptr());
                libc::_exit(127);
            }
        }

        Ok(Self {
            master,
            child_pid: pid,
        })
    }

    pub fn child_pid(&self) -> libc::pid_t {
        self.child_pid
    }

    pub fn resize(&self, cols: u16, rows: u16) -> io::Result<()> {
        set_winsize(self.master.as_raw_fd(), cols, rows)?;
        unsafe {
            // Notify foreground process group of window size change.
            libc::kill(-self.child_pid, libc::SIGWINCH);
        }
        Ok(())
    }

    pub fn write_input(&self, data: &[u8]) -> io::Result<()> {
        let mut offset = 0;
        while offset < data.len() {
            let n = unsafe {
                libc::write(
                    self.master.as_raw_fd(),
                    data[offset..].as_ptr() as *const libc::c_void,
                    data.len() - offset,
                )
            };
            if n < 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(err);
            }
            offset += n as usize;
        }
        Ok(())
    }

    /// Duplicate the master fd as a `File` for a dedicated reader thread.
    pub fn try_clone_reader(&self) -> io::Result<File> {
        let dup = unsafe { libc::fcntl(self.master.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
        if dup < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { File::from_raw_fd(dup) })
    }

    /// Send a signal to the PTY child's session/process group.
    pub fn kill(&self, sig: libc::c_int) {
        unsafe {
            if libc::kill(-self.child_pid, sig) != 0 {
                libc::kill(self.child_pid, sig);
            }
        }
    }
}

/// Wait for `pid` to exit and translate wait status to a shell-style exit code.
pub fn wait_pid_exit_code(pid: libc::pid_t) -> i32 {
    let mut status: libc::c_int = 0;
    loop {
        let rc = unsafe { libc::waitpid(pid, &mut status, 0) };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return -1;
        }
        return decode_wait_status(status);
    }
}

pub fn decode_wait_status(status: libc::c_int) -> i32 {
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        128 + libc::WTERMSIG(status)
    } else {
        -1
    }
}

fn set_winsize(fd: libc::c_int, cols: u16, rows: u16) -> io::Result<()> {
    let ws = libc::winsize {
        ws_row: rows.max(1),
        ws_col: cols.max(1),
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let rc = unsafe { libc::ioctl(fd, libc::TIOCSWINSZ as IoctlReq, &ws) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Drop privileges (`setgroups`, `setgid`, `setuid`, `PR_SET_NO_NEW_PRIVS=1`).
/// Async-signal-safe so it can run inside `pre_exec` / post-`fork`.
pub unsafe fn apply_privilege_drop_raw(privs: PrivilegeDrop) -> libc::c_int {
    if libc::setgroups(0, std::ptr::null()) != 0 {
        return -1;
    }
    if libc::setgid(privs.gid as libc::gid_t) != 0 {
        return -1;
    }
    if libc::setuid(privs.uid as libc::uid_t) != 0 {
        return -1;
    }
    if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
        return -1;
    }
    0
}

fn resolve_executable(program: &str, env: &BTreeMap<String, String>) -> PathBuf {
    if program.contains('/') {
        return PathBuf::from(program);
    }
    let path_var = env
        .get("PATH")
        .map(String::as_str)
        .unwrap_or("/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
    for dir in path_var.split(':') {
        if dir.is_empty() {
            continue;
        }
        let candidate = Path::new(dir).join(program);
        if candidate.is_file() {
            return candidate;
        }
    }
    PathBuf::from(program)
}
