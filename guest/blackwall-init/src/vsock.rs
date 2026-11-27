//! Pure `libc` Linux `AF_VSOCK` listener and stream transport for host-initiated
//! guest connections on Ports `1000` (`NET_MUX`), `1001` (`AUDIT_UNI`), and `1002` (`CTRL_SESSION`).

use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

pub const AF_VSOCK: libc::c_int = 40;
pub const VMADDR_CID_ANY: u32 = u32::MAX;

/// Exact Linux UAPI `struct sockaddr_vm` (`<linux/vm_sockets.h>`).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SockaddrVm {
    pub svm_family: libc::sa_family_t,
    pub svm_reserved1: u16,
    pub svm_port: u32,
    pub svm_cid: u32,
    pub svm_flags: u8,
    pub svm_zero: [u8; 3],
}

const _: () = assert!(std::mem::size_of::<SockaddrVm>() == 16);

pub struct VsockListener {
    fd: OwnedFd,
    port: u32,
}

impl VsockListener {
    /// Bind and listen on `AF_VSOCK` `(VMADDR_CID_ANY, port)`.
    pub fn bind(port: u32) -> io::Result<Self> {
        let raw = unsafe { libc::socket(AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };

        let addr = SockaddrVm {
            svm_family: AF_VSOCK as libc::sa_family_t,
            svm_reserved1: 0,
            svm_port: port,
            svm_cid: VMADDR_CID_ANY,
            svm_flags: 0,
            svm_zero: [0u8; 3],
        };
        let rc = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&addr as *const SockaddrVm) as *const libc::sockaddr,
                std::mem::size_of::<SockaddrVm>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }

        let rc = unsafe { libc::listen(fd.as_raw_fd(), 16) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { fd, port })
    }

    pub fn port(&self) -> u32 {
        self.port
    }

    /// Accept one incoming host-initiated `AF_VSOCK` stream.
    pub fn accept(&self) -> io::Result<VsockStream> {
        loop {
            let mut peer = SockaddrVm {
                svm_family: 0,
                svm_reserved1: 0,
                svm_port: 0,
                svm_cid: 0,
                svm_flags: 0,
                svm_zero: [0u8; 3],
            };
            let mut len = std::mem::size_of::<SockaddrVm>() as libc::socklen_t;
            let raw = unsafe {
                libc::accept4(
                    self.fd.as_raw_fd(),
                    (&mut peer as *mut SockaddrVm) as *mut libc::sockaddr,
                    &mut len,
                    libc::SOCK_CLOEXEC,
                )
            };
            if raw < 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(err);
            }
            return Ok(VsockStream {
                fd: unsafe { OwnedFd::from_raw_fd(raw) },
            });
        }
    }
}

pub struct VsockStream {
    fd: OwnedFd,
}

impl VsockStream {
    pub fn try_clone(&self) -> io::Result<Self> {
        let dup_fd = unsafe { libc::fcntl(self.fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
        if dup_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            fd: unsafe { OwnedFd::from_raw_fd(dup_fd) },
        })
    }

    /// Clear `FD_CLOEXEC` so the raw fd can be inherited by a child process
    /// (e.g. `blackwall-netbridge --vsock-fd <fd>`).
    pub fn clear_cloexec(&self) -> io::Result<()> {
        let flags = unsafe { libc::fcntl(self.fd.as_raw_fd(), libc::F_GETFD) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        let rc = unsafe {
            libc::fcntl(
                self.fd.as_raw_fd(),
                libc::F_SETFD,
                flags & !libc::FD_CLOEXEC,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub fn into_owned_fd(self) -> OwnedFd {
        self.fd
    }
}

impl AsRawFd for VsockStream {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl Read for VsockStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let n = unsafe {
                libc::read(
                    self.fd.as_raw_fd(),
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                )
            };
            if n < 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(err);
            }
            return Ok(n as usize);
        }
    }
}

impl Write for VsockStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        loop {
            let n = unsafe {
                libc::write(
                    self.fd.as_raw_fd(),
                    buf.as_ptr() as *const libc::c_void,
                    buf.len(),
                )
            };
            if n < 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(err);
            }
            return Ok(n as usize);
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sockaddr_vm_layout_matches_linux_uapi() {
        assert_eq!(std::mem::size_of::<SockaddrVm>(), 16);
        assert_eq!(AF_VSOCK, 40);
        assert_eq!(VMADDR_CID_ANY, u32::MAX);
    }
}
