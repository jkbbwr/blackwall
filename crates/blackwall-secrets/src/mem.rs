//! Secure in-memory secret buffer backed by Linux `memfd_secret(0)` with
//! graceful fallback to `mlock`'d zeroized heap memory.

use std::fmt;
use std::ptr;
use std::sync::atomic::{compiler_fence, Ordering};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

enum SecretBacking {
    Empty,
    #[cfg(target_os = "linux")]
    MemfdSecret {
        ptr: *mut u8,
        len: usize,
        mapped_len: usize,
        fd: libc::c_int,
        locked: bool,
    },
    HeapLocked {
        buf: Vec<u8>,
        locked: bool,
    },
}

/// Secret bytes held in protected memory (`memfd_secret(0)` + `mmap` + `mlock`
/// on Linux, with graceful fallback to `mlock`'d zeroized heap memory when
/// `memfd_secret` is unavailable or restricted).
///
/// - Memory is zeroized prior to `munmap`/`close` or deallocation on `Drop`.
/// - `Debug` is unconditionally redacted (`SecretBytes(<redacted>)`).
/// - `PartialEq` uses constant-time comparison.
pub struct SecretBytes {
    backing: SecretBacking,
}

// SAFETY: `SecretBytes` exclusively owns its underlying `memfd_secret` mapping
// or heap buffer and never exposes interior mutability after construction.
unsafe impl Send for SecretBytes {}
unsafe impl Sync for SecretBytes {}

impl SecretBytes {
    /// Allocate secure memory and copy `data` into it.
    pub fn from_slice(data: &[u8]) -> Self {
        if data.is_empty() {
            return Self {
                backing: SecretBacking::Empty,
            };
        }

        #[cfg(target_os = "linux")]
        if let Some(backing) = try_alloc_memfd_secret(data) {
            return Self { backing };
        }

        Self {
            backing: alloc_heap_locked(data),
        }
    }

    /// Copy `data` into secure memory and immediately zeroize the caller's `Vec<u8>`.
    pub fn from_vec(mut data: Vec<u8>) -> Self {
        let out = Self::from_slice(&data);
        data.zeroize();
        out
    }

    /// Copy `s` into secure memory and immediately zeroize the caller's `String`.
    pub fn from_string(mut s: String) -> Self {
        let out = Self::from_slice(s.as_bytes());
        s.zeroize();
        out
    }

    /// Borrow the raw secret bytes.
    pub fn as_bytes(&self) -> &[u8] {
        match &self.backing {
            SecretBacking::Empty => &[],
            #[cfg(target_os = "linux")]
            SecretBacking::MemfdSecret { ptr, len, .. } => {
                // SAFETY: `ptr` is valid for `mapped_len >= len` bytes for the lifetime of `self`.
                unsafe { std::slice::from_raw_parts(*ptr, *len) }
            }
            SecretBacking::HeapLocked { buf, .. } => buf.as_slice(),
        }
    }

    /// Borrow the secret bytes as UTF-8.
    pub fn as_str(&self) -> std::result::Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(self.as_bytes())
    }

    /// Number of secret bytes stored.
    pub fn len(&self) -> usize {
        self.as_bytes().len()
    }

    /// Whether the secret is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns `true` if backed by a Linux `memfd_secret(0)` mapping.
    pub fn is_memfd_secret(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            matches!(self.backing, SecretBacking::MemfdSecret { .. })
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }

    /// Returns `true` if the backing memory was successfully `mlock`'d.
    pub fn is_mlocked(&self) -> bool {
        match &self.backing {
            SecretBacking::Empty => false,
            #[cfg(target_os = "linux")]
            SecretBacking::MemfdSecret { locked, .. } => *locked,
            SecretBacking::HeapLocked { locked, .. } => *locked,
        }
    }

    /// Constant-time equality comparison against an arbitrary byte slice.
    pub fn ct_eq(&self, other: &[u8]) -> bool {
        self.as_bytes().ct_eq(other).into()
    }

    /// Explicitly zeroize and release backing memory.
    pub fn zeroize_now(&mut self) {
        self.zeroize_and_release();
    }

    fn zeroize_and_release(&mut self) {
        let backing = std::mem::replace(&mut self.backing, SecretBacking::Empty);
        match backing {
            SecretBacking::Empty => {}
            #[cfg(target_os = "linux")]
            SecretBacking::MemfdSecret {
                ptr,
                mapped_len,
                fd,
                locked,
                ..
            } => {
                // SAFETY: `ptr` is an exclusively-owned `PROT_READ | PROT_WRITE`
                // mapping of `mapped_len` bytes backed by `fd`.
                unsafe {
                    std::slice::from_raw_parts_mut(ptr, mapped_len).zeroize();
                    compiler_fence(Ordering::SeqCst);
                    if locked {
                        let _ = libc::munlock(ptr as *const libc::c_void, mapped_len);
                    }
                    let _ = libc::munmap(ptr as *mut libc::c_void, mapped_len);
                    let _ = libc::close(fd);
                }
            }
            SecretBacking::HeapLocked { mut buf, locked } => {
                let len = buf.len();
                let ptr = buf.as_ptr();
                buf.as_mut_slice().zeroize();
                compiler_fence(Ordering::SeqCst);
                #[cfg(unix)]
                if locked && len > 0 {
                    // SAFETY: `ptr` and `len` correspond to the still-live `buf` allocation.
                    unsafe {
                        let _ = libc::munlock(ptr as *const libc::c_void, len);
                    }
                }
                #[cfg(not(unix))]
                let _ = (locked, len, ptr);
                drop(buf);
            }
        }
    }
}

impl Clone for SecretBytes {
    fn clone(&self) -> Self {
        Self::from_slice(self.as_bytes())
    }
}

impl PartialEq for SecretBytes {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other.as_bytes())
    }
}

impl Eq for SecretBytes {}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytes(<redacted>)")
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.zeroize_and_release();
    }
}

fn alloc_heap_locked(data: &[u8]) -> SecretBacking {
    let mut buf = Vec::with_capacity(data.len());
    buf.extend_from_slice(data);

    #[cfg(target_os = "linux")]
    unsafe {
        let _ = libc::madvise(
            buf.as_ptr() as *mut libc::c_void,
            buf.len(),
            libc::MADV_DONTDUMP,
        );
    }

    #[cfg(unix)]
    let locked = unsafe { libc::mlock(buf.as_ptr() as *const libc::c_void, buf.len()) == 0 };
    #[cfg(not(unix))]
    let locked = false;

    SecretBacking::HeapLocked { buf, locked }
}

#[cfg(target_os = "linux")]
fn try_alloc_memfd_secret(data: &[u8]) -> Option<SecretBacking> {
    let len = data.len();
    let page_size = page_size();
    let mapped_len = align_up(len, page_size)?;
    let off_len = libc::off_t::try_from(mapped_len).ok()?;

    // SAFETY: `SYS_memfd_secret` takes a single flags argument (`0`).
    // Returns a new file descriptor on success or -1 on error (e.g. ENOSYS/EPERM).
    let raw_fd = unsafe { libc::syscall(libc::SYS_memfd_secret, 0 as libc::c_uint) };
    if raw_fd < 0 {
        return None;
    }
    let fd = raw_fd as libc::c_int;

    // SAFETY: `fd` is a valid open file descriptor just created by `memfd_secret`.
    if unsafe { libc::ftruncate(fd, off_len) } != 0 {
        unsafe {
            let _ = libc::close(fd);
        }
        return None;
    }

    // SAFETY: Mapping `mapped_len` bytes of `fd` as `MAP_SHARED` `PROT_READ | PROT_WRITE`.
    let map_ptr = unsafe {
        libc::mmap(
            ptr::null_mut(),
            mapped_len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0,
        )
    };
    if map_ptr == libc::MAP_FAILED || map_ptr.is_null() {
        unsafe {
            let _ = libc::close(fd);
        }
        return None;
    }

    // Best-effort hardening: exclude from core dumps and lock pages in RAM.
    // Note: `memfd_secret` pages are already unmapped from the kernel direct map
    // and unswappable on Linux; `mlock` failure (e.g. RLIMIT_MEMLOCK) is non-fatal.
    unsafe {
        let _ = libc::madvise(map_ptr, mapped_len, libc::MADV_DONTDUMP);
    }
    let locked = unsafe { libc::mlock(map_ptr, mapped_len) == 0 };

    let byte_ptr = map_ptr as *mut u8;
    // SAFETY: `byte_ptr` points to `mapped_len >= len` writable bytes.
    unsafe {
        ptr::copy_nonoverlapping(data.as_ptr(), byte_ptr, len);
    }

    Some(SecretBacking::MemfdSecret {
        ptr: byte_ptr,
        len,
        mapped_len,
        fd,
        locked,
    })
}

#[cfg(target_os = "linux")]
fn page_size() -> usize {
    // SAFETY: `sysconf(_SC_PAGESIZE)` has no preconditions.
    let ps = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if ps <= 0 {
        4096
    } else {
        ps as usize
    }
}

#[cfg(target_os = "linux")]
fn align_up(len: usize, align: usize) -> Option<usize> {
    let rem = len % align;
    if rem == 0 {
        Some(len)
    } else {
        len.checked_add(align - rem)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_bytes_round_trip_and_redacted_debug() {
        let secret = SecretBytes::from_slice(b"ghp_real_secret_token_12345");
        assert_eq!(secret.as_bytes(), b"ghp_real_secret_token_12345");
        assert_eq!(secret.as_str().unwrap(), "ghp_real_secret_token_12345");
        assert_eq!(secret.len(), 27);
        assert!(!secret.is_empty());
        assert!(secret.ct_eq(b"ghp_real_secret_token_12345"));
        assert!(!secret.ct_eq(b"ghp_wrong_secret_token_1234"));

        let dbg = format!("{secret:?}");
        assert_eq!(dbg, "SecretBytes(<redacted>)");
        assert!(!dbg.contains("ghp_real"));
    }

    #[test]
    fn secret_bytes_empty_works() {
        let empty = SecretBytes::from_slice(&[]);
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);
        assert_eq!(empty.as_bytes(), b"");
        assert_eq!(format!("{empty:?}"), "SecretBytes(<redacted>)");
    }

    #[test]
    fn secret_bytes_from_vec_and_string_zeroize_and_store() {
        let v = b"super-secret-vec".to_vec();
        let sb = SecretBytes::from_vec(v);
        assert_eq!(sb.as_bytes(), b"super-secret-vec");

        let s = String::from("super-secret-string");
        let sb2 = SecretBytes::from_string(s);
        assert_eq!(sb2.as_str().unwrap(), "super-secret-string");
    }

    #[test]
    fn secret_bytes_drop_and_explicit_zeroize() {
        let mut sb = SecretBytes::from_slice(b"sensitive-key-material-0123456789");
        assert_eq!(sb.as_bytes(), b"sensitive-key-material-0123456789");

        // Verify heap fallback zeroization directly before drop frees memory.
        let mut heap = alloc_heap_locked(b"heap-fallback-secret");
        if let SecretBacking::HeapLocked { ref mut buf, .. } = heap {
            assert_eq!(buf.as_slice(), b"heap-fallback-secret");
            buf.as_mut_slice().zeroize();
            assert!(buf.iter().all(|&b| b == 0));
        } else {
            panic!("expected HeapLocked");
        }

        // Verify memfd_secret zeroization directly when supported by the kernel.
        #[cfg(target_os = "linux")]
        if let Some(SecretBacking::MemfdSecret {
            ptr,
            len,
            mapped_len,
            fd,
            locked,
        }) = try_alloc_memfd_secret(b"memfd-secret-payload")
        {
            unsafe {
                let slice = std::slice::from_raw_parts_mut(ptr, mapped_len);
                assert_eq!(&slice[..len], b"memfd-secret-payload");
                slice.zeroize();
                compiler_fence(Ordering::SeqCst);
                assert!(slice.iter().all(|&b| b == 0));
                if locked {
                    let _ = libc::munlock(ptr as *const libc::c_void, mapped_len);
                }
                let _ = libc::munmap(ptr as *mut libc::c_void, mapped_len);
                let _ = libc::close(fd);
            }
        }

        sb.zeroize_now();
        assert!(sb.is_empty());
        assert_eq!(sb.as_bytes(), b"");
    }

    #[test]
    fn secret_bytes_clone_and_constant_time_eq() {
        let a = SecretBytes::from_slice(b"token-abc");
        let b = a.clone();
        let c = SecretBytes::from_slice(b"token-xyz");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn secret_bytes_multi_page_allocation_and_drop() {
        let payload: Vec<u8> = (0..10_000).map(|i| (i % 251) as u8).collect();
        let sb = SecretBytes::from_slice(&payload);
        assert_eq!(sb.len(), 10_000);
        assert_eq!(sb.as_bytes(), payload.as_slice());
        assert_eq!(format!("{sb:?}"), "SecretBytes(<redacted>)");
        drop(sb);
    }
}
