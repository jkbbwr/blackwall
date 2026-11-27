//! Direct Linux Device Mapper (`/dev/mapper/control`) ioctl builders for:
//! - `dm-verity` (`vda`, `DM_VERITY_MODE_PANIC` / `panic_on_corruption` or `restart_on_corruption`)
//! - `dm-crypt` (`vdb`, `aes-xts-plain64` with ephemeral 256-bit RAM key, zeroized after load)

use blackwall_proto::DmVerityConfig;
use std::ffi::CString;
use std::fs::OpenOptions;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::path::Path;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

/// Linux UAPI `DM_IOCTL` magic (`0xfd`).
pub const DM_IOCTL_MAGIC: u32 = 0xfd;
pub const DM_VERSION_MAJOR: u32 = 4;
pub const DM_VERSION_MINOR: u32 = 0;
pub const DM_VERSION_PATCHLEVEL: u32 = 0;

pub const DM_MAX_TYPE_NAME: usize = 16;
pub const DM_NAME_LEN: usize = 128;
pub const DM_UUID_LEN: usize = 128;

pub const DM_READONLY_FLAG: u32 = 1 << 0;
pub const DM_SUSPEND_FLAG: u32 = 1 << 1;

const fn iowr(ty: u32, nr: u32, size: u32) -> u32 {
    (3 << 30) | (size << 16) | (ty << 8) | nr
}

const DM_IOCTL_SIZE: u32 = std::mem::size_of::<DmIoctl>() as u32;

pub const DM_DEV_CREATE: u32 = iowr(DM_IOCTL_MAGIC, 0x03, DM_IOCTL_SIZE);
pub const DM_DEV_REMOVE: u32 = iowr(DM_IOCTL_MAGIC, 0x04, DM_IOCTL_SIZE);
pub const DM_DEV_SUSPEND: u32 = iowr(DM_IOCTL_MAGIC, 0x06, DM_IOCTL_SIZE);
pub const DM_TABLE_LOAD: u32 = iowr(DM_IOCTL_MAGIC, 0x09, DM_IOCTL_SIZE);

/// `BLKGETSIZE64` (`_IOR(0x12, 114, size_t)`) on 64-bit Linux.
pub const BLKGETSIZE64: u32 = (2 << 30) | (8 << 16) | (0x12 << 8) | 114;

#[cfg(target_env = "musl")]
type IoctlReq = libc::c_int;
#[cfg(not(target_env = "musl"))]
type IoctlReq = libc::c_ulong;

/// Exact Linux UAPI `struct dm_ioctl` (`<linux/dm-ioctl.h>`).
/// Total size MUST be 312 bytes with 8-byte alignment.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DmIoctl {
    pub version: [u32; 3],
    pub data_size: u32,
    pub data_start: u32,
    pub target_count: u32,
    pub open_count: i32,
    pub flags: u32,
    pub event_nr: u32,
    pub padding: u32,
    pub dev: u64,
    pub name: [u8; DM_NAME_LEN],
    pub uuid: [u8; DM_UUID_LEN],
    pub data: [u8; 7],
}

const _: () = assert!(std::mem::size_of::<DmIoctl>() == 312);
const _: () = assert!(std::mem::align_of::<DmIoctl>() == 8);

impl DmIoctl {
    pub fn new(name: &str, flags: u32) -> Result<Self, DmError> {
        if name.is_empty() || name.len() >= DM_NAME_LEN || name.contains('\0') {
            return Err(DmError::InvalidName(name.to_string()));
        }
        let mut hdr = Self {
            version: [DM_VERSION_MAJOR, DM_VERSION_MINOR, DM_VERSION_PATCHLEVEL],
            data_size: std::mem::size_of::<Self>() as u32,
            data_start: std::mem::size_of::<Self>() as u32,
            target_count: 0,
            open_count: 0,
            flags,
            event_nr: 0,
            padding: 0,
            dev: 0,
            name: [0u8; DM_NAME_LEN],
            uuid: [0u8; DM_UUID_LEN],
            data: [0u8; 7],
        };
        hdr.name[..name.len()].copy_from_slice(name.as_bytes());
        Ok(hdr)
    }
}

/// Exact Linux UAPI `struct dm_target_spec` (`<linux/dm-ioctl.h>`).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DmTargetSpec {
    pub sector_start: u64,
    pub length: u64,
    pub status: i32,
    pub next: u32,
    pub target_type: [u8; DM_MAX_TYPE_NAME],
}

const _: () = assert!(std::mem::size_of::<DmTargetSpec>() == 40);
const _: () = assert!(std::mem::align_of::<DmTargetSpec>() == 8);

impl DmTargetSpec {
    pub fn new(sector_start: u64, length: u64, target_type: &str) -> Result<Self, DmError> {
        if target_type.is_empty()
            || target_type.len() >= DM_MAX_TYPE_NAME
            || target_type.contains('\0')
        {
            return Err(DmError::InvalidTargetType(target_type.to_string()));
        }
        let mut spec = Self {
            sector_start,
            length,
            status: 0,
            next: 0,
            target_type: [0u8; DM_MAX_TYPE_NAME],
        };
        spec.target_type[..target_type.len()].copy_from_slice(target_type.as_bytes());
        Ok(spec)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerityCorruptionMode {
    /// `DM_VERITY_MODE_PANIC` (`panic_on_corruption`) — immediately panics guest kernel on tampering.
    PanicOnCorruption,
    /// `DM_VERITY_MODE_RESTART` (`restart_on_corruption`) — immediately restarts guest kernel.
    RestartOnCorruption,
}

impl VerityCorruptionMode {
    pub fn as_param(&self) -> &'static str {
        match self {
            Self::PanicOnCorruption => "panic_on_corruption",
            Self::RestartOnCorruption => "restart_on_corruption",
        }
    }
}

#[derive(Debug, Error)]
pub enum DmError {
    #[error("invalid device mapper name: {0}")]
    InvalidName(String),
    #[error("invalid device mapper target type: {0}")]
    InvalidTargetType(String),
    #[error("invalid dm-verity config: {0}")]
    InvalidVerityConfig(String),
    #[error("invalid dm-crypt config: {0}")]
    InvalidCryptConfig(String),
    #[error("device mapper ioctl {op} failed: {source}")]
    Ioctl {
        op: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Build the Linux kernel `dm-verity` target parameter string and sector count.
///
/// Format:
/// `1 <dev> <hash_dev> <data_block_size> <hash_block_size> <num_data_blocks> <hash_start_block> sha256 <roothash> <salt> 1 <corruption_mode>`
pub fn build_verity_table_params(
    dev_path: &str,
    cfg: &DmVerityConfig,
    mode: VerityCorruptionMode,
) -> Result<(u64, String), DmError> {
    if dev_path.is_empty() || dev_path.contains(char::is_whitespace) || dev_path.contains('\0') {
        return Err(DmError::InvalidVerityConfig(format!(
            "invalid block device path: {dev_path:?}"
        )));
    }
    if cfg.data_block_size == 0 || !cfg.data_block_size.is_multiple_of(512) {
        return Err(DmError::InvalidVerityConfig(format!(
            "data_block_size must be a non-zero multiple of 512, got {}",
            cfg.data_block_size
        )));
    }
    if cfg.hash_block_size == 0 || !cfg.hash_block_size.is_multiple_of(512) {
        return Err(DmError::InvalidVerityConfig(format!(
            "hash_block_size must be a non-zero multiple of 512, got {}",
            cfg.hash_block_size
        )));
    }
    if cfg.data_blocks == 0 {
        return Err(DmError::InvalidVerityConfig(
            "data_blocks must be > 0".into(),
        ));
    }
    if cfg.roothash_hex.len() != 64 || !cfg.roothash_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(DmError::InvalidVerityConfig(
            "roothash_hex must be a 64-char SHA-256 hex digest".into(),
        ));
    }
    let salt = if cfg.salt_hex.is_empty() || cfg.salt_hex == "-" {
        "-".to_string()
    } else {
        if !cfg.salt_hex.len().is_multiple_of(2)
            || !cfg.salt_hex.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(DmError::InvalidVerityConfig(
                "salt_hex must be valid even-length hex or '-'".into(),
            ));
        }
        cfg.salt_hex.to_ascii_lowercase()
    };

    let sectors_per_block = (cfg.data_block_size / 512) as u64;
    let total_sectors = cfg
        .data_blocks
        .checked_mul(sectors_per_block)
        .ok_or_else(|| DmError::InvalidVerityConfig("sector count overflow".into()))?;

    let digest = cfg.roothash_hex.to_ascii_lowercase();
    let params = format!(
        "1 {dev_path} {dev_path} {} {} {} {} sha256 {digest} {salt} 1 {}",
        cfg.data_block_size,
        cfg.hash_block_size,
        cfg.data_blocks,
        cfg.hash_start_block,
        mode.as_param()
    );
    Ok((total_sectors, params))
}

/// Build the Linux kernel `dm-crypt` target parameter string (`aes-xts-plain64`)
/// inside a `Zeroizing<String>` so the ephemeral key is wiped on drop.
///
/// Format: `aes-xts-plain64 <hex_key> 0 <dev_path> 0`
pub fn build_crypt_table_params(
    dev_path: &str,
    key: &[u8; 32],
) -> Result<Zeroizing<String>, DmError> {
    if dev_path.is_empty() || dev_path.contains(char::is_whitespace) || dev_path.contains('\0') {
        return Err(DmError::InvalidCryptConfig(format!(
            "invalid block device path: {dev_path:?}"
        )));
    }
    let key_hex = Zeroizing::new(hex::encode(key));
    let params = Zeroizing::new(format!("aes-xts-plain64 {} 0 {} 0", &*key_hex, dev_path));
    Ok(params)
}

/// Generate a 256-bit (32-byte) cryptographic key using Linux `getrandom(2)`,
/// falling back to `/dev/urandom` if needed.
pub fn generate_random_key_256() -> Result<Zeroizing<[u8; 32]>, DmError> {
    let mut key = Zeroizing::new([0u8; 32]);
    let mut filled = 0usize;
    while filled < key.len() {
        let rc = unsafe {
            libc::getrandom(
                key.as_mut_ptr().add(filled) as *mut libc::c_void,
                key.len() - filled,
                0,
            )
        };
        if rc > 0 {
            filled += rc as usize;
            continue;
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        if err.raw_os_error() == Some(libc::ENOSYS) {
            let mut urandom = OpenOptions::new().read(true).open("/dev/urandom")?;
            urandom.read_exact(&mut key[filled..])?;
            return Ok(key);
        }
        return Err(DmError::Io(err));
    }
    Ok(key)
}

/// Build a single-target `DM_TABLE_LOAD` ioctl payload buffer (`DmIoctl` + `DmTargetSpec`
/// + NUL-terminated parameter string + 8-byte alignment padding).
///
/// Returned in `Zeroizing<Vec<u8>>` so callers loading `dm-crypt` keys automatically
/// wipe the serialized key material from RAM immediately after the ioctl returns.
pub fn build_table_load_buffer(
    name: &str,
    target_type: &str,
    sector_start: u64,
    sectors: u64,
    params: &str,
    flags: u32,
) -> Result<Zeroizing<Vec<u8>>, DmError> {
    if params.contains('\0') {
        return Err(DmError::InvalidCryptConfig(
            "target params contain NUL byte".into(),
        ));
    }
    let hdr_size = std::mem::size_of::<DmIoctl>();
    let spec_size = std::mem::size_of::<DmTargetSpec>();
    let raw_params_len = params.len() + 1; // trailing NUL
    let padded_params_len = (raw_params_len + 7) & !7;
    let total_size = hdr_size + spec_size + padded_params_len;

    let mut hdr = DmIoctl::new(name, flags)?;
    hdr.data_size = total_size as u32;
    hdr.data_start = hdr_size as u32;
    hdr.target_count = 1;

    let mut spec = DmTargetSpec::new(sector_start, sectors, target_type)?;
    spec.next = (spec_size + padded_params_len) as u32;

    let mut buf = Zeroizing::new(vec![0u8; total_size]);
    unsafe {
        std::ptr::copy_nonoverlapping(
            (&hdr as *const DmIoctl) as *const u8,
            buf.as_mut_ptr(),
            hdr_size,
        );
        std::ptr::copy_nonoverlapping(
            (&spec as *const DmTargetSpec) as *const u8,
            buf.as_mut_ptr().add(hdr_size),
            spec_size,
        );
    }
    buf[hdr_size + spec_size..hdr_size + spec_size + params.len()]
        .copy_from_slice(params.as_bytes());
    // Trailing NUL and alignment padding are already zeroed.
    Ok(buf)
}

/// Query a block device's size in 512-byte sectors via `BLKGETSIZE64`.
pub fn query_block_device_sectors(dev_path: &str) -> Result<u64, DmError> {
    let file = OpenOptions::new().read(true).open(dev_path)?;
    let mut size_bytes: u64 = 0;
    let rc = unsafe {
        libc::ioctl(
            file.as_raw_fd(),
            BLKGETSIZE64 as IoctlReq,
            &mut size_bytes as *mut u64,
        )
    };
    if rc < 0 {
        return Err(DmError::Ioctl {
            op: "BLKGETSIZE64",
            source: std::io::Error::last_os_error(),
        });
    }
    Ok(size_bytes / 512)
}

fn dm_ioctl_raw(
    ctrl_fd: libc::c_int,
    op_name: &'static str,
    req: u32,
    buf: &mut [u8],
) -> Result<(), DmError> {
    let rc = unsafe { libc::ioctl(ctrl_fd, req as IoctlReq, buf.as_mut_ptr()) };
    if rc < 0 {
        return Err(DmError::Ioctl {
            op: op_name,
            source: std::io::Error::last_os_error(),
        });
    }
    Ok(())
}

fn header_to_buf(hdr: &DmIoctl) -> [u8; std::mem::size_of::<DmIoctl>()] {
    let mut buf = [0u8; std::mem::size_of::<DmIoctl>()];
    unsafe {
        std::ptr::copy_nonoverlapping(
            (hdr as *const DmIoctl) as *const u8,
            buf.as_mut_ptr(),
            buf.len(),
        );
    }
    buf
}

fn header_from_buf(buf: &[u8]) -> DmIoctl {
    let mut hdr = std::mem::MaybeUninit::<DmIoctl>::uninit();
    unsafe {
        std::ptr::copy_nonoverlapping(
            buf.as_ptr(),
            hdr.as_mut_ptr() as *mut u8,
            std::mem::size_of::<DmIoctl>(),
        );
        hdr.assume_init()
    }
}

fn ensure_mapper_node(name: &str, dev_num: u64) -> Result<String, DmError> {
    let mapper_dir = Path::new("/dev/mapper");
    if !mapper_dir.exists() {
        std::fs::create_dir_all(mapper_dir)?;
    }
    let path = format!("/dev/mapper/{name}");
    if !Path::new(&path).exists() && dev_num != 0 {
        let cpath = CString::new(path.as_str()).map_err(|_| DmError::InvalidName(name.into()))?;
        let rc = unsafe { libc::mknod(cpath.as_ptr(), libc::S_IFBLK | 0o600, dev_num as libc::dev_t) };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EEXIST) {
                return Err(DmError::Io(err));
            }
        }
    }
    Ok(path)
}

/// Create, load, and resume a read-only `dm-verity` mapping over `dev_path`
/// (`DM_VERITY_MODE_PANIC` by default). Returns `/dev/mapper/<name>`.
pub fn setup_verity(
    name: &str,
    dev_path: &str,
    cfg: &DmVerityConfig,
    mode: VerityCorruptionMode,
) -> Result<String, DmError> {
    let (sectors, params) = build_verity_table_params(dev_path, cfg, mode)?;
    let ctrl = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/mapper/control")?;
    let fd = ctrl.as_raw_fd();

    let mut create_buf = header_to_buf(&DmIoctl::new(name, DM_READONLY_FLAG)?);
    dm_ioctl_raw(fd, "DM_DEV_CREATE", DM_DEV_CREATE, &mut create_buf)?;

    let mut load_buf =
        build_table_load_buffer(name, "verity", 0, sectors, &params, DM_READONLY_FLAG)?;
    dm_ioctl_raw(fd, "DM_TABLE_LOAD", DM_TABLE_LOAD, &mut load_buf)?;

    // Resume (DM_DEV_SUSPEND without DM_SUSPEND_FLAG)
    let mut resume_buf = header_to_buf(&DmIoctl::new(name, DM_READONLY_FLAG)?);
    dm_ioctl_raw(fd, "DM_DEV_SUSPEND(resume)", DM_DEV_SUSPEND, &mut resume_buf)?;

    let out_hdr = header_from_buf(&resume_buf);
    ensure_mapper_node(name, out_hdr.dev)
}

/// Create, load, and resume an ephemeral random-keyed `dm-crypt` (`aes-xts-plain64`)
/// mapping over `dev_path`. The 256-bit key and ioctl payload are zeroized
/// immediately after `DM_TABLE_LOAD`. Returns `/dev/mapper/<name>`.
pub fn setup_crypt(name: &str, dev_path: &str, sectors: u64) -> Result<String, DmError> {
    if sectors == 0 {
        return Err(DmError::InvalidCryptConfig(
            "block device has 0 sectors".into(),
        ));
    }
    let mut key = generate_random_key_256()?;
    let mut params = build_crypt_table_params(dev_path, &key)?;
    key.zeroize();

    let ctrl = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/mapper/control")?;
    let fd = ctrl.as_raw_fd();

    let mut create_buf = header_to_buf(&DmIoctl::new(name, 0)?);
    dm_ioctl_raw(fd, "DM_DEV_CREATE", DM_DEV_CREATE, &mut create_buf)?;

    let mut load_buf = build_table_load_buffer(name, "crypt", 0, sectors, &params, 0)?;
    params.zeroize();
    let load_res = dm_ioctl_raw(fd, "DM_TABLE_LOAD", DM_TABLE_LOAD, &mut load_buf);
    load_buf.zeroize();
    load_res?;

    let mut resume_buf = header_to_buf(&DmIoctl::new(name, 0)?);
    dm_ioctl_raw(fd, "DM_DEV_SUSPEND(resume)", DM_DEV_SUSPEND, &mut resume_buf)?;

    let out_hdr = header_from_buf(&resume_buf);
    ensure_mapper_node(name, out_hdr.dev)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dm_ioctl_uapi_size_and_alignment() {
        assert_eq!(std::mem::size_of::<DmIoctl>(), 312);
        assert_eq!(std::mem::align_of::<DmIoctl>(), 8);
        assert_eq!(std::mem::size_of::<DmTargetSpec>(), 40);
        assert_eq!(std::mem::align_of::<DmTargetSpec>(), 8);
        assert_eq!(DM_DEV_CREATE, 0xC138_FD03);
        assert_eq!(DM_DEV_SUSPEND, 0xC138_FD06);
        assert_eq!(DM_TABLE_LOAD, 0xC138_FD09);
    }

    #[test]
    fn dm_verity_table_params_and_buffer_layout() {
        let cfg = DmVerityConfig {
            roothash_hex: "A".repeat(64),
            salt_hex: "0123456789abcdef".into(),
            data_blocks: 1024,
            hash_start_block: 1024,
            data_block_size: 4096,
            hash_block_size: 4096,
        };
        let (sectors, params) =
            build_verity_table_params("/dev/vda", &cfg, VerityCorruptionMode::PanicOnCorruption)
                .unwrap();
        assert_eq!(sectors, 1024 * 8);
        assert_eq!(
            params,
            format!(
                "1 /dev/vda /dev/vda 4096 4096 1024 1024 sha256 {} 0123456789abcdef 1 panic_on_corruption",
                "a".repeat(64)
            )
        );

        let (_, restart_params) = build_verity_table_params(
            "/dev/vda",
            &cfg,
            VerityCorruptionMode::RestartOnCorruption,
        )
        .unwrap();
        assert!(restart_params.ends_with("1 restart_on_corruption"));

        let buf = build_table_load_buffer("vda-verity", "verity", 0, sectors, &params, DM_READONLY_FLAG)
            .unwrap();
        assert_eq!(buf.len() % 8, 0);
        let hdr = header_from_buf(&buf);
        assert_eq!(hdr.version, [4, 0, 0]);
        assert_eq!(hdr.data_size as usize, buf.len());
        assert_eq!(hdr.data_start, 312);
        assert_eq!(hdr.target_count, 1);
        assert_eq!(hdr.flags, DM_READONLY_FLAG);
        assert_eq!(&hdr.name[..10], b"vda-verity");

        // Verify target spec starts at byte 312 and params start at byte 352.
        let mut spec = std::mem::MaybeUninit::<DmTargetSpec>::uninit();
        unsafe {
            std::ptr::copy_nonoverlapping(
                buf.as_ptr().add(312),
                spec.as_mut_ptr() as *mut u8,
                40,
            );
        }
        let spec = unsafe { spec.assume_init() };
        assert_eq!(spec.sector_start, 0);
        assert_eq!(spec.length, sectors);
        assert_eq!(&spec.target_type[..6], b"verity");
        let param_slice = &buf[352..352 + params.len()];
        assert_eq!(param_slice, params.as_bytes());
        assert_eq!(buf[352 + params.len()], 0);
    }

    #[test]
    fn dm_crypt_table_params_and_random_key() {
        let key = generate_random_key_256().unwrap();
        assert_ne!(&*key, &[0u8; 32]);

        let params = build_crypt_table_params("/dev/vdb", &key).unwrap();
        let expected_hex = hex::encode(&*key);
        assert_eq!(
            &*params,
            &format!("aes-xts-plain64 {expected_hex} 0 /dev/vdb 0")
        );

        let buf = build_table_load_buffer("vdb-crypt", "crypt", 0, 2097152, &params, 0).unwrap();
        let hdr = header_from_buf(&buf);
        assert_eq!(hdr.data_start, 312);
        assert_eq!(hdr.target_count, 1);
        assert_eq!(&buf[352..352 + params.len()], params.as_bytes());
    }

    #[test]
    fn dm_verity_rejects_invalid_roothash() {
        let bad = DmVerityConfig {
            roothash_hex: "not-hex".into(),
            salt_hex: "".into(),
            data_blocks: 10,
            hash_start_block: 10,
            data_block_size: 4096,
            hash_block_size: 4096,
        };
        assert!(build_verity_table_params("/dev/vda", &bad, VerityCorruptionMode::PanicOnCorruption).is_err());
    }
}
