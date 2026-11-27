//! OCI / declarative `[image]` rootfs (`vda`) builder for Blackwall.
//!
//! Converts either a declarative `[image]` (`base` / `packages` / `run`) or a
//! pre-built OCI/Docker image `ref` into a content-addressed, immutable
//! `erofs + dm-verity` block image (`vda.erofs`, `vda.verity`, `meta.json`)
//! with all setuid/setgid bits and Linux `security.capability` xattrs stripped.
//!
//! Docker/Podman is used strictly at image build time; zero container daemon is
//! needed at VM runtime.

use blackwall_policy::{ImageSpec, DEFAULT_BASE_IMAGE};
use blackwall_proto::DmVerityConfig;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use tempfile::TempDir;
use thiserror::Error;
use tracing::{debug, info};

const HASH_DOMAIN: &[u8] = b"blackwall-oci-image-v1\0";
const EROFS_FILENAME: &str = "vda.erofs";
const VERITY_FILENAME: &str = "vda.verity";
const META_FILENAME: &str = "meta.json";

#[derive(Debug, Error)]
pub enum OciError {
    #[error("required host tool unavailable: {0}")]
    MissingTool(String),
    #[error("invalid image specification: {0}")]
    InvalidSpec(String),
    #[error("command `{program}` failed (exit={status:?}): {stderr}")]
    CommandFailed {
        program: String,
        status: Option<i32>,
        stderr: String,
    },
    #[error("failed to parse veritysetup output: {0}")]
    VerityParse(String),
    #[error("unsafe tar entry during OCI export extraction: {0}")]
    UnsafeTarEntry(String),
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, OciError>;

/// Supported build-time OCI container runtimes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerRuntime {
    Docker,
    Podman,
}

impl ContainerRuntime {
    pub fn program(self) -> &'static str {
        match self {
            Self::Docker => "docker",
            Self::Podman => "podman",
        }
    }
}

/// Host tool probe results used to gate live builds and emit clear diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolAvailability {
    pub container_runtime: Option<ContainerRuntime>,
    pub container_daemon_ready: bool,
    pub mkfs_erofs: Option<PathBuf>,
    pub veritysetup: Option<PathBuf>,
}

impl ToolAvailability {
    /// Verify all tools required for full OCI-to-verity image builds are present
    /// and usable, returning the selected container runtime.
    pub fn check_required(&self) -> Result<ContainerRuntime> {
        let runtime = self.container_runtime.ok_or_else(|| {
            OciError::MissingTool(
                "docker or podman (neither found in PATH for image building)".into(),
            )
        })?;
        if !self.container_daemon_ready {
            return Err(OciError::MissingTool(format!(
                "{} daemon/service is not running or accessible",
                runtime.program()
            )));
        }
        self.check_image_pack_tools()?;
        Ok(runtime)
    }

    /// Verify only the local Linux image packing tools (`mkfs.erofs` + `veritysetup`).
    pub fn check_image_pack_tools(&self) -> Result<()> {
        if self.mkfs_erofs.is_none() {
            return Err(OciError::MissingTool("mkfs.erofs".into()));
        }
        if self.veritysetup.is_none() {
            return Err(OciError::MissingTool("veritysetup".into()));
        }
        Ok(())
    }
}

/// Metadata for a built and cached immutable `vda` image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuiltImage {
    pub content_hash: String,
    pub erofs_path: PathBuf,
    pub verity: DmVerityConfig,
}

impl BuiltImage {
    /// Path to the companion raw `dm-verity` hash tree file in the cache entry directory.
    pub fn verity_path(&self) -> PathBuf {
        self.erofs_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(VERITY_FILENAME)
    }

    /// Path to `meta.json` in the cache entry directory.
    pub fn meta_path(&self) -> PathBuf {
        self.erofs_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(META_FILENAME)
    }
}

/// Statistics returned by [`strip_setuid_and_caps`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StripStats {
    pub files_scanned: u64,
    pub dirs_scanned: u64,
    pub setuid_stripped: u64,
    pub caps_stripped: u64,
}

/// Generate a deterministic `Dockerfile` from a declarative [`ImageSpec`].
///
/// Uses `spec.base` (falling back to `debian:bookworm-slim`), installs any
/// declared `packages` with `apt-get` in a single non-interactive layer that
/// cleans `/var/lib/apt/lists/*`, and appends one `RUN` instruction per `run` step.
pub fn generate_dockerfile(spec: &ImageSpec) -> Result<String> {
    let base = spec
        .base
        .as_deref()
        .or(spec.image_ref.as_deref())
        .unwrap_or(DEFAULT_BASE_IMAGE);

    validate_image_ref(base, "base")?;

    let mut out = String::new();
    out.push_str("FROM ");
    out.push_str(base);
    out.push('\n');

    if !spec.packages.is_empty() {
        for pkg in &spec.packages {
            validate_package_name(pkg)?;
        }
        out.push_str(
            "RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ",
        );
        out.push_str(&spec.packages.join(" "));
        out.push_str(" && rm -rf /var/lib/apt/lists/*\n");
    }

    for step in &spec.run {
        if step.trim().is_empty() {
            return Err(OciError::InvalidSpec(
                "image.run contains an empty command".into(),
            ));
        }
        if step.contains('\0') {
            return Err(OciError::InvalidSpec(
                "image.run command contains a NUL byte".into(),
            ));
        }
        // Escape embedded newlines cleanly for Dockerfile continuation if present.
        let sanitized = step.replace('\r', "").replace('\n', " \\\n    ");
        out.push_str("RUN ");
        out.push_str(&sanitized);
        out.push('\n');
    }

    Ok(out)
}

/// Compute a deterministic SHA-256 hex content hash over `(ref, base, packages, run)`
/// for content-addressed `vda` caching.
pub fn image_content_hash(spec: &ImageSpec) -> String {
    let mut hasher = Sha256::new();
    hasher.update(HASH_DOMAIN);

    hash_opt_str(&mut hasher, spec.image_ref.as_deref());
    hash_opt_str(&mut hasher, spec.base.as_deref());

    hasher.update((spec.packages.len() as u64).to_be_bytes());
    for pkg in &spec.packages {
        hash_str(&mut hasher, pkg);
    }

    hasher.update((spec.run.len() as u64).to_be_bytes());
    for step in &spec.run {
        hash_str(&mut hasher, step);
    }

    hex::encode(hasher.finalize())
}

fn hash_opt_str(hasher: &mut Sha256, val: Option<&str>) {
    match val {
        None => hasher.update([0u8]),
        Some(s) => {
            hasher.update([1u8]);
            hash_str(hasher, s);
        }
    }
}

fn hash_str(hasher: &mut Sha256, s: &str) {
    hasher.update((s.len() as u64).to_be_bytes());
    hasher.update(s.as_bytes());
}

fn validate_image_ref(reference: &str, field: &str) -> Result<()> {
    if reference.trim().is_empty() {
        return Err(OciError::InvalidSpec(format!(
            "image.{field} must not be empty"
        )));
    }
    if reference.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(OciError::InvalidSpec(format!(
            "image.{field} contains invalid whitespace or control characters: {reference:?}"
        )));
    }
    Ok(())
}

fn validate_package_name(pkg: &str) -> Result<()> {
    if pkg.is_empty() {
        return Err(OciError::InvalidSpec(
            "image.packages contains an empty package name".into(),
        ));
    }
    if pkg.starts_with('-') {
        return Err(OciError::InvalidSpec(format!(
            "image.packages entry cannot start with '-': {pkg:?}"
        )));
    }
    let valid = pkg.bytes().all(|b| {
        b.is_ascii_alphanumeric() || matches!(b, b'.' | b'+' | b'-' | b'_' | b':' | b'=' | b'~')
    });
    if !valid {
        return Err(OciError::InvalidSpec(format!(
            "image.packages contains invalid characters: {pkg:?}"
        )));
    }
    Ok(())
}

/// Recursively strip all setuid/setgid mode bits (`mode & !0o6000`) and Linux
/// `security.capability` extended attributes under `root` without following symlinks.
pub fn strip_setuid_and_caps(root: &Path) -> Result<StripStats> {
    let mut stats = StripStats::default();
    strip_recursive(root, &mut stats)?;
    Ok(stats)
}

fn strip_recursive(path: &Path, stats: &mut StripStats) -> Result<()> {
    let meta = fs::symlink_metadata(path)?;
    let ftype = meta.file_type();
    if ftype.is_symlink() {
        return Ok(());
    }

    let mode = meta.permissions().mode();
    let stripped_mode = mode & !0o6000;
    if stripped_mode != mode {
        fs::set_permissions(path, fs::Permissions::from_mode(stripped_mode))?;
        stats.setuid_stripped += 1;
    }

    if remove_security_capability_xattr(path)? {
        stats.caps_stripped += 1;
    }

    if ftype.is_dir() {
        stats.dirs_scanned += 1;
        // Temporarily ensure owner read/exec if a rootfs directory is mode 0000/0111
        let restore_mode = if (stripped_mode & 0o500) != 0o500 {
            fs::set_permissions(path, fs::Permissions::from_mode(stripped_mode | 0o700))?;
            Some(stripped_mode)
        } else {
            None
        };

        for entry in fs::read_dir(path)? {
            let entry = entry?;
            strip_recursive(&entry.path(), stats)?;
        }

        if let Some(orig) = restore_mode {
            fs::set_permissions(path, fs::Permissions::from_mode(orig))?;
        }
    } else if ftype.is_file() {
        stats.files_scanned += 1;
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn remove_security_capability_xattr(path: &Path) -> Result<bool> {
    let c_path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL byte"))?;
    let c_attr = CString::new("security.capability").expect("static cstr");

    // Check whether the xattr exists first; unprivileged `lremovexattr` on `security.*`
    // returns EPERM on Linux before checking whether the attribute is absent.
    let size = unsafe {
        libc::lgetxattr(
            c_path.as_ptr(),
            c_attr.as_ptr(),
            std::ptr::null_mut(),
            0,
        )
    };
    if size < 0 {
        let err = io::Error::last_os_error();
        return match err.raw_os_error() {
            Some(libc::ENODATA) | Some(libc::EOPNOTSUPP) | Some(libc::ENOSYS) => Ok(false),
            _ => Err(OciError::Io(err)),
        };
    }

    let rc = unsafe { libc::lremovexattr(c_path.as_ptr(), c_attr.as_ptr()) };
    if rc == 0 {
        return Ok(true);
    }
    let err = io::Error::last_os_error();
    match err.raw_os_error() {
        Some(libc::ENODATA) | Some(libc::EOPNOTSUPP) | Some(libc::ENOSYS) | Some(libc::EROFS) => {
            Ok(false)
        }
        Some(libc::EPERM) => {
            // Rootless fallback for regular files: copy bytes to a fresh inode (dropping xattrs)
            // and atomically replace the original file.
            let meta = fs::symlink_metadata(path)?;
            if meta.file_type().is_file() {
                let parent = path.parent().unwrap_or_else(|| Path::new("."));
                let tmp = tempfile::NamedTempFile::new_in(parent)?;
                fs::copy(path, tmp.path())?;
                fs::set_permissions(
                    tmp.path(),
                    fs::Permissions::from_mode(meta.permissions().mode() & !0o6000),
                )?;
                tmp.persist(path).map_err(|e| OciError::Io(e.error))?;
                return Ok(true);
            }
            Err(OciError::Io(err))
        }
        _ => Err(OciError::Io(err)),
    }
}

#[cfg(not(target_os = "linux"))]
fn remove_security_capability_xattr(_path: &Path) -> Result<bool> {
    Ok(false)
}

/// Parse `veritysetup format` stdout into a [`DmVerityConfig`].
///
/// Computes `hash_start_block` for a combined single-device `vda` image where
/// the `dm-verity` hash tree is appended immediately after the data blocks.
pub fn parse_veritysetup_output(output: &str) -> Result<DmVerityConfig> {
    let mut roothash_hex: Option<String> = None;
    let mut salt_hex: Option<String> = None;
    let mut data_blocks: Option<u64> = None;
    let mut data_block_size: Option<u32> = None;
    let mut hash_block_size: Option<u32> = None;

    for line in output.lines() {
        let Some((raw_key, raw_val)) = line.split_once(':') else {
            continue;
        };
        let key = raw_key.trim().to_ascii_lowercase();
        let val = raw_val.trim();

        match key.as_str() {
            "root hash" => {
                let token = val.split_whitespace().next().unwrap_or("").to_ascii_lowercase();
                validate_hex_str(&token, "Root hash")?;
                roothash_hex = Some(token);
            }
            "salt" => {
                let token = val.split_whitespace().next().unwrap_or("").to_ascii_lowercase();
                if token == "-" || token.is_empty() {
                    salt_hex = Some(String::new());
                } else {
                    validate_hex_str(&token, "Salt")?;
                    salt_hex = Some(token);
                }
            }
            "data blocks" => {
                let n = parse_leading_u64(val, "Data blocks")?;
                data_blocks = Some(n);
            }
            "data block size" => {
                let n = parse_leading_u32(val, "Data block size")?;
                data_block_size = Some(n);
            }
            "hash block size" => {
                let n = parse_leading_u32(val, "Hash block size")?;
                hash_block_size = Some(n);
            }
            _ => {}
        }
    }

    let roothash_hex =
        roothash_hex.ok_or_else(|| OciError::VerityParse("missing 'Root hash' field".into()))?;
    let salt_hex = salt_hex.ok_or_else(|| OciError::VerityParse("missing 'Salt' field".into()))?;
    let data_blocks =
        data_blocks.ok_or_else(|| OciError::VerityParse("missing 'Data blocks' field".into()))?;
    let data_block_size = data_block_size
        .ok_or_else(|| OciError::VerityParse("missing 'Data block size' field".into()))?;
    let hash_block_size = hash_block_size
        .ok_or_else(|| OciError::VerityParse("missing 'Hash block size' field".into()))?;

    if data_blocks == 0 {
        return Err(OciError::VerityParse("Data blocks must be > 0".into()));
    }
    if data_block_size == 0 || hash_block_size == 0 {
        return Err(OciError::VerityParse(
            "Data block size and Hash block size must be > 0".into(),
        ));
    }

    let data_bytes = data_blocks
        .checked_mul(u64::from(data_block_size))
        .ok_or_else(|| OciError::VerityParse("data_blocks * data_block_size overflow".into()))?;
    let hash_start_block = data_bytes.div_ceil(u64::from(hash_block_size));

    Ok(DmVerityConfig {
        roothash_hex,
        salt_hex,
        data_blocks,
        hash_start_block,
        data_block_size,
        hash_block_size,
    })
}

fn validate_hex_str(s: &str, field: &str) -> Result<()> {
    if s.is_empty() || s.len() % 2 != 0 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(OciError::VerityParse(format!(
            "invalid hex value for '{field}': {s:?}"
        )));
    }
    Ok(())
}

fn parse_leading_u64(val: &str, field: &str) -> Result<u64> {
    let token = val
        .split_whitespace()
        .next()
        .ok_or_else(|| OciError::VerityParse(format!("empty value for '{field}'")))?;
    token
        .parse::<u64>()
        .map_err(|_| OciError::VerityParse(format!("invalid integer for '{field}': {val:?}")))
}

fn parse_leading_u32(val: &str, field: &str) -> Result<u32> {
    let token = val
        .split_whitespace()
        .next()
        .ok_or_else(|| OciError::VerityParse(format!("empty value for '{field}'")))?;
    token
        .parse::<u32>()
        .map_err(|_| OciError::VerityParse(format!("invalid integer for '{field}': {val:?}")))
}

/// Content-addressed `vda` image builder backed by local host tools.
#[derive(Debug, Clone)]
pub struct ImageBuilder {
    cache_dir: PathBuf,
}

impl ImageBuilder {
    pub fn new(cache_dir: impl Into<PathBuf>) -> Self {
        Self {
            cache_dir: cache_dir.into(),
        }
    }

    pub fn cache_dir(&self) -> &Path {
        &self.cache_dir
    }

    /// Detect available container runtime (`docker` or `podman`), daemon readiness,
    /// `mkfs.erofs`, and `veritysetup`.
    pub fn detect_tools() -> ToolAvailability {
        let (container_runtime, container_daemon_ready) = if find_in_path("docker").is_some() {
            let ready = probe_runtime(ContainerRuntime::Docker);
            if ready {
                (Some(ContainerRuntime::Docker), true)
            } else if find_in_path("podman").is_some() && probe_runtime(ContainerRuntime::Podman) {
                (Some(ContainerRuntime::Podman), true)
            } else {
                (Some(ContainerRuntime::Docker), false)
            }
        } else if find_in_path("podman").is_some() {
            let ready = probe_runtime(ContainerRuntime::Podman);
            (Some(ContainerRuntime::Podman), ready)
        } else {
            (None, false)
        };

        ToolAvailability {
            container_runtime,
            container_daemon_ready,
            mkfs_erofs: find_in_path("mkfs.erofs"),
            veritysetup: find_in_path("veritysetup"),
        }
    }

    /// Look up a cached image by content hash of `spec`.
    pub fn lookup_cache(&self, spec: &ImageSpec) -> Result<Option<BuiltImage>> {
        let hash = image_content_hash(spec);
        self.lookup_cache_by_hash(&hash)
    }

    /// Look up a cached image directly by its `content_hash`.
    pub fn lookup_cache_by_hash(&self, content_hash: &str) -> Result<Option<BuiltImage>> {
        let entry_dir = self.cache_dir.join(content_hash);
        let meta_path = entry_dir.join(META_FILENAME);
        let erofs_path = entry_dir.join(EROFS_FILENAME);
        if !meta_path.is_file() || !erofs_path.is_file() {
            return Ok(None);
        }
        let raw = fs::read_to_string(&meta_path)?;
        let mut built: BuiltImage = serde_json::from_str(&raw)?;
        if built.content_hash != content_hash {
            return Ok(None);
        }
        built.erofs_path = erofs_path;
        Ok(Some(built))
    }

    /// List all valid cached images in `cache_dir`.
    pub fn list_cached(&self) -> Result<Vec<BuiltImage>> {
        if !self.cache_dir.exists() {
            return Ok(Vec::new());
        }
        let mut images = Vec::new();
        for entry in fs::read_dir(&self.cache_dir)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                continue;
            };
            if let Ok(Some(img)) = self.lookup_cache_by_hash(&name) {
                images.push(img);
            }
        }
        images.sort_by(|a, b| a.content_hash.cmp(&b.content_hash));
        Ok(images)
    }

    /// Build or return the cached `erofs + dm-verity` `vda` image for `spec`.
    pub fn build(&self, spec: &ImageSpec) -> Result<BuiltImage> {
        let content_hash = image_content_hash(spec);
        if let Some(cached) = self.lookup_cache_by_hash(&content_hash)? {
            debug!(%content_hash, "returning cached vda image");
            return Ok(cached);
        }

        let tools = Self::detect_tools();
        let runtime = tools.check_required()?;

        fs::create_dir_all(&self.cache_dir)?;
        let staging = TempDir::new_in(&self.cache_dir)?;

        let image_tag = if spec.packages.is_empty() && spec.run.is_empty() {
            if let Some(image_ref) = &spec.image_ref {
                validate_image_ref(image_ref, "ref")?;
                image_ref.clone()
            } else {
                let base = spec.base.as_deref().unwrap_or(DEFAULT_BASE_IMAGE);
                validate_image_ref(base, "base")?;
                base.to_string()
            }
        } else {
            let dockerfile = generate_dockerfile(spec)?;
            let build_ctx = staging.path().join("ctx");
            fs::create_dir_all(&build_ctx)?;
            let dockerfile_path = build_ctx.join("Dockerfile");
            fs::write(&dockerfile_path, dockerfile)?;

            let tag = format!("blackwall-build:{}", &content_hash[..12]);
            info!(runtime = runtime.program(), %tag, "building OCI image");
            run_checked(
                Command::new(runtime.program())
                    .arg("build")
                    .arg("-t")
                    .arg(&tag)
                    .arg("-f")
                    .arg(&dockerfile_path)
                    .arg(&build_ctx),
                runtime.program(),
            )?;
            tag
        };

        let rootfs_dir = staging.path().join("rootfs");
        fs::create_dir_all(&rootfs_dir)?;
        export_container_rootfs(runtime, &image_tag, &rootfs_dir)?;

        self.pack_rootfs_dir(&content_hash, &rootfs_dir)
    }

    /// Strip setuid/setgid bits & capabilities from `rootfs_dir`, build `vda.erofs`
    /// with `mkfs.erofs`, generate and append the `dm-verity` hash tree via
    /// `veritysetup format`, and store the result in `<cache_dir>/<content_hash>/`.
    pub fn pack_rootfs_dir(&self, content_hash: &str, rootfs_dir: &Path) -> Result<BuiltImage> {
        let tools = Self::detect_tools();
        tools.check_image_pack_tools()?;

        let strip_stats = strip_setuid_and_caps(rootfs_dir)?;
        debug!(?strip_stats, "stripped setuid/setgid and capability xattrs");

        fs::create_dir_all(&self.cache_dir)?;
        let work_dir = TempDir::new_in(&self.cache_dir)?;
        let tmp_erofs = work_dir.path().join(EROFS_FILENAME);
        let tmp_verity = work_dir.path().join(VERITY_FILENAME);

        build_erofs_image(&tmp_erofs, rootfs_dir)?;

        let verity_out = run_checked(
            Command::new("veritysetup")
                .arg("format")
                .arg("--no-superblock")
                .arg(&tmp_erofs)
                .arg(&tmp_verity),
            "veritysetup",
        )?;
        let verity = parse_veritysetup_output(&verity_out)?;

        // Pad data section to hash_start_block * hash_block_size if needed, then append hash tree.
        let hash_offset_bytes = verity
            .hash_start_block
            .checked_mul(u64::from(verity.hash_block_size))
            .ok_or_else(|| OciError::VerityParse("hash_offset overflow".into()))?;
        append_verity_tree(&tmp_erofs, &tmp_verity, hash_offset_bytes)?;

        let final_dir = self.cache_dir.join(content_hash);
        if final_dir.exists() {
            fs::remove_dir_all(&final_dir)?;
        }
        fs::create_dir_all(&final_dir)?;

        let final_erofs = final_dir.join(EROFS_FILENAME);
        let final_verity = final_dir.join(VERITY_FILENAME);
        let final_meta = final_dir.join(META_FILENAME);

        fs::rename(&tmp_erofs, &final_erofs)?;
        if tmp_verity.exists() {
            fs::rename(&tmp_verity, &final_verity)?;
        } else {
            File::create(&final_verity)?;
        }

        let built = BuiltImage {
            content_hash: content_hash.to_string(),
            erofs_path: final_erofs,
            verity,
        };
        let meta_json = serde_json::to_string_pretty(&built)?;
        fs::write(&final_meta, meta_json)?;

        Ok(built)
    }
}

fn build_erofs_image(out_path: &Path, rootfs_dir: &Path) -> Result<()> {
    let first = Command::new("mkfs.erofs")
        .arg("-zlz4hc")
        .arg(out_path)
        .arg(rootfs_dir)
        .output()?;
    if first.status.success() {
        return Ok(());
    }

    let stderr_first = String::from_utf8_lossy(&first.stderr).to_string();
    debug!(
        stderr = %stderr_first,
        "mkfs.erofs -zlz4hc failed; falling back to -zlz4"
    );
    let _ = fs::remove_file(out_path);
    run_checked(
        Command::new("mkfs.erofs")
            .arg("-zlz4")
            .arg(out_path)
            .arg(rootfs_dir),
        "mkfs.erofs",
    )?;
    Ok(())
}

fn append_verity_tree(erofs_path: &Path, verity_path: &Path, hash_offset_bytes: u64) -> Result<()> {
    let erofs_file = OpenOptions::new().write(true).open(erofs_path)?;
    let current_len = erofs_file.metadata()?.len();
    if current_len < hash_offset_bytes {
        erofs_file.set_len(hash_offset_bytes)?;
    } else if current_len > hash_offset_bytes {
        return Err(OciError::VerityParse(format!(
            "erofs image length ({current_len}) exceeds hash offset ({hash_offset_bytes})"
        )));
    }
    let mut erofs_file = OpenOptions::new().append(true).open(erofs_path)?;
    if verity_path.exists() {
        let mut verity_file = File::open(verity_path)?;
        io::copy(&mut verity_file, &mut erofs_file)?;
    }
    erofs_file.flush()?;
    Ok(())
}

struct ContainerGuard {
    runtime: ContainerRuntime,
    container_id: String,
}

impl Drop for ContainerGuard {
    fn drop(&mut self) {
        let _ = Command::new(self.runtime.program())
            .args(["rm", "-f", &self.container_id])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

fn export_container_rootfs(
    runtime: ContainerRuntime,
    image_tag: &str,
    rootfs_dir: &Path,
) -> Result<()> {
    let cid_out = run_checked(
        Command::new(runtime.program())
            .arg("create")
            .arg(image_tag),
        runtime.program(),
    )?;
    let cid = cid_out.trim().to_string();
    if cid.is_empty() {
        return Err(OciError::CommandFailed {
            program: runtime.program().into(),
            status: Some(0),
            stderr: "container create returned empty container ID".into(),
        });
    }
    let _guard = ContainerGuard {
        runtime,
        container_id: cid.clone(),
    };

    let mut export_child = Command::new(runtime.program())
        .args(["export", &cid])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let stdout = export_child.stdout.take().ok_or_else(|| {
        io::Error::new(io::ErrorKind::BrokenPipe, "failed to capture export stdout")
    })?;

    let unpack_res = unpack_oci_export_tar(stdout, rootfs_dir);
    let output = export_child.wait_with_output()?;
    unpack_res?;

    if !output.status.success() {
        return Err(OciError::CommandFailed {
            program: format!("{} export", runtime.program()),
            status: output.status.code(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }

    Ok(())
}

/// Safely extract a container export tar stream into `rootfs_dir` as an unprivileged user.
///
/// Rejects `..` path traversal, strips setuid/setgid bits (`mode & !0o6000`),
/// preserves symlinks/hardlinks strictly inside `rootfs_dir`, and skips device
/// nodes/FIFOs (which rootless hosts cannot `mknod` and guests do not need in `vda`).
fn unpack_oci_export_tar<R: io::Read>(reader: R, rootfs_dir: &Path) -> Result<()> {
    let mut archive = tar::Archive::new(reader);
    let mut deferred_dir_modes: Vec<(PathBuf, u32)> = Vec::new();

    for entry_res in archive.entries()? {
        let mut entry = entry_res?;
        let raw_path = entry.path()?.into_owned();
        let Some(rel_path) = sanitize_oci_rel_path(&raw_path)? else {
            continue;
        };
        let target = rootfs_dir.join(&rel_path);
        let entry_type = entry.header().entry_type();
        let mode = entry.header().mode().unwrap_or(0o644) & !0o6000;

        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }

        match entry_type {
            tar::EntryType::Directory => {
                fs::create_dir_all(&target)?;
                // Keep owner rwx during extraction so nested children can be created.
                fs::set_permissions(&target, fs::Permissions::from_mode((mode & 0o7777) | 0o700))?;
                deferred_dir_modes.push((target, mode & 0o1777));
            }
            tar::EntryType::Regular | tar::EntryType::Continuous => {
                if target.exists() || target.symlink_metadata().is_ok() {
                    let _ = fs::remove_file(&target);
                }
                let mut out = File::create(&target)?;
                io::copy(&mut entry, &mut out)?;
                fs::set_permissions(&target, fs::Permissions::from_mode(mode & 0o1777))?;
            }
            tar::EntryType::Symlink => {
                if let Some(link_name) = entry.link_name()? {
                    if target.symlink_metadata().is_ok() {
                        let _ = fs::remove_file(&target);
                    }
                    symlink(link_name, &target)?;
                }
            }
            tar::EntryType::Link => {
                if let Some(link_name) = entry.link_name()? {
                    if let Some(rel_link) = sanitize_oci_rel_path(&link_name)? {
                        let link_target = rootfs_dir.join(rel_link);
                        if target.symlink_metadata().is_ok() {
                            let _ = fs::remove_file(&target);
                        }
                        if link_target.exists() {
                            fs::hard_link(&link_target, &target)?;
                        }
                    }
                }
            }
            // Device nodes / FIFOs are skipped in rootless staging; guest devtmpfs mounts /dev.
            tar::EntryType::Char | tar::EntryType::Block | tar::EntryType::Fifo => {}
            _ => {}
        }
    }

    // Apply final directory modes bottom-up (deepest first).
    deferred_dir_modes.sort_by(|a, b| b.0.components().count().cmp(&a.0.components().count()));
    for (dir, mode) in deferred_dir_modes {
        let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(mode));
    }

    Ok(())
}

fn sanitize_oci_rel_path(path: &Path) -> Result<Option<PathBuf>> {
    let mut clean = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(seg) => clean.push(seg),
            Component::ParentDir | Component::Prefix(_) => {
                return Err(OciError::UnsafeTarEntry(format!(
                    "disallowed path component in {}",
                    path.display()
                )));
            }
        }
    }
    if clean.as_os_str().is_empty() {
        Ok(None)
    } else {
        Ok(Some(clean))
    }
}

fn find_in_path(program: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(program);
        if candidate.is_file() {
            if let Ok(meta) = fs::metadata(&candidate) {
                if (meta.permissions().mode() & 0o111) != 0 {
                    return Some(candidate);
                }
            }
        }
    }
    None
}

fn probe_runtime(runtime: ContainerRuntime) -> bool {
    Command::new(runtime.program())
        .arg("info")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn run_checked(cmd: &mut Command, program: &str) -> Result<String> {
    let output = cmd.output()?;
    if !output.status.success() {
        return Err(OciError::CommandFailed {
            program: program.to_string(),
            status: output.status.code(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn generate_dockerfile_default_and_full_spec() {
        let default_spec = ImageSpec {
            image_ref: None,
            base: None,
            packages: vec![],
            run: vec![],
        };
        assert_eq!(
            generate_dockerfile(&default_spec).unwrap(),
            "FROM debian:bookworm-slim\n"
        );

        let full_spec = ImageSpec {
            image_ref: None,
            base: Some("debian:bookworm-slim".into()),
            packages: vec!["ca-certificates".into(), "git".into(), "curl".into()],
            run: vec![
                "useradd -m sandbox".into(),
                "mkdir -p /workspace".into(),
            ],
        };
        let df = generate_dockerfile(&full_spec).unwrap();
        assert_eq!(
            df,
            concat!(
                "FROM debian:bookworm-slim\n",
                "RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates git curl && rm -rf /var/lib/apt/lists/*\n",
                "RUN useradd -m sandbox\n",
                "RUN mkdir -p /workspace\n",
            )
        );
    }

    #[test]
    fn generate_dockerfile_rejects_invalid_packages_and_base() {
        let bad_pkg = ImageSpec {
            image_ref: None,
            base: Some("debian:bookworm-slim".into()),
            packages: vec!["git; rm -rf /".into()],
            run: vec![],
        };
        assert!(matches!(
            generate_dockerfile(&bad_pkg),
            Err(OciError::InvalidSpec(_))
        ));

        let bad_flag_pkg = ImageSpec {
            image_ref: None,
            base: Some("debian:bookworm-slim".into()),
            packages: vec!["--allow-unauthenticated".into()],
            run: vec![],
        };
        assert!(matches!(
            generate_dockerfile(&bad_flag_pkg),
            Err(OciError::InvalidSpec(_))
        ));

        let bad_base = ImageSpec {
            image_ref: None,
            base: Some("debian:bookworm\nRUN evil".into()),
            packages: vec![],
            run: vec![],
        };
        assert!(matches!(
            generate_dockerfile(&bad_base),
            Err(OciError::InvalidSpec(_))
        ));
    }

    #[test]
    fn image_content_hash_is_deterministic_and_sensitive() {
        let spec_a = ImageSpec {
            image_ref: None,
            base: Some("debian:bookworm-slim".into()),
            packages: vec!["git".into(), "curl".into()],
            run: vec!["echo hello".into()],
        };
        let hash_a1 = image_content_hash(&spec_a);
        let hash_a2 = image_content_hash(&spec_a);
        assert_eq!(hash_a1, hash_a2);
        assert_eq!(hash_a1.len(), 64);

        let mut spec_b = spec_a.clone();
        spec_b.packages.push("jq".into());
        assert_ne!(hash_a1, image_content_hash(&spec_b));

        let mut spec_c = spec_a.clone();
        spec_c.image_ref = Some("ghcr.io/org/dev:v1".into());
        assert_ne!(hash_a1, image_content_hash(&spec_c));

        let mut spec_d = spec_a.clone();
        spec_d.run.push("echo world".into());
        assert_ne!(hash_a1, image_content_hash(&spec_d));
    }

    #[test]
    fn strip_setuid_and_caps_clears_special_bits_without_following_symlinks() {
        let dir = TempDir::new().unwrap();
        let bin_dir = dir.path().join("usr/bin");
        fs::create_dir_all(&bin_dir).unwrap();

        let suid_file = bin_dir.join("sudo");
        fs::write(&suid_file, b"fake-suid").unwrap();
        fs::set_permissions(&suid_file, fs::Permissions::from_mode(0o4755)).unwrap();

        let sgid_file = bin_dir.join("wall");
        fs::write(&sgid_file, b"fake-sgid").unwrap();
        fs::set_permissions(&sgid_file, fs::Permissions::from_mode(0o2755)).unwrap();

        let both_file = bin_dir.join("both");
        fs::write(&both_file, b"fake-both").unwrap();
        fs::set_permissions(&both_file, fs::Permissions::from_mode(0o6755)).unwrap();

        let normal_file = bin_dir.join("echo");
        fs::write(&normal_file, b"echo").unwrap();
        fs::set_permissions(&normal_file, fs::Permissions::from_mode(0o0755)).unwrap();

        // Symlink pointing outside the staging dir must not be followed
        let outside = TempDir::new().unwrap();
        let outside_file = outside.path().join("untouched");
        fs::write(&outside_file, b"outside").unwrap();
        fs::set_permissions(&outside_file, fs::Permissions::from_mode(0o4755)).unwrap();
        symlink(&outside_file, bin_dir.join("link_outside")).unwrap();

        let stats = strip_setuid_and_caps(dir.path()).unwrap();
        assert_eq!(stats.setuid_stripped, 3);
        assert_eq!(stats.files_scanned, 4);

        assert_eq!(
            fs::symlink_metadata(&suid_file).unwrap().permissions().mode() & 0o7777,
            0o0755
        );
        assert_eq!(
            fs::symlink_metadata(&sgid_file).unwrap().permissions().mode() & 0o7777,
            0o0755
        );
        assert_eq!(
            fs::symlink_metadata(&both_file).unwrap().permissions().mode() & 0o7777,
            0o0755
        );
        // Outside symlink target remains untouched
        assert_eq!(
            fs::symlink_metadata(&outside_file)
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o4755
        );
    }

    #[test]
    fn parse_veritysetup_output_valid_and_malformed() {
        let sample = "\
VERITY header information for /tmp/vda.verity.
UUID:            \t
Hash type:       \t1
Data blocks:     \t17
Data block size: \t4096 [bytes]
Hash blocks:     \t1
Hash block size: \t4096 [bytes]
Hash algorithm:  \tsha256
Salt:            \t09eccfe612b4b684f6a0a37893fa29d130d1c97b263a4486c38d6171f764d37c
Root hash:      \t220ABEE553EFAF7D20B64C77DF607747A0078E483A3A8472330B4AAB9E0C73FD
Hash device size: \t4096 [bytes]
";
        let cfg = parse_veritysetup_output(sample).unwrap();
        assert_eq!(cfg.data_blocks, 17);
        assert_eq!(cfg.hash_start_block, 17);
        assert_eq!(cfg.data_block_size, 4096);
        assert_eq!(cfg.hash_block_size, 4096);
        assert_eq!(
            cfg.salt_hex,
            "09eccfe612b4b684f6a0a37893fa29d130d1c97b263a4486c38d6171f764d37c"
        );
        assert_eq!(
            cfg.roothash_hex,
            "220abee553efaf7d20b64c77df607747a0078e483a3a8472330b4aab9e0c73fd"
        );

        assert!(matches!(
            parse_veritysetup_output("Data blocks: 10\n"),
            Err(OciError::VerityParse(_))
        ));
        assert!(matches!(
            parse_veritysetup_output("Root hash: not-hex!\nSalt: aa\nData blocks: 1\nData block size: 4096\nHash block size: 4096\n"),
            Err(OciError::VerityParse(_))
        ));
    }

    #[test]
    fn cache_hit_lookup_and_listing() {
        let cache = TempDir::new().unwrap();
        let builder = ImageBuilder::new(cache.path());
        let spec = ImageSpec {
            image_ref: None,
            base: Some("debian:bookworm-slim".into()),
            packages: vec!["ripgrep".into()],
            run: vec![],
        };

        assert!(builder.lookup_cache(&spec).unwrap().is_none());

        let hash = image_content_hash(&spec);
        let entry_dir = cache.path().join(&hash);
        fs::create_dir_all(&entry_dir).unwrap();
        let erofs_path = entry_dir.join(EROFS_FILENAME);
        fs::write(&erofs_path, b"dummy-erofs-image").unwrap();
        fs::write(entry_dir.join(VERITY_FILENAME), b"dummy-verity").unwrap();

        let expected = BuiltImage {
            content_hash: hash.clone(),
            erofs_path: erofs_path.clone(),
            verity: DmVerityConfig {
                roothash_hex: "aa".repeat(32),
                salt_hex: "bb".repeat(32),
                data_blocks: 16,
                hash_start_block: 16,
                data_block_size: 4096,
                hash_block_size: 4096,
            },
        };
        fs::write(
            entry_dir.join(META_FILENAME),
            serde_json::to_string_pretty(&expected).unwrap(),
        )
        .unwrap();

        let hit = builder.lookup_cache(&spec).unwrap().expect("cache hit");
        assert_eq!(hit, expected);
        assert_eq!(hit.verity_path(), entry_dir.join(VERITY_FILENAME));
        assert_eq!(builder.list_cached().unwrap(), vec![expected]);
    }

    #[test]
    fn tool_availability_reports_missing_tools_cleanly() {
        let missing_runtime = ToolAvailability {
            container_runtime: None,
            container_daemon_ready: false,
            mkfs_erofs: Some(PathBuf::from("/usr/bin/mkfs.erofs")),
            veritysetup: Some(PathBuf::from("/usr/bin/veritysetup")),
        };
        assert!(matches!(
            missing_runtime.check_required(),
            Err(OciError::MissingTool(_))
        ));

        let stopped_daemon = ToolAvailability {
            container_runtime: Some(ContainerRuntime::Docker),
            container_daemon_ready: false,
            mkfs_erofs: Some(PathBuf::from("/usr/bin/mkfs.erofs")),
            veritysetup: Some(PathBuf::from("/usr/bin/veritysetup")),
        };
        assert!(matches!(
            stopped_daemon.check_required(),
            Err(OciError::MissingTool(msg)) if msg.contains("docker")
        ));

        let missing_erofs = ToolAvailability {
            container_runtime: Some(ContainerRuntime::Podman),
            container_daemon_ready: true,
            mkfs_erofs: None,
            veritysetup: Some(PathBuf::from("/usr/bin/veritysetup")),
        };
        assert!(matches!(
            missing_erofs.check_required(),
            Err(OciError::MissingTool(msg)) if msg == "mkfs.erofs"
        ));

        let missing_verity = ToolAvailability {
            container_runtime: Some(ContainerRuntime::Podman),
            container_daemon_ready: true,
            mkfs_erofs: Some(PathBuf::from("/usr/bin/mkfs.erofs")),
            veritysetup: None,
        };
        assert!(matches!(
            missing_verity.check_required(),
            Err(OciError::MissingTool(msg)) if msg == "veritysetup"
        ));
    }

    #[test]
    fn unpack_oci_export_tar_rejects_traversal_and_strips_setuid() {
        let mut tar_bytes = Vec::new();
        {
            let mut b = tar::Builder::new(&mut tar_bytes);
            let mut hdr = tar::Header::new_gnu();
            hdr.set_size(4);
            hdr.set_mode(0o4755);
            hdr.set_cksum();
            b.append_data(&mut hdr, "bin/su", &b"test"[..]).unwrap();
            b.finish().unwrap();
        }
        let dst = TempDir::new().unwrap();
        unpack_oci_export_tar(Cursor::new(tar_bytes), dst.path()).unwrap();
        let mode = fs::symlink_metadata(dst.path().join("bin/su"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(mode, 0o0755);

        // Traversal entry
        let mut bad_tar = Vec::new();
        {
            let mut b = tar::Builder::new(&mut bad_tar);
            let mut hdr = tar::Header::new_gnu();
            hdr.set_entry_type(tar::EntryType::Regular);
            hdr.set_size(3);
            hdr.set_mode(0o644);
            // Write raw path bypassing tar::Builder's own check
            let raw = hdr.as_gnu_mut().unwrap();
            raw.name[..11].copy_from_slice(b"../evil.txt");
            hdr.set_cksum();
            b.append(&hdr, &b"bad"[..]).unwrap();
            b.finish().unwrap();
        }
        let dst2 = TempDir::new().unwrap();
        assert!(matches!(
            unpack_oci_export_tar(Cursor::new(bad_tar), dst2.path()),
            Err(OciError::UnsafeTarEntry(_))
        ));
    }

    #[test]
    fn live_pack_rootfs_erofs_and_verity_if_tools_available() {
        let tools = ImageBuilder::detect_tools();
        if tools.check_image_pack_tools().is_err() {
            // Gracefully skip if mkfs.erofs or veritysetup is not installed on host.
            return;
        }

        let staging = TempDir::new().unwrap();
        let rootfs = staging.path().join("rootfs");
        fs::create_dir_all(rootfs.join("usr/bin")).unwrap();
        // Write > 4 KiB so dm-verity builds a non-empty hash tree.
        let payload = vec![0x5Au8; 64 * 1024];
        let bin = rootfs.join("usr/bin/app");
        fs::write(&bin, &payload).unwrap();
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o4755)).unwrap();

        let cache = TempDir::new().unwrap();
        let builder = ImageBuilder::new(cache.path());
        let hash = "a".repeat(64);
        let built = builder.pack_rootfs_dir(&hash, &rootfs).unwrap();

        assert_eq!(built.content_hash, hash);
        assert!(built.erofs_path.is_file());
        assert!(built.verity_path().is_file());
        assert!(built.meta_path().is_file());
        assert_eq!(built.verity.roothash_hex.len(), 64);

        // Verify the combined vda.erofs with veritysetup verify!
        let hash_offset = built.verity.hash_start_block * u64::from(built.verity.hash_block_size);
        let status = Command::new("veritysetup")
            .arg("verify")
            .arg("--no-superblock")
            .arg(format!("--data-blocks={}", built.verity.data_blocks))
            .arg(format!("--hash-offset={hash_offset}"))
            .arg(format!("--salt={}", built.verity.salt_hex))
            .arg(&built.erofs_path)
            .arg(&built.erofs_path)
            .arg(&built.verity.roothash_hex)
            .status()
            .unwrap();
        assert!(status.success(), "veritysetup verify failed on built vda.erofs");

        // Confirm setuid was stripped on staging rootfs
        assert_eq!(
            fs::symlink_metadata(&bin).unwrap().permissions().mode() & 0o6000,
            0
        );
    }

    #[test]
    fn gated_live_container_build_smoke_check() {
        let tools = ImageBuilder::detect_tools();
        if let Err(OciError::MissingTool(_)) = tools.check_required() {
            // Host lacks running docker/podman daemon or erofs/verity tools; gated cleanly.
            return;
        }
        // Only runs when docker/podman daemon + mkfs.erofs + veritysetup are all live.
        assert!(tools.container_daemon_ready);
        assert!(tools.mkfs_erofs.is_some());
        assert!(tools.veritysetup.is_some());
    }
}
