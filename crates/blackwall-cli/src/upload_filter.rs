//! Deterministic host-side `--exclude-secrets` filter and tar builder for `blackwall upload`.

use crate::error::{CliError, Result};
use std::fs::{self, File};
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path};

/// Summary statistics for a tar archive assembled for directory upload.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UploadTarStats {
    pub files_included: u64,
    pub dirs_included: u64,
    pub entries_excluded: u64,
    pub bytes_included: u64,
}

/// Determine whether a relative path should be skipped when `--exclude-secrets` is enabled.
///
/// Matches (case-insensitively on ASCII):
/// - `.env`, `.env.*`
/// - `.npmrc`, `.yarnrc*`, `.pypirc`, `.netrc`
/// - `.docker/config.json`
/// - `.git/config`, `.git/credentials`, `.git/hooks/**`
/// - `*.pem`, `*.key`
/// - `id_rsa*`, `id_ed25519*`
/// - Heavy build directories: `target/`, `node_modules/`, `.venv/`
pub fn should_exclude_path(rel_path: &Path) -> bool {
    let comps: Vec<String> = rel_path
        .components()
        .filter_map(|c| match c {
            Component::Normal(os) => Some(os.to_string_lossy().to_ascii_lowercase()),
            _ => None,
        })
        .collect();

    if comps.is_empty() {
        return false;
    }

    // Heavy build directories anywhere in the tree.
    for comp in &comps {
        if matches!(comp.as_str(), "target" | "node_modules" | ".venv") {
            return true;
        }
    }

    // Multi-segment secret / git paths anywhere in the tree.
    for window in comps.windows(2) {
        let a = window[0].as_str();
        let b = window[1].as_str();
        if a == ".docker" && b == "config.json" {
            return true;
        }
        if a == ".git" && matches!(b, "config" | "credentials" | "hooks") {
            return true;
        }
    }

    // Leaf filename rules.
    let Some(file_name) = comps.last().map(String::as_str) else {
        return false;
    };

    if file_name == ".env" || file_name.starts_with(".env.") {
        return true;
    }
    if matches!(file_name, ".npmrc" | ".pypirc" | ".netrc") {
        return true;
    }
    if file_name.starts_with(".yarnrc") {
        return true;
    }
    if file_name.ends_with(".pem") || file_name.ends_with(".key") {
        return true;
    }
    if file_name.starts_with("id_rsa") || file_name.starts_with("id_ed25519") {
        return true;
    }

    false
}

/// Build a deterministic `application/x-tar` byte buffer from a local directory.
///
/// - Walks entries in sorted filename order.
/// - Never follows symlinks (symlinks and non-regular/non-dir files are skipped).
/// - When `exclude_secrets` is `true`, omits any file or directory matched by
///   [`should_exclude_path`] before descending into excluded directories.
pub fn build_upload_tar(root_dir: &Path, exclude_secrets: bool) -> Result<(Vec<u8>, UploadTarStats)> {
    if !root_dir.is_dir() {
        return Err(CliError::InvalidArgument(format!(
            "'{}' is not a directory",
            root_dir.display()
        )));
    }

    let mut buf = Vec::new();
    let mut stats = UploadTarStats::default();
    {
        let mut builder = tar::Builder::new(&mut buf);
        append_dir_recursive(root_dir, Path::new(""), exclude_secrets, &mut builder, &mut stats)?;
        builder.finish()?;
    }
    Ok((buf, stats))
}

fn append_dir_recursive(
    root_dir: &Path,
    rel_dir: &Path,
    exclude_secrets: bool,
    builder: &mut tar::Builder<&mut Vec<u8>>,
    stats: &mut UploadTarStats,
) -> Result<()> {
    let abs_dir = if rel_dir.as_os_str().is_empty() {
        root_dir.to_path_buf()
    } else {
        root_dir.join(rel_dir)
    };

    let mut entries: Vec<_> = fs::read_dir(&abs_dir)?.collect::<io::Result<Vec<_>>>()?;
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let name = entry.file_name();
        let rel_path = if rel_dir.as_os_str().is_empty() {
            Path::new(&name).to_path_buf()
        } else {
            rel_dir.join(&name)
        };
        let abs_path = entry.path();

        let meta = fs::symlink_metadata(&abs_path)?;
        let ftype = meta.file_type();

        // Never follow symlinks or pack device/FIFO nodes.
        if ftype.is_symlink() || (!ftype.is_dir() && !ftype.is_file()) {
            stats.entries_excluded += 1;
            continue;
        }

        if exclude_secrets && should_exclude_path(&rel_path) {
            stats.entries_excluded += 1;
            continue;
        }

        let rel_str = path_to_tar_str(&rel_path)?;
        let mode = meta.permissions().mode() & 0o777;

        if ftype.is_dir() {
            let mut hdr = tar::Header::new_gnu();
            hdr.set_entry_type(tar::EntryType::Directory);
            hdr.set_size(0);
            hdr.set_mode(if mode == 0 { 0o755 } else { mode });
            hdr.set_uid(0);
            hdr.set_gid(0);
            hdr.set_mtime(0);
            hdr.set_cksum();
            builder.append_data(&mut hdr, &rel_str, io::empty())?;
            stats.dirs_included += 1;

            append_dir_recursive(root_dir, &rel_path, exclude_secrets, builder, stats)?;
        } else if ftype.is_file() {
            let file_len = meta.len();
            let mut file = File::open(&abs_path)?;
            let mut hdr = tar::Header::new_gnu();
            hdr.set_entry_type(tar::EntryType::Regular);
            hdr.set_size(file_len);
            hdr.set_mode(if mode == 0 { 0o644 } else { mode });
            hdr.set_uid(0);
            hdr.set_gid(0);
            hdr.set_mtime(0);
            hdr.set_cksum();
            builder.append_data(&mut hdr, &rel_str, &mut file)?;
            stats.files_included += 1;
            stats.bytes_included = stats.bytes_included.saturating_add(file_len);
        }
    }

    Ok(())
}

fn path_to_tar_str(path: &Path) -> Result<String> {
    let mut parts = Vec::new();
    for comp in path.components() {
        if let Component::Normal(s) = comp {
            let seg = s.to_str().ok_or_else(|| {
                CliError::InvalidArgument(format!(
                    "non-UTF-8 path cannot be uploaded: '{}'",
                    path.display()
                ))
            })?;
            parts.push(seg);
        }
    }
    Ok(parts.join("/"))
}
