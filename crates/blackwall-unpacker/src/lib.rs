//! Hardened streaming validator, canonical `.tar.gz` re-packer, and safe host
//! directory extractor for untrusted guest `GET /files` download streams.
//!
//! Security invariants enforced on every guest stream:
//! - Hard `max_bytes` cap on **decompressed** payload bytes (stops zip-bombs immediately).
//! - Hard `max_files` cap.
//! - Rejects absolute paths, `..` traversal segments, NUL bytes, empty paths, and backslashes.
//! - Rejects symlinks, hardlinks, FIFOs, char/block devices, and any non-regular/non-dir entry.
//! - Strips setuid/setgid/sticky bits (`mode & 0o777`) and normalizes `uid=0`, `gid=0`, `mtime=0`.
//! - Canonically re-packs `.tar.gz` streams so downstream host tools never parse guest tar bytes.
//! - Enforces `deny_touch_globs` with ASCII case-folding AND Unicode NFC/NFD normalization,
//!   and rejects case-colliding sibling paths when unpacking onto a host directory.
//! - Emits `AuditEventKind::UnpackerRejection` to `AuditSink` on every blocked path or limit breach.

pub mod jail;

pub use jail::{apply_unpacker_jail, JailStatus};

use blackwall_audit::{AuditEvent, AuditEventKind, AuditSink};
use blackwall_policy::ExportSpec;
use blackwall_proto::DownloadFormat;
use flate2::read::GzDecoder;
use flate2::{Compression, GzBuilder};
use globset::{GlobBuilder, GlobMatcher};
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use thiserror::Error;
use unicode_normalization::UnicodeNormalization;

#[derive(Debug, Error)]
pub enum UnpackerError {
    #[error("decompressed export size exceeded max_bytes limit ({limit} bytes)")]
    MaxBytesExceeded { limit: u64 },
    #[error("export file count exceeded max_files limit ({limit} files)")]
    MaxFilesExceeded { limit: u64 },
    #[error("invalid archive path '{path}': {reason}")]
    InvalidPath { path: String, reason: String },
    #[error("forbidden entry type '{kind}' at path '{path}'")]
    ForbiddenEntryType { path: String, kind: String },
    #[error("path '{path}' blocked by deny_touch_globs pattern '{glob}'")]
    DeniedByGlob { path: String, glob: String },
    #[error("case/Unicode-colliding path '{path}' conflicts with '{existing}'")]
    CaseCollision { path: String, existing: String },
    #[error("invalid deny_touch_globs pattern '{pattern}': {reason}")]
    InvalidGlob { pattern: String, reason: String },
    #[error("failed to apply unpacker jail: {0}")]
    JailError(String),
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

pub type Result<T> = std::result::Result<T, UnpackerError>;

/// Summary of a validated & re-packed / unpacked guest export stream.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UnpackSummary {
    pub bytes_written: u64,
    pub files_written: u64,
    pub dirs_written: u64,
}

/// Bounded `Read` wrapper that immediately halts decompression or raw reads as
/// soon as `limit` bytes are exceeded (preventing zip-bombs from exhausting RAM/disk).
pub struct BoundedReader<R> {
    inner: R,
    remaining: u64,
    exceeded: Arc<AtomicBool>,
}

impl<R> BoundedReader<R> {
    pub fn new(inner: R, limit: u64) -> (Self, Arc<AtomicBool>) {
        let exceeded = Arc::new(AtomicBool::new(false));
        (
            Self {
                inner,
                remaining: limit,
                exceeded: Arc::clone(&exceeded),
            },
            exceeded,
        )
    }

    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read> Read for BoundedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.remaining == 0 {
            // Probe for 1 additional byte to detect overflow vs clean EOF.
            let mut probe = [0u8; 1];
            match self.inner.read(&mut probe)? {
                0 => return Ok(0),
                _ => {
                    self.exceeded.store(true, Ordering::SeqCst);
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "max_bytes limit exceeded",
                    ));
                }
            }
        }
        let max_read = (buf.len() as u64).min(self.remaining) as usize;
        let n = self.inner.read(&mut buf[..max_read])?;
        self.remaining -= n as u64;
        Ok(n)
    }
}

/// Validate and copy a `Raw` single-file download stream, enforcing `spec.max_bytes`
/// and recording an `AuditEventKind::UnpackerRejection` if exceeded.
pub fn validate_raw_stream<R: Read, W: Write>(
    reader: R,
    mut writer: W,
    display_path: &str,
    spec: &ExportSpec,
    sandbox_id: &str,
    sink: &dyn AuditSink,
) -> Result<UnpackSummary> {
    if spec.max_files == 0 {
        record_rejection(sink, sandbox_id, display_path, "max_files limit is 0");
        return Err(UnpackerError::MaxFilesExceeded { limit: 0 });
    }
    let (mut bounded, exceeded) = BoundedReader::new(reader, spec.max_bytes);
    let copied = match io::copy(&mut bounded, &mut writer) {
        Ok(n) => n,
        Err(err) => {
            if exceeded.load(Ordering::SeqCst) {
                record_rejection(
                    sink,
                    sandbox_id,
                    display_path,
                    &format!("exceeded max_bytes ({})", spec.max_bytes),
                );
                return Err(UnpackerError::MaxBytesExceeded {
                    limit: spec.max_bytes,
                });
            }
            return Err(UnpackerError::Io(err));
        }
    };
    writer.flush()?;
    Ok(UnpackSummary {
        bytes_written: copied,
        files_written: 1,
        dirs_written: 0,
    })
}

/// Validate a guest export stream according to [`DownloadFormat`] (`Raw` or `TarGz`),
/// writing either the bounded raw bytes or a canonically re-packed `.tar.gz` stream.
pub fn sanitize_download_stream<R: Read, W: Write>(
    format: DownloadFormat,
    reader: R,
    writer: W,
    display_path: &str,
    spec: &ExportSpec,
    sandbox_id: &str,
    sink: &dyn AuditSink,
) -> Result<UnpackSummary> {
    match format {
        DownloadFormat::Raw => {
            validate_raw_stream(reader, writer, display_path, spec, sandbox_id, sink)
        }
        DownloadFormat::TarGz => repack_targz(reader, writer, spec, sandbox_id, sink),
    }
}

/// Streaming validator and canonical `.tar.gz` re-packer.
///
/// Reads an untrusted guest `.tar.gz` stream through a decompressed-byte-bounded
/// decoder, validates every entry path and entry type, strips setuid/setgid/sticky
/// bits (`mode & 0o777`), normalizes `uid=0`, `gid=0`, `mtime=0`, and emits a
/// brand-new deterministic `.tar.gz` stream into `writer`.
pub fn repack_targz<R: Read, W: Write>(
    reader: R,
    writer: W,
    spec: &ExportSpec,
    sandbox_id: &str,
    sink: &dyn AuditSink,
) -> Result<UnpackSummary> {
    let gz_decoder = GzDecoder::new(reader);
    // Hard ceiling on total decompressed tar stream (payload + tar headers/padding)
    // to stop gzip bombs hiding in tar padding or trailing garbage.
    let tar_stream_limit = compute_tar_stream_ceiling(spec);
    let (bounded_tar_stream, stream_exceeded) = BoundedReader::new(gz_decoder, tar_stream_limit);
    let mut archive = tar::Archive::new(bounded_tar_stream);

    let gz_encoder = GzBuilder::new()
        .mtime(0)
        .write(writer, Compression::default());
    let mut out_tar = tar::Builder::new(gz_encoder);

    let mut summary = UnpackSummary::default();
    let entries = archive.entries().map_err(|e| {
        map_tar_io_err(e, &stream_exceeded, spec.max_bytes, sandbox_id, "<archive>", sink)
    })?;

    for entry_res in entries {
        let mut entry = entry_res.map_err(|e| {
            map_tar_io_err(e, &stream_exceeded, spec.max_bytes, sandbox_id, "<archive>", sink)
        })?;

        let raw_path_bytes = entry.path_bytes().into_owned();
        let entry_type = entry.header().entry_type();
        let Some(clean_path) =
            validate_archive_path(&raw_path_bytes, entry_type, sandbox_id, sink)?
        else {
            continue;
        };

        validate_entry_type(entry_type, &clean_path, sandbox_id, sink)?;

        let clean_mode = entry.header().mode().unwrap_or(0o644) & 0o777;

        match entry_type {
            tar::EntryType::Directory => {
                let mut hdr = tar::Header::new_gnu();
                hdr.set_entry_type(tar::EntryType::Directory);
                hdr.set_size(0);
                hdr.set_mode(clean_mode);
                hdr.set_uid(0);
                hdr.set_gid(0);
                hdr.set_mtime(0);
                hdr.set_cksum();
                out_tar.append_data(&mut hdr, &clean_path, io::empty())?;
                summary.dirs_written += 1;
            }
            tar::EntryType::Regular => {
                if summary.files_written >= spec.max_files {
                    record_rejection(
                        sink,
                        sandbox_id,
                        &clean_path,
                        &format!("exceeded max_files ({})", spec.max_files),
                    );
                    return Err(UnpackerError::MaxFilesExceeded {
                        limit: spec.max_files,
                    });
                }

                let declared_size = entry.header().size().map_err(|e| {
                    map_tar_io_err(
                        e,
                        &stream_exceeded,
                        spec.max_bytes,
                        sandbox_id,
                        &clean_path,
                        sink,
                    )
                })?;

                let remaining = spec.max_bytes.saturating_sub(summary.bytes_written);
                if declared_size > remaining {
                    record_rejection(
                        sink,
                        sandbox_id,
                        &clean_path,
                        &format!("exceeded max_bytes ({})", spec.max_bytes),
                    );
                    return Err(UnpackerError::MaxBytesExceeded {
                        limit: spec.max_bytes,
                    });
                }

                let mut data = Vec::with_capacity((declared_size as usize).min(64 * 1024));
                let (mut bounded_entry, entry_exceeded) = BoundedReader::new(&mut entry, remaining);
                if let Err(err) = bounded_entry.read_to_end(&mut data) {
                    if entry_exceeded.load(Ordering::SeqCst)
                        || stream_exceeded.load(Ordering::SeqCst)
                    {
                        record_rejection(
                            sink,
                            sandbox_id,
                            &clean_path,
                            &format!("exceeded max_bytes ({})", spec.max_bytes),
                        );
                        return Err(UnpackerError::MaxBytesExceeded {
                            limit: spec.max_bytes,
                        });
                    }
                    return Err(UnpackerError::Io(err));
                }

                let actual_len = data.len() as u64;
                summary.bytes_written = summary.bytes_written.saturating_add(actual_len);
                if summary.bytes_written > spec.max_bytes {
                    record_rejection(
                        sink,
                        sandbox_id,
                        &clean_path,
                        &format!("exceeded max_bytes ({})", spec.max_bytes),
                    );
                    return Err(UnpackerError::MaxBytesExceeded {
                        limit: spec.max_bytes,
                    });
                }

                let mut hdr = tar::Header::new_gnu();
                hdr.set_entry_type(tar::EntryType::Regular);
                hdr.set_size(actual_len);
                hdr.set_mode(clean_mode);
                hdr.set_uid(0);
                hdr.set_gid(0);
                hdr.set_mtime(0);
                hdr.set_cksum();
                out_tar.append_data(&mut hdr, &clean_path, data.as_slice())?;
                summary.files_written += 1;
            }
            _ => unreachable!("validate_entry_type permits only Regular and Directory"),
        }
    }

    let gz_encoder = out_tar.into_inner()?;
    let mut inner_writer = gz_encoder.finish()?;
    inner_writer.flush()?;
    Ok(summary)
}

/// Extract a validated guest `.tar.gz` stream onto a host directory `dest_dir`.
///
/// Enforces all streaming archive validations PLUS:
/// - `spec.deny_touch_globs` with **ASCII case-folding AND Unicode NFC/NFD normalization**
/// - Rejection of **case-colliding / Unicode-colliding** sibling paths inside the archive
///   (e.g., `src/Foo.rs` and `src/foo.rs`, or NFC `café.rs` and NFD `cafe\u{0301}.rs`)
/// - Emits `AuditEventKind::UnpackerRejection` on every blocked path
/// - Writes regular files with `O_NOFOLLOW` and stripped mode bits (`mode & 0o777`).
pub fn unpack_to_dir<R: Read>(
    reader: R,
    dest_dir: &Path,
    spec: &ExportSpec,
    sandbox_id: &str,
    sink: &dyn AuditSink,
) -> Result<UnpackSummary> {
    let deny_matcher = DenyGlobMatcher::new(&spec.deny_touch_globs)?;
    fs::create_dir_all(dest_dir)?;

    let gz_decoder = GzDecoder::new(reader);
    let tar_stream_limit = compute_tar_stream_ceiling(spec);
    let (bounded_tar_stream, stream_exceeded) = BoundedReader::new(gz_decoder, tar_stream_limit);
    let mut archive = tar::Archive::new(bounded_tar_stream);

    // Maps case+NFC-folded canonical path -> first original path seen in archive.
    let mut seen_folded: HashMap<String, String> = HashMap::new();
    let mut summary = UnpackSummary::default();

    let entries = archive.entries().map_err(|e| {
        map_tar_io_err(e, &stream_exceeded, spec.max_bytes, sandbox_id, "<archive>", sink)
    })?;

    for entry_res in entries {
        let mut entry = entry_res.map_err(|e| {
            map_tar_io_err(e, &stream_exceeded, spec.max_bytes, sandbox_id, "<archive>", sink)
        })?;

        let raw_path_bytes = entry.path_bytes().into_owned();
        let entry_type = entry.header().entry_type();
        let Some(clean_path) =
            validate_archive_path(&raw_path_bytes, entry_type, sandbox_id, sink)?
        else {
            continue;
        };

        validate_entry_type(entry_type, &clean_path, sandbox_id, sink)?;

        // Check deny_touch_globs with ASCII case-folding + Unicode NFC/NFD normalization.
        if let Some(matched_glob) = deny_matcher.find_match(&clean_path) {
            record_rejection(
                sink,
                sandbox_id,
                &clean_path,
                &format!("matched deny_touch_globs pattern '{matched_glob}'"),
            );
            return Err(UnpackerError::DeniedByGlob {
                path: clean_path,
                glob: matched_glob.to_string(),
            });
        }

        // Reject case-colliding or Unicode NFC/NFD-colliding paths in the same archive.
        let folded_key = fold_path_nfc(&clean_path);
        if let Some(existing) = seen_folded.get(&folded_key) {
            record_rejection(
                sink,
                sandbox_id,
                &clean_path,
                &format!("case/Unicode collision with existing path '{existing}'"),
            );
            return Err(UnpackerError::CaseCollision {
                path: clean_path,
                existing: existing.clone(),
            });
        }
        seen_folded.insert(folded_key, clean_path.clone());

        // Also check parent prefixes for case collisions against previously created directories
        // with different casing (e.g., `Src/a.rs` vs `src/b.rs`).
        check_parent_case_collisions(&clean_path, &mut seen_folded, sandbox_id, sink)?;

        let clean_mode = entry.header().mode().unwrap_or(0o644) & 0o777;
        let dest_path = dest_dir.join(&clean_path);
        ensure_no_symlink_components(dest_dir, &clean_path, sandbox_id, sink)?;

        match entry_type {
            tar::EntryType::Directory => {
                fs::create_dir_all(&dest_path)?;
                fs::set_permissions(&dest_path, fs::Permissions::from_mode(clean_mode | 0o700))?;
                summary.dirs_written += 1;
            }
            tar::EntryType::Regular => {
                if summary.files_written >= spec.max_files {
                    record_rejection(
                        sink,
                        sandbox_id,
                        &clean_path,
                        &format!("exceeded max_files ({})", spec.max_files),
                    );
                    return Err(UnpackerError::MaxFilesExceeded {
                        limit: spec.max_files,
                    });
                }

                let declared_size = entry.header().size().map_err(|e| {
                    map_tar_io_err(
                        e,
                        &stream_exceeded,
                        spec.max_bytes,
                        sandbox_id,
                        &clean_path,
                        sink,
                    )
                })?;

                let remaining = spec.max_bytes.saturating_sub(summary.bytes_written);
                if declared_size > remaining {
                    record_rejection(
                        sink,
                        sandbox_id,
                        &clean_path,
                        &format!("exceeded max_bytes ({})", spec.max_bytes),
                    );
                    return Err(UnpackerError::MaxBytesExceeded {
                        limit: spec.max_bytes,
                    });
                }

                if let Some(parent) = dest_path.parent() {
                    fs::create_dir_all(parent)?;
                }

                let mut out_file = OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .custom_flags(libc::O_NOFOLLOW)
                    .mode(clean_mode)
                    .open(&dest_path)?;

                let (mut bounded_entry, entry_exceeded) = BoundedReader::new(&mut entry, remaining);
                let written = match io::copy(&mut bounded_entry, &mut out_file) {
                    Ok(n) => n,
                    Err(err) => {
                        let _ = fs::remove_file(&dest_path);
                        if entry_exceeded.load(Ordering::SeqCst)
                            || stream_exceeded.load(Ordering::SeqCst)
                        {
                            record_rejection(
                                sink,
                                sandbox_id,
                                &clean_path,
                                &format!("exceeded max_bytes ({})", spec.max_bytes),
                            );
                            return Err(UnpackerError::MaxBytesExceeded {
                                limit: spec.max_bytes,
                            });
                        }
                        return Err(UnpackerError::Io(err));
                    }
                };
                out_file.flush()?;
                fs::set_permissions(&dest_path, fs::Permissions::from_mode(clean_mode))?;

                summary.bytes_written = summary.bytes_written.saturating_add(written);
                summary.files_written += 1;
            }
            _ => unreachable!("validate_entry_type permits only Regular and Directory"),
        }
    }

    Ok(summary)
}

/// Safely unpack a single raw file onto `dest_dir/<rel_path>` with `deny_touch_globs`
/// and `max_bytes` enforcement.
pub fn unpack_raw_to_dir<R: Read>(
    reader: R,
    dest_dir: &Path,
    rel_path: &str,
    spec: &ExportSpec,
    sandbox_id: &str,
    sink: &dyn AuditSink,
) -> Result<UnpackSummary> {
    let clean_path = validate_archive_path(
        rel_path.as_bytes(),
        tar::EntryType::Regular,
        sandbox_id,
        sink,
    )?
    .ok_or_else(|| UnpackerError::InvalidPath {
        path: rel_path.to_string(),
        reason: "empty destination path".into(),
    })?;

    let deny_matcher = DenyGlobMatcher::new(&spec.deny_touch_globs)?;
    if let Some(matched_glob) = deny_matcher.find_match(&clean_path) {
        record_rejection(
            sink,
            sandbox_id,
            &clean_path,
            &format!("matched deny_touch_globs pattern '{matched_glob}'"),
        );
        return Err(UnpackerError::DeniedByGlob {
            path: clean_path,
            glob: matched_glob.to_string(),
        });
    }

    fs::create_dir_all(dest_dir)?;
    ensure_no_symlink_components(dest_dir, &clean_path, sandbox_id, sink)?;
    let dest_path = dest_dir.join(&clean_path);
    if let Some(parent) = dest_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let out_file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(0o644)
        .open(&dest_path)?;

    match validate_raw_stream(reader, out_file, &clean_path, spec, sandbox_id, sink) {
        Ok(summary) => Ok(summary),
        Err(err) => {
            let _ = fs::remove_file(&dest_path);
            Err(err)
        }
    }
}

/// Compiled `deny_touch_globs` matcher supporting ASCII case-folding and Unicode NFC/NFD equivalence.
#[derive(Debug)]
pub struct DenyGlobMatcher {
    rules: Vec<CompiledDenyRule>,
}

#[derive(Debug)]
struct CompiledDenyRule {
    original: String,
    matchers: Vec<GlobMatcher>,
}

impl DenyGlobMatcher {
    pub fn new(globs: &[String]) -> Result<Self> {
        let mut rules = Vec::with_capacity(globs.len());
        for raw_pat in globs {
            let trimmed = raw_pat.trim().trim_start_matches("./");
            if trimmed.is_empty() {
                continue;
            }
            let folded_nfc = fold_path_nfc(trimmed);
            let mut patterns = vec![folded_nfc.clone()];

            // If pattern has no '/', also match it in nested subdirectories (gitignore semantics).
            if !folded_nfc.contains('/') {
                patterns.push(format!("**/{folded_nfc}"));
            }

            // If pattern ends with `/**`, also deny the directory itself (e.g. `.git` for `.git/**`).
            if let Some(dir_prefix) = folded_nfc.strip_suffix("/**") {
                if !dir_prefix.is_empty() {
                    patterns.push(dir_prefix.to_string());
                    if !dir_prefix.contains('/') {
                        patterns.push(format!("**/{dir_prefix}"));
                        patterns.push(format!("**/{dir_prefix}/**"));
                    }
                }
            }

            let mut matchers = Vec::with_capacity(patterns.len());
            for pat in patterns {
                let glob = GlobBuilder::new(&pat)
                    .literal_separator(true)
                    .build()
                    .map_err(|e| UnpackerError::InvalidGlob {
                        pattern: raw_pat.clone(),
                        reason: e.to_string(),
                    })?;
                matchers.push(glob.compile_matcher());
            }

            rules.push(CompiledDenyRule {
                original: raw_pat.clone(),
                matchers,
            });
        }
        Ok(Self { rules })
    }

    /// Return the first original glob pattern matching `path` (after ASCII case-folding
    /// and Unicode NFC/NFD normalization), or `None` if allowed.
    pub fn find_match(&self, path: &str) -> Option<&str> {
        let folded_nfc = fold_path_nfc(path);
        // Also normalize via NFD -> NFC so any decomposed input is canonically unified,
        // and check full path plus all directory ancestors against directory deny rules.
        let folded_from_nfd: String = path.nfd().collect::<String>().nfc().collect::<String>().to_lowercase();

        for rule in &self.rules {
            for matcher in &rule.matchers {
                if matcher.is_match(&folded_nfc) || matcher.is_match(&folded_from_nfd) {
                    return Some(&rule.original);
                }
            }
        }
        None
    }
}

/// Canonical case-folding + Unicode NFC normalization used for both glob matching
/// and case/Unicode collision detection.
pub fn fold_path_nfc(path: &str) -> String {
    path.nfc().collect::<String>().to_lowercase()
}

fn validate_archive_path(
    raw_bytes: &[u8],
    entry_type: tar::EntryType,
    sandbox_id: &str,
    sink: &dyn AuditSink,
) -> Result<Option<String>> {
    if raw_bytes.contains(&0) {
        let lossy = String::from_utf8_lossy(raw_bytes).into_owned();
        record_rejection(sink, sandbox_id, &lossy, "path contains NUL byte");
        return Err(UnpackerError::InvalidPath {
            path: lossy,
            reason: "path contains NUL byte".into(),
        });
    }

    let raw_str = std::str::from_utf8(raw_bytes).map_err(|_| {
        let lossy = String::from_utf8_lossy(raw_bytes).into_owned();
        record_rejection(sink, sandbox_id, &lossy, "path is not valid UTF-8");
        UnpackerError::InvalidPath {
            path: lossy,
            reason: "path is not valid UTF-8".into(),
        }
    })?;

    if raw_str.is_empty() {
        record_rejection(sink, sandbox_id, "", "empty path");
        return Err(UnpackerError::InvalidPath {
            path: String::new(),
            reason: "empty path".into(),
        });
    }

    if raw_str.starts_with('/') {
        record_rejection(sink, sandbox_id, raw_str, "absolute path is forbidden");
        return Err(UnpackerError::InvalidPath {
            path: raw_str.to_string(),
            reason: "absolute path is forbidden".into(),
        });
    }

    if raw_str.contains('\\') {
        record_rejection(sink, sandbox_id, raw_str, "backslash in path is forbidden");
        return Err(UnpackerError::InvalidPath {
            path: raw_str.to_string(),
            reason: "backslash in path is forbidden".into(),
        });
    }

    // Strip optional leading `./` prefixes and trailing `/` for directories.
    let mut trimmed = raw_str;
    while let Some(rest) = trimmed.strip_prefix("./") {
        trimmed = rest;
    }
    if entry_type == tar::EntryType::Directory {
        trimmed = trimmed.trim_end_matches('/');
        if trimmed.is_empty() || trimmed == "." {
            // Root directory marker `.` or `./` in tar archives is benign and skipped.
            return Ok(None);
        }
    }

    if trimmed.is_empty() {
        record_rejection(sink, sandbox_id, raw_str, "empty path after normalization");
        return Err(UnpackerError::InvalidPath {
            path: raw_str.to_string(),
            reason: "empty path after normalization".into(),
        });
    }

    let mut clean_segments = Vec::new();
    for seg in trimmed.split('/') {
        if seg == ".." {
            record_rejection(sink, sandbox_id, raw_str, "parent traversal '..' is forbidden");
            return Err(UnpackerError::InvalidPath {
                path: raw_str.to_string(),
                reason: "parent traversal '..' is forbidden".into(),
            });
        }
        if seg.is_empty() || seg == "." {
            record_rejection(
                sink,
                sandbox_id,
                raw_str,
                "empty or '.' path segment is forbidden",
            );
            return Err(UnpackerError::InvalidPath {
                path: raw_str.to_string(),
                reason: "empty or '.' path segment is forbidden".into(),
            });
        }
        clean_segments.push(seg);
    }

    Ok(Some(clean_segments.join("/")))
}

fn validate_entry_type(
    entry_type: tar::EntryType,
    path: &str,
    sandbox_id: &str,
    sink: &dyn AuditSink,
) -> Result<()> {
    match entry_type {
        tar::EntryType::Regular | tar::EntryType::Directory => Ok(()),
        other => {
            let kind = describe_entry_type(other);
            record_rejection(
                sink,
                sandbox_id,
                path,
                &format!("forbidden tar entry type: {kind}"),
            );
            Err(UnpackerError::ForbiddenEntryType {
                path: path.to_string(),
                kind: kind.to_string(),
            })
        }
    }
}

fn describe_entry_type(t: tar::EntryType) -> &'static str {
    match t {
        tar::EntryType::Symlink => "symlink",
        tar::EntryType::Link => "hardlink",
        tar::EntryType::Fifo => "fifo",
        tar::EntryType::Char => "char_device",
        tar::EntryType::Block => "block_device",
        tar::EntryType::GNUSparse => "gnu_sparse",
        tar::EntryType::Continuous => "continuous",
        _ => "unsupported",
    }
}

fn check_parent_case_collisions(
    clean_path: &str,
    seen_folded: &mut HashMap<String, String>,
    sandbox_id: &str,
    sink: &dyn AuditSink,
) -> Result<()> {
    let parts: Vec<&str> = clean_path.split('/').collect();
    if parts.len() <= 1 {
        return Ok(());
    }
    let mut prefix = String::new();
    for part in &parts[..parts.len() - 1] {
        if !prefix.is_empty() {
            prefix.push('/');
        }
        prefix.push_str(part);
        let folded = fold_path_nfc(&prefix);
        if let Some(existing) = seen_folded.get(&folded) {
            if existing != &prefix {
                record_rejection(
                    sink,
                    sandbox_id,
                    clean_path,
                    &format!(
                        "parent directory '{prefix}' collides in case/Unicode with '{existing}'"
                    ),
                );
                return Err(UnpackerError::CaseCollision {
                    path: clean_path.to_string(),
                    existing: existing.clone(),
                });
            }
        } else {
            seen_folded.insert(folded, prefix.clone());
        }
    }
    Ok(())
}

fn ensure_no_symlink_components(
    dest_dir: &Path,
    clean_path: &str,
    sandbox_id: &str,
    sink: &dyn AuditSink,
) -> Result<()> {
    let mut cur = PathBuf::from(dest_dir);
    for seg in clean_path.split('/') {
        cur.push(seg);
        if let Ok(meta) = fs::symlink_metadata(&cur) {
            if meta.file_type().is_symlink() {
                record_rejection(
                    sink,
                    sandbox_id,
                    clean_path,
                    "destination path traverses an existing symlink",
                );
                return Err(UnpackerError::InvalidPath {
                    path: clean_path.to_string(),
                    reason: "destination path traverses an existing symlink".into(),
                });
            }
        }
    }
    Ok(())
}

fn compute_tar_stream_ceiling(spec: &ExportSpec) -> u64 {
    // Allow tar 512-byte headers + PAX/padding overhead proportional to max_files
    // while still cutting off multi-megabyte gzip bombs immediately.
    let header_overhead = spec.max_files.saturating_mul(2048).saturating_add(16_384);
    spec.max_bytes.saturating_add(header_overhead)
}

fn map_tar_io_err(
    err: io::Error,
    exceeded: &Arc<AtomicBool>,
    limit: u64,
    sandbox_id: &str,
    path: &str,
    sink: &dyn AuditSink,
) -> UnpackerError {
    if exceeded.load(Ordering::SeqCst) {
        record_rejection(
            sink,
            sandbox_id,
            path,
            &format!("decompressed tar stream exceeded max_bytes ({limit})"),
        );
        UnpackerError::MaxBytesExceeded { limit }
    } else {
        UnpackerError::Io(err)
    }
}

fn record_rejection(sink: &dyn AuditSink, sandbox_id: &str, path: &str, reason: &str) {
    sink.record(AuditEvent::now(
        sandbox_id,
        AuditEventKind::UnpackerRejection {
            path: path.to_string(),
            reason: reason.to_string(),
        },
    ));
}

#[cfg(test)]
mod tests {
    use super::*;
    use blackwall_audit::MemoryAuditSink;
    use flate2::write::GzEncoder;
    use std::io::Cursor;
    use tempfile::TempDir;

    fn make_targz<F>(build_fn: F) -> Vec<u8>
    where
        F: FnOnce(&mut tar::Builder<GzEncoder<Vec<u8>>>),
    {
        let enc = GzEncoder::new(Vec::new(), Compression::default());
        let mut builder = tar::Builder::new(enc);
        build_fn(&mut builder);
        let enc = builder.into_inner().unwrap();
        enc.finish().unwrap()
    }

    fn append_raw_entry(
        builder: &mut tar::Builder<GzEncoder<Vec<u8>>>,
        raw_name: &[u8],
        entry_type: tar::EntryType,
        mode: u32,
        data: &[u8],
        link_name: Option<&[u8]>,
    ) {
        let mut hdr = tar::Header::new_gnu();
        hdr.set_entry_type(entry_type);
        hdr.set_size(data.len() as u64);
        hdr.set_mode(mode);
        hdr.set_uid(1000);
        hdr.set_gid(1000);
        hdr.set_mtime(1_700_000_000);
        {
            let gnu = hdr.as_gnu_mut().unwrap();
            gnu.name[..raw_name.len()].copy_from_slice(raw_name);
            if let Some(link) = link_name {
                gnu.linkname[..link.len()].copy_from_slice(link);
            }
        }
        hdr.set_cksum();
        builder.append(&hdr, data).unwrap();
    }

    #[test]
    fn valid_raw_file_and_targz_canonical_repack_roundtrip() {
        let spec = ExportSpec::default();
        let sink = MemoryAuditSink::new();

        // Raw single file
        let mut raw_out = Vec::new();
        let raw_summary = sanitize_download_stream(
            DownloadFormat::Raw,
            Cursor::new(b"hello blackwall".as_slice()),
            &mut raw_out,
            "/workspace/hello.txt",
            &spec,
            "sb-raw",
            &sink,
        )
        .unwrap();
        assert_eq!(raw_out, b"hello blackwall");
        assert_eq!(raw_summary.bytes_written, 15);
        assert_eq!(raw_summary.files_written, 1);

        // TarGz canonical repack
        let input_tgz = make_targz(|b| {
            append_raw_entry(b, b"src", tar::EntryType::Directory, 0o2755, b"", None);
            append_raw_entry(
                b,
                b"src/main.rs",
                tar::EntryType::Regular,
                0o4755,
                b"fn main() {}\n",
                None,
            );
        });

        let mut clean_tgz_1 = Vec::new();
        let summary = repack_targz(
            Cursor::new(&input_tgz),
            &mut clean_tgz_1,
            &spec,
            "sb-repack",
            &sink,
        )
        .unwrap();
        assert_eq!(summary.files_written, 1);
        assert_eq!(summary.dirs_written, 1);
        assert_eq!(summary.bytes_written, 13);
        assert!(sink.snapshot().is_empty());

        // Second repack produces byte-for-byte identical canonical output
        let mut clean_tgz_2 = Vec::new();
        repack_targz(
            Cursor::new(&input_tgz),
            &mut clean_tgz_2,
            &spec,
            "sb-repack",
            &sink,
        )
        .unwrap();
        assert_eq!(clean_tgz_1, clean_tgz_2);

        // Inspect canonical tar headers: setuid/setgid stripped, uid/gid/mtime == 0
        let mut archive = tar::Archive::new(GzDecoder::new(Cursor::new(&clean_tgz_1)));
        let entries: Vec<_> = archive
            .entries()
            .unwrap()
            .map(|e| {
                let mut e = e.unwrap();
                let path = e.path().unwrap().to_string_lossy().into_owned();
                let mode = e.header().mode().unwrap();
                let uid = e.header().uid().unwrap();
                let gid = e.header().gid().unwrap();
                let mtime = e.header().mtime().unwrap();
                let mut body = Vec::new();
                e.read_to_end(&mut body).unwrap();
                (path, mode, uid, gid, mtime, body)
            })
            .collect();

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0], ("src".into(), 0o0755, 0, 0, 0, vec![]));
        assert_eq!(
            entries[1],
            (
                "src/main.rs".into(),
                0o0755,
                0,
                0,
                0,
                b"fn main() {}\n".to_vec()
            )
        );
    }

    #[test]
    fn rejects_zip_bomb_during_decompression() {
        // Compress 8 MiB of zeroes into a few kilobytes of gzip!
        let bomb_payload = vec![0u8; 8 * 1024 * 1024];
        let bomb_tgz = make_targz(|b| {
            let mut hdr = tar::Header::new_gnu();
            hdr.set_entry_type(tar::EntryType::Regular);
            hdr.set_size(bomb_payload.len() as u64);
            hdr.set_mode(0o644);
            hdr.set_cksum();
            b.append_data(&mut hdr, "bomb.bin", bomb_payload.as_slice())
                .unwrap();
        });
        assert!(
            bomb_tgz.len() < 32 * 1024,
            "compressed bomb should be tiny (was {} bytes)",
            bomb_tgz.len()
        );

        let spec = ExportSpec {
            max_bytes: 4096,
            max_files: 10,
            deny_touch_globs: vec![],
        };
        let sink = MemoryAuditSink::new();
        let mut out = Vec::new();
        let err = repack_targz(Cursor::new(&bomb_tgz), &mut out, &spec, "sb-bomb", &sink)
            .unwrap_err();
        assert!(matches!(err, UnpackerError::MaxBytesExceeded { limit: 4096 }));
        assert_eq!(sink.snapshot().len(), 1);
        assert!(matches!(
            &sink.snapshot()[0].kind,
            AuditEventKind::UnpackerRejection { path, .. } if path == "bomb.bin"
        ));

        // Multi-file cumulative max_bytes exceeded mid-stream
        let multi_tgz = make_targz(|b| {
            let chunk = vec![b'A'; 3000];
            for name in ["a.bin", "b.bin"] {
                let mut hdr = tar::Header::new_gnu();
                hdr.set_entry_type(tar::EntryType::Regular);
                hdr.set_size(chunk.len() as u64);
                hdr.set_mode(0o644);
                hdr.set_cksum();
                b.append_data(&mut hdr, name, chunk.as_slice()).unwrap();
            }
        });
        let sink_multi = MemoryAuditSink::new();
        let err_multi = repack_targz(
            Cursor::new(&multi_tgz),
            Vec::new(),
            &spec,
            "sb-multi",
            &sink_multi,
        )
        .unwrap_err();
        assert!(matches!(
            err_multi,
            UnpackerError::MaxBytesExceeded { limit: 4096 }
        ));
        assert_eq!(sink_multi.snapshot().len(), 1);

        // Metadata zip-bomb: 4 MiB compressed GNU long-name header killed immediately by BoundedReader<GzDecoder>
        let meta_bomb = make_targz(|b| {
            let huge_name = vec![b'a'; 4 * 1024 * 1024];
            let mut hdr = tar::Header::new_gnu();
            hdr.set_entry_type(tar::EntryType::GNULongName);
            hdr.set_size(huge_name.len() as u64);
            hdr.set_mode(0o644);
            hdr.set_cksum();
            b.append_data(&mut hdr, "././@LongLink", huge_name.as_slice())
                .unwrap();
        });
        assert!(meta_bomb.len() < 32 * 1024);

        let sink2 = MemoryAuditSink::new();
        let mut out2 = Vec::new();
        let err2 = repack_targz(Cursor::new(&meta_bomb), &mut out2, &spec, "sb-bomb2", &sink2)
            .unwrap_err();
        assert!(matches!(err2, UnpackerError::MaxBytesExceeded { limit: 4096 }));
        assert_eq!(sink2.snapshot().len(), 1);
    }

    #[test]
    fn rejects_max_files_exceeded() {
        let tgz = make_targz(|b| {
            for i in 0..4 {
                let name = format!("f{i}.txt");
                append_raw_entry(
                    b,
                    name.as_bytes(),
                    tar::EntryType::Regular,
                    0o644,
                    b"x",
                    None,
                );
            }
        });
        let spec = ExportSpec {
            max_bytes: 1024 * 1024,
            max_files: 3,
            deny_touch_globs: vec![],
        };
        let sink = MemoryAuditSink::new();
        let mut out = Vec::new();
        let err = repack_targz(Cursor::new(&tgz), &mut out, &spec, "sb-files", &sink).unwrap_err();
        assert!(matches!(err, UnpackerError::MaxFilesExceeded { limit: 3 }));
        assert_eq!(sink.snapshot().len(), 1);
    }

    #[test]
    fn rejects_traversal_absolute_backslash_empty_and_forbidden_entry_types() {
        let spec = ExportSpec::default();

        // 1. .. traversal
        let traversal = make_targz(|b| {
            append_raw_entry(b, b"../escape.txt", tar::EntryType::Regular, 0o644, b"x", None);
        });
        let sink = MemoryAuditSink::new();
        assert!(matches!(
            repack_targz(Cursor::new(&traversal), Vec::new(), &spec, "sb-1", &sink),
            Err(UnpackerError::InvalidPath { .. })
        ));
        assert_eq!(sink.snapshot().len(), 1);

        // 2. Absolute path
        let abs = make_targz(|b| {
            append_raw_entry(b, b"/etc/passwd", tar::EntryType::Regular, 0o644, b"x", None);
        });
        let sink = MemoryAuditSink::new();
        assert!(matches!(
            repack_targz(Cursor::new(&abs), Vec::new(), &spec, "sb-2", &sink),
            Err(UnpackerError::InvalidPath { .. })
        ));
        assert_eq!(sink.snapshot().len(), 1);

        // 3. Backslash
        let bslash = make_targz(|b| {
            append_raw_entry(b, b"a\\b.txt", tar::EntryType::Regular, 0o644, b"x", None);
        });
        let sink = MemoryAuditSink::new();
        assert!(matches!(
            repack_targz(Cursor::new(&bslash), Vec::new(), &spec, "sb-3", &sink),
            Err(UnpackerError::InvalidPath { .. })
        ));
        assert_eq!(sink.snapshot().len(), 1);

        // 4. Empty path
        let empty = make_targz(|b| {
            append_raw_entry(b, b"", tar::EntryType::Regular, 0o644, b"x", None);
        });
        let sink = MemoryAuditSink::new();
        assert!(matches!(
            repack_targz(Cursor::new(&empty), Vec::new(), &spec, "sb-4", &sink),
            Err(UnpackerError::InvalidPath { .. })
        ));
        assert_eq!(sink.snapshot().len(), 1);

        // 4b. NUL byte inside path (e.g., via crafted PAX header)
        let sink_nul = MemoryAuditSink::new();
        assert!(matches!(
            validate_archive_path(b"foo\0bar.txt", tar::EntryType::Regular, "sb-4b", &sink_nul),
            Err(UnpackerError::InvalidPath { .. })
        ));
        assert_eq!(sink_nul.snapshot().len(), 1);

        // 5. Symlink
        let sym = make_targz(|b| {
            append_raw_entry(
                b,
                b"link",
                tar::EntryType::Symlink,
                0o777,
                b"",
                Some(b"/etc/shadow"),
            );
        });
        let sink = MemoryAuditSink::new();
        assert!(matches!(
            repack_targz(Cursor::new(&sym), Vec::new(), &spec, "sb-5", &sink),
            Err(UnpackerError::ForbiddenEntryType { ref kind, .. }) if kind == "symlink"
        ));
        assert_eq!(sink.snapshot().len(), 1);

        // 6. Hardlink
        let hlink = make_targz(|b| {
            append_raw_entry(
                b,
                b"hardlink",
                tar::EntryType::Link,
                0o644,
                b"",
                Some(b"target.txt"),
            );
        });
        let sink = MemoryAuditSink::new();
        assert!(matches!(
            repack_targz(Cursor::new(&hlink), Vec::new(), &spec, "sb-6", &sink),
            Err(UnpackerError::ForbiddenEntryType { ref kind, .. }) if kind == "hardlink"
        ));
        assert_eq!(sink.snapshot().len(), 1);

        // 7. FIFO, Char device, Block device
        for (ety, expected_kind) in [
            (tar::EntryType::Fifo, "fifo"),
            (tar::EntryType::Char, "char_device"),
            (tar::EntryType::Block, "block_device"),
        ] {
            let dev = make_targz(|b| {
                append_raw_entry(b, b"devnode", ety, 0o600, b"", None);
            });
            let sink = MemoryAuditSink::new();
            assert!(matches!(
                repack_targz(Cursor::new(&dev), Vec::new(), &spec, "sb-dev", &sink),
                Err(UnpackerError::ForbiddenEntryType { ref kind, .. }) if kind == expected_kind
            ));
            assert_eq!(sink.snapshot().len(), 1);
        }
    }

    #[test]
    fn unpack_to_dir_strips_setuid_and_extracts_clean_files() {
        let tgz = make_targz(|b| {
            append_raw_entry(
                b,
                b"bin/tool",
                tar::EntryType::Regular,
                0o4755,
                b"#!/bin/sh\necho ok\n",
                None,
            );
        });
        let dst = TempDir::new().unwrap();
        let spec = ExportSpec::default();
        let sink = MemoryAuditSink::new();

        let summary = unpack_to_dir(Cursor::new(&tgz), dst.path(), &spec, "sb-ok", &sink).unwrap();
        assert_eq!(summary.files_written, 1);
        let extracted = dst.path().join("bin/tool");
        assert_eq!(fs::read(&extracted).unwrap(), b"#!/bin/sh\necho ok\n");
        let mode = fs::symlink_metadata(&extracted).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o0755);
        assert!(sink.snapshot().is_empty());
    }

    #[test]
    fn rejects_ascii_case_bypass_against_deny_touch_globs() {
        let spec = ExportSpec::default();
        let cases = [
            ".GitHub/workflows/ci.yml",
            ".ENVRC",
            ".Cargo/config.toml",
            "makefile",
            ".GIT/hooks/pre-commit",
        ];

        for path in cases {
            let tgz = make_targz(|b| {
                append_raw_entry(
                    b,
                    path.as_bytes(),
                    tar::EntryType::Regular,
                    0o644,
                    b"pwned",
                    None,
                );
            });
            let dst = TempDir::new().unwrap();
            let sink = MemoryAuditSink::new();
            let err = unpack_to_dir(Cursor::new(&tgz), dst.path(), &spec, "sb-case", &sink)
                .unwrap_err();
            assert!(
                matches!(err, UnpackerError::DeniedByGlob { .. }),
                "expected DeniedByGlob for {path}, got {err:?}"
            );
            let events = sink.snapshot();
            assert_eq!(events.len(), 1);
            assert!(matches!(
                &events[0].kind,
                AuditEventKind::UnpackerRejection { path: p, .. } if p == path
            ));
            assert!(!dst.path().join(path).exists());
        }
    }

    #[test]
    fn rejects_unicode_nfd_normalization_bypass_against_deny_touch_globs() {
        // Protected glob written in composed NFC: "café/**" and "résumé.sh"
        let spec = ExportSpec {
            max_bytes: 1024 * 1024,
            max_files: 100,
            deny_touch_globs: vec!["caf\u{00e9}/**".into(), "r\u{00e9}sum\u{00e9}.sh".into()],
        };

        // Guest sends decomposed NFD + mixed uppercase: "CAF\u{0045}\u{0301}/hook.sh"
        let nfd_path = "CAFE\u{0301}/hook.sh";
        let tgz = make_targz(|b| {
            append_raw_entry(
                b,
                nfd_path.as_bytes(),
                tar::EntryType::Regular,
                0o644,
                b"evil",
                None,
            );
        });
        let dst = TempDir::new().unwrap();
        let sink = MemoryAuditSink::new();
        let err =
            unpack_to_dir(Cursor::new(&tgz), dst.path(), &spec, "sb-nfd", &sink).unwrap_err();
        assert!(matches!(err, UnpackerError::DeniedByGlob { .. }));
        assert_eq!(sink.snapshot().len(), 1);
        assert!(matches!(
            &sink.snapshot()[0].kind,
            AuditEventKind::UnpackerRejection { path, .. } if path == nfd_path
        ));

        // Reverse: NFD glob pattern vs NFC uppercase archive path
        let spec_nfd_glob = ExportSpec {
            max_bytes: 1024 * 1024,
            max_files: 100,
            deny_touch_globs: vec!["cafe\u{0301}.toml".into()],
        };
        let nfc_path = "CAF\u{00c9}.TOML";
        let tgz2 = make_targz(|b| {
            append_raw_entry(
                b,
                nfc_path.as_bytes(),
                tar::EntryType::Regular,
                0o644,
                b"evil",
                None,
            );
        });
        let dst2 = TempDir::new().unwrap();
        let sink2 = MemoryAuditSink::new();
        assert!(matches!(
            unpack_to_dir(Cursor::new(&tgz2), dst2.path(), &spec_nfd_glob, "sb-nfc", &sink2),
            Err(UnpackerError::DeniedByGlob { .. })
        ));
        assert_eq!(sink2.snapshot().len(), 1);
    }

    #[test]
    fn rejects_case_and_unicode_colliding_sibling_paths() {
        let spec = ExportSpec::default();

        // ASCII case collision: src/Foo.rs and src/foo.rs
        let tgz = make_targz(|b| {
            append_raw_entry(b, b"src/Foo.rs", tar::EntryType::Regular, 0o644, b"1", None);
            append_raw_entry(b, b"src/foo.rs", tar::EntryType::Regular, 0o644, b"2", None);
        });
        let dst = TempDir::new().unwrap();
        let sink = MemoryAuditSink::new();
        let err =
            unpack_to_dir(Cursor::new(&tgz), dst.path(), &spec, "sb-collide", &sink).unwrap_err();
        assert!(matches!(
            err,
            UnpackerError::CaseCollision { ref path, ref existing }
            if path == "src/foo.rs" && existing == "src/Foo.rs"
        ));
        assert_eq!(sink.snapshot().len(), 1);
        assert!(matches!(
            &sink.snapshot()[0].kind,
            AuditEventKind::UnpackerRejection { path, .. } if path == "src/foo.rs"
        ));

        // Unicode NFC vs NFD sibling collision
        let tgz_uni = make_targz(|b| {
            append_raw_entry(
                b,
                "src/caf\u{00e9}.rs".as_bytes(),
                tar::EntryType::Regular,
                0o644,
                b"1",
                None,
            );
            append_raw_entry(
                b,
                "src/cafe\u{0301}.rs".as_bytes(),
                tar::EntryType::Regular,
                0o644,
                b"2",
                None,
            );
        });
        let dst2 = TempDir::new().unwrap();
        let sink2 = MemoryAuditSink::new();
        assert!(matches!(
            unpack_to_dir(Cursor::new(&tgz_uni), dst2.path(), &spec, "sb-uni-col", &sink2),
            Err(UnpackerError::CaseCollision { .. })
        ));
        assert_eq!(sink2.snapshot().len(), 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn apply_unpacker_jail_blocks_network_sockets_and_restricts_fs_on_thread() {
        let allowed_dir = TempDir::new().unwrap();
        let forbidden_dir = TempDir::new().unwrap();
        let forbidden_file = forbidden_dir.path().join("secret.txt");
        fs::write(&forbidden_file, b"host-secret").unwrap();

        let allowed_path = allowed_dir.path().to_path_buf();
        let forbidden_path = forbidden_file.clone();

        // Run inside a dedicated thread so Landlock & seccomp apply strictly to this thread.
        let handle = std::thread::spawn(move || {
            let status = apply_unpacker_jail(Some(&allowed_path)).unwrap();
            assert!(status.no_new_privs);
            assert!(status.non_dumpable);
            assert!(status.seccomp_enforced);

            // socket() must be denied with EPERM by seccomp-bpf
            let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
            assert_eq!(fd, -1, "socket() must be blocked by seccomp");
            assert_eq!(
                io::Error::last_os_error().raw_os_error(),
                Some(libc::EPERM)
            );

            // Writing inside allowed_path must succeed
            let ok_file = allowed_path.join("output.txt");
            fs::write(&ok_file, b"safe").unwrap();
            assert_eq!(fs::read(&ok_file).unwrap(), b"safe");

            // Reading outside allowed_path must fail when Landlock is enforced
            if status.landlock_enforced {
                let err = fs::read(&forbidden_path).unwrap_err();
                assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
            }
        });
        handle.join().unwrap();
    }
}
