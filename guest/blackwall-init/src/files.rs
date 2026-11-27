//! Streaming `/workspace` file upload (`Raw`, `Tar`, `TarGz`) and download (`Raw`, `TarGz`)
//! strictly confined inside `workspace_root`.

use blackwall_proto::{CtrlErrorCode, CtrlResponse, DownloadFormat, UploadKind};
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use thiserror::Error;

pub const DOWNLOAD_CHUNK_SIZE: usize = 64 * 1024;
pub const MAX_UPLOAD_FILES: u64 = 100_000;

#[derive(Debug, Error)]
pub enum FileError {
    #[error("path escapes workspace confinement: {0}")]
    PathViolation(String),
    #[error("invalid archive entry: {0}")]
    InvalidArchive(String),
    #[error("file not found: {0}")]
    NotFound(String),
    #[error("limit exceeded: {0}")]
    LimitExceeded(String),
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

impl FileError {
    pub fn error_code(&self) -> CtrlErrorCode {
        match self {
            Self::PathViolation(_) | Self::InvalidArchive(_) => CtrlErrorCode::PathViolation,
            Self::NotFound(_) => CtrlErrorCode::NotFound,
            Self::LimitExceeded(_) => CtrlErrorCode::LimitExceeded,
            Self::Io(e) if e.kind() == io::ErrorKind::NotFound => CtrlErrorCode::NotFound,
            Self::Io(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                CtrlErrorCode::PermissionDenied
            }
            Self::Io(_) => CtrlErrorCode::Internal,
        }
    }
}

/// Resolve `requested` strictly inside `workspace_root`.
///
/// Accepts:
/// - `virtual_mount` (e.g. `"/workspace"`) or paths prefixed with `"{virtual_mount}/..."`
/// - Relative paths (e.g. `"src/main.rs"`) without `..`
///
/// Rejects:
/// - NUL bytes
/// - Any `..` (`Component::ParentDir`)
/// - Absolute paths outside `virtual_mount` (e.g. `"/etc/passwd"`)
/// - Any symlink component along the path inside `workspace_root`
pub fn resolve_confined_path(
    workspace_root: &Path,
    virtual_mount: &str,
    requested: &str,
) -> Result<PathBuf, FileError> {
    if requested.contains('\0') {
        return Err(FileError::PathViolation("NUL byte in path".into()));
    }
    let canonical_root = fs::canonicalize(workspace_root)?;
    let vmount = virtual_mount.trim_end_matches('/');

    let rel_str = if requested == vmount {
        ""
    } else if let Some(rest) = requested.strip_prefix(&format!("{vmount}/")) {
        rest
    } else if requested.starts_with('/') {
        return Err(FileError::PathViolation(format!(
            "path {requested:?} is outside {vmount:?}"
        )));
    } else {
        requested
    };

    let rel_clean = sanitize_relative_path(Path::new(rel_str))?;
    let mut cur = canonical_root.clone();

    for comp in rel_clean.components() {
        if let Component::Normal(seg) = comp {
            cur.push(seg);
            if let Ok(meta) = fs::symlink_metadata(&cur) {
                if meta.file_type().is_symlink() {
                    return Err(FileError::PathViolation(format!(
                        "symlink component rejected: {}",
                        cur.display()
                    )));
                }
            }
        }
    }

    // Verify existing ancestor canonical path stays inside `canonical_root`.
    let mut check = cur.as_path();
    while !check.exists() {
        match check.parent() {
            Some(p) => check = p,
            None => break,
        }
    }
    let canon_ancestor = fs::canonicalize(check)?;
    if !canon_ancestor.starts_with(&canonical_root) {
        return Err(FileError::PathViolation(format!(
            "resolved ancestor escapes workspace: {requested:?}"
        )));
    }

    Ok(cur)
}

/// Validate and normalize a relative path with no `..`, root dir, or prefix.
fn sanitize_relative_path(path: &Path) -> Result<PathBuf, FileError> {
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::CurDir => {}
            Component::Normal(seg) => {
                if seg.as_encoded_bytes().contains(&0) {
                    return Err(FileError::PathViolation("NUL byte in component".into()));
                }
                out.push(seg);
            }
            Component::ParentDir => {
                return Err(FileError::PathViolation(format!(
                    "parent directory traversal '..' rejected in {:?}",
                    path
                )));
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(FileError::PathViolation(format!(
                    "absolute path rejected in {:?}",
                    path
                )));
            }
        }
    }
    Ok(out)
}

/// Streaming upload session fed by `CtrlRequest::FileChunk` messages.
pub enum UploadSession {
    Raw {
        file: File,
        bytes_written: u64,
    },
    Archive {
        tx: Option<mpsc::SyncSender<Vec<u8>>>,
        worker: Option<JoinHandle<Result<(u64, u64), FileError>>>,
    },
}

impl UploadSession {
    pub fn begin(
        workspace_root: &Path,
        virtual_mount: &str,
        requested_path: &str,
        kind: UploadKind,
    ) -> Result<Self, FileError> {
        let target = resolve_confined_path(workspace_root, virtual_mount, requested_path)?;

        match kind {
            UploadKind::Raw => {
                if target == fs::canonicalize(workspace_root)? {
                    return Err(FileError::PathViolation(
                        "cannot overwrite workspace root with a raw file".into(),
                    ));
                }
                if let Some(parent) = target.parent() {
                    fs::create_dir_all(parent)?;
                }
                if let Ok(meta) = fs::symlink_metadata(&target) {
                    if meta.file_type().is_symlink() {
                        return Err(FileError::PathViolation(
                            "refusing to write through symlink".into(),
                        ));
                    }
                }
                let file = OpenOptions::new()
                    .create(true)
                    .truncate(true)
                    .write(true)
                    .open(&target)?;
                Ok(Self::Raw {
                    file,
                    bytes_written: 0,
                })
            }
            UploadKind::Tar | UploadKind::TarGz => {
                fs::create_dir_all(&target)?;
                let canonical_root = fs::canonicalize(workspace_root)?;
                let canonical_target = fs::canonicalize(&target)?;
                if !canonical_target.starts_with(&canonical_root) {
                    return Err(FileError::PathViolation(
                        "archive target escapes workspace".into(),
                    ));
                }
                let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(16);
                let is_gzip = matches!(kind, UploadKind::TarGz);
                let worker = thread::spawn(move || {
                    let reader = ChannelReader::new(rx);
                    if is_gzip {
                        let gz = GzDecoder::new(reader);
                        extract_tar_confined(gz, &canonical_root, &canonical_target)
                    } else {
                        extract_tar_confined(reader, &canonical_root, &canonical_target)
                    }
                });
                Ok(Self::Archive {
                    tx: Some(tx),
                    worker: Some(worker),
                })
            }
        }
    }

    pub fn write_chunk(&mut self, data: Vec<u8>) -> Result<(), FileError> {
        if data.is_empty() {
            return Ok(());
        }
        match self {
            Self::Raw {
                file,
                bytes_written,
            } => {
                file.write_all(&data)?;
                *bytes_written += data.len() as u64;
                Ok(())
            }
            Self::Archive { tx, .. } => {
                if let Some(sender) = tx {
                    // If the receiver closed early due to an extraction error, wait for finish()
                    // to surface the real extraction error.
                    let _ = sender.send(data);
                }
                Ok(())
            }
        }
    }

    pub fn finish(mut self) -> Result<(u64, u64), FileError> {
        match &mut self {
            Self::Raw {
                file,
                bytes_written,
            } => {
                file.flush()?;
                Ok((*bytes_written, 1))
            }
            Self::Archive { tx, worker } => {
                // Close channel to signal EOF to extractor thread.
                tx.take();
                match worker.take() {
                    Some(handle) => match handle.join() {
                        Ok(res) => res,
                        Err(_) => Err(FileError::InvalidArchive(
                            "archive extractor thread panicked".into(),
                        )),
                    },
                    None => Ok((0, 0)),
                }
            }
        }
    }
}

struct ChannelReader {
    rx: mpsc::Receiver<Vec<u8>>,
    buf: Vec<u8>,
    pos: usize,
}

impl ChannelReader {
    fn new(rx: mpsc::Receiver<Vec<u8>>) -> Self {
        Self {
            rx,
            buf: Vec::new(),
            pos: 0,
        }
    }
}

impl Read for ChannelReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        while self.pos >= self.buf.len() {
            match self.rx.recv() {
                Ok(chunk) => {
                    self.buf = chunk;
                    self.pos = 0;
                }
                Err(_) => return Ok(0),
            }
        }
        let avail = &self.buf[self.pos..];
        let n = avail.len().min(out.len());
        out[..n].copy_from_slice(&avail[..n]);
        self.pos += n;
        Ok(n)
    }
}

fn extract_tar_confined<R: Read>(
    reader: R,
    canonical_root: &Path,
    canonical_target: &Path,
) -> Result<(u64, u64), FileError> {
    let mut archive = tar::Archive::new(reader);
    let mut total_bytes: u64 = 0;
    let mut total_files: u64 = 0;

    let entries = archive
        .entries()
        .map_err(|e| FileError::InvalidArchive(e.to_string()))?;

    for entry_res in entries {
        let mut entry = entry_res.map_err(|e| FileError::InvalidArchive(e.to_string()))?;
        let entry_type = entry.header().entry_type();
        let entry_path = entry
            .path()
            .map_err(|e| FileError::InvalidArchive(e.to_string()))?
            .into_owned();

        let rel = sanitize_relative_path(&entry_path)?;
        if rel.as_os_str().is_empty() && entry_type.is_dir() {
            continue;
        }
        let dest = canonical_target.join(&rel);

        // Verify no existing path component is a symlink.
        let mut cur = canonical_target.to_path_buf();
        for comp in rel.components() {
            if let Component::Normal(seg) = comp {
                cur.push(seg);
                if let Ok(meta) = fs::symlink_metadata(&cur) {
                    if meta.file_type().is_symlink() {
                        return Err(FileError::PathViolation(format!(
                            "tar entry traverses symlink: {}",
                            rel.display()
                        )));
                    }
                }
            }
        }

        if entry_type.is_dir() {
            fs::create_dir_all(&dest)?;
            let canon = fs::canonicalize(&dest)?;
            if !canon.starts_with(canonical_root) {
                return Err(FileError::PathViolation(
                    "extracted dir escapes workspace".into(),
                ));
            }
        } else if entry_type.is_file() {
            total_files += 1;
            if total_files > MAX_UPLOAD_FILES {
                return Err(FileError::LimitExceeded(
                    "exceeded maximum archive file count".into(),
                ));
            }
            if let Some(parent) = dest.parent() {
                fs::create_dir_all(parent)?;
                let canon_parent = fs::canonicalize(parent)?;
                if !canon_parent.starts_with(canonical_root) {
                    return Err(FileError::PathViolation(
                        "extracted file parent escapes workspace".into(),
                    ));
                }
            }
            let mut out_file = OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&dest)?;
            let copied = io::copy(&mut entry, &mut out_file)?;
            total_bytes += copied;
            if let Ok(mode) = entry.header().mode() {
                // Strip setuid/setgid/sticky bits.
                let safe_mode = (mode & 0o0777) | 0o0600;
                let _ = fs::set_permissions(&dest, fs::Permissions::from_mode(safe_mode));
            }
        } else {
            return Err(FileError::InvalidArchive(format!(
                "unsupported tar entry type {:?} for {}",
                entry_type,
                rel.display()
            )));
        }
    }

    Ok((total_bytes, total_files))
}

/// Stream a file or `.tar.gz` archive out of `workspace_root`, invoking `emit`
/// for each `CtrlResponse::FileChunk`.
pub fn stream_download<F>(
    req_id: u64,
    workspace_root: &Path,
    virtual_mount: &str,
    requested_path: &str,
    format: DownloadFormat,
    mut emit: F,
) -> Result<(), FileError>
where
    F: FnMut(CtrlResponse) -> io::Result<()>,
{
    let target = resolve_confined_path(workspace_root, virtual_mount, requested_path)?;
    let meta = fs::symlink_metadata(&target)
        .map_err(|_| FileError::NotFound(requested_path.to_string()))?;
    if meta.file_type().is_symlink() {
        return Err(FileError::PathViolation(format!(
            "cannot download symlink: {requested_path:?}"
        )));
    }

    match format {
        DownloadFormat::Raw => {
            if !meta.file_type().is_file() {
                return Err(FileError::InvalidArchive(format!(
                    "raw download requires a regular file: {requested_path:?}"
                )));
            }
            let mut file = File::open(&target)?;
            let mut buf = vec![0u8; DOWNLOAD_CHUNK_SIZE];
            let mut sent_any = false;
            loop {
                let n = file.read(&mut buf)?;
                if n == 0 {
                    if !sent_any {
                        emit(CtrlResponse::FileChunk {
                            req_id,
                            data: Vec::new(),
                            eof: true,
                        })?;
                    } else {
                        emit(CtrlResponse::FileChunk {
                            req_id,
                            data: Vec::new(),
                            eof: true,
                        })?;
                    }
                    break;
                }
                sent_any = true;
                emit(CtrlResponse::FileChunk {
                    req_id,
                    data: buf[..n].to_vec(),
                    eof: false,
                })?;
            }
            Ok(())
        }
        DownloadFormat::TarGz => {
            let chunk_writer = ChunkEmitWriter::new(req_id, &mut emit);
            let gz = GzEncoder::new(chunk_writer, Compression::default());
            let mut builder = tar::Builder::new(gz);
            builder.follow_symlinks(false);

            if meta.file_type().is_file() {
                let name = target
                    .file_name()
                    .ok_or_else(|| FileError::InvalidArchive("missing file name".into()))?;
                builder.append_path_with_name(&target, name)?;
            } else if meta.file_type().is_dir() {
                append_dir_confined(&mut builder, &target, Path::new(""))?;
            } else {
                return Err(FileError::InvalidArchive(
                    "unsupported file type for tar.gz download".into(),
                ));
            }

            let gz = builder.into_inner()?;
            let mut chunk_writer = gz.finish()?;
            chunk_writer.finish()?;
            Ok(())
        }
    }
}

fn append_dir_confined<W: Write>(
    builder: &mut tar::Builder<W>,
    dir: &Path,
    prefix: &Path,
) -> Result<(), FileError> {
    let mut entries: Vec<_> = fs::read_dir(dir)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let path = entry.path();
        let meta = fs::symlink_metadata(&path)?;
        let ft = meta.file_type();
        if ft.is_symlink() {
            // Never follow or pack symlinks.
            continue;
        }
        let rel = prefix.join(entry.file_name());
        if ft.is_dir() {
            builder.append_dir(&rel, &path)?;
            append_dir_confined(builder, &path, &rel)?;
        } else if ft.is_file() {
            let mut f = File::open(&path)?;
            let mut header = tar::Header::new_gnu();
            header.set_size(meta.len());
            header.set_mode(meta.permissions().mode() & 0o0777);
            header.set_entry_type(tar::EntryType::Regular);
            header.set_cksum();
            builder.append_data(&mut header, &rel, &mut f)?;
        }
    }
    Ok(())
}

struct ChunkEmitWriter<'a, F> {
    req_id: u64,
    emit: &'a mut F,
    buf: Vec<u8>,
}

impl<'a, F: FnMut(CtrlResponse) -> io::Result<()>> ChunkEmitWriter<'a, F> {
    fn new(req_id: u64, emit: &'a mut F) -> Self {
        Self {
            req_id,
            emit,
            buf: Vec::with_capacity(DOWNLOAD_CHUNK_SIZE),
        }
    }

    fn finish(&mut self) -> io::Result<()> {
        let data = std::mem::take(&mut self.buf);
        (self.emit)(CtrlResponse::FileChunk {
            req_id: self.req_id,
            data,
            eof: true,
        })
    }
}

impl<F: FnMut(CtrlResponse) -> io::Result<()>> Write for ChunkEmitWriter<'_, F> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let mut remaining = data;
        while !remaining.is_empty() {
            let space = DOWNLOAD_CHUNK_SIZE - self.buf.len();
            let take = remaining.len().min(space);
            self.buf.extend_from_slice(&remaining[..take]);
            remaining = &remaining[take..];
            if self.buf.len() >= DOWNLOAD_CHUNK_SIZE {
                let chunk = std::mem::replace(
                    &mut self.buf,
                    Vec::with_capacity(DOWNLOAD_CHUNK_SIZE),
                );
                (self.emit)(CtrlResponse::FileChunk {
                    req_id: self.req_id,
                    data: chunk,
                    eof: false,
                })?;
            }
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn path_confinement_rejects_escapes_and_symlinks() {
        let tmp = tempfile::tempdir().unwrap();
        let ws = tmp.path();

        // Valid paths
        let p1 = resolve_confined_path(ws, "/workspace", "/workspace/a/b.txt").unwrap();
        assert_eq!(p1, fs::canonicalize(ws).unwrap().join("a/b.txt"));
        let p2 = resolve_confined_path(ws, "/workspace", "rel/file.rs").unwrap();
        assert_eq!(p2, fs::canonicalize(ws).unwrap().join("rel/file.rs"));

        // Reject escapes
        assert!(matches!(
            resolve_confined_path(ws, "/workspace", "/etc/passwd"),
            Err(FileError::PathViolation(_))
        ));
        assert!(matches!(
            resolve_confined_path(ws, "/workspace", "/workspace/../etc/passwd"),
            Err(FileError::PathViolation(_))
        ));
        assert!(matches!(
            resolve_confined_path(ws, "/workspace", "../etc/passwd"),
            Err(FileError::PathViolation(_))
        ));

        // Reject symlink escape
        symlink("/etc", ws.join("escape_link")).unwrap();
        assert!(matches!(
            resolve_confined_path(ws, "/workspace", "/workspace/escape_link/passwd"),
            Err(FileError::PathViolation(_))
        ));
    }
}
