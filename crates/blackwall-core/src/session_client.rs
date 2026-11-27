//! Thread-safe, multiplexed Port 1002 (`CTRL_SESSION`) interactive session client.
//!
//! Speaks [`CtrlRequest`] / [`CtrlResponse`] over a persistent `UnixStream` connected
//! to guest PID 1 (`blackwall-init`), multiplexing concurrent synchronous/streaming
//! `exec`, background process management, bidirectional PTY streams, `upload`, and
//! `download` (ALWAYS sanitized through `blackwall_unpacker::sanitize_download_stream`).

use crate::error::{CoreError, Result};
use blackwall_audit::{AuditEvent, AuditEventKind, AuditSink};
use blackwall_policy::ExportSpec;
use blackwall_proto::{
    read_ctrl_response, write_ctrl_request, BootConfig, CtrlErrorCode, CtrlRequest, CtrlResponse,
    DownloadFormat, OutputStream, ProcessInfo, ProtoError, SignalKind, UploadKind,
};
use blackwall_unpacker::{sanitize_download_stream, UnpackSummary};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::thread;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use uuid::Uuid;

/// Maximum raw payload bytes per `FileChunk` / `PtyInput` frame.
///
/// `CtrlRequest` uses JSON encoding where a `Vec<u8>` expands up to 4x (`255,`),
/// so 64 KiB raw bytes stay safely under `blackwall_proto::MAX_CTRL_FRAME` (1 MiB).
const MAX_RAW_CHUNK_BYTES: usize = 64 * 1024;

/// Guest boot readiness confirmation returned by [`SessionClient::boot_configure`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootReady {
    pub version: String,
    pub workspace_mounted: bool,
    pub netbridge_ready: bool,
}

/// Command execution request matching `POST /v1/sandboxes/{id}/exec`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecRequest {
    pub cmd: Vec<String>,
    #[serde(default)]
    pub cwd: Option<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub stdin: Option<String>,
    #[serde(default)]
    pub timeout_sec: Option<u64>,
    #[serde(default)]
    pub background: bool,
}

impl ExecRequest {
    /// Construct a synchronous exec request for `cmd`.
    pub fn new(cmd: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            cmd: cmd.into_iter().map(Into::into).collect(),
            ..Self::default()
        }
    }

    pub fn with_cwd(mut self, cwd: impl Into<String>) -> Self {
        self.cwd = Some(cwd.into());
        self
    }

    pub fn with_env(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.env.insert(k.into(), v.into());
        self
    }

    pub fn with_stdin(mut self, stdin: impl Into<String>) -> Self {
        self.stdin = Some(stdin.into());
        self
    }

    pub fn with_timeout_sec(mut self, timeout_sec: u64) -> Self {
        self.timeout_sec = Some(timeout_sec);
        self
    }

    pub fn background(mut self) -> Self {
        self.background = true;
        self
    }
}

/// Completed synchronous execution result matching `docs/API.md` §2.2 with full run metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecResult {
    #[serde(default)]
    pub sandbox_id: String,
    #[serde(default)]
    pub cmd: Vec<String>,
    #[serde(default)]
    pub cwd: String,
    pub exit_code: i32,
    #[serde(default)]
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
    #[serde(skip)]
    pub stdout_bytes: Vec<u8>,
    #[serde(skip)]
    pub stderr_bytes: Vec<u8>,
    #[serde(default)]
    pub stdout_bytes_len: usize,
    #[serde(default)]
    pub stderr_bytes_len: usize,
    pub timed_out: bool,
    pub duration_ms: u64,
    #[serde(default)]
    pub started_at_ms: u64,
    #[serde(default)]
    pub finished_at_ms: u64,
}

/// Handle returned when spawning a tracked background process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackgroundProcess {
    #[serde(default)]
    pub sandbox_id: String,
    pub proc_id: String,
    pub pid: u32,
    #[serde(default)]
    pub cmd: Vec<String>,
    #[serde(default)]
    pub cwd: String,
    #[serde(default)]
    pub started_at_ms: u64,
}

/// Streaming event emitted by [`SessionClient::exec_stream`] and [`SessionClient::process_logs`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecStreamEvent {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    Exit {
        exit_code: i32,
        timed_out: bool,
        duration_ms: u64,
    },
    LogsEnd,
    Error {
        code: CtrlErrorCode,
        message: String,
    },
}

impl ExecStreamEvent {
    /// Serialize into a JSON object suitable for `application/x-ndjson` HTTP streaming.
    pub fn to_ndjson_value(&self) -> serde_json::Value {
        match self {
            Self::Stdout(bytes) => serde_json::json!({
                "type": "stdout",
                "data": String::from_utf8_lossy(bytes),
            }),
            Self::Stderr(bytes) => serde_json::json!({
                "type": "stderr",
                "data": String::from_utf8_lossy(bytes),
            }),
            Self::Exit {
                exit_code,
                timed_out,
                duration_ms,
            } => serde_json::json!({
                "type": "exit",
                "exit_code": exit_code,
                "timed_out": timed_out,
                "duration_ms": duration_ms,
            }),
            Self::LogsEnd => serde_json::json!({ "type": "end" }),
            Self::Error { code, message } => serde_json::json!({
                "type": "error",
                "code": code,
                "message": message,
            }),
        }
    }
}

/// Parameters for opening an interactive guest PTY session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PtyOpenParams {
    #[serde(default)]
    pub cmd: Option<Vec<String>>,
    #[serde(default)]
    pub cwd: Option<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default = "default_cols")]
    pub cols: u16,
    #[serde(default = "default_rows")]
    pub rows: u16,
}

fn default_cols() -> u16 {
    120
}

fn default_rows() -> u16 {
    40
}

impl Default for PtyOpenParams {
    fn default() -> Self {
        Self {
            cmd: None,
            cwd: None,
            env: BTreeMap::new(),
            cols: default_cols(),
            rows: default_rows(),
        }
    }
}

/// Events produced by an attached guest PTY session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PtyEvent {
    Output(Vec<u8>),
    Exited(i32),
}

/// Write/control half of a live guest PTY session (cheaply cloneable for WebSocket handlers).
#[derive(Clone)]
pub struct PtyWriter {
    session_id: String,
    inner: Arc<SessionInner>,
}

impl PtyWriter {
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Write raw stdin bytes to the guest PTY, chunking automatically under `MAX_CTRL_FRAME`.
    pub fn write_input(&self, data: &[u8]) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        for chunk in data.chunks(MAX_RAW_CHUNK_BYTES) {
            self.inner.send_request(&CtrlRequest::PtyInput {
                session_id: self.session_id.clone(),
                data: chunk.to_vec(),
            })?;
        }
        Ok(())
    }

    /// Resize the guest PTY window dimensions.
    pub fn resize(&self, cols: u16, rows: u16) -> Result<()> {
        self.inner.send_request(&CtrlRequest::PtyResize {
            session_id: self.session_id.clone(),
            cols,
            rows,
        })
    }

    /// Close the guest PTY session and signal the guest shell/agent to terminate.
    pub fn close(&self) -> Result<()> {
        self.inner.remove_pty(&self.session_id);
        self.inner.send_request(&CtrlRequest::PtyClose {
            session_id: self.session_id.clone(),
        })
    }
}

/// Bidirectional interactive PTY handle bridging Port 1002 to WebSockets or local terminals.
pub struct PtyHandle {
    writer: PtyWriter,
    output_rx: mpsc::UnboundedReceiver<PtyEvent>,
}

impl PtyHandle {
    pub fn session_id(&self) -> &str {
        self.writer.session_id()
    }

    pub fn write_input(&self, data: &[u8]) -> Result<()> {
        self.writer.write_input(data)
    }

    pub fn resize(&self, cols: u16, rows: u16) -> Result<()> {
        self.writer.resize(cols, rows)
    }

    pub fn close(&self) -> Result<()> {
        self.writer.close()
    }

    pub async fn recv(&mut self) -> Option<PtyEvent> {
        self.output_rx.recv().await
    }

    /// Split into independent write/control and output-stream halves (ideal for WebSocket tasks).
    pub fn split(self) -> (PtyWriter, mpsc::UnboundedReceiver<PtyEvent>) {
        (self.writer, self.output_rx)
    }
}

/// Events produced by a host-to-guest TCP ingress tunnel over Port 1002.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpTunnelEvent {
    Data(Vec<u8>),
    Closed(Option<String>),
}

struct TunnelCloseState {
    stream_id: String,
    guest_port: u16,
    inner: Arc<SessionInner>,
    bytes_in: Arc<AtomicU64>,
    bytes_out: Arc<AtomicU64>,
    closed: AtomicBool,
    audit_sink: Option<Arc<dyn AuditSink>>,
}

impl TunnelCloseState {
    fn close_once(&self, send_ctrl: bool) -> Result<()> {
        if self.closed.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        self.inner.remove_tcp_tunnel(&self.stream_id);
        if let Some(sink) = &self.audit_sink {
            sink.record(AuditEvent::now(
                &self.inner.sandbox_id,
                AuditEventKind::IngressTunnel {
                    guest_port: self.guest_port,
                    bytes_in: self.bytes_in.load(Ordering::Acquire),
                    bytes_out: self.bytes_out.load(Ordering::Acquire),
                    allowed: true,
                },
            ));
        }
        if send_ctrl && !self.inner.is_closed() {
            self.inner.send_request(&CtrlRequest::TcpClose {
                stream_id: self.stream_id.clone(),
            })?;
        }
        Ok(())
    }
}

impl Drop for TunnelCloseState {
    fn drop(&mut self) {
        let _ = self.close_once(true);
    }
}

/// Write/control half of a live host-to-guest TCP ingress tunnel (cheaply cloneable).
#[derive(Clone)]
pub struct TcpTunnelWriter {
    state: Arc<TunnelCloseState>,
}

impl TcpTunnelWriter {
    pub fn stream_id(&self) -> &str {
        &self.state.stream_id
    }

    pub fn guest_port(&self) -> u16 {
        self.state.guest_port
    }

    pub fn bytes_in(&self) -> u64 {
        self.state.bytes_in.load(Ordering::Acquire)
    }

    pub fn bytes_out(&self) -> u64 {
        self.state.bytes_out.load(Ordering::Acquire)
    }

    /// Write raw bytes to the guest loopback TCP socket, chunking under `MAX_CTRL_FRAME`.
    pub fn write_data(&self, data: &[u8]) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        if self.state.closed.load(Ordering::Acquire) {
            return Err(CoreError::SessionClosed("TCP tunnel already closed".into()));
        }
        for chunk in data.chunks(MAX_RAW_CHUNK_BYTES) {
            self.state.inner.send_request(&CtrlRequest::TcpData {
                stream_id: self.state.stream_id.clone(),
                data: chunk.to_vec(),
            })?;
            self.state
                .bytes_in
                .fetch_add(chunk.len() as u64, Ordering::Relaxed);
        }
        Ok(())
    }

    /// Close the guest TCP tunnel stream cleanly (idempotent).
    pub fn close(&self) -> Result<()> {
        self.state.close_once(true)
    }
}

/// Bidirectional host-to-guest TCP ingress tunnel handle over Port 1002.
pub struct TcpTunnelHandle {
    writer: TcpTunnelWriter,
    rx: mpsc::UnboundedReceiver<TcpTunnelEvent>,
}

impl TcpTunnelHandle {
    pub fn stream_id(&self) -> &str {
        self.writer.stream_id()
    }

    pub fn guest_port(&self) -> u16 {
        self.writer.guest_port()
    }

    pub fn write_data(&self, data: &[u8]) -> Result<()> {
        self.writer.write_data(data)
    }

    pub fn close(&self) -> Result<()> {
        self.writer.close()
    }

    pub async fn recv(&mut self) -> Option<TcpTunnelEvent> {
        self.rx.recv().await
    }

    /// Split into independent write/control and receive-stream halves.
    pub fn split(self) -> (TcpTunnelWriter, mpsc::UnboundedReceiver<TcpTunnelEvent>) {
        (self.writer, self.rx)
    }

    /// Convert into an [`AsyncRead`] + [`AsyncWrite`] stream for Hyper/Axum proxying or raw TCP forwarding.
    pub fn into_stream(self) -> TcpTunnelStream {
        TcpTunnelStream::new(self)
    }
}

/// Tokio [`AsyncRead`] + [`AsyncWrite`] adapter over a [`TcpTunnelHandle`].
pub struct TcpTunnelStream {
    writer: TcpTunnelWriter,
    rx: mpsc::UnboundedReceiver<TcpTunnelEvent>,
    read_buf: Vec<u8>,
    read_pos: usize,
    eof: bool,
}

impl TcpTunnelStream {
    pub fn new(handle: TcpTunnelHandle) -> Self {
        let (writer, rx) = handle.split();
        Self {
            writer,
            rx,
            read_buf: Vec::new(),
            read_pos: 0,
            eof: false,
        }
    }

    pub fn stream_id(&self) -> &str {
        self.writer.stream_id()
    }

    pub fn guest_port(&self) -> u16 {
        self.writer.guest_port()
    }

    pub fn bytes_in(&self) -> u64 {
        self.writer.bytes_in()
    }

    pub fn bytes_out(&self) -> u64 {
        self.writer.bytes_out()
    }
}

impl From<TcpTunnelHandle> for TcpTunnelStream {
    fn from(handle: TcpTunnelHandle) -> Self {
        Self::new(handle)
    }
}

impl AsyncRead for TcpTunnelStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if self.read_pos < self.read_buf.len() {
            let avail = &self.read_buf[self.read_pos..];
            let n = avail.len().min(buf.remaining());
            buf.put_slice(&avail[..n]);
            self.read_pos += n;
            if self.read_pos >= self.read_buf.len() {
                self.read_buf.clear();
                self.read_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }
        if self.eof {
            return Poll::Ready(Ok(()));
        }
        loop {
            match self.rx.poll_recv(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(TcpTunnelEvent::Data(data))) => {
                    if data.is_empty() {
                        continue;
                    }
                    let n = data.len().min(buf.remaining());
                    buf.put_slice(&data[..n]);
                    if n < data.len() {
                        self.read_buf = data;
                        self.read_pos = n;
                    }
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Some(TcpTunnelEvent::Closed(_))) | Poll::Ready(None) => {
                    self.eof = true;
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

impl AsyncWrite for TcpTunnelStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        match self.writer.write_data(buf) {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            Err(err) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                err.to_string(),
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let _ = self.writer.close();
        Poll::Ready(Ok(()))
    }
}

impl Drop for TcpTunnelStream {
    fn drop(&mut self) {
        let _ = self.writer.close();
    }
}

/// Result returned by [`SessionClient::upload_files`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UploadResult {
    #[serde(default)]
    pub sandbox_id: String,
    #[serde(default)]
    pub path: String,
    #[serde(default = "default_upload_kind")]
    pub kind: UploadKind,
    pub bytes_written: u64,
    pub files_written: u64,
    #[serde(default)]
    pub duration_ms: u64,
}

fn default_upload_kind() -> UploadKind {
    UploadKind::Raw
}

fn unix_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

struct RegisteredTcpTunnel {
    tx: mpsc::UnboundedSender<TcpTunnelEvent>,
    bytes_out: Arc<AtomicU64>,
}

struct SessionInner {
    sandbox_id: String,
    writer: Mutex<UnixStream>,
    next_req_id: AtomicU64,
    pending_reqs: Mutex<HashMap<u64, mpsc::UnboundedSender<CtrlResponse>>>,
    pty_sessions: Mutex<HashMap<String, mpsc::UnboundedSender<PtyEvent>>>,
    tcp_tunnels: Mutex<HashMap<String, RegisteredTcpTunnel>>,
    host_bridge_open_tx: Mutex<Option<mpsc::UnboundedSender<(String, u16)>>>,
    closed: AtomicBool,
}

impl SessionInner {
    fn alloc_req_id(&self) -> u64 {
        self.next_req_id.fetch_add(1, Ordering::Relaxed)
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    fn register_req(&self, req_id: u64) -> Result<mpsc::UnboundedReceiver<CtrlResponse>> {
        if self.is_closed() {
            return Err(CoreError::SessionClosed(
                "Port 1002 transport already closed".into(),
            ));
        }
        let (tx, rx) = mpsc::unbounded_channel();
        let mut guard = self
            .pending_reqs
            .lock()
            .map_err(|_| CoreError::Internal("pending_reqs lock poisoned".into()))?;
        if self.is_closed() {
            return Err(CoreError::SessionClosed(
                "Port 1002 transport already closed".into(),
            ));
        }
        guard.insert(req_id, tx);
        Ok(rx)
    }

    fn unregister_req(&self, req_id: u64) {
        if let Ok(mut guard) = self.pending_reqs.lock() {
            guard.remove(&req_id);
        }
    }

    fn register_pty(&self, session_id: String) -> Result<mpsc::UnboundedReceiver<PtyEvent>> {
        if self.is_closed() {
            return Err(CoreError::SessionClosed(
                "Port 1002 transport already closed".into(),
            ));
        }
        let (tx, rx) = mpsc::unbounded_channel();
        let mut guard = self
            .pty_sessions
            .lock()
            .map_err(|_| CoreError::Internal("pty_sessions lock poisoned".into()))?;
        guard.insert(session_id, tx);
        Ok(rx)
    }

    fn remove_pty(&self, session_id: &str) {
        if let Ok(mut guard) = self.pty_sessions.lock() {
            guard.remove(session_id);
        }
    }

    fn register_tcp_tunnel(
        &self,
        stream_id: String,
        bytes_out: Arc<AtomicU64>,
    ) -> Result<mpsc::UnboundedReceiver<TcpTunnelEvent>> {
        if self.is_closed() {
            return Err(CoreError::SessionClosed(
                "Port 1002 transport already closed".into(),
            ));
        }
        let (tx, rx) = mpsc::unbounded_channel();
        let mut guard = self
            .tcp_tunnels
            .lock()
            .map_err(|_| CoreError::Internal("tcp_tunnels lock poisoned".into()))?;
        if self.is_closed() {
            return Err(CoreError::SessionClosed(
                "Port 1002 transport already closed".into(),
            ));
        }
        guard.insert(stream_id, RegisteredTcpTunnel { tx, bytes_out });
        Ok(rx)
    }

    fn remove_tcp_tunnel(&self, stream_id: &str) {
        if let Ok(mut guard) = self.tcp_tunnels.lock() {
            guard.remove(stream_id);
        }
    }

    fn send_request(&self, req: &CtrlRequest) -> Result<()> {
        if self.is_closed() {
            return Err(CoreError::SessionClosed(
                "Port 1002 transport already closed".into(),
            ));
        }
        let mut writer = self
            .writer
            .lock()
            .map_err(|_| CoreError::Internal("Port 1002 writer lock poisoned".into()))?;
        write_ctrl_request(&mut *writer, req).map_err(|e| match e {
            ProtoError::Io(ioe) => CoreError::SessionClosed(ioe.to_string()),
            other => CoreError::Proto(other),
        })?;
        writer
            .flush()
            .map_err(|e| CoreError::SessionClosed(e.to_string()))?;
        Ok(())
    }

    fn close_all(&self) {
        self.closed.store(true, Ordering::Release);
        if let Ok(mut guard) = self.pending_reqs.lock() {
            guard.clear();
        }
        if let Ok(mut guard) = self.pty_sessions.lock() {
            guard.clear();
        }
        if let Ok(mut guard) = self.tcp_tunnels.lock() {
            guard.clear();
        }
        if let Ok(mut guard) = self.host_bridge_open_tx.lock() {
            *guard = None;
        }
    }
}

/// Thread-safe multiplexed client for Blackwall's Port 1002 (`CTRL_SESSION`) channel.
#[derive(Clone)]
pub struct SessionClient {
    inner: Arc<SessionInner>,
}

impl SessionClient {
    /// Wrap a handshaked Port 1002 `UnixStream` and start its background frame demultiplexer.
    pub fn new(sandbox_id: impl Into<String>, stream: UnixStream) -> Result<Self> {
        let reader_stream = stream.try_clone()?;
        let sandbox_id = sandbox_id.into();
        let inner = Arc::new(SessionInner {
            sandbox_id: sandbox_id.clone(),
            writer: Mutex::new(stream),
            next_req_id: AtomicU64::new(1),
            pending_reqs: Mutex::new(HashMap::new()),
            pty_sessions: Mutex::new(HashMap::new()),
            tcp_tunnels: Mutex::new(HashMap::new()),
            host_bridge_open_tx: Mutex::new(None),
            closed: AtomicBool::new(false),
        });

        let reader_inner = Arc::clone(&inner);
        thread::Builder::new()
            .name(format!("bw-ctrl-{sandbox_id}"))
            .spawn(move || reader_loop(reader_stream, reader_inner))
            .map_err(CoreError::Io)?;

        Ok(Self { inner })
    }

    pub fn sandbox_id(&self) -> &str {
        &self.inner.sandbox_id
    }

    pub fn is_closed(&self) -> bool {
        self.inner.is_closed()
    }

    /// Register a channel to receive guest-initiated `CtrlResponse::HostBridgeOpen` frames.
    pub fn set_host_bridge_open_tx(&self, tx: mpsc::UnboundedSender<(String, u16)>) {
        if let Ok(mut guard) = self.inner.host_bridge_open_tx.lock() {
            *guard = Some(tx);
        }
    }

    /// Send `BootConfigure` over Port 1002 and wait for `BootReady`.
    pub async fn boot_configure(&self, config: BootConfig) -> Result<BootReady> {
        let req_id = self.inner.alloc_req_id();
        let mut rx = self.inner.register_req(req_id)?;
        if let Err(err) = self
            .inner
            .send_request(&CtrlRequest::BootConfigure { req_id, config })
        {
            self.inner.unregister_req(req_id);
            return Err(err);
        }

        match rx.recv().await {
            Some(CtrlResponse::BootReady {
                version,
                workspace_mounted,
                netbridge_ready,
                ..
            }) => Ok(BootReady {
                version,
                workspace_mounted,
                netbridge_ready,
            }),
            Some(CtrlResponse::Error { code, message, .. }) => {
                Err(CoreError::GuestError { code, message })
            }
            Some(other) => Err(CoreError::Internal(format!(
                "unexpected BootConfigure response: {other:?}"
            ))),
            None => Err(CoreError::SessionClosed(
                "session closed waiting for BootReady".into(),
            )),
        }
    }

    /// Execute a command synchronously and collect stdout, stderr, exit code, and timing.
    pub async fn exec_sync(&self, req: ExecRequest) -> Result<ExecResult> {
        let cmd_meta = req.cmd.clone();
        let cwd_meta = req.cwd.clone().unwrap_or_else(|| "/workspace".to_string());
        let started_at_ms = unix_now_ms();
        let mut rx = self.exec_stream(req).await?;
        let mut stdout_bytes = Vec::new();
        let mut stderr_bytes = Vec::new();

        while let Some(ev) = rx.recv().await {
            match ev {
                ExecStreamEvent::Stdout(chunk) => stdout_bytes.extend_from_slice(&chunk),
                ExecStreamEvent::Stderr(chunk) => stderr_bytes.extend_from_slice(&chunk),
                ExecStreamEvent::Exit {
                    exit_code,
                    timed_out,
                    duration_ms,
                } => {
                    let finished_at_ms = unix_now_ms();
                    let stdout_bytes_len = stdout_bytes.len();
                    let stderr_bytes_len = stderr_bytes.len();
                    let stdout = String::from_utf8_lossy(&stdout_bytes).into_owned();
                    let stderr = String::from_utf8_lossy(&stderr_bytes).into_owned();
                    return Ok(ExecResult {
                        sandbox_id: self.inner.sandbox_id.clone(),
                        cmd: cmd_meta,
                        cwd: cwd_meta,
                        exit_code,
                        success: exit_code == 0 && !timed_out,
                        stdout,
                        stderr,
                        stdout_bytes,
                        stderr_bytes,
                        stdout_bytes_len,
                        stderr_bytes_len,
                        timed_out,
                        duration_ms,
                        started_at_ms,
                        finished_at_ms,
                    });
                }
                ExecStreamEvent::Error { code, message } => {
                    return Err(CoreError::GuestError { code, message });
                }
                ExecStreamEvent::LogsEnd => {}
            }
        }

        Err(CoreError::SessionClosed(
            "session closed before ExecExit was received".into(),
        ))
    }

    /// Execute a command and stream `Stdout` / `Stderr` / `Exit` frames as they arrive.
    pub async fn exec_stream(
        &self,
        req: ExecRequest,
    ) -> Result<mpsc::UnboundedReceiver<ExecStreamEvent>> {
        if req.cmd.is_empty() {
            return Err(CoreError::InvalidRequest("exec cmd must not be empty".into()));
        }
        let req_id = self.inner.alloc_req_id();
        let mut raw_rx = self.inner.register_req(req_id)?;
        let ctrl_req = CtrlRequest::ExecStart {
            req_id,
            cmd: req.cmd,
            cwd: req.cwd,
            env: req.env,
            stdin: req.stdin.map(String::into_bytes),
            timeout_sec: req.timeout_sec,
            background: false,
        };
        if let Err(err) = self.inner.send_request(&ctrl_req) {
            self.inner.unregister_req(req_id);
            return Err(err);
        }

        let (out_tx, out_rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Some(resp) = raw_rx.recv().await {
                match resp {
                    CtrlResponse::ExecOutput { stream, data, .. } => {
                        let ev = match stream {
                            OutputStream::Stdout => ExecStreamEvent::Stdout(data),
                            OutputStream::Stderr => ExecStreamEvent::Stderr(data),
                        };
                        if out_tx.send(ev).is_err() {
                            break;
                        }
                    }
                    CtrlResponse::ExecExit {
                        exit_code,
                        timed_out,
                        duration_ms,
                        ..
                    } => {
                        let _ = out_tx.send(ExecStreamEvent::Exit {
                            exit_code,
                            timed_out,
                            duration_ms,
                        });
                        break;
                    }
                    CtrlResponse::Error { code, message, .. } => {
                        let _ = out_tx.send(ExecStreamEvent::Error { code, message });
                        break;
                    }
                    _ => {}
                }
            }
        });

        Ok(out_rx)
    }

    /// Start a tracked background process and return its `{ proc_id, pid }` with metadata.
    pub async fn exec_background(&self, req: ExecRequest) -> Result<BackgroundProcess> {
        if req.cmd.is_empty() {
            return Err(CoreError::InvalidRequest("exec cmd must not be empty".into()));
        }
        let cmd_meta = req.cmd.clone();
        let cwd_meta = req.cwd.clone().unwrap_or_else(|| "/workspace".to_string());
        let started_at_ms = unix_now_ms();
        let req_id = self.inner.alloc_req_id();
        let mut rx = self.inner.register_req(req_id)?;
        let ctrl_req = CtrlRequest::ExecStart {
            req_id,
            cmd: req.cmd,
            cwd: req.cwd,
            env: req.env,
            stdin: req.stdin.map(String::into_bytes),
            timeout_sec: None,
            background: true,
        };
        if let Err(err) = self.inner.send_request(&ctrl_req) {
            self.inner.unregister_req(req_id);
            return Err(err);
        }

        match rx.recv().await {
            Some(CtrlResponse::ProcessSpawned { proc_id, pid, .. }) => Ok(BackgroundProcess {
                sandbox_id: self.inner.sandbox_id.clone(),
                proc_id,
                pid,
                cmd: cmd_meta,
                cwd: cwd_meta,
                started_at_ms,
            }),
            Some(CtrlResponse::Error { code, message, .. }) => {
                Err(CoreError::GuestError { code, message })
            }
            Some(other) => Err(CoreError::Internal(format!(
                "unexpected background exec response: {other:?}"
            ))),
            None => Err(CoreError::SessionClosed(
                "session closed waiting for ProcessSpawned".into(),
            )),
        }
    }

    /// List tracked background processes inside the guest.
    pub async fn list_processes(&self) -> Result<Vec<ProcessInfo>> {
        let req_id = self.inner.alloc_req_id();
        let mut rx = self.inner.register_req(req_id)?;
        if let Err(err) = self.inner.send_request(&CtrlRequest::ProcessList { req_id }) {
            self.inner.unregister_req(req_id);
            return Err(err);
        }

        match rx.recv().await {
            Some(CtrlResponse::ProcessListResult { processes, .. }) => Ok(processes),
            Some(CtrlResponse::Error { code, message, .. }) => {
                Err(CoreError::GuestError { code, message })
            }
            Some(other) => Err(CoreError::Internal(format!(
                "unexpected ProcessList response: {other:?}"
            ))),
            None => Err(CoreError::SessionClosed(
                "session closed waiting for ProcessListResult".into(),
            )),
        }
    }

    /// Stream buffered or live (`follow = true`) logs for a tracked background process.
    pub async fn process_logs(
        &self,
        proc_id: impl Into<String>,
        tail: Option<usize>,
        follow: bool,
    ) -> Result<mpsc::UnboundedReceiver<ExecStreamEvent>> {
        let req_id = self.inner.alloc_req_id();
        let mut raw_rx = self.inner.register_req(req_id)?;
        let ctrl_req = CtrlRequest::ProcessLogs {
            req_id,
            proc_id: proc_id.into(),
            tail,
            follow,
        };
        if let Err(err) = self.inner.send_request(&ctrl_req) {
            self.inner.unregister_req(req_id);
            return Err(err);
        }

        let (out_tx, out_rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Some(resp) = raw_rx.recv().await {
                match resp {
                    CtrlResponse::ExecOutput { stream, data, .. } => {
                        let ev = match stream {
                            OutputStream::Stdout => ExecStreamEvent::Stdout(data),
                            OutputStream::Stderr => ExecStreamEvent::Stderr(data),
                        };
                        if out_tx.send(ev).is_err() {
                            break;
                        }
                    }
                    CtrlResponse::ProcessLogsEnd { .. } => {
                        let _ = out_tx.send(ExecStreamEvent::LogsEnd);
                        break;
                    }
                    CtrlResponse::Error { code, message, .. } => {
                        let _ = out_tx.send(ExecStreamEvent::Error { code, message });
                        break;
                    }
                    _ => {}
                }
            }
        });

        Ok(out_rx)
    }

    /// Send a POSIX signal (`SIGTERM`, `SIGKILL`, `SIGINT`) to a background process group.
    pub async fn signal_process(
        &self,
        proc_id: impl Into<String>,
        signal: SignalKind,
    ) -> Result<()> {
        let req_id = self.inner.alloc_req_id();
        let mut rx = self.inner.register_req(req_id)?;
        if let Err(err) = self.inner.send_request(&CtrlRequest::ProcessSignal {
            req_id,
            proc_id: proc_id.into(),
            signal,
        }) {
            self.inner.unregister_req(req_id);
            return Err(err);
        }

        expect_ack(&mut rx, "ProcessSignal").await
    }

    /// Kill and delete a tracked background process handle.
    pub async fn delete_process(&self, proc_id: impl Into<String>) -> Result<()> {
        let req_id = self.inner.alloc_req_id();
        let mut rx = self.inner.register_req(req_id)?;
        if let Err(err) = self.inner.send_request(&CtrlRequest::ProcessDelete {
            req_id,
            proc_id: proc_id.into(),
        }) {
            self.inner.unregister_req(req_id);
            return Err(err);
        }

        expect_ack(&mut rx, "ProcessDelete").await
    }

    /// Open an interactive guest PTY returning a bidirectional [`PtyHandle`].
    pub async fn open_pty(&self, params: PtyOpenParams) -> Result<PtyHandle> {
        let req_id = self.inner.alloc_req_id();
        let session_id = format!("pty-{}", &Uuid::new_v4().simple().to_string()[..12]);
        let mut rx = self.inner.register_req(req_id)?;
        // Register the PTY output channel BEFORE sending PtyOpen so no early output is lost.
        let output_rx = self.inner.register_pty(session_id.clone())?;

        let ctrl_req = CtrlRequest::PtyOpen {
            req_id,
            session_id: session_id.clone(),
            cmd: params.cmd,
            cwd: params.cwd,
            env: params.env,
            cols: params.cols,
            rows: params.rows,
        };
        if let Err(err) = self.inner.send_request(&ctrl_req) {
            self.inner.unregister_req(req_id);
            self.inner.remove_pty(&session_id);
            return Err(err);
        }

        match rx.recv().await {
            Some(CtrlResponse::PtyOpened { session_id, .. }) => Ok(PtyHandle {
                writer: PtyWriter {
                    session_id,
                    inner: Arc::clone(&self.inner),
                },
                output_rx,
            }),
            Some(CtrlResponse::Error { code, message, .. }) => {
                self.inner.remove_pty(&session_id);
                Err(CoreError::GuestError { code, message })
            }
            Some(other) => {
                self.inner.remove_pty(&session_id);
                Err(CoreError::Internal(format!(
                    "unexpected PtyOpen response: {other:?}"
                )))
            }
            None => {
                self.inner.remove_pty(&session_id);
                Err(CoreError::SessionClosed(
                    "session closed waiting for PtyOpened".into(),
                ))
            }
        }
    }

    /// Open a host-to-guest TCP ingress tunnel to `127.0.0.1:<guest_port>` over Port 1002.
    pub async fn open_tcp_tunnel(&self, guest_port: u16) -> Result<TcpTunnelHandle> {
        self.open_tcp_tunnel_with_audit(guest_port, None).await
    }

    /// Open a host-to-guest TCP ingress tunnel, optionally recording an `IngressTunnel` audit
    /// event with byte counters when the tunnel closes.
    pub(crate) async fn open_tcp_tunnel_with_audit(
        &self,
        guest_port: u16,
        audit_sink: Option<Arc<dyn AuditSink>>,
    ) -> Result<TcpTunnelHandle> {
        if guest_port == 0 {
            return Err(CoreError::InvalidRequest(
                "guest_port must be > 0".into(),
            ));
        }
        let req_id = self.inner.alloc_req_id();
        let stream_id = format!("tcp-{}", &Uuid::new_v4().simple().to_string()[..12]);
        let mut rx = self.inner.register_req(req_id)?;
        let bytes_in = Arc::new(AtomicU64::new(0));
        let bytes_out = Arc::new(AtomicU64::new(0));
        // Register the tunnel channel BEFORE sending TcpConnect so early frames are never lost.
        let tunnel_rx = self
            .inner
            .register_tcp_tunnel(stream_id.clone(), Arc::clone(&bytes_out))?;

        let ctrl_req = CtrlRequest::TcpConnect {
            req_id,
            stream_id: stream_id.clone(),
            guest_port,
        };
        if let Err(err) = self.inner.send_request(&ctrl_req) {
            self.inner.unregister_req(req_id);
            self.inner.remove_tcp_tunnel(&stream_id);
            return Err(err);
        }

        match rx.recv().await {
            Some(CtrlResponse::TcpConnected { stream_id, .. }) => Ok(TcpTunnelHandle {
                writer: TcpTunnelWriter {
                    state: Arc::new(TunnelCloseState {
                        stream_id,
                        guest_port,
                        inner: Arc::clone(&self.inner),
                        bytes_in,
                        bytes_out,
                        closed: AtomicBool::new(false),
                        audit_sink,
                    }),
                },
                rx: tunnel_rx,
            }),
            Some(CtrlResponse::Error { code, message, .. }) => {
                self.inner.remove_tcp_tunnel(&stream_id);
                Err(CoreError::GuestError { code, message })
            }
            Some(other) => {
                self.inner.remove_tcp_tunnel(&stream_id);
                Err(CoreError::Internal(format!(
                    "unexpected TcpConnect response: {other:?}"
                )))
            }
            None => {
                self.inner.remove_tcp_tunnel(&stream_id);
                Err(CoreError::SessionClosed(
                    "session closed waiting for TcpConnected".into(),
                ))
            }
        }
    }

    /// Bind a guest loopback listener on `127.0.0.1:<guest_port>` for a host service bridge.
    pub async fn host_bridge_bind(&self, guest_port: u16) -> Result<()> {
        if guest_port == 0 {
            return Err(CoreError::InvalidRequest(
                "guest_port must be > 0".into(),
            ));
        }
        let req_id = self.inner.alloc_req_id();
        let mut rx = self.inner.register_req(req_id)?;
        if let Err(err) = self.inner.send_request(&CtrlRequest::HostBridgeBind {
            req_id,
            guest_port,
        }) {
            self.inner.unregister_req(req_id);
            return Err(err);
        }
        expect_ack(&mut rx, "HostBridgeBind").await
    }

    /// Unbind a previously bound guest loopback host-bridge listener on `guest_port`.
    pub async fn host_bridge_unbind(&self, guest_port: u16) -> Result<()> {
        if guest_port == 0 {
            return Err(CoreError::InvalidRequest(
                "guest_port must be > 0".into(),
            ));
        }
        let req_id = self.inner.alloc_req_id();
        let mut rx = self.inner.register_req(req_id)?;
        if let Err(err) = self.inner.send_request(&CtrlRequest::HostBridgeUnbind {
            req_id,
            guest_port,
        }) {
            self.inner.unregister_req(req_id);
            return Err(err);
        }
        expect_ack(&mut rx, "HostBridgeUnbind").await
    }

    /// Accept or reject a guest-initiated `CtrlResponse::HostBridgeOpen` stream.
    ///
    /// When `ok == true`, registers `stream_id` in the active TCP tunnel map BEFORE sending
    /// `CtrlRequest::HostBridgeAccepted { ok: true }` so no early guest `TcpData` frames are lost.
    pub async fn register_host_bridge_stream(
        &self,
        stream_id: String,
        ok: bool,
        reason: Option<String>,
    ) -> Result<Option<TcpTunnelHandle>> {
        if !ok {
            self.inner.send_request(&CtrlRequest::HostBridgeAccepted {
                stream_id,
                ok: false,
                reason,
            })?;
            return Ok(None);
        }

        let bytes_in = Arc::new(AtomicU64::new(0));
        let bytes_out = Arc::new(AtomicU64::new(0));
        // Register BEFORE sending HostBridgeAccepted so early frames are never dropped.
        let tunnel_rx = self
            .inner
            .register_tcp_tunnel(stream_id.clone(), Arc::clone(&bytes_out))?;

        if let Err(err) = self.inner.send_request(&CtrlRequest::HostBridgeAccepted {
            stream_id: stream_id.clone(),
            ok: true,
            reason: None,
        }) {
            self.inner.remove_tcp_tunnel(&stream_id);
            return Err(err);
        }

        Ok(Some(TcpTunnelHandle {
            writer: TcpTunnelWriter {
                state: Arc::new(TunnelCloseState {
                    stream_id,
                    guest_port: 0,
                    inner: Arc::clone(&self.inner),
                    bytes_in,
                    bytes_out,
                    closed: AtomicBool::new(false),
                    audit_sink: None,
                }),
            },
            rx: tunnel_rx,
        }))
    }

    /// Upload a raw file or tar/tar.gz archive into `/workspace` over Port 1002.
    pub async fn upload_files(
        &self,
        path: impl Into<String>,
        kind: UploadKind,
        data: &[u8],
    ) -> Result<UploadResult> {
        let path_str = path.into();
        let started = std::time::Instant::now();
        let req_id = self.inner.alloc_req_id();
        let mut rx = self.inner.register_req(req_id)?;
        if let Err(err) = self.inner.send_request(&CtrlRequest::UploadBegin {
            req_id,
            path: path_str.clone(),
            kind,
        }) {
            self.inner.unregister_req(req_id);
            return Err(err);
        }

        if data.is_empty() {
            if let Err(err) = self.inner.send_request(&CtrlRequest::FileChunk {
                req_id,
                data: Vec::new(),
                eof: true,
            }) {
                self.inner.unregister_req(req_id);
                return Err(err);
            }
        } else {
            let total_chunks = data.len().div_ceil(MAX_RAW_CHUNK_BYTES);
            for (idx, chunk) in data.chunks(MAX_RAW_CHUNK_BYTES).enumerate() {
                // Short-circuit if the guest already rejected UploadBegin or an earlier chunk.
                if let Ok(CtrlResponse::Error { code, message, .. }) = rx.try_recv() {
                    return Err(CoreError::GuestError { code, message });
                }
                let eof = idx + 1 == total_chunks;
                if let Err(err) = self.inner.send_request(&CtrlRequest::FileChunk {
                    req_id,
                    data: chunk.to_vec(),
                    eof,
                }) {
                    self.inner.unregister_req(req_id);
                    return Err(err);
                }
            }
        }

        match rx.recv().await {
            Some(CtrlResponse::UploadComplete {
                bytes_written,
                files_written,
                ..
            }) => Ok(UploadResult {
                sandbox_id: self.inner.sandbox_id.clone(),
                path: path_str,
                kind,
                bytes_written,
                files_written,
                duration_ms: started.elapsed().as_millis() as u64,
            }),
            Some(CtrlResponse::Error { code, message, .. }) => {
                Err(CoreError::GuestError { code, message })
            }
            Some(other) => Err(CoreError::Internal(format!(
                "unexpected UploadComplete response: {other:?}"
            ))),
            None => Err(CoreError::SessionClosed(
                "session closed waiting for UploadComplete".into(),
            )),
        }
    }

    /// Stream an upload from any blocking [`Read`] source into `/workspace` over Port 1002.
    pub async fn upload_files_reader<R: Read + Send + 'static>(
        &self,
        path: impl Into<String>,
        kind: UploadKind,
        mut reader: R,
    ) -> Result<UploadResult> {
        let path_str = path.into();
        let started = std::time::Instant::now();
        let req_id = self.inner.alloc_req_id();
        let mut rx = self.inner.register_req(req_id)?;
        if let Err(err) = self.inner.send_request(&CtrlRequest::UploadBegin {
            req_id,
            path: path_str.clone(),
            kind,
        }) {
            self.inner.unregister_req(req_id);
            return Err(err);
        }

        let inner = Arc::clone(&self.inner);
        let pump_res = tokio::task::spawn_blocking(move || -> Result<()> {
            let mut buf = vec![0u8; MAX_RAW_CHUNK_BYTES];
            let mut sent_any = false;
            loop {
                let n = reader.read(&mut buf)?;
                if n == 0 {
                    inner.send_request(&CtrlRequest::FileChunk {
                        req_id,
                        data: Vec::new(),
                        eof: true,
                    })?;
                    break;
                }
                sent_any = true;
                inner.send_request(&CtrlRequest::FileChunk {
                    req_id,
                    data: buf[..n].to_vec(),
                    eof: false,
                })?;
            }
            let _ = sent_any;
            Ok(())
        })
        .await
        .map_err(|e| CoreError::Internal(format!("upload pump task failed: {e}")))?;

        if let Err(err) = pump_res {
            self.inner.unregister_req(req_id);
            return Err(err);
        }

        match rx.recv().await {
            Some(CtrlResponse::UploadComplete {
                bytes_written,
                files_written,
                ..
            }) => Ok(UploadResult {
                sandbox_id: self.inner.sandbox_id.clone(),
                path: path_str,
                kind,
                bytes_written,
                files_written,
                duration_ms: started.elapsed().as_millis() as u64,
            }),
            Some(CtrlResponse::Error { code, message, .. }) => {
                Err(CoreError::GuestError { code, message })
            }
            Some(other) => Err(CoreError::Internal(format!(
                "unexpected UploadComplete response: {other:?}"
            ))),
            None => Err(CoreError::SessionClosed(
                "session closed waiting for UploadComplete".into(),
            )),
        }
    }

    /// Download a file or directory from `/workspace`, **unconditionally** piping guest
    /// bytes through [`blackwall_unpacker::sanitize_download_stream`] (enforcing `max_bytes`,
    /// `max_files`, canonical `.tar.gz` re-pack, and rejecting traversal/symlinks/zip-bombs).
    pub async fn download_files(
        &self,
        path: impl Into<String>,
        format: DownloadFormat,
        export_spec: &ExportSpec,
        audit_sink: Arc<dyn AuditSink>,
    ) -> Result<Vec<u8>> {
        let (bytes, _summary) = self
            .download_files_with_summary(path, format, export_spec, audit_sink)
            .await?;
        Ok(bytes)
    }

    /// Same as [`Self::download_files`], also returning the unpacker's [`UnpackSummary`].
    pub async fn download_files_with_summary(
        &self,
        path: impl Into<String>,
        format: DownloadFormat,
        export_spec: &ExportSpec,
        audit_sink: Arc<dyn AuditSink>,
    ) -> Result<(Vec<u8>, UnpackSummary)> {
        let path_str = path.into();
        let req_id = self.inner.alloc_req_id();
        let mut raw_rx = self.inner.register_req(req_id)?;
        if let Err(err) = self.inner.send_request(&CtrlRequest::DownloadBegin {
            req_id,
            path: path_str.clone(),
            format,
        }) {
            self.inner.unregister_req(req_id);
            return Err(err);
        }

        // Wait for the first frame before spawning the sanitizer so immediate guest errors
        // (e.g., NotFound / PathViolation) surface cleanly as CoreError::GuestError.
        let first_frame = match raw_rx.recv().await {
            Some(CtrlResponse::Error { code, message, .. }) => {
                return Err(CoreError::GuestError { code, message });
            }
            Some(CtrlResponse::FileChunk { data, eof, .. }) => (data, eof),
            Some(other) => {
                return Err(CoreError::Internal(format!(
                    "unexpected DownloadBegin response: {other:?}"
                )));
            }
            None => {
                return Err(CoreError::SessionClosed(
                    "session closed waiting for DownloadBegin response".into(),
                ));
            }
        };

        let (chunk_tx, chunk_rx) =
            std::sync::mpsc::sync_channel::<std::result::Result<Vec<u8>, CoreError>>(16);
        let guest_err_slot: Arc<Mutex<Option<CoreError>>> = Arc::new(Mutex::new(None));
        let guest_err_writer = Arc::clone(&guest_err_slot);

        let sandbox_id = self.inner.sandbox_id.clone();
        let spec_clone = export_spec.clone();
        let display_path = path_str.clone();

        let sanitizer_task = tokio::task::spawn_blocking(move || {
            let reader = SyncChannelReader::new(chunk_rx);
            let mut sanitized = Vec::new();
            let summary = sanitize_download_stream(
                format,
                reader,
                &mut sanitized,
                &display_path,
                &spec_clone,
                &sandbox_id,
                audit_sink.as_ref(),
            )?;
            Ok::<(Vec<u8>, UnpackSummary), CoreError>((sanitized, summary))
        });

        // Feed the first chunk and stream any remaining chunks into the sanitizer.
        let pump_task = tokio::spawn(async move {
            let (first_data, first_eof) = first_frame;
            if !first_data.is_empty() && chunk_tx.send(Ok(first_data)).is_err() {
                return;
            }
            if first_eof {
                return;
            }
            while let Some(resp) = raw_rx.recv().await {
                match resp {
                    CtrlResponse::FileChunk { data, eof, .. } => {
                        if !data.is_empty() && chunk_tx.send(Ok(data)).is_err() {
                            break;
                        }
                        if eof {
                            break;
                        }
                    }
                    CtrlResponse::Error { code, message, .. } => {
                        if let Ok(mut g) = guest_err_writer.lock() {
                            *g = Some(CoreError::GuestError { code, message });
                        }
                        let _ = chunk_tx.send(Err(CoreError::SessionClosed(
                            "guest aborted download stream".into(),
                        )));
                        break;
                    }
                    _ => {}
                }
            }
        });

        let sanitize_res = sanitizer_task
            .await
            .map_err(|e| CoreError::Internal(format!("download sanitizer task panicked: {e}")))?;
        let _ = pump_task.await;

        if let Ok(mut g) = guest_err_slot.lock() {
            if let Some(guest_err) = g.take() {
                return Err(guest_err);
            }
        }

        sanitize_res
    }

    /// Gracefully ask `blackwall-init` to shut down the session.
    pub async fn shutdown(&self) -> Result<()> {
        if self.inner.is_closed() {
            return Ok(());
        }
        let req_id = self.inner.alloc_req_id();
        let mut rx = self.inner.register_req(req_id)?;
        if let Err(err) = self.inner.send_request(&CtrlRequest::Shutdown { req_id }) {
            self.inner.unregister_req(req_id);
            return Err(err);
        }
        let res = expect_ack(&mut rx, "Shutdown").await;
        self.inner.close_all();
        res
    }
}

async fn expect_ack(
    rx: &mut mpsc::UnboundedReceiver<CtrlResponse>,
    op: &str,
) -> Result<()> {
    match rx.recv().await {
        Some(CtrlResponse::Ack { .. }) => Ok(()),
        Some(CtrlResponse::Error { code, message, .. }) => {
            Err(CoreError::GuestError { code, message })
        }
        Some(other) => Err(CoreError::Internal(format!(
            "unexpected {op} response: {other:?}"
        ))),
        None => Err(CoreError::SessionClosed(format!(
            "session closed waiting for {op} Ack"
        ))),
    }
}

fn reader_loop(mut stream: UnixStream, inner: Arc<SessionInner>) {
    loop {
        match read_ctrl_response(&mut stream) {
            Ok(resp) => dispatch_response(&inner, resp),
            Err(_) => break,
        }
    }
    inner.close_all();
}

fn dispatch_response(inner: &SessionInner, resp: CtrlResponse) {
    match &resp {
        CtrlResponse::PtyOutput { session_id, data } => {
            let tx = inner
                .pty_sessions
                .lock()
                .ok()
                .and_then(|g| g.get(session_id).cloned());
            if let Some(tx) = tx {
                let _ = tx.send(PtyEvent::Output(data.clone()));
            }
        }
        CtrlResponse::PtyExited {
            session_id,
            exit_code,
        } => {
            let tx = inner
                .pty_sessions
                .lock()
                .ok()
                .and_then(|mut g| g.remove(session_id));
            if let Some(tx) = tx {
                let _ = tx.send(PtyEvent::Exited(*exit_code));
            }
        }
        CtrlResponse::TcpData { stream_id, data } => {
            let target = inner
                .tcp_tunnels
                .lock()
                .ok()
                .and_then(|g| g.get(stream_id).map(|t| (t.tx.clone(), Arc::clone(&t.bytes_out))));
            if let Some((tx, bytes_out)) = target {
                bytes_out.fetch_add(data.len() as u64, Ordering::Relaxed);
                let _ = tx.send(TcpTunnelEvent::Data(data.clone()));
            }
        }
        CtrlResponse::TcpClosed { stream_id, reason } => {
            let target = inner
                .tcp_tunnels
                .lock()
                .ok()
                .and_then(|mut g| g.remove(stream_id));
            if let Some(t) = target {
                let _ = t.tx.send(TcpTunnelEvent::Closed(reason.clone()));
            }
        }
        CtrlResponse::HostBridgeOpen {
            stream_id,
            guest_port,
        } => {
            let tx = inner
                .host_bridge_open_tx
                .lock()
                .ok()
                .and_then(|g| g.clone());
            if let Some(tx) = tx {
                let _ = tx.send((stream_id.clone(), *guest_port));
            }
        }
        _ => {
            let Some((req_id, is_terminal)) = response_req_meta(&resp) else {
                return;
            };
            let tx = inner.pending_reqs.lock().ok().and_then(|mut g| {
                if is_terminal {
                    g.remove(&req_id)
                } else {
                    g.get(&req_id).cloned()
                }
            });
            if let Some(tx) = tx {
                let _ = tx.send(resp);
            }
        }
    }
}

fn response_req_meta(resp: &CtrlResponse) -> Option<(u64, bool)> {
    match resp {
        CtrlResponse::BootReady { req_id, .. }
        | CtrlResponse::ExecExit { req_id, .. }
        | CtrlResponse::ProcessSpawned { req_id, .. }
        | CtrlResponse::ProcessListResult { req_id, .. }
        | CtrlResponse::ProcessLogsEnd { req_id }
        | CtrlResponse::PtyOpened { req_id, .. }
        | CtrlResponse::TcpConnected { req_id, .. }
        | CtrlResponse::UploadComplete { req_id, .. }
        | CtrlResponse::Ack { req_id }
        | CtrlResponse::Error { req_id, .. } => Some((*req_id, true)),
        CtrlResponse::ExecOutput { req_id, .. } => Some((*req_id, false)),
        CtrlResponse::FileChunk { req_id, eof, .. } => Some((*req_id, *eof)),
        CtrlResponse::PtyOutput { .. }
        | CtrlResponse::PtyExited { .. }
        | CtrlResponse::TcpData { .. }
        | CtrlResponse::TcpClosed { .. }
        | CtrlResponse::HostBridgeOpen { .. } => None,
    }
}

/// Blocking `Read` adapter feeding streamed `FileChunk`s directly into `blackwall-unpacker`.
struct SyncChannelReader {
    rx: std::sync::mpsc::Receiver<std::result::Result<Vec<u8>, CoreError>>,
    buf: Vec<u8>,
    pos: usize,
}

impl SyncChannelReader {
    fn new(rx: std::sync::mpsc::Receiver<std::result::Result<Vec<u8>, CoreError>>) -> Self {
        Self {
            rx,
            buf: Vec::new(),
            pos: 0,
        }
    }
}

impl Read for SyncChannelReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        while self.pos >= self.buf.len() {
            match self.rx.recv() {
                Ok(Ok(chunk)) => {
                    self.buf = chunk;
                    self.pos = 0;
                }
                Ok(Err(err)) => return Err(io::Error::other(err.to_string())),
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
