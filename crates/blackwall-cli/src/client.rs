//! Pure-Tokio/Hyper HTTP/1.1 + WebSocket client over a local Unix domain socket.
//!
//! Zero OpenSSL dependency.

use crate::error::{CliError, Result};
use blackwall_audit::AuditEvent;
use blackwall_core::{
    BackgroundProcess, BuiltImage, ExecRequest, ExecResult, ProcessInfo, ProfileDraft,
    SandboxDetail, SandboxSpec, SandboxSummary, SignalKind, UploadResult,
};
use blackwall_policy::HostServiceSpec;
use bytes::Bytes;
use http::{header, Method, Request, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use tokio::net::UnixStream;
use tokio_tungstenite::WebSocketStream;

/// Response returned by `POST /v1/sandboxes/{id}/keepalive`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeepaliveResponse {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_deadline_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    #[serde(default)]
    pub idle_remaining_sec: u64,
    #[serde(default)]
    pub wall_remaining_sec: u64,
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

/// RFC 3986 percent-encoding set for query values and path segments.
const QUERY_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'&')
    .add(b'+')
    .add(b'/')
    .add(b':')
    .add(b';')
    .add(b'<')
    .add(b'=')
    .add(b'>')
    .add(b'?')
    .add(b'@')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');

pub fn encode_uri_component(s: &str) -> String {
    utf8_percent_encode(s, QUERY_ENCODE_SET).to_string()
}

/// Decoded frame from an `application/x-ndjson` stream (`exec --stream` or `logs`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NdjsonFrame {
    Stdout(String),
    Stderr(String),
    Exit {
        exit_code: i32,
        timed_out: bool,
        duration_ms: u64,
    },
    End,
    Error {
        code: String,
        message: String,
    },
    Raw(serde_json::Value),
}

impl NdjsonFrame {
    /// Parse a single NDJSON line matching `ExecStreamEvent::to_ndjson_value()`.
    pub fn parse_line(line: &str) -> Result<Self> {
        let val: serde_json::Value = serde_json::from_str(line)?;
        let kind = val.get("type").and_then(|v| v.as_str()).unwrap_or("");
        match kind {
            "stdout" => Ok(Self::Stdout(
                val.get("data")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string(),
            )),
            "stderr" => Ok(Self::Stderr(
                val.get("data")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string(),
            )),
            "exit" => Ok(Self::Exit {
                exit_code: val
                    .get("exit_code")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0) as i32,
                timed_out: val
                    .get("timed_out")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false),
                duration_ms: val
                    .get("duration_ms")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
            }),
            "end" => Ok(Self::End),
            "error" => Ok(Self::Error {
                code: val
                    .get("code")
                    .map(|v| {
                        v.as_str()
                            .map(ToOwned::to_owned)
                            .unwrap_or_else(|| v.to_string())
                    })
                    .unwrap_or_else(|| "error".to_string()),
                message: val
                    .get("message")
                    .and_then(|v| v.as_str())
                    .unwrap_or("stream error")
                    .to_string(),
            }),
            _ => Ok(Self::Raw(val)),
        }
    }
}

/// Incremental NDJSON response stream over a Hyper HTTP/1.1 UDS connection.
pub struct NdjsonStream {
    body: Incoming,
    buf: Vec<u8>,
    eof: bool,
}

impl NdjsonStream {
    pub fn new(body: Incoming) -> Self {
        Self {
            body,
            buf: Vec::new(),
            eof: false,
        }
    }

    /// Read the next non-empty line from the HTTP stream without parsing its schema.
    pub async fn next_line(&mut self) -> Result<Option<String>> {
        loop {
            if let Some(pos) = self.buf.iter().position(|&b| b == b'\n') {
                let mut line_bytes: Vec<u8> = self.buf.drain(..=pos).collect();
                while matches!(line_bytes.last(), Some(b'\n' | b'\r')) {
                    line_bytes.pop();
                }
                if line_bytes.is_empty() {
                    continue;
                }
                return Ok(Some(String::from_utf8_lossy(&line_bytes).into_owned()));
            }

            if self.eof {
                if !self.buf.is_empty() {
                    let line_bytes = std::mem::take(&mut self.buf);
                    let line = String::from_utf8_lossy(&line_bytes).trim().to_string();
                    if !line.is_empty() {
                        return Ok(Some(line));
                    }
                }
                return Ok(None);
            }

            match self.body.frame().await {
                Some(Ok(frame)) => {
                    if let Some(data) = frame.data_ref() {
                        self.buf.extend_from_slice(data);
                    }
                }
                Some(Err(err)) => return Err(CliError::Hyper(err)),
                None => {
                    self.eof = true;
                }
            }
        }
    }

    /// Read the next non-empty NDJSON line from the HTTP stream, returning `(raw_line, parsed_frame)`.
    pub async fn next_frame(&mut self) -> Result<Option<(String, NdjsonFrame)>> {
        let Some(line) = self.next_line().await? else {
            return Ok(None);
        };
        let frame = NdjsonFrame::parse_line(&line)?;
        Ok(Some((line, frame)))
    }
}

/// Pure Tokio + Hyper HTTP/1.1 & WebSocket client targeting `blackwall-daemon`'s Unix socket.
#[derive(Debug, Clone)]
pub struct UdsClient {
    socket_path: PathBuf,
}

impl UdsClient {
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Send an HTTP/1.1 request over the Unix domain socket and return the raw response.
    pub async fn send_raw(
        &self,
        method: Method,
        path_and_query: &str,
        content_type: Option<&str>,
        accept: Option<&str>,
        body: Bytes,
    ) -> Result<http::Response<Incoming>> {
        let stream = UnixStream::connect(&self.socket_path).await.map_err(|source| {
            CliError::SocketConnect {
                socket: self.socket_path.display().to_string(),
                source,
            }
        })?;
        let io = TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
        tokio::spawn(async move {
            let _ = conn.await;
        });

        let mut builder = Request::builder()
            .method(method)
            .uri(path_and_query)
            .header(header::HOST, "localhost");
        if let Some(ct) = content_type {
            builder = builder.header(header::CONTENT_TYPE, ct);
        }
        if let Some(acc) = accept {
            builder = builder.header(header::ACCEPT, acc);
        }

        let req = builder.body(Full::new(body))?;
        let resp = sender.send_request(req).await?;
        Ok(resp)
    }

    async fn send_expect_success(
        &self,
        method: Method,
        path_and_query: &str,
        content_type: Option<&str>,
        accept: Option<&str>,
        body: Bytes,
    ) -> Result<http::Response<Incoming>> {
        let resp = self
            .send_raw(method, path_and_query, content_type, accept, body)
            .await?;
        let status = resp.status();
        if status.is_success() {
            return Ok(resp);
        }
        let err_bytes = resp.into_body().collect().await?.to_bytes();
        Err(api_error(status, &err_bytes))
    }

    async fn send_json<T: DeserializeOwned>(
        &self,
        method: Method,
        path_and_query: &str,
        body: Option<Bytes>,
    ) -> Result<T> {
        let (ct, payload) = match body {
            Some(b) => (Some("application/json"), b),
            None => (None, Bytes::new()),
        };
        let resp = self
            .send_expect_success(method, path_and_query, ct, Some("application/json"), payload)
            .await?;
        let bytes = resp.into_body().collect().await?.to_bytes();
        Ok(serde_json::from_slice(&bytes)?)
    }

    // -----------------------------------------------------------------------
    // Sandbox Lifecycle (§2.1)
    // -----------------------------------------------------------------------

    /// `POST /v1/sandboxes`
    pub async fn create_sandbox(&self, draft: &ProfileDraft) -> Result<SandboxSummary> {
        let payload = Bytes::from(serde_json::to_vec(draft)?);
        self.send_json(Method::POST, "/v1/sandboxes", Some(payload))
            .await
    }

    /// `GET /v1/sandboxes`
    pub async fn list_sandboxes(&self) -> Result<Vec<SandboxSummary>> {
        self.send_json(Method::GET, "/v1/sandboxes", None).await
    }

    /// `GET /v1/sandboxes/{id}`
    pub async fn inspect_sandbox(&self, id: &str) -> Result<SandboxDetail> {
        let path = format!("/v1/sandboxes/{}", encode_uri_component(id));
        self.send_json(Method::GET, &path, None).await
    }

    /// `DELETE /v1/sandboxes/{id}`
    pub async fn destroy_sandbox(&self, id: &str) -> Result<()> {
        let path = format!("/v1/sandboxes/{}", encode_uri_component(id));
        let resp = self
            .send_expect_success(Method::DELETE, &path, None, None, Bytes::new())
            .await?;
        let _ = resp.into_body().collect().await?;
        Ok(())
    }

    /// `POST /v1/sandboxes/{id}/keepalive`
    pub async fn keepalive_sandbox(&self, id: &str) -> Result<KeepaliveResponse> {
        let path = format!("/v1/sandboxes/{}/keepalive", encode_uri_component(id));
        self.send_json(Method::POST, &path, None).await
    }

    // -----------------------------------------------------------------------
    // Command Execution & Background Processes (§2.2)
    // -----------------------------------------------------------------------

    /// `POST /v1/sandboxes/{id}/exec` (synchronous)
    pub async fn exec_sync(&self, id: &str, req: &ExecRequest) -> Result<ExecResult> {
        let path = format!("/v1/sandboxes/{}/exec", encode_uri_component(id));
        let payload = Bytes::from(serde_json::to_vec(req)?);
        self.send_json(Method::POST, &path, Some(payload)).await
    }

    /// `POST /v1/sandboxes/{id}/exec` with `background: true`
    pub async fn exec_background(&self, id: &str, req: &ExecRequest) -> Result<BackgroundProcess> {
        let path = format!("/v1/sandboxes/{}/exec", encode_uri_component(id));
        let mut bg_req = req.clone();
        bg_req.background = true;
        let payload = Bytes::from(serde_json::to_vec(&bg_req)?);
        self.send_json(Method::POST, &path, Some(payload)).await
    }

    /// `POST /v1/sandboxes/{id}/exec?stream=true` (NDJSON stream)
    pub async fn exec_stream(&self, id: &str, req: &ExecRequest) -> Result<NdjsonStream> {
        let path = format!("/v1/sandboxes/{}/exec?stream=true", encode_uri_component(id));
        let payload = Bytes::from(serde_json::to_vec(req)?);
        let resp = self
            .send_expect_success(
                Method::POST,
                &path,
                Some("application/json"),
                Some("application/x-ndjson"),
                payload,
            )
            .await?;
        Ok(NdjsonStream::new(resp.into_body()))
    }

    /// `GET /v1/sandboxes/{id}/processes`
    pub async fn list_processes(&self, id: &str) -> Result<Vec<ProcessInfo>> {
        let path = format!("/v1/sandboxes/{}/processes", encode_uri_component(id));
        self.send_json(Method::GET, &path, None).await
    }

    /// `GET /v1/sandboxes/{id}/processes/{proc_id}/logs`
    pub async fn process_logs(
        &self,
        id: &str,
        proc_id: &str,
        tail: Option<usize>,
        follow: bool,
    ) -> Result<NdjsonStream> {
        let mut qs = Vec::new();
        if let Some(n) = tail {
            qs.push(format!("tail={n}"));
        }
        if follow {
            qs.push("follow=true".to_string());
        }
        let path = if qs.is_empty() {
            format!(
                "/v1/sandboxes/{}/processes/{}/logs",
                encode_uri_component(id),
                encode_uri_component(proc_id)
            )
        } else {
            format!(
                "/v1/sandboxes/{}/processes/{}/logs?{}",
                encode_uri_component(id),
                encode_uri_component(proc_id),
                qs.join("&")
            )
        };
        let resp = self
            .send_expect_success(
                Method::GET,
                &path,
                None,
                Some("application/x-ndjson"),
                Bytes::new(),
            )
            .await?;
        Ok(NdjsonStream::new(resp.into_body()))
    }

    /// `POST /v1/sandboxes/{id}/processes/{proc_id}/signal`
    pub async fn signal_process(
        &self,
        id: &str,
        proc_id: &str,
        signal: SignalKind,
    ) -> Result<()> {
        let path = format!(
            "/v1/sandboxes/{}/processes/{}/signal",
            encode_uri_component(id),
            encode_uri_component(proc_id)
        );
        let payload = Bytes::from(serde_json::to_vec(&serde_json::json!({ "signal": signal }))?);
        let resp = self
            .send_expect_success(
                Method::POST,
                &path,
                Some("application/json"),
                None,
                payload,
            )
            .await?;
        let _ = resp.into_body().collect().await?;
        Ok(())
    }

    /// `DELETE /v1/sandboxes/{id}/processes/{proc_id}`
    pub async fn delete_process(&self, id: &str, proc_id: &str) -> Result<()> {
        let path = format!(
            "/v1/sandboxes/{}/processes/{}",
            encode_uri_component(id),
            encode_uri_component(proc_id)
        );
        let resp = self
            .send_expect_success(Method::DELETE, &path, None, None, Bytes::new())
            .await?;
        let _ = resp.into_body().collect().await?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Interactive PTY WebSocket (§2.3)
    // -----------------------------------------------------------------------

    /// Connect to `GET /v1/sandboxes/{id}/pty` over the Unix socket via WebSocket upgrade.
    pub async fn connect_pty_ws(
        &self,
        id: &str,
        cols: u16,
        rows: u16,
        cwd: Option<&str>,
        cmd: &[String],
    ) -> Result<WebSocketStream<UnixStream>> {
        let mut qs = vec![format!("cols={cols}"), format!("rows={rows}")];
        if let Some(dir) = cwd {
            qs.push(format!("cwd={}", encode_uri_component(dir)));
        }
        for arg in cmd {
            qs.push(format!("cmd={}", encode_uri_component(arg)));
        }
        let url = format!(
            "ws://localhost/v1/sandboxes/{}/pty?{}",
            encode_uri_component(id),
            qs.join("&")
        );

        let stream = UnixStream::connect(&self.socket_path).await.map_err(|source| {
            CliError::SocketConnect {
                socket: self.socket_path.display().to_string(),
                source,
            }
        })?;
        let (ws_stream, _resp) = tokio_tungstenite::client_async(url, stream).await?;
        Ok(ws_stream)
    }

    /// Connect to `GET /v1/sandboxes/{id}/tunnel/{guest_port}` over the Unix socket via WebSocket upgrade.
    pub async fn connect_tunnel_ws(
        &self,
        id: &str,
        guest_port: u16,
    ) -> Result<WebSocketStream<UnixStream>> {
        let url = format!(
            "ws://localhost/v1/sandboxes/{}/tunnel/{guest_port}",
            encode_uri_component(id)
        );
        let stream = UnixStream::connect(&self.socket_path).await.map_err(|source| {
            CliError::SocketConnect {
                socket: self.socket_path.display().to_string(),
                source,
            }
        })?;
        match tokio_tungstenite::client_async(url, stream).await {
            Ok((ws_stream, _resp)) => Ok(ws_stream),
            Err(tokio_tungstenite::tungstenite::Error::Http(resp)) => {
                let status = resp.status();
                let body = resp.body().as_deref().unwrap_or(&[]);
                Err(api_error(status, body))
            }
            Err(err) => Err(err.into()),
        }
    }

    // -----------------------------------------------------------------------
    // Ingress Ports
    // -----------------------------------------------------------------------

    /// `GET /v1/sandboxes/{id}/ingress`
    pub async fn list_ingress_ports(&self, id: &str) -> Result<Vec<u16>> {
        let path = format!("/v1/sandboxes/{}/ingress", encode_uri_component(id));
        self.send_json(Method::GET, &path, None).await
    }

    /// `POST /v1/sandboxes/{id}/ingress`
    pub async fn allow_ingress_port(&self, id: &str, port: u16) -> Result<Vec<u16>> {
        let path = format!("/v1/sandboxes/{}/ingress", encode_uri_component(id));
        let payload = Bytes::from(serde_json::to_vec(&serde_json::json!({ "port": port }))?);
        self.send_json(Method::POST, &path, Some(payload)).await
    }

    /// `DELETE /v1/sandboxes/{id}/ingress/{port}`
    pub async fn close_ingress_port(&self, id: &str, port: u16) -> Result<()> {
        let path = format!("/v1/sandboxes/{}/ingress/{port}", encode_uri_component(id));
        let resp = self
            .send_expect_success(Method::DELETE, &path, None, None, Bytes::new())
            .await?;
        let _ = resp.into_body().collect().await?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Host Service Bridges
    // -----------------------------------------------------------------------

    /// `GET /v1/sandboxes/{id}/bridges`
    pub async fn list_bridges(&self, id: &str) -> Result<Vec<HostServiceSpec>> {
        let path = format!("/v1/sandboxes/{}/bridges", encode_uri_component(id));
        self.send_json(Method::GET, &path, None).await
    }

    /// `POST /v1/sandboxes/{id}/bridges`
    pub async fn attach_bridge(
        &self,
        id: &str,
        spec: &HostServiceSpec,
    ) -> Result<HostServiceSpec> {
        let path = format!("/v1/sandboxes/{}/bridges", encode_uri_component(id));
        let payload = Bytes::from(serde_json::to_vec(spec)?);
        self.send_json(Method::POST, &path, Some(payload)).await
    }

    /// `DELETE /v1/sandboxes/{id}/bridges/{guest_port}`
    pub async fn detach_bridge(&self, id: &str, guest_port: u16) -> Result<()> {
        let path = format!(
            "/v1/sandboxes/{}/bridges/{guest_port}",
            encode_uri_component(id)
        );
        let resp = self
            .send_expect_success(Method::DELETE, &path, None, None, Bytes::new())
            .await?;
        let _ = resp.into_body().collect().await?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // File I/O (§2.4)
    // -----------------------------------------------------------------------

    /// `PUT /v1/sandboxes/{id}/files?path=<remote_path>`
    pub async fn upload_files(
        &self,
        id: &str,
        remote_path: &str,
        content_type: &str,
        data: Bytes,
    ) -> Result<UploadResult> {
        let path = format!(
            "/v1/sandboxes/{}/files?path={}",
            encode_uri_component(id),
            encode_uri_component(remote_path)
        );
        let resp = self
            .send_expect_success(
                Method::PUT,
                &path,
                Some(content_type),
                Some("application/json"),
                data,
            )
            .await?;
        let bytes = resp.into_body().collect().await?.to_bytes();
        if bytes.is_empty() {
            return Ok(UploadResult {
                sandbox_id: id.to_string(),
                path: remote_path.to_string(),
                kind: blackwall_core::UploadKind::Raw,
                bytes_written: 0,
                files_written: 0,
                duration_ms: 0,
            });
        }
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// `GET /v1/sandboxes/{id}/files?path=<remote_path>&format=<raw|tar.gz>`
    pub async fn download_files(
        &self,
        id: &str,
        remote_path: &str,
        format: &str,
    ) -> Result<Bytes> {
        let path = format!(
            "/v1/sandboxes/{}/files?path={}&format={}",
            encode_uri_component(id),
            encode_uri_component(remote_path),
            encode_uri_component(format)
        );
        let resp = self
            .send_expect_success(Method::GET, &path, None, None, Bytes::new())
            .await?;
        let bytes = resp.into_body().collect().await?.to_bytes();
        Ok(bytes)
    }

    // -----------------------------------------------------------------------
    // Profiles & Images (§2.5)
    // -----------------------------------------------------------------------

    /// `GET /v1/profiles`
    pub async fn list_profiles(&self) -> Result<Vec<String>> {
        self.send_json(Method::GET, "/v1/profiles", None).await
    }

    /// `GET /v1/profiles/{name}`
    pub async fn get_profile(&self, name: &str) -> Result<SandboxSpec> {
        let path = format!("/v1/profiles/{}", encode_uri_component(name));
        self.send_json(Method::GET, &path, None).await
    }

    /// `GET /v1/images`
    pub async fn list_images(&self) -> Result<Vec<BuiltImage>> {
        self.send_json(Method::GET, "/v1/images", None).await
    }

    // -----------------------------------------------------------------------
    // Audit Events (§2.6)
    // -----------------------------------------------------------------------

    fn audit_path(id: Option<&str>, limit: usize, follow: bool) -> String {
        match id {
            Some(sb_id) => format!(
                "/v1/sandboxes/{}/audit?limit={limit}&follow={follow}",
                encode_uri_component(sb_id)
            ),
            None => format!("/v1/audit?limit={limit}&follow={follow}"),
        }
    }

    /// `GET /v1/audit?limit={limit}&follow=false` or `GET /v1/sandboxes/{id}/audit?limit={limit}&follow=false`
    pub async fn audit_events(&self, id: Option<&str>, limit: usize) -> Result<Vec<AuditEvent>> {
        let path = Self::audit_path(id, limit, false);
        self.send_json(Method::GET, &path, None).await
    }

    /// `GET /v1/audit?limit={limit}&follow=true` or `GET /v1/sandboxes/{id}/audit?limit={limit}&follow=true`
    pub async fn audit_stream(&self, id: Option<&str>, limit: usize) -> Result<NdjsonStream> {
        let path = Self::audit_path(id, limit, true);
        let resp = self
            .send_expect_success(
                Method::GET,
                &path,
                None,
                Some("application/x-ndjson"),
                Bytes::new(),
            )
            .await?;
        Ok(NdjsonStream::new(resp.into_body()))
    }
}

#[derive(Deserialize)]
struct ErrorEnvelope {
    error: Option<String>,
    message: Option<String>,
}

fn api_error(status: StatusCode, body: &[u8]) -> CliError {
    let message = serde_json::from_slice::<ErrorEnvelope>(body)
        .ok()
        .and_then(|e| e.error.or(e.message))
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| {
            let text = String::from_utf8_lossy(body).trim().to_string();
            if text.is_empty() {
                status.canonical_reason().unwrap_or("request failed").to_string()
            } else {
                text
            }
        });
    CliError::Api {
        status: status.as_u16(),
        message,
    }
}
