//! End-to-end integration tests for `blackwall-daemon` over a real `0600` Unix domain socket.

use blackwall_core::{
    AuditEvent, AuditEventKind, BuiltImage, CoreConfig, ExecResult, FsEntry, HostServiceSpec,
    KeepaliveResponse, ListeningPort, MemoryAuditSink, MockSessionVmmBackend, NetworkMode,
    PolicyCeiling, ProcessInfo, SandboxDetail, SandboxManager, SandboxSpec, SandboxState,
    SandboxSummary, StaticDnsResolver, UploadResult,
};
use blackwall_daemon::{
    ApiErrorBody, AuthStatusResponse, BoundDaemon, DaemonError, HttpOptions, PrincipalRole,
};
use bytes::Bytes;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use futures_util::{SinkExt, StreamExt};
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1;
use hyper::header::{CONTENT_TYPE, HOST};
use hyper::{Method, Request, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::json;
use std::fs;
use std::io::{Cursor, Read};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UnixStream;
use tokio::sync::oneshot;
use tokio_tungstenite::tungstenite::Message as WsMessage;

/// Minimal HTTP/1.1 client speaking directly over the daemon's Unix domain socket.
struct UdsHttpClient {
    socket_path: PathBuf,
}

struct HttpReply {
    status: StatusCode,
    content_type: Option<String>,
    body: Bytes,
}

impl UdsHttpClient {
    fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }

    async fn request(
        &self,
        method: Method,
        path_and_query: &str,
        content_type: Option<&str>,
        body: impl Into<Bytes>,
    ) -> HttpReply {
        let stream = UnixStream::connect(&self.socket_path)
            .await
            .expect("failed to connect to daemon UDS");
        let io = TokioIo::new(stream);
        let (mut sender, conn) = http1::handshake(io)
            .await
            .expect("HTTP/1.1 UDS handshake failed");
        tokio::spawn(async move {
            let _ = conn.await;
        });

        let mut builder = Request::builder()
            .method(method)
            .uri(path_and_query)
            .header(HOST, "localhost");
        if let Some(ct) = content_type {
            builder = builder.header(CONTENT_TYPE, ct);
        }

        let req = builder
            .body(Full::new(body.into()))
            .expect("failed to build HTTP request");
        let resp = sender
            .send_request(req)
            .await
            .expect("HTTP request over UDS failed");
        let status = resp.status();
        let content_type = resp
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(ToOwned::to_owned);
        let collected = resp
            .into_body()
            .collect()
            .await
            .expect("failed to read HTTP response body");

        HttpReply {
            status,
            content_type,
            body: collected.to_bytes(),
        }
    }

    async fn get(&self, path_and_query: &str) -> HttpReply {
        self.request(Method::GET, path_and_query, None, Bytes::new())
            .await
    }

    async fn delete(&self, path_and_query: &str) -> HttpReply {
        self.request(Method::DELETE, path_and_query, None, Bytes::new())
            .await
    }

    async fn post_json(&self, path_and_query: &str, payload: &serde_json::Value) -> HttpReply {
        let bytes = serde_json::to_vec(payload).unwrap();
        self.request(Method::POST, path_and_query, Some("application/json"), bytes)
            .await
    }

    async fn put_bytes(&self, path_and_query: &str, content_type: &str, data: Vec<u8>) -> HttpReply {
        self.request(Method::PUT, path_and_query, Some(content_type), data)
            .await
    }
}

fn make_tar(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut out);
        for &(name, data) in files {
            let mut hdr = tar::Header::new_gnu();
            hdr.set_entry_type(tar::EntryType::Regular);
            hdr.set_mode(0o644);
            hdr.set_size(data.len() as u64);
            hdr.set_cksum();
            builder.append_data(&mut hdr, name, data).unwrap();
        }
        builder.finish().unwrap();
    }
    out
}

fn make_targz(files: &[(&str, &[u8])]) -> Vec<u8> {
    let raw_tar = make_tar(files);
    let mut gz = GzEncoder::new(Vec::new(), Compression::default());
    std::io::Write::write_all(&mut gz, &raw_tar).unwrap();
    gz.finish().unwrap()
}

struct TestDaemon {
    _tmp: tempfile::TempDir,
    socket_path: PathBuf,
    client: UdsHttpClient,
    shutdown_tx: Option<oneshot::Sender<()>>,
    server_task: Option<tokio::task::JoinHandle<Result<(), blackwall_daemon::DaemonError>>>,
}

impl TestDaemon {
    fn start(setup_profiles: impl FnOnce(&Path)) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let profiles_dir = tmp.path().join("profiles");
        fs::create_dir_all(&profiles_dir).unwrap();
        setup_profiles(&profiles_dir);

        let sink = Arc::new(MemoryAuditSink::new());
        let cfg = CoreConfig::for_testing(tmp.path(), sink);
        let manager = Arc::new(
            SandboxManager::with_backend(
                cfg,
                Box::new(MockSessionVmmBackend::new()),
                Arc::new(StaticDnsResolver::new()),
            )
            .expect("SandboxManager::with_backend should succeed"),
        );

        // Place socket inside a non-existent nested dir so parent 0700 creation is also exercised.
        let socket_path = tmp.path().join("sockdir").join("blackwall.sock");
        let bound = BoundDaemon::bind(manager, &socket_path).expect("BoundDaemon::bind failed");

        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let server_task = tokio::spawn(async move {
            bound
                .serve(async move {
                    let _ = shutdown_rx.await;
                })
                .await
        });

        let client = UdsHttpClient::new(&socket_path);
        Self {
            _tmp: tmp,
            socket_path,
            client,
            shutdown_tx: Some(shutdown_tx),
            server_task: Some(server_task),
        }
    }

    async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(task) = self.server_task.take() {
            task.await
                .expect("daemon task panicked")
                .expect("daemon serve returned error");
        }
        assert!(
            !self.socket_path.exists(),
            "daemon shutdown must clean up Unix socket file"
        );
    }
}

#[tokio::test]
async fn full_daemon_api_e2e_over_0600_unix_socket() {
    let daemon = TestDaemon::start(|profiles_dir| {
        fs::write(
            profiles_dir.join("dev-profile.toml"),
            r#"
version = 1
name = "dev-profile"
extends = ["base"]

[compute]
vcpus = 2
memory_mib = 1024
workspace_mib = 256
idle_timeout_sec = 60
max_wall_time_sec = 300

[env]
DAEMON_PROFILE_ENV = "profile-loaded"

[secrets.MY_TOKEN]
placeholder_prefix = "tok_bw_"
sealed = "seal1_dummy_sealed_payload_redacted_in_profile_view"
"#,
        )
        .unwrap();
    });

    // 1. Verify strict socket (0600) and parent dir (0700) permissions.
    let sock_mode = fs::metadata(&daemon.socket_path)
        .expect("socket should exist")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(sock_mode, 0o600, "Unix socket permissions must be strictly 0600");

    let parent_mode = fs::metadata(daemon.socket_path.parent().unwrap())
        .expect("socket parent dir should exist")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        parent_mode, 0o700,
        "Newly created socket parent directory must be strictly 0700"
    );

    // 2. GET /v1/profiles, GET /v1/profiles/base, GET /v1/profiles/dev-profile (redacted), GET /v1/images.
    let resp = daemon.client.get("/v1/profiles").await;
    assert_eq!(resp.status, StatusCode::OK);
    let profiles: Vec<String> = serde_json::from_slice(&resp.body).unwrap();
    assert!(profiles.contains(&"base".to_string()));
    assert!(profiles.contains(&"dev-profile".to_string()));

    let resp = daemon.client.get("/v1/profiles/base").await;
    assert_eq!(resp.status, StatusCode::OK);
    let base_spec: SandboxSpec = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(base_spec.name, "base");

    let resp = daemon.client.get("/v1/profiles/dev-profile").await;
    assert_eq!(resp.status, StatusCode::OK);
    let dev_spec: SandboxSpec = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(
        dev_spec.env.get("DAEMON_PROFILE_ENV").map(String::as_str),
        Some("profile-loaded")
    );
    let secret = dev_spec.secrets.get("MY_TOKEN").expect("MY_TOKEN present");
    assert_eq!(secret.sealed.as_deref(), Some("seal1_<redacted>"));

    let resp = daemon.client.get("/v1/profiles/does-not-exist").await;
    assert_eq!(resp.status, StatusCode::NOT_FOUND);
    let err_body: ApiErrorBody = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(err_body.code, "profile_not_found");

    let resp = daemon.client.get("/v1/images").await;
    assert_eq!(resp.status, StatusCode::OK);
    let images: Vec<BuiltImage> = serde_json::from_slice(&resp.body).unwrap();
    assert!(images.is_empty());

    // 3. POST /v1/sandboxes -> 201 Created, GET /v1/sandboxes, GET /v1/sandboxes/{id}.
    let create_payload = json!({
        "extends": ["base"],
        "compute": {
            "vcpus": 2,
            "memory_mib": 1024,
            "workspace_mib": 256,
            "idle_timeout_sec": 60,
            "max_wall_time_sec": 300
        },
        "env": {
            "GREETING": "hello-daemon"
        },
        "secrets": {
            "EPHEM_KEY": {
                "placeholder_prefix": "ek_bw_",
                "ephemeral": "ek_REAL_EPHEMERAL_VALUE"
            }
        }
    });
    let resp = daemon.client.post_json("/v1/sandboxes", &create_payload).await;
    assert_eq!(resp.status, StatusCode::CREATED);
    let created: SandboxSummary = serde_json::from_slice(&resp.body).unwrap();
    assert!(created.id.starts_with("bw-"));
    assert_eq!(created.state, SandboxState::Running);
    assert!(!created.image_roothash.is_empty());
    assert!(created.created_at > 0);
    assert!(created.expires_at >= created.created_at);
    assert!(created.idle_deadline_at >= created.created_at);

    let sb_id = created.id.clone();

    let resp = daemon.client.get("/v1/sandboxes").await;
    assert_eq!(resp.status, StatusCode::OK);
    let sandboxes: Vec<SandboxSummary> = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(sandboxes.len(), 1);
    assert_eq!(sandboxes[0].id, sb_id);

    let resp = daemon.client.get(&format!("/v1/sandboxes/{sb_id}")).await;
    assert_eq!(resp.status, StatusCode::OK);
    let detail: SandboxDetail = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(detail.id, sb_id);
    assert_eq!(detail.compute.memory_mib, 1024);

    // 4. PUT /v1/sandboxes/{id}/files (raw, tar, tar.gz) and GET /v1/sandboxes/{id}/files (raw & tar.gz).
    let raw_content = b"raw file uploaded over UDS\n";
    let resp = daemon
        .client
        .put_bytes(
            &format!("/v1/sandboxes/{sb_id}/files?path=/workspace/raw.txt"),
            "application/octet-stream",
            raw_content.to_vec(),
        )
        .await;
    assert_eq!(resp.status, StatusCode::OK);
    let upload_raw: UploadResult = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(upload_raw.bytes_written, raw_content.len() as u64);
    assert_eq!(upload_raw.files_written, 1);

    let tar_bytes = make_tar(&[
        ("from_tar/a.txt", b"alpha\n"),
        ("from_tar/b.txt", b"beta\n"),
    ]);
    let resp = daemon
        .client
        .put_bytes(
            &format!("/v1/sandboxes/{sb_id}/files?path=/workspace"),
            "application/x-tar",
            tar_bytes,
        )
        .await;
    assert_eq!(resp.status, StatusCode::OK);
    let upload_tar: UploadResult = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(upload_tar.files_written, 2);

    let targz_bytes = make_targz(&[("from_gz/c.txt", b"gamma\n")]);
    let resp = daemon
        .client
        .put_bytes(
            &format!("/v1/sandboxes/{sb_id}/files?path=/workspace"),
            "application/gzip",
            targz_bytes,
        )
        .await;
    assert_eq!(resp.status, StatusCode::OK);
    let upload_gz: UploadResult = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(upload_gz.files_written, 1);

    // Unsupported Content-Type -> 415
    let resp = daemon
        .client
        .put_bytes(
            &format!("/v1/sandboxes/{sb_id}/files?path=/workspace/bad.txt"),
            "text/plain",
            b"nope".to_vec(),
        )
        .await;
    assert_eq!(resp.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);

    // Download raw file
    let resp = daemon
        .client
        .get(&format!(
            "/v1/sandboxes/{sb_id}/files?path=/workspace/raw.txt&format=raw"
        ))
        .await;
    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(
        resp.content_type.as_deref(),
        Some("application/octet-stream")
    );
    assert_eq!(resp.body.as_ref(), raw_content);

    // Download tar.gz and inspect canonical blackwall-unpacker archive
    let resp = daemon
        .client
        .get(&format!(
            "/v1/sandboxes/{sb_id}/files?path=/workspace&format=tar.gz"
        ))
        .await;
    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(resp.content_type.as_deref(), Some("application/gzip"));

    let mut archive = tar::Archive::new(GzDecoder::new(Cursor::new(resp.body.as_ref())));
    let mut unpacked_files = std::collections::BTreeMap::new();
    for entry in archive.entries().unwrap() {
        let mut entry = entry.unwrap();
        assert_eq!(entry.header().uid().unwrap(), 0);
        assert_eq!(entry.header().gid().unwrap(), 0);
        assert_eq!(entry.header().mtime().unwrap(), 0);
        let p = entry.path().unwrap().to_string_lossy().into_owned();
        if entry.header().entry_type().is_file() {
            let mut content = String::new();
            entry.read_to_string(&mut content).unwrap();
            unpacked_files.insert(p, content);
        }
    }
    assert_eq!(
        unpacked_files.get("raw.txt").map(String::as_str),
        Some("raw file uploaded over UDS\n")
    );
    assert_eq!(
        unpacked_files.get("from_tar/a.txt").map(String::as_str),
        Some("alpha\n")
    );
    assert_eq!(
        unpacked_files.get("from_tar/b.txt").map(String::as_str),
        Some("beta\n")
    );
    assert_eq!(
        unpacked_files.get("from_gz/c.txt").map(String::as_str),
        Some("gamma\n")
    );

    // 5a. POST /v1/sandboxes/{id}/exec (sync JSON)
    let resp = daemon
        .client
        .post_json(
            &format!("/v1/sandboxes/{sb_id}/exec"),
            &json!({
                "cmd": ["/bin/sh", "-c", "echo \"$GREETING|$EPHEM_KEY\"; cat raw.txt; echo err_msg >&2"],
                "cwd": "/workspace"
            }),
        )
        .await;
    assert_eq!(resp.status, StatusCode::OK);
    let exec_res: ExecResult = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(exec_res.exit_code, 0);
    assert!(!exec_res.timed_out);
    assert!(exec_res.stdout.contains("hello-daemon|ek_bw_"));
    assert!(!exec_res.stdout.contains("ek_REAL_EPHEMERAL_VALUE"));
    assert!(exec_res.stdout.contains("raw file uploaded over UDS"));
    assert!(exec_res.stderr.contains("err_msg"));

    // 5b. POST /v1/sandboxes/{id}/exec?stream=true (NDJSON)
    let resp = daemon
        .client
        .post_json(
            &format!("/v1/sandboxes/{sb_id}/exec?stream=true"),
            &json!({
                "cmd": ["/bin/sh", "-c", "echo stream_out_1; echo stream_err_1 >&2; echo stream_out_2"]
            }),
        )
        .await;
    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(resp.content_type.as_deref(), Some("application/x-ndjson"));
    let body_text = std::str::from_utf8(&resp.body).unwrap();
    let frames: Vec<serde_json::Value> = body_text
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| serde_json::from_str(l).expect("each NDJSON line must be valid JSON"))
        .collect();
    let stdout_all: String = frames
        .iter()
        .filter(|v| v["type"] == "stdout")
        .filter_map(|v| v["data"].as_str())
        .collect();
    let stderr_all: String = frames
        .iter()
        .filter(|v| v["type"] == "stderr")
        .filter_map(|v| v["data"].as_str())
        .collect();
    assert!(stdout_all.contains("stream_out_1"));
    assert!(stdout_all.contains("stream_out_2"));
    assert!(stderr_all.contains("stream_err_1"));
    let exit_frame = frames
        .iter()
        .find(|v| v["type"] == "exit")
        .expect("NDJSON exec stream must terminate with exit frame");
    assert_eq!(exit_frame["exit_code"], 0);
    assert_eq!(exit_frame["timed_out"], false);

    // 5c. POST /v1/sandboxes/{id}/exec with background: true -> 202 Accepted
    //     + GET .../processes, GET .../logs, POST .../signal, DELETE .../processes/{proc_id}
    let resp = daemon
        .client
        .post_json(
            &format!("/v1/sandboxes/{sb_id}/exec"),
            &json!({
                "cmd": ["/bin/sh", "-c", "echo bg_daemon_started; sleep 30"],
                "background": true
            }),
        )
        .await;
    assert_eq!(resp.status, StatusCode::ACCEPTED);
    let bg_json: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
    let proc_id = bg_json["proc_id"].as_str().unwrap().to_string();
    assert!(!proc_id.is_empty());
    assert!(bg_json["pid"].as_u64().unwrap() > 0);

    tokio::time::sleep(Duration::from_millis(80)).await;

    let resp = daemon
        .client
        .get(&format!("/v1/sandboxes/{sb_id}/processes"))
        .await;
    assert_eq!(resp.status, StatusCode::OK);
    let procs: Vec<ProcessInfo> = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(procs.len(), 1);
    assert_eq!(procs[0].proc_id, proc_id);

    let resp = daemon
        .client
        .get(&format!(
            "/v1/sandboxes/{sb_id}/processes/{proc_id}/logs?tail=20&follow=false"
        ))
        .await;
    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(resp.content_type.as_deref(), Some("application/x-ndjson"));
    let log_text = std::str::from_utf8(&resp.body).unwrap();
    let log_frames: Vec<serde_json::Value> = log_text
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let combined_logs: String = log_frames
        .iter()
        .filter(|v| v["type"] == "stdout")
        .filter_map(|v| v["data"].as_str())
        .collect();
    assert!(combined_logs.contains("bg_daemon_started"));

    let resp = daemon
        .client
        .post_json(
            &format!("/v1/sandboxes/{sb_id}/processes/{proc_id}/signal"),
            &json!({ "signal": "SIGTERM" }),
        )
        .await;
    assert_eq!(resp.status, StatusCode::NO_CONTENT);

    let resp = daemon
        .client
        .delete(&format!("/v1/sandboxes/{sb_id}/processes/{proc_id}"))
        .await;
    assert_eq!(resp.status, StatusCode::NO_CONTENT);

    let resp = daemon
        .client
        .get(&format!("/v1/sandboxes/{sb_id}/processes"))
        .await;
    assert_eq!(resp.status, StatusCode::OK);
    let procs_after: Vec<ProcessInfo> = serde_json::from_slice(&resp.body).unwrap();
    assert!(procs_after.is_empty());

    // 6. GET /v1/sandboxes/{id}/pty real WebSocket handshake over Unix socket!
    let ws_stream = UnixStream::connect(&daemon.socket_path)
        .await
        .expect("failed to open UDS for WebSocket");
    let ws_url = format!("ws://localhost/v1/sandboxes/{sb_id}/pty?cols=120&rows=40&cmd=/bin/sh");
    let (mut ws, ws_resp) = tokio_tungstenite::client_async(ws_url, ws_stream)
        .await
        .expect("WebSocket handshake over UDS failed");
    assert_eq!(ws_resp.status(), StatusCode::SWITCHING_PROTOCOLS);

    // Send resize JSON text frame and stdin binary frame.
    ws.send(WsMessage::Text(
        json!({ "type": "resize", "cols": 100, "rows": 32 })
            .to_string()
            .into(),
    ))
    .await
    .expect("failed to send resize frame");
    ws.send(WsMessage::Binary(
        b"echo WS_PTY_MAGIC_TOKEN\nexit 0\n".to_vec().into(),
    ))
    .await
    .expect("failed to send PTY stdin frame");

    let mut pty_stdout = Vec::new();
    let mut exit_code: Option<i64> = None;

    let read_result = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(msg) = ws.next().await {
            match msg.expect("WS receive error") {
                WsMessage::Binary(bytes) => pty_stdout.extend_from_slice(&bytes),
                WsMessage::Text(text) => {
                    let val: serde_json::Value =
                        serde_json::from_str(text.as_str()).expect("PTY text frame must be JSON");
                    if val["type"] == "exit" {
                        exit_code = val["code"].as_i64();
                        break;
                    }
                }
                WsMessage::Close(_) => break,
                _ => {}
            }
        }
    })
    .await;
    assert!(read_result.is_ok(), "PTY WebSocket timed out waiting for exit");
    assert!(
        String::from_utf8_lossy(&pty_stdout).contains("WS_PTY_MAGIC_TOKEN"),
        "PTY binary frames did not contain expected token; got: {:?}",
        String::from_utf8_lossy(&pty_stdout)
    );
    assert_eq!(exit_code, Some(0));

    // 7. DELETE /v1/sandboxes/{id} -> 204 No Content, subsequent GET -> 404 Not Found.
    // Also verify unknown sandbox PTY returns 404 before WebSocket upgrade.
    let bad_pty_stream = UnixStream::connect(&daemon.socket_path)
        .await
        .expect("failed to connect to daemon UDS");
    let bad_pty_err = tokio_tungstenite::client_async(
        "ws://localhost/v1/sandboxes/bw-nonexistent/pty?cols=80&rows=24",
        bad_pty_stream,
    )
    .await
    .expect_err("unknown sandbox PTY must reject upgrade");
    match bad_pty_err {
        tokio_tungstenite::tungstenite::Error::Http(resp) => {
            assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        }
        other => panic!("expected HTTP 404 error for nonexistent PTY sandbox, got {other:?}"),
    }

    let resp = daemon
        .client
        .delete(&format!("/v1/sandboxes/{sb_id}"))
        .await;
    assert_eq!(resp.status, StatusCode::NO_CONTENT);

    let resp = daemon.client.get(&format!("/v1/sandboxes/{sb_id}")).await;
    assert_eq!(resp.status, StatusCode::NOT_FOUND);
    let err_body: ApiErrorBody = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(err_body.code, "sandbox_not_found");

    // 8. Verify idle-timeout automatic reaping reflects as 404 over the HTTP API.
    let short_idle_resp = daemon
        .client
        .post_json(
            "/v1/sandboxes",
            &json!({
                "compute": {
                    "idle_timeout_sec": 1,
                    "max_wall_time_sec": 10
                }
            }),
        )
        .await;
    assert_eq!(short_idle_resp.status, StatusCode::CREATED);
    let idle_sb: SandboxSummary = serde_json::from_slice(&short_idle_resp.body).unwrap();

    // Sleep past idle_timeout_sec = 1 without touching the sandbox so the reaper destroys it.
    tokio::time::sleep(Duration::from_millis(1350)).await;

    let resp = daemon
        .client
        .get(&format!("/v1/sandboxes/{}", idle_sb.id))
        .await;
    assert_eq!(
        resp.status,
        StatusCode::NOT_FOUND,
        "idle-reaped sandbox must return 404"
    );

    // 9. Graceful shutdown cleans up socket file.
    daemon.shutdown().await;
}

#[tokio::test]
async fn daemon_error_mapping_and_stale_socket_cleanup() {
    let tmp = tempfile::tempdir().unwrap();
    let socket_path = tmp.path().join("blackwall.sock");

    // Create a stale Unix socket file first and confirm BoundDaemon replaces it cleanly.
    {
        let _stale = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();
    }
    assert!(socket_path.exists());

    let sink = Arc::new(MemoryAuditSink::new());
    let cfg = CoreConfig::for_testing(tmp.path(), sink);
    let manager = Arc::new(
        SandboxManager::with_backend(
            cfg,
            Box::new(MockSessionVmmBackend::new()),
            Arc::new(StaticDnsResolver::new()),
        )
        .unwrap(),
    );

    let bound = BoundDaemon::bind(Arc::clone(&manager), &socket_path)
        .expect("should cleanly remove stale socket and bind");
    let mode = fs::metadata(&socket_path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);

    let (tx, rx) = oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        bound
            .serve(async move {
                let _ = rx.await;
            })
            .await
    });

    let client = UdsHttpClient::new(&socket_path);

    // Invalid JSON returns structured JSON error (400).
    let resp = client
        .request(
            Method::POST,
            "/v1/sandboxes",
            Some("application/json"),
            b"{not valid json".to_vec(),
        )
        .await;
    assert_eq!(resp.status, StatusCode::BAD_REQUEST);
    let err: ApiErrorBody = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(err.code, "invalid_json");

    // Policy error (network rules while mode=loopback) returns 422 JSON error.
    let resp = client
        .post_json(
            "/v1/sandboxes",
            &json!({
                "network": {
                    "mode": "loopback",
                    "http": [{
                        "host": "example.com",
                        "methods": ["GET"],
                        "path_prefixes": ["/"]
                    }]
                }
            }),
        )
        .await;
    assert_eq!(resp.status, StatusCode::UNPROCESSABLE_ENTITY);
    let err: ApiErrorBody = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(err.code, "policy_error");

    // Create a sandbox and leave it running, then trigger shutdown -> verify destroy_all runs.
    let resp = client.post_json("/v1/sandboxes", &json!({})).await;
    assert_eq!(resp.status, StatusCode::CREATED);
    assert_eq!(manager.list_sandboxes().len(), 1);

    let _ = tx.send(());
    server.await.unwrap().unwrap();

    assert!(
        manager.list_sandboxes().is_empty(),
        "graceful shutdown must call manager.destroy_all()"
    );
    assert!(
        !socket_path.exists(),
        "graceful shutdown must remove Unix socket"
    );
}

async fn tcp_http_request(
    addr: std::net::SocketAddr,
    method: Method,
    path_and_query: &str,
    body: impl Into<Bytes>,
) -> HttpReply {
    tcp_http_request_with_auth(addr, method, path_and_query, None, body).await
}

async fn tcp_http_request_with_auth(
    addr: std::net::SocketAddr,
    method: Method,
    path_and_query: &str,
    bearer_token: Option<&str>,
    body: impl Into<Bytes>,
) -> HttpReply {
    let stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("failed to connect to loopback HTTP daemon");
    let io = TokioIo::new(stream);
    let (mut sender, conn) = http1::handshake(io)
        .await
        .expect("HTTP/1.1 TCP handshake failed");
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let mut builder = Request::builder()
        .method(method)
        .uri(path_and_query)
        .header(HOST, addr.to_string());
    if let Some(tok) = bearer_token {
        builder = builder.header(hyper::header::AUTHORIZATION, format!("Bearer {tok}"));
    }
    let req = builder
        .body(Full::new(body.into()))
        .expect("failed to build TCP HTTP request");
    let resp = sender
        .send_request(req)
        .await
        .expect("TCP HTTP request failed");
    let status = resp.status();
    let content_type = resp
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(ToOwned::to_owned);
    let collected = resp
        .into_body()
        .collect()
        .await
        .expect("failed to collect TCP HTTP response");
    HttpReply {
        status,
        content_type,
        body: collected.to_bytes(),
    }
}

#[tokio::test]
async fn ingress_tunnel_http_proxy_and_loopback_static_ui_e2e() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let tmp = tempfile::tempdir().unwrap();
    let ui_dir = tmp.path().join("ui-dist");
    fs::create_dir_all(ui_dir.join("assets")).unwrap();
    fs::write(
        ui_dir.join("index.html"),
        "<!doctype html><html><body>BLACKWALL_UI_INDEX</body></html>",
    )
    .unwrap();
    fs::write(
        ui_dir.join("assets/app.js"),
        "console.log('blackwall-ui-bundle');",
    )
    .unwrap();
    // Write a secret file OUTSIDE ui_dir to verify path traversal rejection.
    fs::write(tmp.path().join("secret.txt"), "TOP_SECRET_OUTSIDE_UI").unwrap();

    // Start a mock "guest" HTTP/1.1 server on 127.0.0.1:0 (reachable from MockSessionVmmBackend).
    let guest_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let guest_port = guest_listener.local_addr().unwrap().port();
    let guest_server_task = tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = guest_listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let Ok(n) = sock.read(&mut buf).await else {
                    return;
                };
                if n == 0 {
                    return;
                }
                let raw = String::from_utf8_lossy(&buf[..n]);
                let first_line = raw.lines().next().unwrap_or("");
                let body_part = raw.split("\r\n\r\n").nth(1).unwrap_or("");
                let resp_body = format!("GUEST_OK|line={first_line}|body={body_part}");
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-Guest-Echo: yes\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    resp_body.len(),
                    resp_body
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.shutdown().await;
            });
        }
    });

    // Pick a second unused port that is NOT allowlisted.
    let denied_port = if guest_port == 65000 { 65001 } else { 65000 };

    let sink = Arc::new(MemoryAuditSink::new());
    let cfg = CoreConfig::for_testing(tmp.path(), sink.clone());
    let manager = Arc::new(
        SandboxManager::with_backend(
            cfg,
            Box::new(MockSessionVmmBackend::new()),
            Arc::new(StaticDnsResolver::new()),
        )
        .unwrap(),
    );

    let socket_path = tmp.path().join("blackwall.sock");

    // Non-loopback bind MUST fail closed when allow_non_loopback == false.
    let bad_bind = BoundDaemon::bind(Arc::clone(&manager), &socket_path)
        .unwrap()
        .with_http(HttpOptions {
            listen_addr: "0.0.0.0:0".parse().unwrap(),
            preview_listen: None,
            allow_non_loopback: false,
            ui_dir: Some(ui_dir.clone()),
            http_token: None,
        });
    assert!(matches!(
        bad_bind,
        Err(DaemonError::NonLoopbackHttpDisallowed(_))
    ));

    // Bind UDS + loopback HTTP + isolated preview origin + --ui-dir.
    let bound = BoundDaemon::bind(Arc::clone(&manager), &socket_path)
        .unwrap()
        .with_http(HttpOptions {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            preview_listen: None,
            allow_non_loopback: false,
            ui_dir: Some(ui_dir.clone()),
            http_token: None,
        })
        .expect("loopback HTTP + UI bind should succeed");
    let http_addr = bound.http_addr().expect("http_addr must be set");
    let preview_addr = bound.preview_addr().expect("preview_addr must be set");
    let http_token = bound
        .http_token()
        .expect("http_token must be generated")
        .to_string();

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let server_task = tokio::spawn(async move {
        bound
            .serve(async move {
                let _ = shutdown_rx.await;
            })
            .await
    });

    let uds = UdsHttpClient::new(&socket_path);

    // 1. Create sandbox allowing ONLY `guest_port`.
    let resp = uds
        .post_json(
            "/v1/sandboxes",
            &json!({
                "ingress": {
                    "allow_ports": [guest_port]
                }
            }),
        )
        .await;
    assert_eq!(resp.status, StatusCode::CREATED);
    let created: SandboxSummary = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(created.ingress_allow_ports, vec![guest_port]);
    let sb_id = created.id.clone();

    // 2. Hit guest server through raw WebSocket TCP tunnel over UDS.
    let ws_stream = UnixStream::connect(&socket_path).await.unwrap();
    let ws_url = format!("ws://localhost/v1/sandboxes/{sb_id}/tunnel/{guest_port}");
    let (mut ws, ws_resp) = tokio_tungstenite::client_async(ws_url, ws_stream)
        .await
        .expect("TCP tunnel WebSocket handshake should succeed");
    assert_eq!(ws_resp.status(), StatusCode::SWITCHING_PROTOCOLS);

    ws.send(WsMessage::Binary(
        b"GET /ws-tunnel HTTP/1.1\r\nHost: localhost\r\n\r\n"
            .to_vec()
            .into(),
    ))
    .await
    .unwrap();

    let mut tunnel_reply = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(msg) = ws.next().await {
            match msg {
                Ok(WsMessage::Binary(data)) => tunnel_reply.extend_from_slice(&data),
                Ok(WsMessage::Close(_)) | Err(_) => break,
                _ => {}
            }
        }
    })
    .await;
    let tunnel_text = String::from_utf8_lossy(&tunnel_reply);
    assert!(
        tunnel_text.contains("GUEST_OK|line=GET /ws-tunnel HTTP/1.1"),
        "expected guest HTTP reply over WS TCP tunnel, got: {tunnel_text:?}"
    );

    // 3. Hit guest server through direct HTTP reverse proxy over UDS (GET + query string).
    let resp = uds
        .get(&format!(
            "/v1/sandboxes/{sb_id}/proxy/{guest_port}/hello?who=blackwall"
        ))
        .await;
    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(resp.content_type.as_deref(), Some("text/plain"));
    let proxy_text = String::from_utf8_lossy(&resp.body);
    assert!(
        proxy_text.contains("GUEST_OK|line=GET /hello?who=blackwall HTTP/1.1"),
        "unexpected proxy response: {proxy_text:?}"
    );

    // 3b. Hit direct HTTP reverse proxy root path and POST body on the isolated preview origin!
    //     Control-plane HTTP listener rejects /proxy with 403 preview_origin_required.
    let cp_proxy = tcp_http_request_with_auth(
        http_addr,
        Method::POST,
        &format!("/v1/sandboxes/{sb_id}/proxy/{guest_port}"),
        Some(&http_token),
        "payload=123",
    )
    .await;
    assert_eq!(cp_proxy.status, StatusCode::FORBIDDEN);
    let cp_proxy_err: ApiErrorBody = serde_json::from_slice(&cp_proxy.body).unwrap();
    assert_eq!(cp_proxy_err.code, "preview_origin_required");

    let resp = tcp_http_request(
        preview_addr,
        Method::POST,
        &format!("/v1/sandboxes/{sb_id}/proxy/{guest_port}"),
        "payload=123",
    )
    .await;
    assert_eq!(resp.status, StatusCode::OK);
    let post_text = String::from_utf8_lossy(&resp.body);
    assert!(
        post_text.contains("GUEST_OK|line=POST / HTTP/1.1|body=payload=123"),
        "unexpected POST proxy response: {post_text:?}"
    );

    // 4. Verify non-allowlisted port returns 403 Forbidden on BOTH proxy and tunnel WS!
    let denied_proxy = uds
        .get(&format!("/v1/sandboxes/{sb_id}/proxy/{denied_port}/hello"))
        .await;
    assert_eq!(denied_proxy.status, StatusCode::FORBIDDEN);
    let err_body: ApiErrorBody = serde_json::from_slice(&denied_proxy.body).unwrap();
    assert_eq!(err_body.code, "ingress_port_denied");

    let denied_ws_stream = UnixStream::connect(&socket_path).await.unwrap();
    let denied_ws_err = tokio_tungstenite::client_async(
        format!("ws://localhost/v1/sandboxes/{sb_id}/tunnel/{denied_port}"),
        denied_ws_stream,
    )
    .await
    .expect_err("non-allowlisted port tunnel must reject upgrade with 403");
    match denied_ws_err {
        tokio_tungstenite::tungstenite::Error::Http(resp) => {
            assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        }
        other => panic!("expected HTTP 403 error for denied tunnel port, got {other:?}"),
    }

    // 5. Verify SandboxDetail exposes ingress_allow_ports and stats.ingress_connections_count.
    let detail_resp = tcp_http_request_with_auth(
        http_addr,
        Method::GET,
        &format!("/v1/sandboxes/{sb_id}"),
        Some(&http_token),
        Bytes::new(),
    )
    .await;
    assert_eq!(detail_resp.status, StatusCode::OK);
    let detail: SandboxDetail = serde_json::from_slice(&detail_resp.body).unwrap();
    assert_eq!(detail.ingress_allow_ports, vec![guest_port]);
    assert!(detail.stats.ingress_connections_count >= 3);

    // 6. Verify static UI hosting + SPA fallback + strict `..` traversal rejection on loopback HTTP.
    let root_ui = tcp_http_request(http_addr, Method::GET, "/", Bytes::new()).await;
    assert_eq!(root_ui.status, StatusCode::OK);
    assert_eq!(
        root_ui.content_type.as_deref(),
        Some("text/html; charset=utf-8")
    );
    assert!(String::from_utf8_lossy(&root_ui.body).contains("BLACKWALL_UI_INDEX"));

    let js_asset = tcp_http_request(http_addr, Method::GET, "/assets/app.js", Bytes::new()).await;
    assert_eq!(js_asset.status, StatusCode::OK);
    assert_eq!(
        js_asset.content_type.as_deref(),
        Some("application/javascript; charset=utf-8")
    );
    assert!(String::from_utf8_lossy(&js_asset.body).contains("blackwall-ui-bundle"));

    let spa_route = tcp_http_request(
        http_addr,
        Method::GET,
        "/sandboxes/bw-some-view",
        Bytes::new(),
    )
    .await;
    assert_eq!(spa_route.status, StatusCode::OK);
    assert_eq!(
        spa_route.content_type.as_deref(),
        Some("text/html; charset=utf-8")
    );
    assert!(String::from_utf8_lossy(&spa_route.body).contains("BLACKWALL_UI_INDEX"));

    // Unknown /v1/* path must NOT SPA-fallback to index.html (404 when authenticated).
    let unknown_api = tcp_http_request_with_auth(
        http_addr,
        Method::GET,
        "/v1/does-not-exist",
        Some(&http_token),
        Bytes::new(),
    )
    .await;
    assert_eq!(unknown_api.status, StatusCode::NOT_FOUND);

    // Traversal attempts (raw `..` and percent-encoded `%2e%2e`) MUST be rejected with 403!
    let trav_raw =
        tcp_http_request(http_addr, Method::GET, "/../secret.txt", Bytes::new()).await;
    assert_eq!(trav_raw.status, StatusCode::FORBIDDEN);
    assert!(!String::from_utf8_lossy(&trav_raw.body).contains("TOP_SECRET_OUTSIDE_UI"));

    let trav_enc = tcp_http_request(
        http_addr,
        Method::GET,
        "/%2e%2e/secret.txt",
        Bytes::new(),
    )
    .await;
    assert_eq!(trav_enc.status, StatusCode::FORBIDDEN);
    assert!(!String::from_utf8_lossy(&trav_enc.body).contains("TOP_SECRET_OUTSIDE_UI"));

    // 7. Verify audit events recorded both allowed and denied ingress attempts.
    let events = sink.snapshot();
    assert!(events.iter().any(|e| matches!(
        &e.kind,
        AuditEventKind::IngressTunnel {
            guest_port: p,
            allowed: false,
            ..
        } if *p == denied_port
    )));
    assert!(events.iter().any(|e| matches!(
        &e.kind,
        AuditEventKind::IngressTunnel {
            guest_port: p,
            allowed: true,
            ..
        } if *p == guest_port
    )));

    guest_server_task.abort();
    let _ = shutdown_tx.send(());
    server_task.await.unwrap().unwrap();
}

/// Open a streaming HTTP/1.1 GET request over UDS and return `(status, content_type, cache_control, body)`.
async fn open_uds_stream(
    socket_path: &Path,
    path_and_query: &str,
) -> (
    StatusCode,
    Option<String>,
    Option<String>,
    hyper::body::Incoming,
) {
    let stream = UnixStream::connect(socket_path)
        .await
        .expect("failed to connect to daemon UDS for streaming");
    let io = TokioIo::new(stream);
    let (mut sender, conn) = http1::handshake(io)
        .await
        .expect("HTTP/1.1 UDS handshake failed");
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let req = Request::builder()
        .method(Method::GET)
        .uri(path_and_query)
        .header(HOST, "localhost")
        .body(Full::new(Bytes::new()))
        .expect("failed to build streaming GET request");
    let resp = sender
        .send_request(req)
        .await
        .expect("streaming GET over UDS failed");
    let status = resp.status();
    let content_type = resp
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(ToOwned::to_owned);
    let cache_control = resp
        .headers()
        .get(hyper::header::CACHE_CONTROL)
        .and_then(|v| v.to_str().ok())
        .map(ToOwned::to_owned);
    (status, content_type, cache_control, resp.into_body())
}

/// Read NDJSON lines from a streaming hyper body until `predicate` holds (or timeout).
async fn read_ndjson_until<F>(
    body: &mut hyper::body::Incoming,
    buf: &mut String,
    collected: &mut Vec<AuditEvent>,
    predicate: F,
) where
    F: Fn(&[AuditEvent]) -> bool,
{
    tokio::time::timeout(Duration::from_secs(5), async {
        while !predicate(collected) {
            let frame = body
                .frame()
                .await
                .expect("NDJSON stream ended before expected event arrived")
                .expect("NDJSON body frame error");
            if let Ok(data) = frame.into_data() {
                buf.push_str(&String::from_utf8_lossy(&data));
                while let Some(pos) = buf.find('\n') {
                    let line: String = buf.drain(..=pos).collect();
                    let trimmed = line.trim();
                    if !trimmed.is_empty() {
                        let ev: AuditEvent = serde_json::from_str(trimmed)
                            .expect("NDJSON audit line must deserialize into AuditEvent");
                        collected.push(ev);
                    }
                }
            }
        }
    })
    .await
    .expect("timed out waiting for expected NDJSON audit event");
}

#[tokio::test]
async fn audit_endpoints_return_recent_json_and_stream_live_ndjson() {
    let tmp = tempfile::tempdir().unwrap();
    let sink = Arc::new(MemoryAuditSink::new());
    let cfg = CoreConfig::for_testing(tmp.path(), sink.clone());
    let manager = Arc::new(
        SandboxManager::with_backend(
            cfg,
            Box::new(MockSessionVmmBackend::new()),
            Arc::new(StaticDnsResolver::new()),
        )
        .unwrap(),
    );

    let socket_path = tmp.path().join("blackwall.sock");
    let bound = BoundDaemon::bind(Arc::clone(&manager), &socket_path).unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let server_task = tokio::spawn(async move {
        bound
            .serve(async move {
                let _ = shutdown_rx.await;
            })
            .await
    });

    let client = UdsHttpClient::new(&socket_path);

    // 1. Create two sandboxes and run commands on both.
    let resp_a = client.post_json("/v1/sandboxes", &json!({})).await;
    assert_eq!(resp_a.status, StatusCode::CREATED);
    let sb_a: SandboxSummary = serde_json::from_slice(&resp_a.body).unwrap();

    let resp_b = client.post_json("/v1/sandboxes", &json!({})).await;
    assert_eq!(resp_b.status, StatusCode::CREATED);
    let sb_b: SandboxSummary = serde_json::from_slice(&resp_b.body).unwrap();

    let exec_a = client
        .post_json(
            &format!("/v1/sandboxes/{}/exec", sb_a.id),
            &json!({ "cmd": ["/bin/sh", "-c", "echo audit_a_1"] }),
        )
        .await;
    assert_eq!(exec_a.status, StatusCode::OK);

    // Record a DnsQuery event through manager.audit_sink() (verifying AuditHub + downstream).
    manager.audit_sink().record(AuditEvent::now(
        &sb_a.id,
        AuditEventKind::DnsQuery {
            fqdn: "api.github.com".into(),
            allowed: true,
            synthetic_ip: Some("198.18.1.2".into()),
        },
    ));

    // 2. GET /v1/audit -> JSON array containing events from BOTH sandboxes.
    let all_resp = client.get("/v1/audit").await;
    assert_eq!(all_resp.status, StatusCode::OK);
    let all_events: Vec<AuditEvent> = serde_json::from_slice(&all_resp.body).unwrap();
    assert!(all_events.iter().any(|e| e.sandbox_id == sb_a.id));
    assert!(all_events.iter().any(|e| e.sandbox_id == sb_b.id));
    assert!(all_events.iter().any(|e| matches!(
        &e.kind,
        AuditEventKind::DnsQuery { fqdn, allowed: true, .. } if fqdn == "api.github.com"
    )));

    // 3. GET /v1/audit?sandbox_id=<sb_a>&limit=2 -> filtered & capped to 2 recent events.
    let filtered_resp = client
        .get(&format!("/v1/audit?sandbox_id={}&limit=2", sb_a.id))
        .await;
    assert_eq!(filtered_resp.status, StatusCode::OK);
    let filtered_events: Vec<AuditEvent> = serde_json::from_slice(&filtered_resp.body).unwrap();
    assert_eq!(filtered_events.len(), 2);
    assert!(filtered_events.iter().all(|e| e.sandbox_id == sb_a.id));

    // 4. GET /v1/sandboxes/{id}/audit -> JSON array scoped strictly to sb_a.
    let sb_a_resp = client
        .get(&format!("/v1/sandboxes/{}/audit", sb_a.id))
        .await;
    assert_eq!(sb_a_resp.status, StatusCode::OK);
    let sb_a_events: Vec<AuditEvent> = serde_json::from_slice(&sb_a_resp.body).unwrap();
    assert!(!sb_a_events.is_empty());
    assert!(sb_a_events.iter().all(|e| e.sandbox_id == sb_a.id));
    assert!(sb_a_events
        .iter()
        .any(|e| matches!(&e.kind, AuditEventKind::ExecCommand { .. })));

    // 5. Open live NDJSON stream on BOTH `/v1/sandboxes/{sb_a}/audit?follow=true`
    //    and `/v1/audit?follow=true`.
    let (status_sb, ct_sb, cc_sb, mut body_sb) =
        open_uds_stream(&socket_path, &format!("/v1/sandboxes/{}/audit?follow=true", sb_a.id))
            .await;
    assert_eq!(status_sb, StatusCode::OK);
    assert_eq!(ct_sb.as_deref(), Some("application/x-ndjson"));
    assert_eq!(cc_sb.as_deref(), Some("no-store"));

    let (status_all, ct_all, cc_all, mut body_all) =
        open_uds_stream(&socket_path, "/v1/audit?follow=true").await;
    assert_eq!(status_all, StatusCode::OK);
    assert_eq!(ct_all.as_deref(), Some("application/x-ndjson"));
    assert_eq!(cc_all.as_deref(), Some("no-store"));

    let mut sb_buf = String::new();
    let mut sb_streamed = Vec::new();
    let mut all_buf = String::new();
    let mut all_streamed = Vec::new();

    // First verify initial recent events arrive on sb_a's stream before triggering new live events.
    read_ndjson_until(&mut body_sb, &mut sb_buf, &mut sb_streamed, |evs| {
        evs.iter().any(|e| matches!(
            &e.kind,
            AuditEventKind::DnsQuery { fqdn, allowed: true, .. } if fqdn == "api.github.com"
        ))
    })
    .await;

    // Trigger live events while BOTH streams are open:
    // - Exec on sb_b (must appear on `/v1/audit?follow=true`, MUST NOT appear on `/v1/sandboxes/{sb_a}/audit?follow=true`)
    let exec_b = client
        .post_json(
            &format!("/v1/sandboxes/{}/exec", sb_b.id),
            &json!({ "cmd": ["/bin/sh", "-c", "echo live_b_event"] }),
        )
        .await;
    assert_eq!(exec_b.status, StatusCode::OK);

    // - Blocked DNS query (`google.com`) + live exec on sb_a
    manager.audit_sink().record(AuditEvent::now(
        &sb_a.id,
        AuditEventKind::DnsQuery {
            fqdn: "google.com".into(),
            allowed: false,
            synthetic_ip: None,
        },
    ));
    let exec_a2 = client
        .post_json(
            &format!("/v1/sandboxes/{}/exec", sb_a.id),
            &json!({ "cmd": ["/bin/sh", "-c", "echo live_a_event"] }),
        )
        .await;
    assert_eq!(exec_a2.status, StatusCode::OK);

    // Wait for sb_a's live exec + blocked google.com DNS query on `/v1/sandboxes/{sb_a}/audit?follow=true`.
    read_ndjson_until(&mut body_sb, &mut sb_buf, &mut sb_streamed, |evs| {
        evs.iter().any(|e| matches!(
            &e.kind,
            AuditEventKind::ExecCommand { cmd, .. } if cmd.iter().any(|c| c.contains("live_a_event"))
        ))
    })
    .await;

    assert!(sb_streamed.iter().all(|e| e.sandbox_id == sb_a.id));
    assert!(sb_streamed.iter().any(|e| matches!(
        &e.kind,
        AuditEventKind::DnsQuery { fqdn, allowed: false, synthetic_ip: None } if fqdn == "google.com"
    )));
    // Verify the pre-existing `api.github.com` event was NOT duplicated across recent -> live handoff.
    let github_dns_count = sb_streamed
        .iter()
        .filter(|e| matches!(
            &e.kind,
            AuditEventKind::DnsQuery { fqdn, .. } if fqdn == "api.github.com"
        ))
        .count();
    assert_eq!(github_dns_count, 1, "recent event must not be duplicated in follow stream");

    // Wait for BOTH sb_b's and sb_a's live events on `/v1/audit?follow=true`.
    read_ndjson_until(&mut body_all, &mut all_buf, &mut all_streamed, |evs| {
        evs.iter().any(|e| {
            e.sandbox_id == sb_b.id
                && matches!(
                    &e.kind,
                    AuditEventKind::ExecCommand { cmd, .. } if cmd.iter().any(|c| c.contains("live_b_event"))
                )
        }) && evs.iter().any(|e| {
            e.sandbox_id == sb_a.id
                && matches!(
                    &e.kind,
                    AuditEventKind::ExecCommand { cmd, .. } if cmd.iter().any(|c| c.contains("live_a_event"))
                )
        })
    })
    .await;

    // Downstream sink also received everything (including both DnsQuery events).
    let downstream_events = sink.snapshot();
    assert!(downstream_events.iter().any(|e| matches!(
        &e.kind,
        AuditEventKind::DnsQuery { fqdn, allowed: false, synthetic_ip: None } if fqdn == "google.com"
    )));

    drop(body_sb);
    drop(body_all);
    let _ = shutdown_tx.send(());
    server_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn new_api_routes_fs_keepalive_ports_profiles_and_images_e2e() {
    let tmp = tempfile::tempdir().unwrap();
    let profiles_dir = tmp.path().join("profiles");
    let images_dir = tmp.path().join("images");
    fs::create_dir_all(&profiles_dir).unwrap();
    fs::create_dir_all(&images_dir).unwrap();

    let sink = Arc::new(MemoryAuditSink::new());
    let cfg = CoreConfig::for_testing(tmp.path(), sink.clone());
    let manager = Arc::new(
        SandboxManager::with_backend(
            cfg,
            Box::new(MockSessionVmmBackend::new()),
            Arc::new(StaticDnsResolver::new()),
        )
        .unwrap(),
    );

    let socket_path = tmp.path().join("blackwall.sock");
    let bound = BoundDaemon::bind(Arc::clone(&manager), &socket_path).unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let server_task = tokio::spawn(async move {
        bound
            .serve(async move {
                let _ = shutdown_rx.await;
            })
            .await
    });

    let client = UdsHttpClient::new(&socket_path);

    // -----------------------------------------------------------------------
    // 1. POST /v1/profiles & DELETE /v1/profiles/{name}
    // -----------------------------------------------------------------------
    // Reject reserved name "base" and invalid names with 400
    for bad_name in ["base", "", "-bad", "Upper", "has space", "../escape"] {
        let resp = client
            .post_json(
                "/v1/profiles",
                &json!({
                    "name": bad_name,
                    "toml": "version = 1\n"
                }),
            )
            .await;
        assert_eq!(
            resp.status,
            StatusCode::BAD_REQUEST,
            "expected 400 for bad profile name {bad_name:?}"
        );
    }

    // Reject plaintext ephemeral secret via TOML -> 400
    let resp = client
        .post_json(
            "/v1/profiles",
            &json!({
                "name": "bad-ephem-toml",
                "toml": r#"
version = 1
name = "bad-ephem-toml"
[secrets.MY_KEY]
placeholder_prefix = "k_"
ephemeral = "plaintext-forbidden-on-disk"
"#
            }),
        )
        .await;
    assert_eq!(resp.status, StatusCode::BAD_REQUEST);

    // Reject plaintext ephemeral secret via draft -> 400
    let resp = client
        .post_json(
            "/v1/profiles",
            &json!({
                "name": "bad-ephem-draft",
                "draft": {
                    "secrets": {
                        "MY_KEY": {
                            "placeholder_prefix": "k_",
                            "ephemeral": "plaintext-forbidden-on-disk"
                        }
                    }
                }
            }),
        )
        .await;
    assert_eq!(resp.status, StatusCode::BAD_REQUEST);

    // Reject unknown extends -> 400
    let resp = client
        .post_json(
            "/v1/profiles",
            &json!({
                "name": "bad-extends",
                "toml": "version = 1\nextends = [\"does-not-exist\"]\n"
            }),
        )
        .await;
    assert_eq!(resp.status, StatusCode::BAD_REQUEST);

    // Reject missing both toml and draft -> 400
    let resp = client
        .post_json("/v1/profiles", &json!({ "name": "empty-req" }))
        .await;
    assert_eq!(resp.status, StatusCode::BAD_REQUEST);

    // Create profile via TOML with a sealed secret -> 201 Created, secrets redacted
    let resp = client
        .post_json(
            "/v1/profiles",
            &json!({
                "name": "my-toml-prof",
                "toml": r#"
version = 1
name = "my-toml-prof"
extends = ["base"]

[compute]
vcpus = 3
idle_timeout_sec = 4
max_wall_time_sec = 20

[ingress]
allow_ports = [8080]

[secrets.GH_TOKEN]
placeholder_prefix = "ghp_bw_"
sealed = "seal1_should_be_redacted_in_response"
"#
            }),
        )
        .await;
    assert_eq!(resp.status, StatusCode::CREATED);
    let created_prof: SandboxSpec = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(created_prof.name, "my-toml-prof");
    assert_eq!(created_prof.compute.vcpus, 3);
    assert_eq!(created_prof.compute.workspace_mib, 2048); // new base default
    assert_eq!(
        created_prof.secrets["GH_TOKEN"].sealed.as_deref(),
        Some("seal1_<redacted>")
    );
    assert!(profiles_dir.join("my-toml-prof.toml").is_file());

    // Immediately visible in GET /v1/profiles and GET /v1/profiles/{name}
    let resp = client.get("/v1/profiles").await;
    assert_eq!(resp.status, StatusCode::OK);
    let names: Vec<String> = serde_json::from_slice(&resp.body).unwrap();
    assert!(names.contains(&"my-toml-prof".to_string()));

    let resp = client.get("/v1/profiles/my-toml-prof").await;
    assert_eq!(resp.status, StatusCode::OK);
    let fetched_prof: SandboxSpec = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(fetched_prof.compute.vcpus, 3);
    assert_eq!(
        fetched_prof.secrets["GH_TOKEN"].sealed.as_deref(),
        Some("seal1_<redacted>")
    );

    // Create second profile via `draft` extending `my-toml-prof`
    let resp = client
        .post_json(
            "/v1/profiles",
            &json!({
                "name": "my-draft-prof",
                "draft": {
                    "extends": ["my-toml-prof"],
                    "env": {
                        "DRAFT_FLAG": "yes"
                    }
                }
            }),
        )
        .await;
    assert_eq!(resp.status, StatusCode::CREATED);
    let draft_prof: SandboxSpec = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(draft_prof.name, "my-draft-prof");
    assert_eq!(draft_prof.compute.vcpus, 3);
    assert_eq!(
        draft_prof.env.get("DRAFT_FLAG").map(String::as_str),
        Some("yes")
    );
    assert!(profiles_dir.join("my-draft-prof.toml").is_file());

    // Reject cycle when updating `my-toml-prof` to extend `my-draft-prof` -> 400
    let resp = client
        .post_json(
            "/v1/profiles",
            &json!({
                "name": "my-toml-prof",
                "toml": "version = 1\nname = \"my-toml-prof\"\nextends = [\"my-draft-prof\"]\n"
            }),
        )
        .await;
    assert_eq!(resp.status, StatusCode::BAD_REQUEST);

    // DELETE /v1/profiles/base -> 400, missing -> 404, existing -> 204
    let resp = client.delete("/v1/profiles/base").await;
    assert_eq!(resp.status, StatusCode::BAD_REQUEST);

    let resp = client.delete("/v1/profiles/not-there").await;
    assert_eq!(resp.status, StatusCode::NOT_FOUND);

    let resp = client.delete("/v1/profiles/my-draft-prof").await;
    assert_eq!(resp.status, StatusCode::NO_CONTENT);
    assert!(!profiles_dir.join("my-draft-prof.toml").exists());

    let resp = client.get("/v1/profiles/my-draft-prof").await;
    assert_eq!(resp.status, StatusCode::NOT_FOUND);

    // -----------------------------------------------------------------------
    // 2. Sandbox creation (`bw-` prefix), keepalive, fs listing, and ports
    // -----------------------------------------------------------------------
    // Open a real loopback TCP listener so `/proc/net/tcp` has a known LISTEN port.
    let probe_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let probe_port = probe_listener.local_addr().unwrap().port();

    let resp = client
        .post_json(
            "/v1/sandboxes",
            &json!({
                "compute": {
                    "idle_timeout_sec": 3,
                    "max_wall_time_sec": 20
                },
                "ingress": {
                    "allow_ports": [probe_port]
                }
            }),
        )
        .await;
    assert_eq!(resp.status, StatusCode::CREATED);
    let sb: SandboxSummary = serde_json::from_slice(&resp.body).unwrap();
    assert!(sb.id.starts_with("bw-"));
    assert_eq!(sb.compute.workspace_mib, 2048);

    // Upload files & subdirs into /workspace to exercise GET /v1/sandboxes/{id}/fs
    let tar_bytes = make_tar(&[
        ("zeta.txt", b"hello zeta"),
        ("alpha.txt", b"hi"),
        ("sub_b/nested.txt", b"nested"),
        ("sub_a/inside.txt", b"inside"),
    ]);
    let resp = client
        .put_bytes(
            &format!("/v1/sandboxes/{}/files?path=/workspace", sb.id),
            "application/x-tar",
            tar_bytes,
        )
        .await;
    assert_eq!(resp.status, StatusCode::OK);

    // Call GET /v1/sandboxes/{id}/fs (default path=/workspace)
    let resp = client.get(&format!("/v1/sandboxes/{}/fs", sb.id)).await;
    assert_eq!(resp.status, StatusCode::OK);
    let entries: Vec<FsEntry> = serde_json::from_slice(&resp.body).unwrap();
    let entry_names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(entry_names, vec!["sub_a", "sub_b", "alpha.txt", "zeta.txt"]);
    assert!(entries[0].is_dir && entries[0].kind == "dir");
    assert_eq!(entries[0].path, "/workspace/sub_a");
    assert!(!entries[2].is_dir && entries[2].kind == "file" && entries[2].size == 2);
    assert_eq!(entries[2].path, "/workspace/alpha.txt");

    // Subdir listing
    let resp = client
        .get(&format!("/v1/sandboxes/{}/fs?path=/workspace/sub_a", sb.id))
        .await;
    assert_eq!(resp.status, StatusCode::OK);
    let sub_entries: Vec<FsEntry> = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(sub_entries.len(), 1);
    assert_eq!(sub_entries[0].name, "inside.txt");
    assert_eq!(sub_entries[0].path, "/workspace/sub_a/inside.txt");

    // Non-existent path -> 404, regular file -> 400
    let resp = client
        .get(&format!("/v1/sandboxes/{}/fs?path=/workspace/nope", sb.id))
        .await;
    assert_eq!(resp.status, StatusCode::NOT_FOUND);

    let resp = client
        .get(&format!(
            "/v1/sandboxes/{}/fs?path=/workspace/alpha.txt",
            sb.id
        ))
        .await;
    assert_eq!(resp.status, StatusCode::BAD_REQUEST);

    // Call GET /v1/sandboxes/{id}/ports and verify probe_port appears with allowed=true
    let resp = client.get(&format!("/v1/sandboxes/{}/ports", sb.id)).await;
    assert_eq!(resp.status, StatusCode::OK);
    let ports: Vec<ListeningPort> = serde_json::from_slice(&resp.body).unwrap();
    let found_probe = ports
        .iter()
        .find(|p| p.port == probe_port)
        .expect("listening probe_port must be detected from /proc/net/tcp");
    assert!(found_probe.allowed);
    assert_eq!(
        found_probe.proxy_url,
        format!("/v1/sandboxes/{}/proxy/{probe_port}/", sb.id)
    );
    // Ports must be sorted ascending
    assert!(ports.windows(2).all(|w| w[0].port < w[1].port));
    drop(probe_listener);

    // Verify neither /fs nor /ports emitted ExecCommand audit events or incremented exec_count!
    let detail_resp = client.get(&format!("/v1/sandboxes/{}", sb.id)).await;
    assert_eq!(detail_resp.status, StatusCode::OK);
    let detail: SandboxDetail = serde_json::from_slice(&detail_resp.body).unwrap();
    assert_eq!(
        detail.stats.exec_count, 0,
        "internal /fs and /ports commands must not increment stats.exec_count"
    );
    let sb_events = sink.snapshot();
    assert!(
        !sb_events
            .iter()
            .any(|e| e.sandbox_id == sb.id && matches!(e.kind, AuditEventKind::ExecCommand { .. })),
        "internal /fs and /ports commands must not emit ExecCommand audit events"
    );

    // Call POST /v1/sandboxes/{id}/keepalive after waiting 1.1s and verify idle_deadline_at advances
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let resp = client
        .post_json(&format!("/v1/sandboxes/{}/keepalive", sb.id), &json!({}))
        .await;
    assert_eq!(resp.status, StatusCode::OK);
    let ka: KeepaliveResponse = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(ka.id, sb.id);
    assert_eq!(ka.expires_at, sb.expires_at);
    assert!(ka.idle_deadline_at >= sb.idle_deadline_at);
    assert!(ka.idle_deadline_at <= ka.expires_at);
    assert!(ka.idle_remaining_sec <= 3);
    assert!(ka.wall_remaining_sec <= 20);

    let resp = client
        .post_json("/v1/sandboxes/bw-missing/keepalive", &json!({}))
        .await;
    assert_eq!(resp.status, StatusCode::NOT_FOUND);

    // -----------------------------------------------------------------------
    // 3. POST /v1/images/build & DELETE /v1/images/{content_hash}
    // -----------------------------------------------------------------------
    // Build request validation
    let resp = client.post_json("/v1/images/build", &json!({})).await;
    assert_eq!(resp.status, StatusCode::BAD_REQUEST);

    let resp = client
        .post_json(
            "/v1/images/build",
            &json!({ "oci_ref": "alpine:3.20", "profile": "base" }),
        )
        .await;
    assert_eq!(resp.status, StatusCode::BAD_REQUEST);

    let resp = client
        .post_json("/v1/images/build", &json!({ "profile": "no-such-profile" }))
        .await;
    assert_eq!(resp.status, StatusCode::NOT_FOUND);

    // Seed a fake cached image entry matching the active sandbox's `image_content_hash`
    let active_hash = sb.image_content_hash.clone();
    assert_eq!(active_hash.len(), 64);
    let cached_dir = images_dir.join(&active_hash);
    fs::create_dir_all(&cached_dir).unwrap();
    fs::write(cached_dir.join("vda.erofs"), b"fake-erofs-bytes").unwrap();
    fs::write(
        cached_dir.join("meta.json"),
        serde_json::to_vec(&json!({
            "content_hash": active_hash,
            "erofs_path": cached_dir.join("vda.erofs"),
            "verity": {
                "roothash_hex": "0".repeat(64),
                "salt_hex": "aa",
                "data_blocks": 1,
                "hash_start_block": 1,
                "data_block_size": 4096,
                "hash_block_size": 4096
            }
        }))
        .unwrap(),
    )
    .unwrap();

    // POST /v1/images/build for "base" hits cache and returns 200 OK BuiltImage!
    let resp = client
        .post_json("/v1/images/build", &json!({ "profile": "base" }))
        .await;
    assert_eq!(resp.status, StatusCode::OK);
    let built: BuiltImage = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(built.content_hash, active_hash);

    // DELETE /v1/images/{bad_hash} -> 400 Bad Request
    for bad_hash in ["too-short", &"A".repeat(64), &"g".repeat(64)] {
        let resp = client.delete(&format!("/v1/images/{bad_hash}")).await;
        assert_eq!(
            resp.status,
            StatusCode::BAD_REQUEST,
            "expected 400 for invalid image hash {bad_hash:?}"
        );
    }

    // DELETE missing valid hash -> 404 Not Found
    let missing_hash = "f".repeat(64);
    let resp = client.delete(&format!("/v1/images/{missing_hash}")).await;
    assert_eq!(resp.status, StatusCode::NOT_FOUND);

    // DELETE image currently in use by active sandbox -> 409 Conflict!
    let resp = client.delete(&format!("/v1/images/{active_hash}")).await;
    assert_eq!(resp.status, StatusCode::CONFLICT);
    let err: ApiErrorBody = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(err.code, "image_in_use");
    assert!(cached_dir.exists());

    // Destroy active sandbox, then DELETE succeeds with 204 No Content!
    let resp = client.delete(&format!("/v1/sandboxes/{}", sb.id)).await;
    assert_eq!(resp.status, StatusCode::NO_CONTENT);

    let resp = client.delete(&format!("/v1/images/{active_hash}")).await;
    assert_eq!(resp.status, StatusCode::NO_CONTENT);
    assert!(!cached_dir.exists());

    // Deleting again -> 404 Not Found
    let resp = client.delete(&format!("/v1/images/{active_hash}")).await;
    assert_eq!(resp.status, StatusCode::NOT_FOUND);

    let _ = shutdown_tx.send(());
    server_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn host_service_bridges_e2e_and_policy_enforcement() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let tmp = tempfile::tempdir().unwrap();
    let profiles_dir = tmp.path().join("profiles");
    fs::create_dir_all(&profiles_dir).unwrap();
    // Write a locked profile to verify locked = true rejects bridge attach with 403
    // while allowing bridge detach (narrowing exposure is always permitted).
    let locked_static_bridge_port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let echo_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();
    fs::write(
        profiles_dir.join("locked-dev.toml"),
        format!(
            r#"
version = 1
name = "locked-dev"
extends = ["base"]

[policy]
locked = true

[[host_services]]
name = "locked-echo"
guest_port = {locked_static_bridge_port}
target = "{echo_addr}"
"#
        ),
    )
    .unwrap();

    let sink = Arc::new(MemoryAuditSink::new());
    let mut cfg = CoreConfig::for_testing(tmp.path(), sink);
    // Explicitly seed canonical daemon HTTP (7700) and preview (7701) ports in config as well
    // as letting BoundDaemon register the ephemeral bound ports + UDS socket path.
    cfg.forbidden_bridge_ports = vec![7700, 7701];

    let manager = Arc::new(
        SandboxManager::with_backend(
            cfg,
            Box::new(MockSessionVmmBackend::new()),
            Arc::new(StaticDnsResolver::new()),
        )
        .unwrap(),
    );

    let socket_path = tmp.path().join("blackwall.sock");
    let bound = BoundDaemon::bind(Arc::clone(&manager), &socket_path)
        .unwrap()
        .with_http(HttpOptions {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            preview_listen: None,
            allow_non_loopback: false,
            ui_dir: None,
            http_token: None,
        })
        .unwrap();
    let http_port = bound.http_addr().unwrap().port();
    let preview_addr = bound.preview_addr().unwrap();
    let preview_port = preview_addr.port();

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let server_task = tokio::spawn(async move {
        bound
            .serve(async move {
                let _ = shutdown_rx.await;
            })
            .await
    });

    let client = UdsHttpClient::new(&socket_path);

    // Start the echo accept loop on the host loopback TCP echo service bound above.
    let echo_task = tokio::spawn(async move {
        while let Ok((mut sock, _)) = echo_listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 512];
                if let Ok(n) = sock.read(&mut buf).await {
                    let _ = sock.write_all(&buf[..n]).await;
                }
                let _ = sock.shutdown().await;
            });
        }
    });

    // -----------------------------------------------------------------------
    // 1. Loopback sandbox: GET / POST / DELETE /v1/sandboxes/{id}/bridges E2E
    // -----------------------------------------------------------------------
    let resp = client.post_json("/v1/sandboxes", &json!({})).await;
    assert_eq!(resp.status, StatusCode::CREATED);
    let sb: SandboxSummary = serde_json::from_slice(&resp.body).unwrap();
    assert!(sb.host_services.is_empty());

    // Initially empty list
    let resp = client
        .get(&format!("/v1/sandboxes/{}/bridges", sb.id))
        .await;
    assert_eq!(resp.status, StatusCode::OK);
    let bridges: Vec<HostServiceSpec> = serde_json::from_slice(&resp.body).unwrap();
    assert!(bridges.is_empty());

    // Self-protection: daemon HTTP port (7700 & bound http_port), preview port (7701 & bound preview_port),
    // and daemon UDS socket MUST all be rejected with 403 Forbidden!
    for forbidden_target in [
        "127.0.0.1:7700".to_string(),
        "127.0.0.1:7701".to_string(),
        format!("127.0.0.1:{http_port}"),
        format!("127.0.0.1:{preview_port}"),
        format!("unix://{}", socket_path.display()),
    ] {
        let resp = client
            .post_json(
                &format!("/v1/sandboxes/{}/bridges", sb.id),
                &json!({
                    "name": "evil-self",
                    "guest_port": 18888,
                    "target": forbidden_target,
                }),
            )
            .await;
        assert_eq!(
            resp.status,
            StatusCode::FORBIDDEN,
            "expected 403 Forbidden for target {forbidden_target}, got {} ({})",
            resp.status,
            String::from_utf8_lossy(&resp.body)
        );
        let err: ApiErrorBody = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(err.code, "policy_violation");
    }

    // Attach bridge with omitted `name` -> defaults to `bridge-<guest_port>` and returns 201 Created.
    let free_guest_port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let resp = client
        .post_json(
            &format!("/v1/sandboxes/{}/bridges", sb.id),
            &json!({
                "guest_port": free_guest_port,
                "target": echo_addr.to_string(),
            }),
        )
        .await;
    assert_eq!(
        resp.status,
        StatusCode::CREATED,
        "attach failed: {}",
        String::from_utf8_lossy(&resp.body)
    );
    let attached: HostServiceSpec = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(attached.name, format!("bridge-{free_guest_port}"));
    assert_eq!(attached.guest_port, free_guest_port);
    assert_eq!(attached.target, echo_addr.to_string());

    // GET /bridges and GET /v1/sandboxes/{id} both reflect the live attached bridge.
    let resp = client
        .get(&format!("/v1/sandboxes/{}/bridges", sb.id))
        .await;
    assert_eq!(resp.status, StatusCode::OK);
    let bridges: Vec<HostServiceSpec> = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(bridges, vec![attached.clone()]);

    let resp = client.get(&format!("/v1/sandboxes/{}", sb.id)).await;
    assert_eq!(resp.status, StatusCode::OK);
    let detail: SandboxDetail = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(detail.host_services, vec![attached.clone()]);

    // Duplicate guest_port -> 400 Bad Request.
    let resp = client
        .post_json(
            &format!("/v1/sandboxes/{}/bridges", sb.id),
            &json!({
                "name": "dup",
                "guest_port": free_guest_port,
                "target": echo_addr.to_string(),
            }),
        )
        .await;
    assert_eq!(resp.status, StatusCode::BAD_REQUEST);

    // Real TCP round-trip through the attached host bridge!
    {
        let mut conn = tokio::net::TcpStream::connect(("127.0.0.1", free_guest_port))
            .await
            .unwrap();
        conn.write_all(b"daemon-bridge-e2e").await.unwrap();
        let mut out = Vec::new();
        conn.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"daemon-bridge-e2e");
    }

    // Preview router MUST NEVER expose /v1/sandboxes/{id}/bridges!
    {
        let stream = tokio::net::TcpStream::connect(preview_addr).await.unwrap();
        let io = TokioIo::new(stream);
        let (mut sender, conn) = http1::handshake(io).await.unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let req = Request::builder()
            .method(Method::GET)
            .uri(format!("/v1/sandboxes/{}/bridges", sb.id))
            .header(HOST, preview_addr.to_string())
            .body(Full::new(Bytes::new()))
            .unwrap();
        let preview_resp = sender.send_request(req).await.unwrap();
        assert_eq!(preview_resp.status(), StatusCode::NOT_FOUND);
    }

    // DELETE /v1/sandboxes/{id}/bridges/{guest_port} -> 204 No Content.
    let resp = client
        .delete(&format!("/v1/sandboxes/{}/bridges/{free_guest_port}", sb.id))
        .await;
    assert_eq!(resp.status, StatusCode::NO_CONTENT);

    let resp = client
        .get(&format!("/v1/sandboxes/{}/bridges", sb.id))
        .await;
    assert_eq!(resp.status, StatusCode::OK);
    let bridges: Vec<HostServiceSpec> = serde_json::from_slice(&resp.body).unwrap();
    assert!(bridges.is_empty());

    // DELETE again -> 404 Not Found.
    let resp = client
        .delete(&format!("/v1/sandboxes/{}/bridges/{free_guest_port}", sb.id))
        .await;
    assert_eq!(resp.status, StatusCode::NOT_FOUND);

    // -----------------------------------------------------------------------
    // 2. Locked policy sandbox -> 403 Forbidden on attach, 204 No Content on detach
    // -----------------------------------------------------------------------
    let resp = client
        .post_json("/v1/sandboxes", &json!({ "extends": ["locked-dev"] }))
        .await;
    assert_eq!(resp.status, StatusCode::CREATED);
    let locked_sb: SandboxSummary = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(locked_sb.host_services.len(), 1);
    assert_eq!(locked_sb.host_services[0].guest_port, locked_static_bridge_port);

    let resp = client
        .post_json(
            &format!("/v1/sandboxes/{}/bridges", locked_sb.id),
            &json!({
                "name": "blocked-locked",
                "guest_port": free_guest_port,
                "target": echo_addr.to_string(),
            }),
        )
        .await;
    assert_eq!(resp.status, StatusCode::FORBIDDEN);
    let err: ApiErrorBody = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(err.code, "policy_violation");

    // Detaching an existing bridge on a locked sandbox is allowed (narrowing exposure).
    let resp = client
        .delete(&format!(
            "/v1/sandboxes/{}/bridges/{locked_static_bridge_port}",
            locked_sb.id
        ))
        .await;
    assert_eq!(resp.status, StatusCode::NO_CONTENT);
    let resp = client
        .get(&format!("/v1/sandboxes/{}/bridges", locked_sb.id))
        .await;
    assert_eq!(resp.status, StatusCode::OK);
    let locked_bridges: Vec<HostServiceSpec> = serde_json::from_slice(&resp.body).unwrap();
    assert!(locked_bridges.is_empty());

    // -----------------------------------------------------------------------
    // 3. network.mode = "none" sandbox -> 400 Bad Request on attach
    // -----------------------------------------------------------------------
    let resp = client
        .post_json(
            "/v1/sandboxes",
            &json!({ "network": { "mode": "none" } }),
        )
        .await;
    assert_eq!(resp.status, StatusCode::CREATED);
    let none_sb: SandboxSummary = serde_json::from_slice(&resp.body).unwrap();

    let resp = client
        .post_json(
            &format!("/v1/sandboxes/{}/bridges", none_sb.id),
            &json!({
                "name": "blocked-none",
                "guest_port": free_guest_port,
                "target": echo_addr.to_string(),
            }),
        )
        .await;
    assert_eq!(resp.status, StatusCode::BAD_REQUEST);
    let err: ApiErrorBody = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(err.code, "invalid_request");

    // Cleanup
    echo_task.abort();
    let _ = shutdown_tx.send(());
    server_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn dynamic_ingress_ports_e2e_and_policy_enforcement() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn spawn_mock_http_server(tag: &'static str) -> (u16, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let Ok(n) = sock.read(&mut buf).await else {
                        return;
                    };
                    if n == 0 {
                        return;
                    }
                    let body = format!("OK:{tag}");
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        (port, task)
    }

    let (initial_port, initial_server) = spawn_mock_http_server("initial").await;
    let (dynamic_port, dynamic_server) = spawn_mock_http_server("dynamic").await;

    let tmp = tempfile::tempdir().unwrap();
    let profiles_dir = tmp.path().join("profiles");
    fs::create_dir_all(&profiles_dir).unwrap();
    fs::write(
        profiles_dir.join("locked-ingress.toml"),
        format!(
            r#"
version = 1
name = "locked-ingress"
extends = ["base"]

[policy]
locked = true

[ingress]
allow_ports = [{initial_port}]
"#
        ),
    )
    .unwrap();

    let sink = Arc::new(MemoryAuditSink::new());
    let cfg = CoreConfig::for_testing(tmp.path(), sink.clone());
    let manager = Arc::new(
        SandboxManager::with_backend(
            cfg,
            Box::new(MockSessionVmmBackend::new()),
            Arc::new(StaticDnsResolver::new()),
        )
        .unwrap(),
    );

    let socket_path = tmp.path().join("blackwall.sock");
    let bound = BoundDaemon::bind(Arc::clone(&manager), &socket_path)
        .unwrap()
        .with_http(HttpOptions {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            preview_listen: None,
            allow_non_loopback: false,
            ui_dir: None,
            http_token: None,
        })
        .unwrap();
    let http_addr = bound.http_addr().unwrap();
    let preview_addr = bound.preview_addr().unwrap();
    let http_token = bound.http_token().unwrap().to_string();

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let server_task = tokio::spawn(async move {
        bound
            .serve(async move {
                let _ = shutdown_rx.await;
            })
            .await
    });

    let uds = UdsHttpClient::new(&socket_path);

    // -----------------------------------------------------------------------
    // 1. Standard loopback sandbox: GET / POST / DELETE /v1/sandboxes/{id}/ingress
    // -----------------------------------------------------------------------
    let resp = uds
        .post_json(
            "/v1/sandboxes",
            &json!({ "ingress": { "allow_ports": [initial_port] } }),
        )
        .await;
    assert_eq!(resp.status, StatusCode::CREATED);
    let sb: SandboxSummary = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(sb.ingress_allow_ports, vec![initial_port]);

    // GET /v1/sandboxes/{id}/ingress returns initial ports on BOTH UDS and HTTP control-plane.
    let resp = uds
        .get(&format!("/v1/sandboxes/{}/ingress", sb.id))
        .await;
    assert_eq!(resp.status, StatusCode::OK);
    let ports: Vec<u16> = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(ports, vec![initial_port]);

    let cp_get = tcp_http_request_with_auth(
        http_addr,
        Method::GET,
        &format!("/v1/sandboxes/{}/ingress", sb.id),
        Some(&http_token),
        Bytes::new(),
    )
    .await;
    assert_eq!(cp_get.status, StatusCode::OK);
    let cp_ports: Vec<u16> = serde_json::from_slice(&cp_get.body).unwrap();
    assert_eq!(cp_ports, vec![initial_port]);

    // Dynamic port is initially blocked by proxy -> 403 Forbidden.
    let denied = uds
        .get(&format!("/v1/sandboxes/{}/proxy/{dynamic_port}/", sb.id))
        .await;
    assert_eq!(denied.status, StatusCode::FORBIDDEN);
    let err: ApiErrorBody = serde_json::from_slice(&denied.body).unwrap();
    assert_eq!(err.code, "ingress_port_denied");

    // Port 0 is rejected with 400 Bad Request.
    let bad_zero = uds
        .post_json(
            &format!("/v1/sandboxes/{}/ingress", sb.id),
            &json!({ "port": 0 }),
        )
        .await;
    assert_eq!(bad_zero.status, StatusCode::BAD_REQUEST);

    // POST /v1/sandboxes/{id}/ingress dynamically opens `dynamic_port` -> 201 Created.
    let opened = uds
        .post_json(
            &format!("/v1/sandboxes/{}/ingress", sb.id),
            &json!({ "port": dynamic_port }),
        )
        .await;
    assert_eq!(opened.status, StatusCode::CREATED);
    let opened_ports: Vec<u16> = serde_json::from_slice(&opened.body).unwrap();
    let mut expected_ports = vec![initial_port, dynamic_port];
    expected_ports.sort_unstable();
    assert_eq!(opened_ports, expected_ports);

    // Immediately allows GET /v1/sandboxes/{id}/proxy/{dynamic_port}/!
    let proxied = uds
        .get(&format!("/v1/sandboxes/{}/proxy/{dynamic_port}/", sb.id))
        .await;
    assert_eq!(proxied.status, StatusCode::OK);
    assert_eq!(String::from_utf8_lossy(&proxied.body), "OK:dynamic");

    // SandboxDetail and /ports reflect the dynamically opened port.
    let detail_resp = uds.get(&format!("/v1/sandboxes/{}", sb.id)).await;
    assert_eq!(detail_resp.status, StatusCode::OK);
    let detail: SandboxDetail = serde_json::from_slice(&detail_resp.body).unwrap();
    assert_eq!(detail.ingress_allow_ports, expected_ports);
    assert_eq!(detail.ingress.allow_ports, expected_ports);

    let ports_resp = uds.get(&format!("/v1/sandboxes/{}/ports", sb.id)).await;
    assert_eq!(ports_resp.status, StatusCode::OK);
    let listening: Vec<ListeningPort> = serde_json::from_slice(&ports_resp.body).unwrap();
    let dyn_entry = listening
        .iter()
        .find(|p| p.port == dynamic_port)
        .expect("dynamic_port should be visible in /ports");
    assert!(dyn_entry.allowed);

    // Preview router MUST return 404 on /v1/sandboxes/{id}/ingress (GET, POST, DELETE).
    for (method, path) in [
        (Method::GET, format!("/v1/sandboxes/{}/ingress", sb.id)),
        (Method::POST, format!("/v1/sandboxes/{}/ingress", sb.id)),
        (
            Method::DELETE,
            format!("/v1/sandboxes/{}/ingress/{dynamic_port}", sb.id),
        ),
    ] {
        let preview_resp = tcp_http_request(preview_addr, method, &path, Bytes::new()).await;
        assert_eq!(preview_resp.status, StatusCode::NOT_FOUND);
    }

    // DELETE /v1/sandboxes/{id}/ingress/{dynamic_port} via HTTP control-plane -> 204 No Content.
    let cp_del = tcp_http_request_with_auth(
        http_addr,
        Method::DELETE,
        &format!("/v1/sandboxes/{}/ingress/{dynamic_port}", sb.id),
        Some(&http_token),
        Bytes::new(),
    )
    .await;
    assert_eq!(cp_del.status, StatusCode::NO_CONTENT);

    // Immediately causes GET /v1/sandboxes/{id}/proxy/{dynamic_port}/ to return 403 Forbidden.
    let closed_proxy = uds
        .get(&format!("/v1/sandboxes/{}/proxy/{dynamic_port}/", sb.id))
        .await;
    assert_eq!(closed_proxy.status, StatusCode::FORBIDDEN);
    let err: ApiErrorBody = serde_json::from_slice(&closed_proxy.body).unwrap();
    assert_eq!(err.code, "ingress_port_denied");

    // Repeating DELETE returns 404 Not Found.
    let dup_del = uds
        .delete(&format!("/v1/sandboxes/{}/ingress/{dynamic_port}", sb.id))
        .await;
    assert_eq!(dup_del.status, StatusCode::NOT_FOUND);

    // Audit events include ingress_port_opened and ingress_port_closed.
    let events = sink.snapshot();
    assert!(events.iter().any(|e| {
        e.sandbox_id == sb.id
            && matches!(
                &e.kind,
                AuditEventKind::SandboxLifecycle { phase, details, .. }
                    if phase == "ingress_port_opened"
                        && details.as_deref() == Some(format!("port={dynamic_port}").as_str())
            )
    }));
    assert!(events.iter().any(|e| {
        e.sandbox_id == sb.id
            && matches!(
                &e.kind,
                AuditEventKind::SandboxLifecycle { phase, details, .. }
                    if phase == "ingress_port_closed"
                        && details.as_deref() == Some(format!("port={dynamic_port}").as_str())
            )
    }));

    // -----------------------------------------------------------------------
    // 2. Locked policy sandbox: POST -> 403, DELETE -> 204 (narrowing allowed!)
    // -----------------------------------------------------------------------
    let resp = uds
        .post_json("/v1/sandboxes", &json!({ "extends": ["locked-ingress"] }))
        .await;
    assert_eq!(resp.status, StatusCode::CREATED);
    let locked_sb: SandboxSummary = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(locked_sb.ingress_allow_ports, vec![initial_port]);

    let resp = uds
        .post_json(
            &format!("/v1/sandboxes/{}/ingress", locked_sb.id),
            &json!({ "port": dynamic_port }),
        )
        .await;
    assert_eq!(resp.status, StatusCode::FORBIDDEN);
    let err: ApiErrorBody = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(err.code, "policy_violation");

    let resp = uds
        .delete(&format!(
            "/v1/sandboxes/{}/ingress/{initial_port}",
            locked_sb.id
        ))
        .await;
    assert_eq!(resp.status, StatusCode::NO_CONTENT);

    let resp = uds
        .get(&format!("/v1/sandboxes/{}/ingress", locked_sb.id))
        .await;
    assert_eq!(resp.status, StatusCode::OK);
    let remaining: Vec<u16> = serde_json::from_slice(&resp.body).unwrap();
    assert!(remaining.is_empty());

    let locked_proxy = uds
        .get(&format!(
            "/v1/sandboxes/{}/proxy/{initial_port}/",
            locked_sb.id
        ))
        .await;
    assert_eq!(locked_proxy.status, StatusCode::FORBIDDEN);

    // -----------------------------------------------------------------------
    // 3. network.mode = "none" sandbox: POST -> 400 Bad Request
    // -----------------------------------------------------------------------
    let resp = uds
        .post_json("/v1/sandboxes", &json!({ "network": { "mode": "none" } }))
        .await;
    assert_eq!(resp.status, StatusCode::CREATED);
    let none_sb: SandboxSummary = serde_json::from_slice(&resp.body).unwrap();

    let resp = uds
        .post_json(
            &format!("/v1/sandboxes/{}/ingress", none_sb.id),
            &json!({ "port": dynamic_port }),
        )
        .await;
    assert_eq!(resp.status, StatusCode::BAD_REQUEST);
    let err: ApiErrorBody = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(err.code, "invalid_request");

    // Cleanup
    initial_server.abort();
    dynamic_server.abort();
    let _ = shutdown_tx.send(());
    server_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn operator_lockdown_readonly_profiles_require_locked_and_policy_ceiling_e2e() {
    // -----------------------------------------------------------------------
    // 1. readonly_profiles = true -> POST /v1/profiles and DELETE /v1/profiles/{name} -> 403
    // -----------------------------------------------------------------------
    {
        let tmp = tempfile::tempdir().unwrap();
        let profiles_dir = tmp.path().join("profiles");
        fs::create_dir_all(&profiles_dir).unwrap();
        fs::write(
            profiles_dir.join("existing-prof.toml"),
            r#"
version = 1
name = "existing-prof"
extends = ["base"]
"#,
        )
        .unwrap();

        let sink = Arc::new(MemoryAuditSink::new());
        let mut cfg = CoreConfig::for_testing(tmp.path(), sink);
        cfg.readonly_profiles = true;

        let manager = Arc::new(
            SandboxManager::with_backend(
                cfg,
                Box::new(MockSessionVmmBackend::new()),
                Arc::new(StaticDnsResolver::new()),
            )
            .unwrap(),
        );
        let socket_path = tmp.path().join("blackwall.sock");
        let bound = BoundDaemon::bind(Arc::clone(&manager), &socket_path)
            .unwrap()
            .with_http(HttpOptions {
                listen_addr: "127.0.0.1:0".parse().unwrap(),
                preview_listen: None,
                allow_non_loopback: false,
                ui_dir: None,
                http_token: None,
            })
            .unwrap();
        let http_addr = bound.http_addr().unwrap();
        let http_token = bound.http_token().unwrap().to_string();

        let (tx, rx) = oneshot::channel::<()>();
        let server = tokio::spawn(async move {
            bound
                .serve(async move {
                    let _ = rx.await;
                })
                .await
        });

        let uds = UdsHttpClient::new(&socket_path);

        // POST /v1/profiles -> 403
        let resp = uds
            .post_json(
                "/v1/profiles",
                &json!({
                    "name": "new-prof",
                    "toml": "version = 1\nname = \"new-prof\"\nextends = [\"base\"]\n"
                }),
            )
            .await;
        assert_eq!(resp.status, StatusCode::FORBIDDEN);
        let err: ApiErrorBody = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(err.code, "policy_violation");

        // DELETE /v1/profiles/{name} -> 403
        let resp = uds.delete("/v1/profiles/existing-prof").await;
        assert_eq!(resp.status, StatusCode::FORBIDDEN);
        let err: ApiErrorBody = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(err.code, "policy_violation");

        // GET /v1/auth/status reports role=operator and active lockdown flags
        let auth_resp = tcp_http_request_with_auth(
            http_addr,
            Method::GET,
            "/v1/auth/status",
            Some(&http_token),
            Bytes::new(),
        )
        .await;
        assert_eq!(auth_resp.status, StatusCode::OK);
        let st: AuthStatusResponse = serde_json::from_slice(&auth_resp.body).unwrap();
        assert!(st.authenticated);
        assert_eq!(st.role, PrincipalRole::Operator);
        assert!(st.readonly_profiles);
        assert!(!st.require_locked_profiles);
        assert!(!st.has_policy_ceiling);
        assert!(st.allow_image_build);

        let _ = tx.send(());
        server.await.unwrap().unwrap();
    }

    // -----------------------------------------------------------------------
    // 2. require_locked_profiles = true -> base/unlocked return 403; locked returns 201
    //    and still rejects widening with 403
    // -----------------------------------------------------------------------
    {
        let tmp = tempfile::tempdir().unwrap();
        let profiles_dir = tmp.path().join("profiles");
        fs::create_dir_all(&profiles_dir).unwrap();
        fs::write(
            profiles_dir.join("unlocked-dev.toml"),
            r#"
version = 1
name = "unlocked-dev"
extends = ["base"]

[compute]
vcpus = 2
"#,
        )
        .unwrap();
        fs::write(
            profiles_dir.join("locked-safe.toml"),
            r#"
version = 1
name = "locked-safe"
extends = ["base"]

[compute]
vcpus = 2
memory_mib = 1024

[policy]
locked = true
"#,
        )
        .unwrap();

        let sink = Arc::new(MemoryAuditSink::new());
        let mut cfg = CoreConfig::for_testing(tmp.path(), sink);
        cfg.require_locked_profiles = true;

        let manager = Arc::new(
            SandboxManager::with_backend(
                cfg,
                Box::new(MockSessionVmmBackend::new()),
                Arc::new(StaticDnsResolver::new()),
            )
            .unwrap(),
        );
        let socket_path = tmp.path().join("blackwall.sock");
        let bound = BoundDaemon::bind(Arc::clone(&manager), &socket_path).unwrap();
        let (tx, rx) = oneshot::channel::<()>();
        let server = tokio::spawn(async move {
            bound
                .serve(async move {
                    let _ = rx.await;
                })
                .await
        });

        let uds = UdsHttpClient::new(&socket_path);

        // extends = ["base"] -> 403
        let resp = uds
            .post_json("/v1/sandboxes", &json!({ "extends": ["base"] }))
            .await;
        assert_eq!(resp.status, StatusCode::FORBIDDEN);
        let err: ApiErrorBody = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(err.code, "locked_policy_violation");

        // empty extends -> 403
        let resp = uds.post_json("/v1/sandboxes", &json!({})).await;
        assert_eq!(resp.status, StatusCode::FORBIDDEN);

        // unlocked profile -> 403
        let resp = uds
            .post_json("/v1/sandboxes", &json!({ "extends": ["unlocked-dev"] }))
            .await;
        assert_eq!(resp.status, StatusCode::FORBIDDEN);
        let err: ApiErrorBody = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(err.code, "locked_policy_violation");

        // locked profile with widening override -> 403
        let resp = uds
            .post_json(
                "/v1/sandboxes",
                &json!({
                    "extends": ["locked-safe"],
                    "compute": { "vcpus": 4 }
                }),
            )
            .await;
        assert_eq!(resp.status, StatusCode::FORBIDDEN);
        let err: ApiErrorBody = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(err.code, "locked_policy_violation");

        // locked profile (with narrowing) -> 201 Created
        let resp = uds
            .post_json(
                "/v1/sandboxes",
                &json!({
                    "extends": ["locked-safe"],
                    "compute": { "vcpus": 1 }
                }),
            )
            .await;
        assert_eq!(resp.status, StatusCode::CREATED);
        let sb: SandboxSummary = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(sb.compute.vcpus, 1);

        let _ = tx.send(());
        server.await.unwrap().unwrap();
    }

    // -----------------------------------------------------------------------
    // 3. policy_ceiling -> blocks disallowed egress host, excessive vCPUs,
    //    allow_host_services = false (create & attach), and allow_image_build = false
    // -----------------------------------------------------------------------
    {
        let tmp = tempfile::tempdir().unwrap();
        let sink = Arc::new(MemoryAuditSink::new());
        let mut cfg = CoreConfig::for_testing(tmp.path(), sink);
        cfg.policy_ceiling = Some(PolicyCeiling {
            max_network_mode: Some(NetworkMode::Egress),
            allowed_egress_hosts: Some(vec!["api.github.com".into()]),
            allow_host_services: Some(false),
            allow_image_build: Some(false),
            max_vcpus: Some(2),
            max_memory_mib: Some(2048),
            max_workspace_mib: None,
            max_idle_timeout_sec: None,
            max_wall_time_sec: None,
        });

        let mut dns = StaticDnsResolver::new();
        dns.insert_ips(
            "api.github.com",
            vec![std::net::IpAddr::V4(std::net::Ipv4Addr::new(140, 82, 121, 6))],
        );

        let manager = Arc::new(
            SandboxManager::with_backend(
                cfg,
                Box::new(MockSessionVmmBackend::new()),
                Arc::new(dns),
            )
            .unwrap(),
        );
        let socket_path = tmp.path().join("blackwall.sock");
        let bound = BoundDaemon::bind(Arc::clone(&manager), &socket_path)
            .unwrap()
            .with_http(HttpOptions {
                listen_addr: "127.0.0.1:0".parse().unwrap(),
                preview_listen: None,
                allow_non_loopback: false,
                ui_dir: None,
                http_token: None,
            })
            .unwrap();
        let http_addr = bound.http_addr().unwrap();
        let http_token = bound.http_token().unwrap().to_string();

        let (tx, rx) = oneshot::channel::<()>();
        let server = tokio::spawn(async move {
            bound
                .serve(async move {
                    let _ = rx.await;
                })
                .await
        });

        let uds = UdsHttpClient::new(&socket_path);

        // /v1/auth/status reflects has_policy_ceiling=true and allow_image_build=false
        let auth_resp = tcp_http_request_with_auth(
            http_addr,
            Method::GET,
            "/v1/auth/status",
            Some(&http_token),
            Bytes::new(),
        )
        .await;
        assert_eq!(auth_resp.status, StatusCode::OK);
        let st: AuthStatusResponse = serde_json::from_slice(&auth_resp.body).unwrap();
        assert!(st.has_policy_ceiling);
        assert!(!st.allow_image_build);

        // Disallowed egress host -> 403
        let resp = uds
            .post_json(
                "/v1/sandboxes",
                &json!({
                    "network": {
                        "mode": "egress",
                        "http": [{
                            "host": "evil.example",
                            "methods": ["GET"],
                            "path_prefixes": ["/"]
                        }]
                    }
                }),
            )
            .await;
        assert_eq!(resp.status, StatusCode::FORBIDDEN);
        let err: ApiErrorBody = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(err.code, "locked_policy_violation");

        // Excessive vCPUs -> 403
        let resp = uds
            .post_json("/v1/sandboxes", &json!({ "compute": { "vcpus": 4 } }))
            .await;
        assert_eq!(resp.status, StatusCode::FORBIDDEN);
        let err: ApiErrorBody = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(err.code, "locked_policy_violation");

        // Profile creation exceeding ceiling -> 403 (and not written to disk)
        let resp = uds
            .post_json(
                "/v1/profiles",
                &json!({
                    "name": "over-ceiling",
                    "toml": "version = 1\nname = \"over-ceiling\"\nextends = [\"base\"]\n[compute]\nvcpus = 8\n"
                }),
            )
            .await;
        assert_eq!(resp.status, StatusCode::FORBIDDEN);
        assert!(!tmp.path().join("profiles/over-ceiling.toml").exists());

        // Host services on create -> 403
        let resp = uds
            .post_json(
                "/v1/sandboxes",
                &json!({
                    "host_services": [{
                        "name": "pg",
                        "guest_port": 5432,
                        "target": "127.0.0.1:5432"
                    }]
                }),
            )
            .await;
        assert_eq!(resp.status, StatusCode::FORBIDDEN);

        // Image build disabled by policy ceiling -> 403
        let resp = uds
            .post_json("/v1/images/build", &json!({ "profile": "base" }))
            .await;
        assert_eq!(resp.status, StatusCode::FORBIDDEN);
        let err: ApiErrorBody = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(err.code, "policy_violation");

        // Valid sandbox within ceiling succeeds -> 201 Created, then attach_host_bridge -> 403
        let resp = uds
            .post_json(
                "/v1/sandboxes",
                &json!({
                    "compute": { "vcpus": 2 },
                    "network": {
                        "mode": "egress",
                        "http": [{
                            "host": "api.github.com",
                            "methods": ["GET"],
                            "path_prefixes": ["/repos/"]
                        }]
                    }
                }),
            )
            .await;
        assert_eq!(resp.status, StatusCode::CREATED);
        let sb: SandboxSummary = serde_json::from_slice(&resp.body).unwrap();

        let attach_resp = uds
            .post_json(
                &format!("/v1/sandboxes/{}/bridges", sb.id),
                &json!({
                    "name": "pg",
                    "guest_port": 5432,
                    "target": "127.0.0.1:5432"
                }),
            )
            .await;
        assert_eq!(attach_resp.status, StatusCode::FORBIDDEN);
        let err: ApiErrorBody = serde_json::from_slice(&attach_resp.body).unwrap();
        assert_eq!(err.code, "policy_violation");

        let _ = tx.send(());
        server.await.unwrap().unwrap();
    }
}
