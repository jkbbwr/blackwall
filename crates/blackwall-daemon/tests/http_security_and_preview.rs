//! Integration tests for:
//! 1. Separate isolated preview origin (`--preview-listen`, defaulting to HTTP port + 1).
//! 2. Per-boot HTTP control-plane authentication token (`0600` token file, Bearer / Cookie / `?token=`).
//! 3. DNS rebinding protection (`Host` header validation) and CSRF protection (`Origin`, `Sec-Fetch-Site`).

use blackwall_core::{
    CoreConfig, MemoryAuditSink, MockSessionVmmBackend, SandboxManager, SandboxSummary,
    StaticDnsResolver,
};
use blackwall_daemon::{
    ct_eq, ApiErrorBody, AuthStatusResponse, BoundDaemon, DaemonError, HttpOptions,
    SESSION_COOKIE_NAME, TOKEN_FILE_NAME,
};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1;
use hyper::header::{HeaderName, HeaderValue, AUTHORIZATION, CONTENT_TYPE, COOKIE, HOST, LOCATION, ORIGIN, SET_COOKIE};
use hyper::{HeaderMap, Method, Request, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::json;
use std::fs;
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::oneshot;

struct RawReply {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

async fn send_raw_http(
    addr: SocketAddr,
    method: Method,
    path_and_query: &str,
    headers: &[(&str, &str)],
    body: impl Into<Bytes>,
) -> RawReply {
    let stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("TCP connect failed");
    let io = TokioIo::new(stream);
    let (mut sender, conn) = http1::handshake(io).await.expect("HTTP/1.1 handshake failed");
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let mut builder = Request::builder().method(method).uri(path_and_query);
    for &(name, value) in headers {
        builder = builder.header(
            HeaderName::from_bytes(name.as_bytes()).unwrap(),
            HeaderValue::from_str(value).unwrap(),
        );
    }
    let req = builder
        .body(Full::new(body.into()))
        .expect("failed to build HTTP request");
    let resp = sender.send_request(req).await.expect("HTTP send failed");
    let status = resp.status();
    let resp_headers = resp.headers().clone();
    let collected = resp
        .into_body()
        .collect()
        .await
        .expect("failed to collect response body");
    RawReply {
        status,
        headers: resp_headers,
        body: collected.to_bytes(),
    }
}

fn new_test_manager(root: &std::path::Path) -> Arc<SandboxManager> {
    let sink = Arc::new(MemoryAuditSink::new());
    let cfg = CoreConfig::for_testing(root, sink);
    Arc::new(
        SandboxManager::with_backend(
            cfg,
            Box::new(MockSessionVmmBackend::new()),
            Arc::new(StaticDnsResolver::new()),
        )
        .expect("SandboxManager::with_backend failed"),
    )
}

/// Find a free `(port, port + 1)` pair on `127.0.0.1` for testing default `port + 1` preview binding.
fn find_adjacent_free_loopback_ports() -> (u16, u16) {
    for _ in 0..64 {
        let l1 = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let p1 = l1.local_addr().unwrap().port();
        if let Some(p2) = p1.checked_add(1) {
            if let Ok(l2) = StdTcpListener::bind(("127.0.0.1", p2)) {
                drop(l2);
                drop(l1);
                return (p1, p2);
            }
        }
    }
    panic!("could not find adjacent free loopback ports");
}

#[test]
fn constant_time_eq_behaves_correctly() {
    assert!(ct_eq(b"abcdef", b"abcdef"));
    assert!(!ct_eq(b"abcdef", b"abcdeg"));
    assert!(!ct_eq(b"abc", b"abcdef"));
    assert!(!ct_eq(b"abcdef", b"abc"));
    assert!(ct_eq(b"", b""));
}

#[tokio::test]
async fn default_preview_port_plus_one_non_loopback_rejection_and_0600_token_file() {
    let tmp = tempfile::tempdir().unwrap();
    let manager = new_test_manager(tmp.path());
    let sock_dir = tmp.path().join("run");
    let socket_path = sock_dir.join("blackwall.sock");

    // Non-loopback preview_listen must be rejected when allow_non_loopback == false.
    let bad_preview = BoundDaemon::bind(Arc::clone(&manager), &socket_path)
        .unwrap()
        .with_http(HttpOptions {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            preview_listen: Some("0.0.0.0:0".parse().unwrap()),
            allow_non_loopback: false,
            ui_dir: None,
            http_token: None,
        });
    assert!(matches!(
        bad_preview,
        Err(DaemonError::NonLoopbackPreviewDisallowed(_))
    ));

    // Empty or malformed --http-token must be rejected.
    let empty_tok = BoundDaemon::bind(Arc::clone(&manager), &socket_path)
        .unwrap()
        .with_http(HttpOptions {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            preview_listen: None,
            allow_non_loopback: false,
            ui_dir: None,
            http_token: Some(String::new()),
        });
    assert!(matches!(empty_tok, Err(DaemonError::InvalidHttpToken(_))));

    let semi_tok = BoundDaemon::bind(Arc::clone(&manager), &socket_path)
        .unwrap()
        .with_http(HttpOptions {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            preview_listen: None,
            allow_non_loopback: false,
            ui_dir: None,
            http_token: Some("bad;cookie".to_string()),
        });
    assert!(matches!(semi_tok, Err(DaemonError::InvalidHttpToken(_))));

    // Explicit HTTP port without --preview-listen defaults to same IP with port + 1.
    let (http_port, expected_preview_port) = find_adjacent_free_loopback_ports();
    let bound = BoundDaemon::bind(Arc::clone(&manager), &socket_path)
        .unwrap()
        .with_http(HttpOptions {
            listen_addr: SocketAddr::from(([127, 0, 0, 1], http_port)),
            preview_listen: None,
            allow_non_loopback: false,
            ui_dir: None,
            http_token: None,
        })
        .expect("default port+1 preview bind should succeed");

    assert_eq!(
        bound.http_addr(),
        Some(SocketAddr::from(([127, 0, 0, 1], http_port)))
    );
    assert_eq!(
        bound.preview_addr(),
        Some(SocketAddr::from(([127, 0, 0, 1], expected_preview_port)))
    );
    assert_eq!(
        bound.preview_origin(),
        Some(format!("http://127.0.0.1:{expected_preview_port}").as_str())
    );

    // Generated token must be 64 lowercase hex chars and written to `<sock_dir>/blackwall-http.token` with 0600.
    let token = bound.http_token().expect("token must exist").to_string();
    assert_eq!(token.len(), 64);
    assert!(token.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));

    let token_path = bound
        .http_token_path()
        .expect("token path must exist")
        .to_path_buf();
    assert_eq!(token_path, sock_dir.join(TOKEN_FILE_NAME));
    let mode = fs::metadata(&token_path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "token file must have strict 0600 permissions");
    assert_eq!(fs::read_to_string(&token_path).unwrap(), token);

    // Shutdown must clean up both socket and token file.
    let http_addr = bound.http_addr().unwrap();
    let host_hdr = http_addr.to_string();
    let (tx, rx) = oneshot::channel::<()>();
    let task = tokio::spawn(async move {
        bound
            .serve(async move {
                let _ = rx.await;
            })
            .await
    });

    // Even when `ui_dir` is None, `GET /?token=<valid>` must still bootstrap the session cookie.
    let resp = send_raw_http(
        http_addr,
        Method::GET,
        &format!("/?token={token}"),
        &[(HOST.as_str(), &host_hdr)],
        Bytes::new(),
    )
    .await;
    assert_eq!(resp.status, StatusCode::FOUND);
    assert_eq!(
        resp.headers.get(LOCATION).and_then(|v| v.to_str().ok()),
        Some("/")
    );
    let cookie = resp
        .headers
        .get(SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap();
    assert_eq!(
        cookie,
        format!("{SESSION_COOKIE_NAME}={token}; HttpOnly; SameSite=Strict; Path=/")
    );

    let _ = tx.send(());
    task.await.unwrap().unwrap();
    assert!(!token_path.exists(), "shutdown must remove token file");
}

#[tokio::test]
async fn http_control_plane_auth_host_origin_and_isolated_preview_origin_e2e() {
    let tmp = tempfile::tempdir().unwrap();
    let ui_dir = tmp.path().join("ui-dist");
    fs::create_dir_all(ui_dir.join("assets")).unwrap();
    fs::write(
        ui_dir.join("index.html"),
        "<!doctype html><html><body>UNLOCK_BLACKWALL_UI</body></html>",
    )
    .unwrap();
    fs::write(ui_dir.join("assets/main.js"), "console.log('ui');").unwrap();

    // Mock guest HTTP/1.1 server echoing request line and received Cookie header.
    let guest_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let guest_port = guest_listener.local_addr().unwrap().port();
    let guest_task = tokio::spawn(async move {
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
                let cookie_line = raw
                    .lines()
                    .find(|l| l.to_ascii_lowercase().starts_with("cookie:"))
                    .unwrap_or("cookie:<none>");
                let resp_body = format!("PREVIEW_GUEST|line={first_line}|{cookie_line}");
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    resp_body.len(),
                    resp_body
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.shutdown().await;
            });
        }
    });

    let manager = new_test_manager(tmp.path());
    let socket_path = tmp.path().join("blackwall.sock");
    let custom_token = "bw_test_token_0123456789abcdef".to_string();

    let bound = BoundDaemon::bind(Arc::clone(&manager), &socket_path)
        .unwrap()
        .with_http(HttpOptions {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            preview_listen: Some("127.0.0.1:0".parse().unwrap()),
            allow_non_loopback: false,
            ui_dir: Some(ui_dir),
            http_token: Some(custom_token.clone()),
        })
        .expect("daemon with_http should succeed");

    let http_addr = bound.http_addr().unwrap();
    let preview_addr = bound.preview_addr().unwrap();
    let preview_origin = bound.preview_origin().unwrap().to_string();
    let host_hdr = http_addr.to_string();
    let http_origin = format!("http://{http_addr}");

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let server_task = tokio::spawn(async move {
        bound
            .serve(async move {
                let _ = shutdown_rx.await;
            })
            .await
    });

    // -----------------------------------------------------------------------
    // 1. Unauthenticated GET /v1/sandboxes -> 401 Unauthorized
    // -----------------------------------------------------------------------
    let resp = send_raw_http(
        http_addr,
        Method::GET,
        "/v1/sandboxes",
        &[("host", &host_hdr)],
        Bytes::new(),
    )
    .await;
    assert_eq!(resp.status, StatusCode::UNAUTHORIZED);
    let err: ApiErrorBody = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(err.code, "unauthorized");

    // -----------------------------------------------------------------------
    // 2. DNS Rebinding protection: wrong or missing Host -> 403 invalid_host
    // -----------------------------------------------------------------------
    for bad_host in [
        "evil.attacker.com",
        &format!("evil.attacker.com:{}", http_addr.port()),
        "127.0.0.1:1",
    ] {
        let resp = send_raw_http(
            http_addr,
            Method::GET,
            "/v1/sandboxes",
            &[
                ("host", bad_host),
                ("authorization", &format!("Bearer {custom_token}")),
            ],
            Bytes::new(),
        )
        .await;
        assert_eq!(
            resp.status,
            StatusCode::FORBIDDEN,
            "bad Host '{bad_host}' must be rejected with 403"
        );
        let err: ApiErrorBody = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(err.code, "invalid_host");
    }

    // Missing Host header -> 403 invalid_host
    let resp = send_raw_http(
        http_addr,
        Method::GET,
        "/v1/auth/status",
        &[],
        Bytes::new(),
    )
    .await;
    assert_eq!(resp.status, StatusCode::FORBIDDEN);
    let err: ApiErrorBody = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(err.code, "invalid_host");

    // Case-insensitive localhost:<port> Host header is accepted.
    let localhost_host = format!("LOCALHOST:{}", http_addr.port());
    let resp = send_raw_http(
        http_addr,
        Method::GET,
        "/v1/auth/status",
        &[("host", &localhost_host)],
        Bytes::new(),
    )
    .await;
    assert_eq!(resp.status, StatusCode::OK);
    let status_body: AuthStatusResponse = serde_json::from_slice(&resp.body).unwrap();
    assert!(!status_body.authenticated);
    assert_eq!(status_body.preview_origin, preview_origin);

    // -----------------------------------------------------------------------
    // 3. CSRF / Cross-Origin mutation protection on POST/PUT/DELETE/PATCH
    // -----------------------------------------------------------------------
    // Cross-origin POST /v1/sandboxes with Origin: http://evil.example -> 403
    let resp = send_raw_http(
        http_addr,
        Method::POST,
        "/v1/sandboxes",
        &[
            ("host", &host_hdr),
            (ORIGIN.as_str(), "http://evil.example"),
            (CONTENT_TYPE.as_str(), "application/json"),
            (AUTHORIZATION.as_str(), &format!("Bearer {custom_token}")),
        ],
        b"{}".to_vec(),
    )
    .await;
    assert_eq!(resp.status, StatusCode::FORBIDDEN);
    let err: ApiErrorBody = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(err.code, "cross_origin_forbidden");

    // Preview origin trying to POST to control plane -> 403 cross_origin_forbidden
    let resp = send_raw_http(
        http_addr,
        Method::POST,
        "/v1/sandboxes",
        &[
            ("host", &host_hdr),
            (ORIGIN.as_str(), &preview_origin),
            (COOKIE.as_str(), &format!("{SESSION_COOKIE_NAME}={custom_token}")),
            (CONTENT_TYPE.as_str(), "application/json"),
        ],
        b"{}".to_vec(),
    )
    .await;
    assert_eq!(resp.status, StatusCode::FORBIDDEN);
    let err: ApiErrorBody = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(err.code, "cross_origin_forbidden");

    // Sec-Fetch-Site: cross-site or same-site (different port) -> 403 cross_site_forbidden
    for bad_sfs in ["cross-site", "same-site"] {
        let resp = send_raw_http(
            http_addr,
            Method::POST,
            "/v1/sandboxes",
            &[
                ("host", &host_hdr),
                ("sec-fetch-site", bad_sfs),
                (AUTHORIZATION.as_str(), &format!("Bearer {custom_token}")),
                (CONTENT_TYPE.as_str(), "application/json"),
            ],
            b"{}".to_vec(),
        )
        .await;
        assert_eq!(resp.status, StatusCode::FORBIDDEN);
        let err: ApiErrorBody = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(err.code, "cross_site_forbidden");
    }

    // POST /v1/auth/login is STILL subject to Origin checks!
    let resp = send_raw_http(
        http_addr,
        Method::POST,
        "/v1/auth/login",
        &[
            ("host", &host_hdr),
            (ORIGIN.as_str(), "http://evil.example"),
            (CONTENT_TYPE.as_str(), "application/json"),
        ],
        serde_json::to_vec(&json!({ "token": custom_token })).unwrap(),
    )
    .await;
    assert_eq!(resp.status, StatusCode::FORBIDDEN);
    let err: ApiErrorBody = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(err.code, "cross_origin_forbidden");

    // -----------------------------------------------------------------------
    // 4. GET /?token=<valid|invalid> bootstrap + static UI without auth
    // -----------------------------------------------------------------------
    // Static UI `/` and `/assets/main.js` remain accessible without auth so Unlock UI renders.
    let resp = send_raw_http(
        http_addr,
        Method::GET,
        "/",
        &[("host", &host_hdr)],
        Bytes::new(),
    )
    .await;
    assert_eq!(resp.status, StatusCode::OK);
    assert!(String::from_utf8_lossy(&resp.body).contains("UNLOCK_BLACKWALL_UI"));

    let resp = send_raw_http(
        http_addr,
        Method::GET,
        "/assets/main.js",
        &[("host", &host_hdr)],
        Bytes::new(),
    )
    .await;
    assert_eq!(resp.status, StatusCode::OK);

    // GET /?token=<wrong> -> 401 Unauthorized
    let resp = send_raw_http(
        http_addr,
        Method::GET,
        "/?token=wrong-token",
        &[("host", &host_hdr)],
        Bytes::new(),
    )
    .await;
    assert_eq!(resp.status, StatusCode::UNAUTHORIZED);

    // GET /?token=<valid> -> 302 Found, Location: /, Set-Cookie: bw_session=<valid>; HttpOnly; SameSite=Strict; Path=/
    let resp = send_raw_http(
        http_addr,
        Method::GET,
        &format!("/?token={custom_token}"),
        &[("host", &host_hdr)],
        Bytes::new(),
    )
    .await;
    assert_eq!(resp.status, StatusCode::FOUND);
    assert_eq!(
        resp.headers.get(LOCATION).and_then(|v| v.to_str().ok()),
        Some("/")
    );
    let set_cookie = resp
        .headers
        .get(SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .expect("Set-Cookie header must be present");
    assert_eq!(
        set_cookie,
        format!("{SESSION_COOKIE_NAME}={custom_token}; HttpOnly; SameSite=Strict; Path=/")
    );

    // -----------------------------------------------------------------------
    // 5. POST /v1/auth/login (invalid -> 401, valid -> 200 + Set-Cookie)
    // -----------------------------------------------------------------------
    let resp = send_raw_http(
        http_addr,
        Method::POST,
        "/v1/auth/login",
        &[
            ("host", &host_hdr),
            (ORIGIN.as_str(), &http_origin),
            ("sec-fetch-site", "same-origin"),
            (CONTENT_TYPE.as_str(), "application/json"),
        ],
        serde_json::to_vec(&json!({ "token": "wrong" })).unwrap(),
    )
    .await;
    assert_eq!(resp.status, StatusCode::UNAUTHORIZED);
    assert!(resp.headers.get(SET_COOKIE).is_none());

    let resp = send_raw_http(
        http_addr,
        Method::POST,
        "/v1/auth/login",
        &[
            ("host", &host_hdr),
            (ORIGIN.as_str(), &http_origin),
            ("sec-fetch-site", "same-origin"),
            (CONTENT_TYPE.as_str(), "application/json"),
        ],
        serde_json::to_vec(&json!({ "token": custom_token })).unwrap(),
    )
    .await;
    assert_eq!(resp.status, StatusCode::OK);
    let login_body: AuthStatusResponse = serde_json::from_slice(&resp.body).unwrap();
    assert!(login_body.authenticated);
    assert_eq!(login_body.preview_origin, preview_origin);
    let login_cookie = resp
        .headers
        .get(SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .expect("login must set session cookie");
    assert!(login_cookie.contains(&format!("{SESSION_COOKIE_NAME}={custom_token}")));
    assert!(login_cookie.contains("HttpOnly"));
    assert!(login_cookie.contains("SameSite=Strict"));

    // -----------------------------------------------------------------------
    // 6. Authenticated control-plane calls via Bearer, Cookie, and ?token=
    // -----------------------------------------------------------------------
    let bearer_hdr = format!("Bearer {custom_token}");
    let cookie_hdr = format!("{SESSION_COOKIE_NAME}={custom_token}");

    let resp = send_raw_http(
        http_addr,
        Method::GET,
        "/v1/sandboxes",
        &[("host", &host_hdr), (AUTHORIZATION.as_str(), &bearer_hdr)],
        Bytes::new(),
    )
    .await;
    assert_eq!(resp.status, StatusCode::OK);

    let resp = send_raw_http(
        http_addr,
        Method::GET,
        "/v1/sandboxes",
        &[("host", &host_hdr), (COOKIE.as_str(), &cookie_hdr)],
        Bytes::new(),
    )
    .await;
    assert_eq!(resp.status, StatusCode::OK);

    let resp = send_raw_http(
        http_addr,
        Method::GET,
        &format!("/v1/sandboxes?token={custom_token}"),
        &[("host", &host_hdr)],
        Bytes::new(),
    )
    .await;
    assert_eq!(resp.status, StatusCode::OK);

    // GET /v1/auth/status reports authenticated: true for both Bearer and Cookie.
    for hdr in [(AUTHORIZATION.as_str(), bearer_hdr.as_str()), (COOKIE.as_str(), cookie_hdr.as_str())] {
        let resp = send_raw_http(
            http_addr,
            Method::GET,
            "/v1/auth/status",
            &[("host", &host_hdr), hdr],
            Bytes::new(),
        )
        .await;
        assert_eq!(resp.status, StatusCode::OK);
        let st: AuthStatusResponse = serde_json::from_slice(&resp.body).unwrap();
        assert!(st.authenticated);
        assert_eq!(st.preview_origin, preview_origin);
    }

    // Create a sandbox allowing `guest_port` over the authenticated HTTP control plane.
    let resp = send_raw_http(
        http_addr,
        Method::POST,
        "/v1/sandboxes",
        &[
            ("host", &host_hdr),
            (ORIGIN.as_str(), &http_origin),
            ("sec-fetch-site", "same-origin"),
            (COOKIE.as_str(), &cookie_hdr),
            (CONTENT_TYPE.as_str(), "application/json"),
        ],
        serde_json::to_vec(&json!({
            "ingress": { "allow_ports": [guest_port] }
        }))
        .unwrap(),
    )
    .await;
    assert_eq!(resp.status, StatusCode::CREATED);
    let created: SandboxSummary = serde_json::from_slice(&resp.body).unwrap();
    let sb_id = created.id;

    // -----------------------------------------------------------------------
    // 7. HTTP control plane rejects /v1/sandboxes/{id}/proxy/{port}* with 403
    // -----------------------------------------------------------------------
    for path in [
        format!("/v1/sandboxes/{sb_id}/proxy/{guest_port}"),
        format!("/v1/sandboxes/{sb_id}/proxy/{guest_port}/"),
        format!("/v1/sandboxes/{sb_id}/proxy/{guest_port}/index.html"),
    ] {
        let resp = send_raw_http(
            http_addr,
            Method::GET,
            &path,
            &[("host", &host_hdr), (AUTHORIZATION.as_str(), &bearer_hdr)],
            Bytes::new(),
        )
        .await;
        assert_eq!(resp.status, StatusCode::FORBIDDEN);
        let err: ApiErrorBody = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(err.code, "preview_origin_required");
        assert!(
            err.message.contains(&preview_origin),
            "expected error message to point to preview origin '{preview_origin}', got: {}",
            err.message
        );
    }

    // -----------------------------------------------------------------------
    // 8. Isolated preview origin serves ONLY /proxy/{port}* with security headers
    //    and returns 404 on ALL control-plane routes.
    // -----------------------------------------------------------------------
    let preview_host = preview_addr.to_string();
    for cp_path in [
        "/v1/sandboxes",
        "/v1/profiles",
        "/v1/images",
        "/v1/audit",
        "/v1/auth/status",
        &format!("/v1/sandboxes/{sb_id}"),
        &format!("/v1/sandboxes/{sb_id}/exec"),
        &format!("/v1/sandboxes/{sb_id}/pty"),
        "/",
    ] {
        let resp = send_raw_http(
            preview_addr,
            Method::GET,
            cp_path,
            &[(HOST.as_str(), &preview_host)],
            Bytes::new(),
        )
        .await;
        assert_eq!(
            resp.status,
            StatusCode::NOT_FOUND,
            "preview router must return 404 for control-plane path '{cp_path}'"
        );
    }

    // Proxy request on preview origin succeeds cleanly with nosniff + no-referrer headers,
    // AND strips `bw_session` cookie so the guest server never sees the control-plane token!
    let resp = send_raw_http(
        preview_addr,
        Method::GET,
        &format!("/v1/sandboxes/{sb_id}/proxy/{guest_port}/app/page?x=1"),
        &[
            (HOST.as_str(), &preview_host),
            (
                COOKIE.as_str(),
                &format!("{SESSION_COOKIE_NAME}={custom_token}; guest_pref=dark"),
            ),
        ],
        Bytes::new(),
    )
    .await;
    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(
        resp.headers
            .get("x-content-type-options")
            .and_then(|v| v.to_str().ok()),
        Some("nosniff")
    );
    assert_eq!(
        resp.headers
            .get("referrer-policy")
            .and_then(|v| v.to_str().ok()),
        Some("no-referrer")
    );
    let body_text = String::from_utf8_lossy(&resp.body);
    assert!(
        body_text.contains("PREVIEW_GUEST|line=GET /app/page?x=1 HTTP/1.1"),
        "unexpected preview proxy body: {body_text:?}"
    );
    assert!(
        body_text.contains("guest_pref=dark"),
        "non-session guest cookies must still be forwarded: {body_text:?}"
    );
    assert!(
        !body_text.contains(&custom_token) && !body_text.contains(SESSION_COOKIE_NAME),
        "bw_session control-plane cookie MUST NOT leak to guest app: {body_text:?}"
    );

    // -----------------------------------------------------------------------
    // 9. WebSocket /pty over TCP --http-listen requires auth & rejects cross-origin CSWSH
    // -----------------------------------------------------------------------
    let ws_unauth_stream = tokio::net::TcpStream::connect(http_addr).await.unwrap();
    let ws_unauth = tokio_tungstenite::client_async(
        format!("ws://{http_addr}/v1/sandboxes/{sb_id}/pty?cols=80&rows=24"),
        ws_unauth_stream,
    )
    .await
    .expect_err("unauthenticated WS /pty must fail");
    match ws_unauth {
        tokio_tungstenite::tungstenite::Error::Http(resp) => {
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        }
        other => panic!("expected HTTP 401 for unauthenticated WS /pty, got {other:?}"),
    }

    let ws_evil_stream = tokio::net::TcpStream::connect(http_addr).await.unwrap();
    let ws_evil_req = hyper::Request::builder()
        .uri(format!(
            "ws://{http_addr}/v1/sandboxes/{sb_id}/pty?cols=80&rows=24&token={custom_token}"
        ))
        .header(HOST, &host_hdr)
        .header(ORIGIN, "http://evil.example")
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
        .body(())
        .unwrap();
    let ws_evil = tokio_tungstenite::client_async(ws_evil_req, ws_evil_stream)
        .await
        .expect_err("cross-origin WS /pty must fail with 403");
    match ws_evil {
        tokio_tungstenite::tungstenite::Error::Http(resp) => {
            assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        }
        other => panic!("expected HTTP 403 for cross-origin WS /pty, got {other:?}"),
    }

    let ws_ok_stream = tokio::net::TcpStream::connect(http_addr).await.unwrap();
    let (_ws, ws_resp) = tokio_tungstenite::client_async(
        format!("ws://{http_addr}/v1/sandboxes/{sb_id}/pty?cols=80&rows=24&token={custom_token}"),
        ws_ok_stream,
    )
    .await
    .expect("authenticated WS /pty with ?token= must succeed");
    assert_eq!(ws_resp.status(), StatusCode::SWITCHING_PROTOCOLS);

    guest_task.abort();
    let _ = shutdown_tx.send(());
    server_task.await.unwrap().unwrap();
}
