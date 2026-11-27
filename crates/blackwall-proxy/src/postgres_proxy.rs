//! Sibling Tokio PostgreSQL v3 wire-protocol proxy with TLS termination, placeholder
//! authentication, upstream `SCRAM-SHA-256`, and SQL audit framing.
//!
//! Protocol flow (per `docs/ARCHITECTURE.md` §7.4):
//! 1. **Downstream (Guest <-> Proxy):**
//!    - Handles `SSLRequest` (`len=8, code=80877103`), replies `'S'`, and upgrades to TLS
//!      using the per-VM [`EphemeralCa`].
//!    - Reads `StartupMessage` (v3.0, code `196608`), verifies `(host, port)` is allowed
//!      by `PostgresRule` and resolver-pinned.
//!    - Sends `AuthenticationCleartextPassword` (`'R'`, type `3`), reads `PasswordMessage`
//!      (`'p'`), and validates the guest's random `PGPASSWORD` placeholder in constant time.
//!      On failure, emits `AuditEventKind::AuthMismatch`, returns Postgres `ErrorResponse`
//!      (`SQLSTATE 28P01`), and closes the connection.
//! 2. **Upstream (Proxy <-> Real Postgres):**
//!    - Dials the exact resolver-pinned `SocketAddr` (never resolves DNS).
//!    - When `require_upstream_tls = true`, negotiates upstream `SSLRequest` (`'S'`) +
//!      TLS verification (`verify-full`) with SNI `target_host`.
//!    - Forwards `StartupMessage`, completes a full RFC 5802 / RFC 7677 **`SCRAM-SHA-256`**
//!      authentication handshake (`AuthenticationSASL` -> `SASLInitialResponse` ->
//!      `AuthenticationSASLContinue` -> PBKDF2-HMAC-SHA256 `ClientProof` ->
//!      `AuthenticationSASLFinal` server signature verification) using the real DB password
//!      from [`SecretResolver`].
//! 3. **SQL Audit Relay:**
//!    - Once authenticated (`AuthenticationOk`), relays all frames bidirectionally while
//!      inspecting Frontend `'Q'` (Simple Query), `'P'` (Parse), `'B'` (Bind), and `'E'`
//!      (Execute) messages to emit `AuditEventKind::PostgresQuery` to `AuditSink`.

use crate::ca::EphemeralCa;
use crate::error::{ProxyError, Result};
use crate::http_proxy::{lookup_pinned_addr, PinnedHostMap};
use crate::secrets::SecretResolver;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use blackwall_audit::{AuditEvent, AuditEventKind, AuditSink};
use blackwall_policy::PostgresRule;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac_array;
use rand::RngCore;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use zeroize::Zeroizing;

pub const PG_SSL_REQUEST_CODE: i32 = 80_877_103;
pub const PG_PROTOCOL_V3: i32 = 196_608;
pub const PG_AUTH_OK: i32 = 0;
pub const PG_AUTH_CLEARTEXT_PASSWORD: i32 = 3;
pub const PG_AUTH_SASL: i32 = 10;
pub const PG_AUTH_SASL_CONTINUE: i32 = 11;
pub const PG_AUTH_SASL_FINAL: i32 = 12;

const MAX_PG_STARTUP_LEN: usize = 64 * 1024;
const MAX_PG_MSG_LEN: usize = 64 * 1024 * 1024;

type HmacSha256 = Hmac<Sha256>;

/// Configuration for [`PostgresProxyServer`].
#[derive(Clone)]
pub struct PostgresProxyConfig {
    pub sandbox_id: String,
    pub rules: Vec<PostgresRule>,
    pub pinned_hosts: PinnedHostMap,
    /// Optional custom root certificate store for upstream Postgres TLS verification.
    /// When `None`, uses Mozilla WebPKI roots (`webpki-roots`).
    pub upstream_root_store: Option<Arc<RootCertStore>>,
}

impl PostgresProxyConfig {
    pub fn new(
        sandbox_id: impl Into<String>,
        rules: Vec<PostgresRule>,
        pinned_hosts: PinnedHostMap,
    ) -> Self {
        Self {
            sandbox_id: sandbox_id.into(),
            rules,
            pinned_hosts,
            upstream_root_store: None,
        }
    }
}

/// Sibling Tokio PostgreSQL v3 wire proxy.
pub struct PostgresProxyServer {
    config: PostgresProxyConfig,
    ca: Arc<EphemeralCa>,
    secrets: Arc<dyn SecretResolver>,
    audit_sink: Arc<dyn AuditSink>,
}

impl PostgresProxyServer {
    pub fn new(
        config: PostgresProxyConfig,
        ca: Arc<EphemeralCa>,
        secrets: Arc<dyn SecretResolver>,
        audit_sink: Arc<dyn AuditSink>,
    ) -> Self {
        Self {
            config,
            ca,
            secrets,
            audit_sink,
        }
    }

    /// Accept connections on a local TCP listener and proxy each to `(target_host, target_port)`.
    pub async fn serve_tcp(
        self: Arc<Self>,
        listener: TcpListener,
        target_host: String,
        target_port: u16,
    ) -> Result<()> {
        loop {
            let (stream, _) = listener.accept().await?;
            let this = Arc::clone(&self);
            let host = target_host.clone();
            tokio::spawn(async move {
                if let Err(e) = this.handle_connection(stream, &host, target_port).await {
                    tracing::debug!(error = %e, host = %host, port = target_port, "postgres proxy session ended");
                }
            });
        }
    }

    /// Proxy a single downstream PostgreSQL client stream to `(target_host, target_port)`.
    pub async fn handle_connection<S>(
        &self,
        mut downstream: S,
        target_host: &str,
        target_port: u16,
    ) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        // 1. Read initial startup / SSLRequest packet.
        let initial = read_startup_packet(&mut downstream).await?;
        if initial.len() != 8
            || i32::from_be_bytes([initial[4], initial[5], initial[6], initial[7]])
                != PG_SSL_REQUEST_CODE
        {
            write_error_response(
                &mut downstream,
                "08000",
                "blackwall-proxy requires TLS (SSLRequest) on downstream Postgres connections",
            )
            .await?;
            return Err(ProxyError::Postgres(
                "downstream client did not negotiate SSLRequest".into(),
            ));
        }

        // Reply 'S' and upgrade downstream to TLS using the per-VM ephemeral CA.
        downstream.write_all(b"S").await?;
        downstream.flush().await?;

        let server_cfg = self.ca.server_config(vec![])?;
        let acceptor = TlsAcceptor::from(server_cfg);
        let mut tls_downstream = acceptor
            .accept(downstream)
            .await
            .map_err(|e| ProxyError::Tls(format!("downstream Postgres TLS accept failed: {e}")))?;

        // 2. Read real StartupMessage over TLS.
        let startup_packet = read_startup_packet(&mut tls_downstream).await?;
        if startup_packet.len() < 8 {
            return Err(ProxyError::Postgres("truncated StartupMessage".into()));
        }
        let proto_ver = i32::from_be_bytes([
            startup_packet[4],
            startup_packet[5],
            startup_packet[6],
            startup_packet[7],
        ]);
        if proto_ver != PG_PROTOCOL_V3 {
            write_error_response(
                &mut tls_downstream,
                "0A000",
                "unsupported PostgreSQL protocol version (only v3.0 supported)",
            )
            .await?;
            return Err(ProxyError::Postgres(format!(
                "unsupported startup protocol version {proto_ver}"
            )));
        }

        // 3. Find matching PostgresRule and resolver-pinned IP.
        let rule = self
            .config
            .rules
            .iter()
            .find(|r| r.host.eq_ignore_ascii_case(target_host) && r.port == target_port)
            .cloned()
            .ok_or_else(|| {
                ProxyError::PolicyRejected(format!(
                    "postgres target '{target_host}:{target_port}' is not allowlisted"
                ))
            });
        let rule = match rule {
            Ok(r) => r,
            Err(e) => {
                let _ = write_error_response(&mut tls_downstream, "28000", &e.to_string()).await;
                return Err(e);
            }
        };

        let pinned_addr = match lookup_pinned_addr(
            &self.config.pinned_hosts,
            target_host,
            target_port,
        ) {
            Some(addr) => addr,
            None => {
                let msg = format!(
                    "postgres target '{target_host}:{target_port}' has no resolver-pinned IP"
                );
                let _ = write_error_response(&mut tls_downstream, "08001", &msg).await;
                return Err(ProxyError::PolicyRejected(msg));
            }
        };

        // 4. Challenge guest with AuthenticationCleartextPassword ('R', type 3).
        write_backend_msg(
            &mut tls_downstream,
            b'R',
            &PG_AUTH_CLEARTEXT_PASSWORD.to_be_bytes(),
        )
        .await?;

        // 5. Read PasswordMessage ('p') and validate placeholder in constant time.
        let (msg_type, body) = read_typed_msg(&mut tls_downstream).await?;
        if msg_type != b'p' {
            write_error_response(
                &mut tls_downstream,
                "08P01",
                "expected PasswordMessage ('p') from client",
            )
            .await?;
            return Err(ProxyError::Postgres(format!(
                "expected 'p' PasswordMessage, got 0x{msg_type:02x}"
            )));
        }
        let presented = parse_cstr(&body)
            .ok_or_else(|| ProxyError::Postgres("non-UTF8 PasswordMessage".into()))?;

        if !self.secrets.verify_placeholder(&rule.secret, &presented) {
            self.audit_sink.record(AuditEvent::now(
                &self.config.sandbox_id,
                AuditEventKind::AuthMismatch {
                    host: target_host.to_string(),
                    path: format!("postgres://{target_host}:{target_port}"),
                    reason: format!(
                        "invalid guest PGPASSWORD placeholder for secret '{}'",
                        rule.secret
                    ),
                },
            ));
            write_error_response(
                &mut tls_downstream,
                "28P01",
                "password authentication failed (invalid Blackwall placeholder)",
            )
            .await?;
            return Err(ProxyError::AuthFailed(
                "downstream postgres placeholder mismatch".into(),
            ));
        }

        let real_password = self.secrets.resolve_secret(&rule.secret).ok_or_else(|| {
            ProxyError::AuthFailed(format!(
                "real secret '{}' missing in proxy secret store",
                rule.secret
            ))
        })?;

        // 6. Dial exact resolver-pinned upstream IP:port.
        let mut upstream_tcp = TcpStream::connect(pinned_addr).await?;

        if rule.require_upstream_tls {
            // Send SSLRequest to real Postgres.
            let mut ssl_req = [0u8; 8];
            ssl_req[0..4].copy_from_slice(&8i32.to_be_bytes());
            ssl_req[4..8].copy_from_slice(&PG_SSL_REQUEST_CODE.to_be_bytes());
            upstream_tcp.write_all(&ssl_req).await?;
            upstream_tcp.flush().await?;

            let mut reply = [0u8; 1];
            upstream_tcp.read_exact(&mut reply).await?;
            if reply[0] != b'S' {
                write_error_response(
                    &mut tls_downstream,
                    "08000",
                    "upstream PostgreSQL server refused TLS",
                )
                .await?;
                return Err(ProxyError::Tls(
                    "upstream Postgres server rejected SSLRequest".into(),
                ));
            }

            let root_store = match &self.config.upstream_root_store {
                Some(custom) => (**custom).clone(),
                None => RootCertStore {
                    roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
                },
            };
            let client_cfg = Arc::new(
                ClientConfig::builder_with_provider(Arc::new(
                    rustls::crypto::ring::default_provider(),
                ))
                .with_safe_default_protocol_versions()
                .map_err(|e| ProxyError::Tls(format!("upstream TLS config failed: {e}")))?
                .with_root_certificates(root_store)
                .with_no_client_auth(),
            );
            let connector = TlsConnector::from(client_cfg);
            let sni = ServerName::try_from(target_host.to_string()).map_err(|e| {
                ProxyError::Tls(format!("invalid upstream Postgres SNI '{target_host}': {e}"))
            })?;
            let upstream_tls = connector.connect(sni, upstream_tcp).await.map_err(|e| {
                ProxyError::Tls(format!("upstream Postgres TLS handshake failed: {e}"))
            })?;

            self.authenticate_and_relay(
                tls_downstream,
                upstream_tls,
                &startup_packet,
                real_password,
                target_host,
                target_port,
            )
            .await
        } else {
            self.authenticate_and_relay(
                tls_downstream,
                upstream_tcp,
                &startup_packet,
                real_password,
                target_host,
                target_port,
            )
            .await
        }
    }

    async fn authenticate_and_relay<D, U>(
        &self,
        mut downstream: D,
        mut upstream: U,
        startup_packet: &[u8],
        real_password: Zeroizing<String>,
        target_host: &str,
        target_port: u16,
    ) -> Result<()>
    where
        D: AsyncRead + AsyncWrite + Unpin + Send,
        U: AsyncRead + AsyncWrite + Unpin + Send,
    {
        // Forward StartupMessage to upstream Postgres.
        upstream.write_all(startup_packet).await?;
        upstream.flush().await?;

        // Execute upstream SCRAM-SHA-256 authentication handshake.
        perform_upstream_scram_sha256(&mut upstream, &mut downstream, &real_password).await?;
        drop(real_password);

        // Authenticated! Relay bidirectionally while auditing Frontend Q/P/B/E SQL frames.
        let (mut down_read, mut down_write) = tokio::io::split(downstream);
        let (mut up_read, mut up_write) = tokio::io::split(upstream);

        let audit_sink = Arc::clone(&self.audit_sink);
        let sandbox_id = self.config.sandbox_id.clone();
        let host = target_host.to_string();

        let client_to_server = async move {
            loop {
                let (msg_type, body) = match read_typed_msg_opt(&mut down_read).await? {
                    Some(msg) => msg,
                    None => break,
                };

                if let Some((ch, statement)) = extract_sql_audit_event(msg_type, &body) {
                    audit_sink.record(AuditEvent::now(
                        &sandbox_id,
                        AuditEventKind::PostgresQuery {
                            host: host.clone(),
                            port: target_port,
                            message_type: ch,
                            statement,
                        },
                    ));
                }

                write_typed_msg(&mut up_write, msg_type, &body).await?;
                if msg_type == b'X' {
                    break;
                }
            }
            let _ = up_write.shutdown().await;
            Result::Ok(())
        };

        let server_to_client = async move {
            let _ = tokio::io::copy(&mut up_read, &mut down_write).await?;
            let _ = down_write.shutdown().await;
            Result::Ok(())
        };

        let (r1, r2) = tokio::join!(client_to_server, server_to_client);
        r1?;
        r2?;
        Ok(())
    }
}

/// Complete upstream PostgreSQL `SCRAM-SHA-256` handshake (RFC 5802 / RFC 7677).
async fn perform_upstream_scram_sha256<U, D>(
    upstream: &mut U,
    downstream: &mut D,
    real_password: &Zeroizing<String>,
) -> Result<()>
where
    U: AsyncRead + AsyncWrite + Unpin,
    D: AsyncRead + AsyncWrite + Unpin,
{
    let mut client_nonce = String::new();
    let mut client_first_bare = String::new();
    let mut expected_server_sig: Option<[u8; 32]> = None;
    let mut server_sig_verified = false;

    loop {
        let (msg_type, body) = read_typed_msg(upstream).await?;
        match msg_type {
            b'E' => {
                // Forward upstream ErrorResponse to downstream.
                write_typed_msg(downstream, b'E', &body).await?;
                return Err(ProxyError::AuthFailed(
                    "upstream PostgreSQL returned ErrorResponse during auth".into(),
                ));
            }
            b'R' => {
                if body.len() < 4 {
                    return Err(ProxyError::Postgres(
                        "truncated Authentication message from upstream".into(),
                    ));
                }
                let auth_type = i32::from_be_bytes([body[0], body[1], body[2], body[3]]);
                let rest = &body[4..];
                match auth_type {
                    PG_AUTH_OK => {
                        if expected_server_sig.is_some() && !server_sig_verified {
                            return Err(ProxyError::AuthFailed(
                                "upstream sent AuthenticationOk without verified SCRAM ServerSignature"
                                    .into(),
                            ));
                        }
                        write_backend_msg(downstream, b'R', &PG_AUTH_OK.to_be_bytes()).await?;
                        return Ok(());
                    }
                    PG_AUTH_SASL => {
                        let mechanisms = parse_cstr_list(rest);
                        if !mechanisms.iter().any(|m| m == "SCRAM-SHA-256") {
                            return Err(ProxyError::AuthFailed(format!(
                                "upstream SASL mechanisms {mechanisms:?} do not include SCRAM-SHA-256"
                            )));
                        }
                        let mut nonce_bytes = [0u8; 18];
                        rand::thread_rng().fill_bytes(&mut nonce_bytes);
                        client_nonce = BASE64.encode(nonce_bytes);
                        client_first_bare = format!("n=,r={client_nonce}");
                        let client_first_msg = format!("n,,{client_first_bare}");

                        let mut payload = Vec::new();
                        payload.extend_from_slice(b"SCRAM-SHA-256\0");
                        payload.extend_from_slice(&(client_first_msg.len() as i32).to_be_bytes());
                        payload.extend_from_slice(client_first_msg.as_bytes());
                        write_typed_msg(upstream, b'p', &payload).await?;
                    }
                    PG_AUTH_SASL_CONTINUE => {
                        let server_first = std::str::from_utf8(rest).map_err(|_| {
                            ProxyError::Postgres("non-UTF8 SCRAM server-first-message".into())
                        })?;
                        let (client_final, server_sig) = compute_scram_client_final(
                            real_password.as_str(),
                            &client_nonce,
                            &client_first_bare,
                            server_first,
                        )?;
                        expected_server_sig = Some(server_sig);
                        write_typed_msg(upstream, b'p', client_final.as_bytes()).await?;
                    }
                    PG_AUTH_SASL_FINAL => {
                        let server_final = std::str::from_utf8(rest).map_err(|_| {
                            ProxyError::Postgres("non-UTF8 SCRAM server-final-message".into())
                        })?;
                        let expected = expected_server_sig.ok_or_else(|| {
                            ProxyError::Postgres("unexpected AuthenticationSASLFinal".into())
                        })?;
                        verify_scram_server_final(server_final, &expected)?;
                        server_sig_verified = true;
                    }
                    other => {
                        return Err(ProxyError::AuthFailed(format!(
                            "unsupported upstream PostgreSQL auth type {other} (SCRAM-SHA-256 required)"
                        )));
                    }
                }
            }
            other => {
                return Err(ProxyError::Postgres(format!(
                    "unexpected backend message 0x{other:02x} during upstream auth"
                )));
            }
        }
    }
}

/// Compute `client-final-message` and expected 32-byte `ServerSignature` for SCRAM-SHA-256.
pub fn compute_scram_client_final(
    password: &str,
    client_nonce: &str,
    client_first_bare: &str,
    server_first: &str,
) -> Result<(String, [u8; 32])> {
    let mut full_nonce: Option<&str> = None;
    let mut salt_b64: Option<&str> = None;
    let mut iterations: Option<u32> = None;

    for part in server_first.split(',') {
        if let Some(v) = part.strip_prefix("r=") {
            full_nonce = Some(v);
        } else if let Some(v) = part.strip_prefix("s=") {
            salt_b64 = Some(v);
        } else if let Some(v) = part.strip_prefix("i=") {
            iterations = v.parse::<u32>().ok();
        }
    }

    let full_nonce = full_nonce
        .ok_or_else(|| ProxyError::Postgres("missing nonce 'r=' in SCRAM server-first".into()))?;
    if !full_nonce.starts_with(client_nonce) || full_nonce.len() <= client_nonce.len() {
        return Err(ProxyError::AuthFailed(
            "SCRAM server nonce does not extend client nonce".into(),
        ));
    }
    let salt_b64 = salt_b64
        .ok_or_else(|| ProxyError::Postgres("missing salt 's=' in SCRAM server-first".into()))?;
    let salt = BASE64
        .decode(salt_b64)
        .map_err(|e| ProxyError::Postgres(format!("invalid SCRAM base64 salt: {e}")))?;
    let iterations = iterations
        .filter(|&i| i >= 1)
        .ok_or_else(|| ProxyError::Postgres("missing or zero SCRAM iteration count".into()))?;

    let mut salted_password =
        Zeroizing::new(pbkdf2_hmac_array::<Sha256, 32>(password.as_bytes(), &salt, iterations));

    let client_key = hmac_sha256(&*salted_password, b"Client Key");
    let stored_key: [u8; 32] = Sha256::digest(client_key).into();

    // "biws" = base64("n,,") (no channel binding)
    let client_final_without_proof = format!("c=biws,r={full_nonce}");
    let auth_message = format!("{client_first_bare},{server_first},{client_final_without_proof}");

    let client_signature = hmac_sha256(&stored_key, auth_message.as_bytes());
    let mut client_proof = [0u8; 32];
    for i in 0..32 {
        client_proof[i] = client_key[i] ^ client_signature[i];
    }

    let server_key = hmac_sha256(&*salted_password, b"Server Key");
    let expected_server_sig = hmac_sha256(&server_key, auth_message.as_bytes());
    salted_password.fill(0);

    let client_final = format!(
        "{client_final_without_proof},p={}",
        BASE64.encode(client_proof)
    );
    Ok((client_final, expected_server_sig))
}

/// Verify the `v=<base64>` server signature from `server-final-message` in constant time.
pub fn verify_scram_server_final(server_final: &str, expected_sig: &[u8; 32]) -> Result<()> {
    let sig_b64 = server_final
        .split(',')
        .find_map(|p| p.strip_prefix("v="))
        .ok_or_else(|| {
            ProxyError::AuthFailed(format!(
                "SCRAM server-final missing 'v=' signature: {server_final}"
            ))
        })?;
    let sig_bytes = BASE64
        .decode(sig_b64)
        .map_err(|e| ProxyError::AuthFailed(format!("invalid SCRAM server signature b64: {e}")))?;
    if sig_bytes.len() != 32 || !bool::from(sig_bytes.as_slice().ct_eq(expected_sig.as_slice())) {
        return Err(ProxyError::AuthFailed(
            "SCRAM-SHA-256 ServerSignature verification failed".into(),
        ));
    }
    Ok(())
}

fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg);
    mac.finalize().into_bytes().into()
}

/// Extract structured SQL audit information from Frontend `'Q'`, `'P'`, `'B'`, and `'E'` frames.
pub fn extract_sql_audit_event(msg_type: u8, body: &[u8]) -> Option<(char, String)> {
    match msg_type {
        b'Q' => {
            let sql = parse_cstr(body)?;
            Some(('Q', sql))
        }
        b'P' => {
            let (stmt_name, rest) = split_cstr(body)?;
            let (query, _) = split_cstr(rest)?;
            let desc = if stmt_name.is_empty() {
                query
            } else {
                format!("{stmt_name}: {query}")
            };
            Some(('P', desc))
        }
        b'B' => {
            let (portal, rest) = split_cstr(body)?;
            let (stmt_name, _) = split_cstr(rest)?;
            Some(('B', format!("portal={portal} stmt={stmt_name}")))
        }
        b'E' => {
            let (portal, rest) = split_cstr(body)?;
            let max_rows = if rest.len() >= 4 {
                i32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]])
            } else {
                0
            };
            Some(('E', format!("portal={portal} max_rows={max_rows}")))
        }
        _ => None,
    }
}

fn parse_cstr(buf: &[u8]) -> Option<String> {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8(buf[..end].to_vec()).ok()
}

fn split_cstr(buf: &[u8]) -> Option<(String, &[u8])> {
    let pos = buf.iter().position(|&b| b == 0)?;
    let s = String::from_utf8(buf[..pos].to_vec()).ok()?;
    Some((s, &buf[pos + 1..]))
}

fn parse_cstr_list(mut buf: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    while !buf.is_empty() && buf[0] != 0 {
        if let Some((s, rest)) = split_cstr(buf) {
            out.push(s);
            buf = rest;
        } else {
            break;
        }
    }
    out
}

async fn read_startup_packet<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let total_len = u32::from_be_bytes(len_buf) as usize;
    if !(8..=MAX_PG_STARTUP_LEN).contains(&total_len) {
        return Err(ProxyError::Postgres(format!(
            "invalid startup packet length {total_len}"
        )));
    }
    let mut packet = vec![0u8; total_len];
    packet[0..4].copy_from_slice(&len_buf);
    reader.read_exact(&mut packet[4..]).await?;
    Ok(packet)
}

async fn read_typed_msg<R: AsyncRead + Unpin>(reader: &mut R) -> Result<(u8, Vec<u8>)> {
    read_typed_msg_opt(reader)
        .await?
        .ok_or_else(|| ProxyError::Postgres("unexpected EOF reading Postgres frame".into()))
}

async fn read_typed_msg_opt<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Option<(u8, Vec<u8>)>> {
    let mut hdr = [0u8; 5];
    match reader.read_exact(&mut hdr[0..1]).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(ProxyError::Io(e)),
    }
    reader.read_exact(&mut hdr[1..5]).await?;
    let msg_type = hdr[0];
    let len = u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]) as usize;
    if !(4..=MAX_PG_MSG_LEN).contains(&len) {
        return Err(ProxyError::Postgres(format!(
            "invalid Postgres message length {len}"
        )));
    }
    let mut body = vec![0u8; len - 4];
    if !body.is_empty() {
        reader.read_exact(&mut body).await?;
    }
    Ok(Some((msg_type, body)))
}

async fn write_typed_msg<W: AsyncWrite + Unpin>(
    writer: &mut W,
    msg_type: u8,
    body: &[u8],
) -> Result<()> {
    let len = (body.len() + 4) as u32;
    writer.write_all(&[msg_type]).await?;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(body).await?;
    writer.flush().await?;
    Ok(())
}

async fn write_backend_msg<W: AsyncWrite + Unpin>(
    writer: &mut W,
    msg_type: u8,
    body: &[u8],
) -> Result<()> {
    write_typed_msg(writer, msg_type, body).await
}

async fn write_error_response<W: AsyncWrite + Unpin>(
    writer: &mut W,
    sqlstate: &str,
    message: &str,
) -> Result<()> {
    let mut body = Vec::new();
    body.push(b'S');
    body.extend_from_slice(b"FATAL\0");
    body.push(b'C');
    body.extend_from_slice(sqlstate.as_bytes());
    body.push(0);
    body.push(b'M');
    body.extend_from_slice(message.as_bytes());
    body.push(0);
    body.push(0);
    write_typed_msg(writer, b'E', &body).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::InMemorySecretResolver;
    use blackwall_audit::MemoryAuditSink;
    use std::net::SocketAddr;

    /// In-process mock PostgreSQL v3 server enforcing TLS (`SSLRequest`) and real `SCRAM-SHA-256`!
    async fn spawn_mock_scram_postgres(
        upstream_ca: Arc<EphemeralCa>,
        expected_password: String,
    ) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            loop {
                let Ok((mut tcp, _)) = listener.accept().await else {
                    break;
                };
                let ca = Arc::clone(&upstream_ca);
                let pw = expected_password.clone();
                tokio::spawn(async move {
                    // 1. SSLRequest -> 'S' -> TLS
                    let ssl_pkt = read_startup_packet(&mut tcp).await.unwrap();
                    assert_eq!(
                        i32::from_be_bytes([ssl_pkt[4], ssl_pkt[5], ssl_pkt[6], ssl_pkt[7]]),
                        PG_SSL_REQUEST_CODE
                    );
                    tcp.write_all(b"S").await.unwrap();
                    let acceptor = TlsAcceptor::from(ca.server_config(vec![]).unwrap());
                    let mut stream = acceptor.accept(tcp).await.unwrap();

                    // 2. StartupMessage
                    let startup = read_startup_packet(&mut stream).await.unwrap();
                    assert_eq!(
                        i32::from_be_bytes([startup[4], startup[5], startup[6], startup[7]]),
                        PG_PROTOCOL_V3
                    );

                    // 3. Send AuthenticationSASL ("SCRAM-SHA-256")
                    let mut sasl_body = Vec::new();
                    sasl_body.extend_from_slice(&PG_AUTH_SASL.to_be_bytes());
                    sasl_body.extend_from_slice(b"SCRAM-SHA-256\0\0");
                    write_typed_msg(&mut stream, b'R', &sasl_body).await.unwrap();

                    // 4. Read SASLInitialResponse ('p')
                    let (t, init_body) = read_typed_msg(&mut stream).await.unwrap();
                    assert_eq!(t, b'p');
                    let (mech, rest) = split_cstr(&init_body).unwrap();
                    assert_eq!(mech, "SCRAM-SHA-256");
                    let msg_len =
                        i32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
                    let client_first = std::str::from_utf8(&rest[4..4 + msg_len]).unwrap();
                    let client_first_bare = client_first.strip_prefix("n,,").unwrap();
                    let c_nonce = client_first_bare
                        .split(',')
                        .find_map(|p| p.strip_prefix("r="))
                        .unwrap();

                    // 5. Send AuthenticationSASLContinue
                    let salt = b"blackwall_pg_salt_16";
                    let iterations = 4096u32;
                    let full_nonce = format!("{c_nonce}SERVERNONCE12345");
                    let server_first = format!(
                        "r={full_nonce},s={},i={iterations}",
                        BASE64.encode(salt)
                    );
                    let mut cont_body = Vec::new();
                    cont_body.extend_from_slice(&PG_AUTH_SASL_CONTINUE.to_be_bytes());
                    cont_body.extend_from_slice(server_first.as_bytes());
                    write_typed_msg(&mut stream, b'R', &cont_body).await.unwrap();

                    // 6. Read SASLResponse ('p') and verify ClientProof!
                    let (t2, final_body) = read_typed_msg(&mut stream).await.unwrap();
                    assert_eq!(t2, b'p');
                    let client_final = std::str::from_utf8(&final_body).unwrap();
                    let proof_b64 = client_final
                        .split(',')
                        .find_map(|p| p.strip_prefix("p="))
                        .unwrap();
                    let proof = BASE64.decode(proof_b64).unwrap();

                    let salted =
                        pbkdf2_hmac_array::<Sha256, 32>(pw.as_bytes(), salt, iterations);
                    let client_key = hmac_sha256(&salted, b"Client Key");
                    let stored_key: [u8; 32] = Sha256::digest(client_key).into();
                    let client_final_no_proof = format!("c=biws,r={full_nonce}");
                    let auth_msg =
                        format!("{client_first_bare},{server_first},{client_final_no_proof}");
                    let client_sig = hmac_sha256(&stored_key, auth_msg.as_bytes());
                    let mut recovered_key = [0u8; 32];
                    for i in 0..32 {
                        recovered_key[i] = proof[i] ^ client_sig[i];
                    }
                    let recovered_stored: [u8; 32] = Sha256::digest(recovered_key).into();
                    assert_eq!(recovered_stored, stored_key, "SCRAM ClientProof mismatch");

                    // 7. Send AuthenticationSASLFinal + AuthenticationOk + ReadyForQuery ('Z')
                    let server_key = hmac_sha256(&salted, b"Server Key");
                    let server_sig = hmac_sha256(&server_key, auth_msg.as_bytes());
                    let server_final = format!("v={}", BASE64.encode(server_sig));
                    let mut final_auth = Vec::new();
                    final_auth.extend_from_slice(&PG_AUTH_SASL_FINAL.to_be_bytes());
                    final_auth.extend_from_slice(server_final.as_bytes());
                    write_typed_msg(&mut stream, b'R', &final_auth)
                        .await
                        .unwrap();
                    write_typed_msg(&mut stream, b'R', &PG_AUTH_OK.to_be_bytes())
                        .await
                        .unwrap();
                    write_typed_msg(&mut stream, b'Z', b"I").await.unwrap();

                    // 8. Respond to Q/P/B/E frames with CommandComplete ('C') + ReadyForQuery ('Z')
                    while let Ok(Some((mt, _body))) = read_typed_msg_opt(&mut stream).await {
                        match mt {
                            b'Q' => {
                                write_typed_msg(&mut stream, b'C', b"SELECT 1\0")
                                    .await
                                    .unwrap();
                                write_typed_msg(&mut stream, b'Z', b"I").await.unwrap();
                            }
                            b'P' => {
                                write_typed_msg(&mut stream, b'1', &[]).await.unwrap();
                            }
                            b'B' => {
                                write_typed_msg(&mut stream, b'2', &[]).await.unwrap();
                            }
                            b'E' => {
                                write_typed_msg(&mut stream, b'C', b"EXECUTE 1\0")
                                    .await
                                    .unwrap();
                                write_typed_msg(&mut stream, b'Z', b"I").await.unwrap();
                            }
                            b'X' => break,
                            _ => {}
                        }
                    }
                });
            }
        });

        addr
    }

    fn build_startup_packet(user: &str, database: &str) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&PG_PROTOCOL_V3.to_be_bytes());
        payload.extend_from_slice(b"user\0");
        payload.extend_from_slice(user.as_bytes());
        payload.push(0);
        payload.extend_from_slice(b"database\0");
        payload.extend_from_slice(database.as_bytes());
        payload.push(0);
        payload.push(0);

        let total_len = (payload.len() + 4) as u32;
        let mut pkt = Vec::with_capacity(total_len as usize);
        pkt.extend_from_slice(&total_len.to_be_bytes());
        pkt.extend_from_slice(&payload);
        pkt
    }

    #[tokio::test]
    async fn end_to_end_postgres_tls_placeholder_scram_and_sql_audit() {
        let upstream_ca = Arc::new(EphemeralCa::generate("mock-upstream-pg").unwrap());
        let downstream_ca = Arc::new(EphemeralCa::generate("sb-pg-vm").unwrap());
        let pg_addr =
            spawn_mock_scram_postgres(upstream_ca.clone(), "REAL_DB_PASSWORD_99".into()).await;

        let mut secrets = InMemorySecretResolver::new();
        secrets.insert("PGPASSWORD", "bwpg_random_placeholder", "REAL_DB_PASSWORD_99");
        let secrets = Arc::new(secrets);
        let audit = Arc::new(MemoryAuditSink::new());

        let mut pinned = PinnedHostMap::new();
        pinned.insert("db.internal:5432".into(), vec![pg_addr]);

        let mut cfg = PostgresProxyConfig::new(
            "sb-pg-vm",
            vec![PostgresRule {
                host: "db.internal".into(),
                port: 5432,
                secret: "PGPASSWORD".into(),
                require_upstream_tls: true,
            }],
            pinned,
        );
        cfg.upstream_root_store = Some(Arc::new(upstream_ca.root_cert_store().unwrap()));

        let proxy = Arc::new(PostgresProxyServer::new(
            cfg,
            downstream_ca.clone(),
            secrets,
            audit.clone(),
        ));

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let proxy_clone = Arc::clone(&proxy);
        tokio::spawn(async move {
            let _ = proxy_clone
                .serve_tcp(proxy_listener, "db.internal".into(), 5432)
                .await;
        });

        let client_tls_cfg = Arc::new(
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(downstream_ca.root_cert_store().unwrap())
                .with_no_client_auth(),
        );
        let connector = TlsConnector::from(client_tls_cfg);

        // --- Test 1: Wrong placeholder is rejected with ErrorResponse + AuthMismatch ---
        {
            let mut tcp = TcpStream::connect(proxy_addr).await.unwrap();
            let mut ssl_req = [0u8; 8];
            ssl_req[0..4].copy_from_slice(&8i32.to_be_bytes());
            ssl_req[4..8].copy_from_slice(&PG_SSL_REQUEST_CODE.to_be_bytes());
            tcp.write_all(&ssl_req).await.unwrap();
            let mut b = [0u8; 1];
            tcp.read_exact(&mut b).await.unwrap();
            assert_eq!(b[0], b'S');

            let mut tls = connector
                .connect(ServerName::try_from("db.internal".to_string()).unwrap(), tcp)
                .await
                .unwrap();
            tls.write_all(&build_startup_packet("agent_ro", "app"))
                .await
                .unwrap();

            let (mt, body) = read_typed_msg(&mut tls).await.unwrap();
            assert_eq!(mt, b'R');
            assert_eq!(
                i32::from_be_bytes([body[0], body[1], body[2], body[3]]),
                PG_AUTH_CLEARTEXT_PASSWORD
            );

            // Send wrong attacker password
            write_typed_msg(&mut tls, b'p', b"wrong_password\0")
                .await
                .unwrap();
            let (err_t, err_body) = read_typed_msg(&mut tls).await.unwrap();
            assert_eq!(err_t, b'E', "expected ErrorResponse for wrong placeholder");
            assert!(String::from_utf8_lossy(&err_body).contains("28P01"));
        }

        // --- Test 2: Valid placeholder -> upstream SCRAM-SHA-256 -> Q/P/B/E SQL audit ---
        {
            let mut tcp = TcpStream::connect(proxy_addr).await.unwrap();
            let mut ssl_req = [0u8; 8];
            ssl_req[0..4].copy_from_slice(&8i32.to_be_bytes());
            ssl_req[4..8].copy_from_slice(&PG_SSL_REQUEST_CODE.to_be_bytes());
            tcp.write_all(&ssl_req).await.unwrap();
            let mut b = [0u8; 1];
            tcp.read_exact(&mut b).await.unwrap();
            assert_eq!(b[0], b'S');

            let mut tls = connector
                .connect(ServerName::try_from("db.internal".to_string()).unwrap(), tcp)
                .await
                .unwrap();
            tls.write_all(&build_startup_packet("agent_ro", "app"))
                .await
                .unwrap();

            // Expect AuthenticationCleartextPassword
            let (mt, body) = read_typed_msg(&mut tls).await.unwrap();
            assert_eq!(mt, b'R');
            assert_eq!(
                i32::from_be_bytes([body[0], body[1], body[2], body[3]]),
                PG_AUTH_CLEARTEXT_PASSWORD
            );

            // Send valid random placeholder
            write_typed_msg(&mut tls, b'p', b"bwpg_random_placeholder\0")
                .await
                .unwrap();

            // Expect AuthenticationOk + ReadyForQuery ('Z') from upstream after SCRAM!
            let (ok_t, ok_b) = read_typed_msg(&mut tls).await.unwrap();
            assert_eq!(ok_t, b'R');
            assert_eq!(
                i32::from_be_bytes([ok_b[0], ok_b[1], ok_b[2], ok_b[3]]),
                PG_AUTH_OK
            );
            let (z_t, _) = read_typed_msg(&mut tls).await.unwrap();
            assert_eq!(z_t, b'Z');

            // Send Simple Query ('Q')
            write_typed_msg(&mut tls, b'Q', b"SELECT 1;\0")
                .await
                .unwrap();
            assert_eq!(read_typed_msg(&mut tls).await.unwrap().0, b'C');
            assert_eq!(read_typed_msg(&mut tls).await.unwrap().0, b'Z');

            // Send Parse ('P'), Bind ('B'), Execute ('E')
            let mut parse_body = Vec::new();
            parse_body.extend_from_slice(b"s1\0SELECT id FROM users WHERE id = $1\0");
            parse_body.extend_from_slice(&0i16.to_be_bytes());
            write_typed_msg(&mut tls, b'P', &parse_body).await.unwrap();
            assert_eq!(read_typed_msg(&mut tls).await.unwrap().0, b'1');

            let mut bind_body = Vec::new();
            bind_body.extend_from_slice(b"p1\0s1\0");
            bind_body.extend_from_slice(&[0u8; 6]);
            write_typed_msg(&mut tls, b'B', &bind_body).await.unwrap();
            assert_eq!(read_typed_msg(&mut tls).await.unwrap().0, b'2');

            let mut exec_body = Vec::new();
            exec_body.extend_from_slice(b"p1\0");
            exec_body.extend_from_slice(&10i32.to_be_bytes());
            write_typed_msg(&mut tls, b'E', &exec_body).await.unwrap();
            assert_eq!(read_typed_msg(&mut tls).await.unwrap().0, b'C');
            assert_eq!(read_typed_msg(&mut tls).await.unwrap().0, b'Z');

            // Terminate ('X')
            write_typed_msg(&mut tls, b'X', &[]).await.unwrap();
        }

        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        let events = audit.snapshot();

        assert!(events
            .iter()
            .any(|e| matches!(&e.kind, AuditEventKind::AuthMismatch { host, .. } if host == "db.internal")));

        let pg_types: Vec<char> = events
            .iter()
            .filter_map(|e| match &e.kind {
                AuditEventKind::PostgresQuery { message_type, .. } => Some(*message_type),
                _ => None,
            })
            .collect();
        assert_eq!(pg_types, vec!['Q', 'P', 'B', 'E']);

        assert!(events.iter().any(|e| matches!(
            &e.kind,
            AuditEventKind::PostgresQuery {
                message_type: 'Q',
                statement,
                ..
            } if statement == "SELECT 1;"
        )));
        assert!(events.iter().any(|e| matches!(
            &e.kind,
            AuditEventKind::PostgresQuery {
                message_type: 'P',
                statement,
                ..
            } if statement.contains("SELECT id FROM users")
        )));
    }
}
