//! Pingora HTTP/1.1 & HTTP/2 reverse/MITM proxy (`BlackwallHttpProxy`).
//!
//! Security invariants enforced on every request:
//! 1. **Out-of-process resolver-pinned IP dialing:** `upstream_peer()` dials ONLY exact
//!    pre-resolved `SocketAddr`s from [`PinnedHostMap`] — Pingora NEVER resolves DNS.
//! 2. **Strict L7 Policy Enforcement:** Enforces `HttpRule` allowed host, HTTP `methods`,
//!    `path_prefixes`, and `max_request_bytes` (checked on both `Content-Length` and
//!    streaming request body chunks).
//! 3. **Mandatory Auth Stripping & Identity Pinning:** Whenever a matched `HttpRule` has
//!    `auth: Some(AuthSpec)`:
//!    - Constant-time verification that the guest presented its assigned per-VM random
//!      placeholder (`Authorization`, `x-api-key`, configured custom header, or Basic auth).
//!      On mismatch/missing placeholder, emits `AuditEventKind::AuthMismatch` and rejects
//!      with `403 Forbidden`.
//!    - Unconditionally strips ALL guest-supplied auth headers and cookies (`Authorization`,
//!      `Cookie`, `X-Api-Key`, `Proxy-Authorization`, `Proxy-Authenticate`,
//!      `x-amz-security-token`, `x-amz-credential`, `x-amz-signature`, `x-amz-date`, plus
//!      any custom configured auth header).
//!    - Injects the real brokered secret per `AuthSpec` (`Bearer`, `Header`, or `Basic`).
//! 4. **Authoritative Audit Emission:** Emits `AuditEventKind::HttpRequest` to `AuditSink`
//!    for every completed or rejected HTTP request.

use crate::ca::EphemeralCa;
use crate::secrets::SecretResolver;
use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use blackwall_audit::{AuditEvent, AuditEventKind, AuditSink};
use blackwall_policy::{AuthSpec, HttpRule};
use bytes::Bytes;
use pingora_core::listeners::tls::TlsSettings;
use pingora_core::server::configuration::ServerConf;
use pingora_core::services::listening::Service;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_error::{Error, ErrorType, Result as PingoraResult};
use pingora_http::RequestHeader;
use pingora_proxy::{http_proxy_service, HttpProxy, ProxyHttp, Session};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use zeroize::Zeroizing;

/// Out-of-process resolver-pinned IP endpoints keyed by lowercase hostname (or `host:port`).
pub type PinnedHostMap = BTreeMap<String, Vec<SocketAddr>>;

/// Headers unconditionally stripped whenever an `HttpRule` specifies `auth: Some(...)`.
pub const STRIPPED_AUTH_HEADERS: &[&str] = &[
    "authorization",
    "cookie",
    "x-api-key",
    "proxy-authorization",
    "proxy-authenticate",
    "x-amz-security-token",
    "x-amz-credential",
    "x-amz-signature",
    "x-amz-date",
];

/// Configuration for [`BlackwallHttpProxy`].
#[derive(Debug, Clone)]
pub struct HttpProxyConfig {
    pub sandbox_id: String,
    pub rules: Vec<HttpRule>,
    pub pinned_hosts: PinnedHostMap,
    /// Use TLS when dialing upstream pinned endpoints (always `true` in production).
    pub upstream_tls: bool,
    /// Verify upstream TLS certificate & hostname (always `true` in production).
    pub verify_upstream_cert: bool,
}

impl HttpProxyConfig {
    pub fn new(
        sandbox_id: impl Into<String>,
        rules: Vec<HttpRule>,
        pinned_hosts: PinnedHostMap,
    ) -> Self {
        Self {
            sandbox_id: sandbox_id.into(),
            rules,
            pinned_hosts,
            upstream_tls: true,
            verify_upstream_cert: true,
        }
    }
}

/// Successful policy evaluation outcome for an incoming HTTP request.
#[derive(Debug)]
pub struct PolicyDecision {
    pub matched_rule: HttpRule,
    pub host: String,
    pub port: u16,
    pub pinned_addr: SocketAddr,
    pub injected_header: Option<(String, Zeroizing<String>)>,
    pub custom_strip_header: Option<String>,
}

/// Reason why an HTTP request was rejected by policy or authentication pinning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRejection {
    pub status: u16,
    pub reason: String,
    pub is_auth_mismatch: bool,
}

impl PolicyRejection {
    fn forbidden(reason: impl Into<String>) -> Self {
        Self {
            status: 403,
            reason: reason.into(),
            is_auth_mismatch: false,
        }
    }

    fn auth_mismatch(reason: impl Into<String>) -> Self {
        Self {
            status: 403,
            reason: reason.into(),
            is_auth_mismatch: true,
        }
    }

    fn payload_too_large(reason: impl Into<String>) -> Self {
        Self {
            status: 413,
            reason: reason.into(),
            is_auth_mismatch: false,
        }
    }
}

/// Extract lowercase hostname and optional explicit port from an HTTP request header.
pub fn extract_host_and_port(req: &RequestHeader) -> Option<(String, Option<u16>)> {
    if let Some(host_val) = req.headers.get("host").and_then(|v| v.to_str().ok()) {
        if let Some(parsed) = parse_host_port(host_val) {
            return Some(parsed);
        }
    }
    if let Some(authority) = req.uri.authority() {
        return Some((
            authority.host().trim_end_matches('.').to_ascii_lowercase(),
            authority.port_u16(),
        ));
    }
    None
}

fn parse_host_port(raw: &str) -> Option<(String, Option<u16>)> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(rest) = trimmed.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = rest[..end].to_ascii_lowercase();
        let after = &rest[end + 1..];
        let port = if let Some(p) = after.strip_prefix(':') {
            Some(p.parse::<u16>().ok()?)
        } else {
            None
        };
        return Some((host, port));
    }
    if let Some((h, p)) = trimmed.rsplit_once(':') {
        if !h.contains(':') {
            if let Ok(port) = p.parse::<u16>() {
                return Some((h.trim_end_matches('.').to_ascii_lowercase(), Some(port)));
            }
        }
    }
    Some((trimmed.trim_end_matches('.').to_ascii_lowercase(), None))
}

/// Lookup an exact resolver-pinned [`SocketAddr`] for `(host, port)` without ever doing DNS.
pub fn lookup_pinned_addr(
    pinned_hosts: &PinnedHostMap,
    host: &str,
    port: u16,
) -> Option<SocketAddr> {
    let host_lower = host.trim_end_matches('.').to_ascii_lowercase();
    let host_port_key = format!("{host_lower}:{port}");

    if let Some(addrs) = pinned_hosts.get(&host_port_key) {
        if let Some(&addr) = addrs.first() {
            return Some(addr);
        }
    }
    if let Some(addrs) = pinned_hosts.get(&host_lower) {
        // Prefer an entry whose port matches; otherwise use the first pinned IP with `port`.
        if let Some(&exact) = addrs.iter().find(|a| a.port() == port) {
            return Some(exact);
        }
        if let Some(&first) = addrs.first() {
            return Some(first);
        }
    }
    None
}

/// Normalize path (rejecting traversal segments like `/../`) and match against a policy prefix.
fn path_matches_prefix(path: &str, prefix: &str) -> bool {
    if !path.starts_with('/') {
        return false;
    }
    // Reject obvious dot-segment traversal attempts before prefix matching.
    if path.split('/').any(|seg| seg == "..") {
        return false;
    }
    path.starts_with(prefix)
}

/// Extract the guest-presented placeholder token from `req` for a given [`AuthSpec`].
fn extract_guest_placeholder(req: &RequestHeader, auth: &AuthSpec) -> Option<String> {
    match auth {
        AuthSpec::Bearer { .. } => {
            if let Some(val) = req
                .headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
            {
                let trimmed = val.trim();
                if let Some(tok) = trimmed
                    .strip_prefix("Bearer ")
                    .or_else(|| trimmed.strip_prefix("bearer "))
                {
                    return Some(tok.trim().to_string());
                }
                return Some(trimmed.to_string());
            }
            if let Some(val) = req.headers.get("x-api-key").and_then(|v| v.to_str().ok()) {
                return Some(val.trim().to_string());
            }
            None
        }
        AuthSpec::Header { name, prefix, .. } => {
            let hdr_name = name.to_ascii_lowercase();
            if let Some(val) = req.headers.get(&hdr_name).and_then(|v| v.to_str().ok()) {
                let trimmed = val.trim();
                if let Some(pfx) = prefix {
                    return trimmed.strip_prefix(pfx.as_str()).map(|s| s.to_string());
                }
                return Some(trimmed.to_string());
            }
            None
        }
        AuthSpec::Basic { .. } => {
            let val = req
                .headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())?;
            let trimmed = val.trim();
            let b64 = trimmed
                .strip_prefix("Basic ")
                .or_else(|| trimmed.strip_prefix("basic "))?
                .trim();
            let decoded = BASE64.decode(b64).ok()?;
            let creds = String::from_utf8(decoded).ok()?;
            let (_user, pass) = creds.split_once(':')?;
            Some(pass.to_string())
        }
    }
}

/// Evaluate an HTTP request against `rules`, `pinned_hosts`, and `secrets`.
///
/// Pure policy/auth decision function reusable both inside Pingora's `request_filter`
/// and in unit tests.
pub fn evaluate_http_request(
    req: &RequestHeader,
    rules: &[HttpRule],
    pinned_hosts: &PinnedHostMap,
    secrets: &dyn SecretResolver,
) -> std::result::Result<PolicyDecision, PolicyRejection> {
    let (host, req_port) = extract_host_and_port(req)
        .ok_or_else(|| PolicyRejection::forbidden("missing or invalid Host header"))?;
    let method = req.method.as_str().to_ascii_uppercase();
    let path = req.uri.path();

    // 1. Host filter
    let host_rules: Vec<&HttpRule> = rules
        .iter()
        .filter(|r| r.host.eq_ignore_ascii_case(&host))
        .collect();
    if host_rules.is_empty() {
        return Err(PolicyRejection::forbidden(format!(
            "host '{host}' is not allowlisted"
        )));
    }

    // 2. Path prefix filter (select longest matching prefix)
    let mut prefix_matches: Vec<&HttpRule> = host_rules
        .into_iter()
        .filter(|r| r.path_prefixes.iter().any(|p| path_matches_prefix(path, p)))
        .collect();
    if prefix_matches.is_empty() {
        return Err(PolicyRejection::forbidden(format!(
            "path '{path}' on host '{host}' does not match any allowed path_prefixes"
        )));
    }
    prefix_matches.sort_by_key(|r| {
        std::cmp::Reverse(
            r.path_prefixes
                .iter()
                .filter(|p| path_matches_prefix(path, p))
                .map(|p| p.len())
                .max()
                .unwrap_or(0),
        )
    });

    // 3. Method filter
    let matched_rule = prefix_matches
        .into_iter()
        .find(|r| r.methods.iter().any(|m| m.eq_ignore_ascii_case(&method)))
        .ok_or_else(|| {
            PolicyRejection::forbidden(format!(
                "HTTP method '{method}' is not allowed for '{host}{path}'"
            ))
        })?
        .clone();

    // 4. Content-Length check against max_request_bytes (streaming body also enforced in request_body_filter)
    if let Some(limit) = matched_rule.max_request_bytes {
        if let Some(cl_val) = req
            .headers
            .get("content-length")
            .and_then(|v| v.to_str().ok())
        {
            if let Ok(cl) = cl_val.trim().parse::<u64>() {
                if cl > limit {
                    return Err(PolicyRejection::payload_too_large(format!(
                        "Content-Length {cl} exceeds max_request_bytes {limit}"
                    )));
                }
            }
        }
    }

    // 5. Resolver-pinned IP lookup (fail-closed, zero DNS inside proxy)
    let target_port = req_port.unwrap_or(matched_rule.port);
    let pinned_addr = lookup_pinned_addr(pinned_hosts, &host, target_port).ok_or_else(|| {
        PolicyRejection::forbidden(format!(
            "host '{host}:{target_port}' has no resolver-pinned upstream IP"
        ))
    })?;

    // 6. Mandatory Auth Pinning & Brokered Credential Resolution
    let (injected_header, custom_strip_header) = if let Some(auth_spec) = &matched_rule.auth {
        let secret_name = auth_spec.secret_name();
        let presented = extract_guest_placeholder(req, auth_spec).ok_or_else(|| {
            PolicyRejection::auth_mismatch(format!(
                "missing guest placeholder credential for secret '{secret_name}'"
            ))
        })?;

        if !secrets.verify_placeholder(secret_name, &presented) {
            return Err(PolicyRejection::auth_mismatch(format!(
                "guest presented invalid or third-party credential for secret '{secret_name}'"
            )));
        }

        let real_secret = secrets.resolve_secret(secret_name).ok_or_else(|| {
            PolicyRejection::auth_mismatch(format!(
                "brokered secret '{secret_name}' not loaded in proxy secret store"
            ))
        })?;

        match auth_spec {
            AuthSpec::Bearer { .. } => (
                Some((
                    "authorization".to_string(),
                    Zeroizing::new(format!("Bearer {}", real_secret.as_str())),
                )),
                None,
            ),
            AuthSpec::Header { name, prefix, .. } => {
                let hdr = name.to_ascii_lowercase();
                let val = match prefix {
                    Some(p) => Zeroizing::new(format!("{p}{}", real_secret.as_str())),
                    None => real_secret,
                };
                (Some((hdr.clone(), val)), Some(hdr))
            }
            AuthSpec::Basic { username, .. } => {
                let raw = Zeroizing::new(format!("{username}:{}", real_secret.as_str()));
                let encoded = BASE64.encode(raw.as_bytes());
                (
                    Some((
                        "authorization".to_string(),
                        Zeroizing::new(format!("Basic {encoded}")),
                    )),
                    None,
                )
            }
        }
    } else {
        (None, None)
    };

    Ok(PolicyDecision {
        matched_rule,
        host,
        port: target_port,
        pinned_addr,
        injected_header,
        custom_strip_header,
    })
}

/// Apply mandatory auth stripping and brokered credential injection to an upstream
/// Pingora [`RequestHeader`].
pub fn apply_auth_rewrite(upstream_req: &mut RequestHeader, decision: &PolicyDecision) -> bool {
    if decision.matched_rule.auth.is_none() {
        return false;
    }

    // Unconditionally strip all guest-supplied auth headers and cookies.
    for &hdr in STRIPPED_AUTH_HEADERS {
        upstream_req.remove_header(hdr);
    }
    if let Some(custom) = &decision.custom_strip_header {
        upstream_req.remove_header(custom.as_str());
    }

    if let Some((hdr_name, hdr_val)) = &decision.injected_header {
        let _ = upstream_req.insert_header(hdr_name.clone(), hdr_val.as_str());
        true
    } else {
        false
    }
}

/// Per-request state carried across Pingora `ProxyHttp` phases.
#[derive(Default)]
pub struct ProxyRequestCtx {
    pub host: String,
    pub method: String,
    pub path: String,
    pub decision: Option<PolicyDecision>,
    pub request_bytes: u64,
    pub response_bytes: u64,
    pub status: u16,
    pub auth_injected: bool,
}

/// Pingora [`ProxyHttp`] implementation enforcing Blackwall HTTP policy, resolver-pinned
/// dialing, mandatory auth stripping/pinning, and `AuditSink` telemetry.
pub struct BlackwallHttpProxy {
    config: HttpProxyConfig,
    secrets: Arc<dyn SecretResolver>,
    audit_sink: Arc<dyn AuditSink>,
}

impl BlackwallHttpProxy {
    pub fn new(
        config: HttpProxyConfig,
        secrets: Arc<dyn SecretResolver>,
        audit_sink: Arc<dyn AuditSink>,
    ) -> Self {
        Self {
            config,
            secrets,
            audit_sink,
        }
    }

    pub fn config(&self) -> &HttpProxyConfig {
        &self.config
    }
}

#[async_trait]
impl ProxyHttp for BlackwallHttpProxy {
    type CTX = ProxyRequestCtx;

    fn new_ctx(&self) -> Self::CTX {
        ProxyRequestCtx::default()
    }

    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> PingoraResult<bool> {
        let req_header = session.req_header();
        ctx.method = req_header.method.as_str().to_string();
        ctx.path = req_header.uri.path().to_string();
        ctx.host = extract_host_and_port(req_header)
            .map(|(h, _)| h)
            .unwrap_or_default();

        match evaluate_http_request(
            req_header,
            &self.config.rules,
            &self.config.pinned_hosts,
            self.secrets.as_ref(),
        ) {
            Ok(decision) => {
                ctx.host = decision.host.clone();
                ctx.decision = Some(decision);
                Ok(false)
            }
            Err(rej) => {
                ctx.status = rej.status;
                if rej.is_auth_mismatch {
                    self.audit_sink.record(AuditEvent::now(
                        &self.config.sandbox_id,
                        AuditEventKind::AuthMismatch {
                            host: ctx.host.clone(),
                            path: ctx.path.clone(),
                            reason: rej.reason.clone(),
                        },
                    ));
                }
                let _ = session
                    .respond_error_with_body(rej.status, Bytes::from(rej.reason))
                    .await;
                Ok(true)
            }
        }
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> PingoraResult<Box<HttpPeer>> {
        let decision = ctx.decision.as_ref().ok_or_else(|| {
            Error::explain(
                ErrorType::InternalError,
                "upstream_peer called without approved policy decision",
            )
        })?;

        // Dial the exact pre-resolved SocketAddr directly — NEVER resolves DNS!
        let mut peer = Box::new(HttpPeer::new(
            decision.pinned_addr,
            self.config.upstream_tls,
            decision.host.clone(),
        ));
        peer.options.verify_cert = self.config.verify_upstream_cert;
        peer.options.verify_hostname = self.config.verify_upstream_cert;
        Ok(peer)
    }

    async fn request_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> PingoraResult<()> {
        if let Some(chunk) = body.as_ref() {
            ctx.request_bytes = ctx.request_bytes.saturating_add(chunk.len() as u64);
            if let Some(limit) = ctx
                .decision
                .as_ref()
                .and_then(|d| d.matched_rule.max_request_bytes)
            {
                if ctx.request_bytes > limit {
                    ctx.status = 413;
                    return Err(Error::explain(
                        ErrorType::HTTPStatus(413),
                        format!(
                            "request body size {} exceeds max_request_bytes {}",
                            ctx.request_bytes, limit
                        ),
                    ));
                }
            }
        }
        Ok(())
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> PingoraResult<()> {
        if let Some(decision) = ctx.decision.as_ref() {
            let _ = upstream_request.insert_header("host", decision.host.as_str());
            ctx.auth_injected = apply_auth_rewrite(upstream_request, decision);
        }
        Ok(())
    }

    fn response_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> PingoraResult<Option<std::time::Duration>> {
        if let Some(chunk) = body.as_ref() {
            ctx.response_bytes = ctx.response_bytes.saturating_add(chunk.len() as u64);
        }
        Ok(None)
    }

    async fn logging(&self, session: &mut Session, _e: Option<&Error>, ctx: &mut Self::CTX) {
        let status = session
            .response_written()
            .map(|r| r.status.as_u16())
            .unwrap_or(ctx.status);

        self.audit_sink.record(AuditEvent::now(
            &self.config.sandbox_id,
            AuditEventKind::HttpRequest {
                host: ctx.host.clone(),
                method: ctx.method.clone(),
                path: ctx.path.clone(),
                status,
                request_bytes: ctx.request_bytes,
                response_bytes: ctx.response_bytes,
                auth_injected: ctx.auth_injected,
            },
        ));
    }
}

/// Build a Pingora [`Service`] hosting [`BlackwallHttpProxy`].
///
/// When `mitm_ca` is `Some`, configures downstream TLS 1.2/1.3 + HTTP/2 (ALPN H2/H1)
/// using [`EphemeralCa`] as the dynamic SNI certificate resolver.
pub fn build_pingora_http_service(
    proxy: BlackwallHttpProxy,
    listen_addr: &str,
    mitm_ca: Option<Arc<EphemeralCa>>,
) -> crate::error::Result<Service<HttpProxy<BlackwallHttpProxy>>> {
    let conf = Arc::new(ServerConf::default());
    let mut service = http_proxy_service(&conf, proxy);

    if let Some(ca) = mitm_ca {
        let mut tls_settings = TlsSettings::intermediate("", "").map_err(|e| {
            crate::error::ProxyError::Tls(format!("failed to create Pingora TlsSettings: {e}"))
        })?;
        tls_settings.set_cert_resolver(ca);
        tls_settings.enable_h2();
        service.add_tls_with_settings(listen_addr, None, tls_settings);
    } else {
        service.add_tcp(listen_addr);
    }

    Ok(service)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::InMemorySecretResolver;
    use blackwall_audit::MemoryAuditSink;
    use pingora_core::services::Service as PingoraService;
    use rustls::pki_types::ServerName;
    use rustls::ClientConfig;
    use std::net::TcpListener as StdTcpListener;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::TlsConnector;

    fn sample_rules() -> Vec<HttpRule> {
        vec![
            HttpRule {
                host: "api.github.com".into(),
                port: 443,
                methods: vec!["GET".into(), "POST".into()],
                path_prefixes: vec!["/repos/my-org/my-repo/".into()],
                max_request_bytes: Some(128),
                auth: Some(AuthSpec::Bearer {
                    secret: "GITHUB_TOKEN".into(),
                }),
            },
            HttpRule {
                host: "api.anthropic.com".into(),
                port: 443,
                methods: vec!["POST".into()],
                path_prefixes: vec!["/v1/messages".into()],
                max_request_bytes: Some(4096),
                auth: Some(AuthSpec::Header {
                    secret: "ANTHROPIC_KEY".into(),
                    name: "x-api-key".into(),
                    prefix: None,
                }),
            },
            HttpRule {
                host: "github.com".into(),
                port: 443,
                methods: vec!["GET".into(), "POST".into()],
                path_prefixes: vec!["/my-org/my-repo.git/".into()],
                max_request_bytes: None,
                auth: Some(AuthSpec::Basic {
                    secret: "GITHUB_TOKEN".into(),
                    username: "x-access-token".into(),
                }),
            },
        ]
    }

    fn sample_secrets() -> Arc<InMemorySecretResolver> {
        let mut s = InMemorySecretResolver::new();
        s.insert(
            "GITHUB_TOKEN",
            "ghp_bw00_placeholder_token",
            "ghp_REAL_GITHUB_SECRET",
        );
        s.insert(
            "ANTHROPIC_KEY",
            "sk-ant-bw00_placeholder",
            "sk-ant-REAL_ANTHROPIC_KEY",
        );
        Arc::new(s)
    }

    fn make_req(method: &str, path: &str, host: &str, headers: &[(&str, &str)]) -> RequestHeader {
        let mut req = RequestHeader::build(method, path.as_bytes(), None).unwrap();
        req.insert_header("host", host).unwrap();
        for (k, v) in headers {
            req.insert_header(k.to_string(), *v).unwrap();
        }
        req
    }

    #[test]
    fn policy_enforces_host_method_prefix_size_and_auth_pinning() {
        let rules = sample_rules();
        let secrets = sample_secrets();
        let pinned: PinnedHostMap = BTreeMap::from([
            (
                "api.github.com".into(),
                vec!["127.0.0.1:18443".parse().unwrap()],
            ),
            (
                "api.anthropic.com".into(),
                vec!["127.0.0.1:18444".parse().unwrap()],
            ),
            (
                "github.com".into(),
                vec!["127.0.0.1:18445".parse().unwrap()],
            ),
        ]);

        // Denied host
        let req = make_req("GET", "/", "evil.example", &[]);
        let err = evaluate_http_request(&req, &rules, &pinned, secrets.as_ref()).unwrap_err();
        assert_eq!(err.status, 403);
        assert!(!err.is_auth_mismatch);

        // Denied path prefix (including traversal attempt)
        let req = make_req(
            "GET",
            "/repos/other-org/other-repo/issues",
            "api.github.com",
            &[("authorization", "Bearer ghp_bw00_placeholder_token")],
        );
        assert_eq!(
            evaluate_http_request(&req, &rules, &pinned, secrets.as_ref())
                .unwrap_err()
                .status,
            403
        );
        let traversal = make_req(
            "GET",
            "/repos/my-org/my-repo/../../other-org/secret",
            "api.github.com",
            &[("authorization", "Bearer ghp_bw00_placeholder_token")],
        );
        assert_eq!(
            evaluate_http_request(&traversal, &rules, &pinned, secrets.as_ref())
                .unwrap_err()
                .status,
            403
        );

        // Denied HTTP method
        let req = make_req(
            "DELETE",
            "/repos/my-org/my-repo/issues/1",
            "api.github.com",
            &[("authorization", "Bearer ghp_bw00_placeholder_token")],
        );
        assert_eq!(
            evaluate_http_request(&req, &rules, &pinned, secrets.as_ref())
                .unwrap_err()
                .status,
            403
        );

        // Exceeds max_request_bytes
        let req = make_req(
            "POST",
            "/repos/my-org/my-repo/issues",
            "api.github.com",
            &[
                ("authorization", "Bearer ghp_bw00_placeholder_token"),
                ("content-length", "256"),
            ],
        );
        assert_eq!(
            evaluate_http_request(&req, &rules, &pinned, secrets.as_ref())
                .unwrap_err()
                .status,
            413
        );

        // Attacker BYO-token rejected with 403 + AuthMismatch
        let attacker = make_req(
            "POST",
            "/repos/my-org/my-repo/issues",
            "api.github.com",
            &[("authorization", "Bearer ghp_ATTACKER")],
        );
        let err = evaluate_http_request(&attacker, &rules, &pinned, secrets.as_ref()).unwrap_err();
        assert_eq!(err.status, 403);
        assert!(err.is_auth_mismatch);

        // Valid Bearer placeholder -> stripped Cookie & X-Api-Key, injected real Bearer token
        let mut valid_bearer = make_req(
            "POST",
            "/repos/my-org/my-repo/issues",
            "api.github.com",
            &[
                ("authorization", "Bearer ghp_bw00_placeholder_token"),
                ("cookie", "session=attacker_cookie"),
                ("x-api-key", "leaked-key"),
                ("x-amz-security-token", "aws-junk"),
                ("x-custom-ok", "keep-me"),
            ],
        );
        let decision =
            evaluate_http_request(&valid_bearer, &rules, &pinned, secrets.as_ref()).unwrap();
        assert!(apply_auth_rewrite(&mut valid_bearer, &decision));
        assert_eq!(
            valid_bearer.headers.get("authorization").unwrap(),
            "Bearer ghp_REAL_GITHUB_SECRET"
        );
        assert!(valid_bearer.headers.get("cookie").is_none());
        assert!(valid_bearer.headers.get("x-api-key").is_none());
        assert!(valid_bearer.headers.get("x-amz-security-token").is_none());
        assert_eq!(valid_bearer.headers.get("x-custom-ok").unwrap(), "keep-me");

        // Valid Header auth (x-api-key)
        let mut valid_hdr = make_req(
            "POST",
            "/v1/messages",
            "api.anthropic.com",
            &[
                ("x-api-key", "sk-ant-bw00_placeholder"),
                ("authorization", "Bearer rogue"),
                ("cookie", "sid=rogue"),
            ],
        );
        let dec_hdr =
            evaluate_http_request(&valid_hdr, &rules, &pinned, secrets.as_ref()).unwrap();
        assert!(apply_auth_rewrite(&mut valid_hdr, &dec_hdr));
        assert_eq!(
            valid_hdr.headers.get("x-api-key").unwrap(),
            "sk-ant-REAL_ANTHROPIC_KEY"
        );
        assert!(valid_hdr.headers.get("authorization").is_none());
        assert!(valid_hdr.headers.get("cookie").is_none());

        // Valid Basic auth (git HTTPS)
        let guest_basic = BASE64.encode("x-access-token:ghp_bw00_placeholder_token");
        let mut valid_basic = make_req(
            "GET",
            "/my-org/my-repo.git/info/refs",
            "github.com",
            &[
                ("authorization", &format!("Basic {guest_basic}")),
                ("cookie", "bad=1"),
            ],
        );
        let dec_basic =
            evaluate_http_request(&valid_basic, &rules, &pinned, secrets.as_ref()).unwrap();
        assert!(apply_auth_rewrite(&mut valid_basic, &dec_basic));
        let expected_basic = BASE64.encode("x-access-token:ghp_REAL_GITHUB_SECRET");
        assert_eq!(
            valid_basic.headers.get("authorization").unwrap(),
            &format!("Basic {expected_basic}")
        );
        assert!(valid_basic.headers.get("cookie").is_none());
    }

    fn reserve_ephemeral_port() -> u16 {
        let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    }

    /// Read a simple HTTP/1.1 request and echo its headers as JSON.
    async fn spawn_mock_upstream() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let (read_half, mut write_half) = stream.into_split();
                    let mut reader = BufReader::new(read_half);
                    let mut request_line = String::new();
                    if reader.read_line(&mut request_line).await.unwrap_or(0) == 0 {
                        return;
                    }
                    let mut hdrs = BTreeMap::new();
                    let mut content_len: usize = 0;
                    loop {
                        let mut line = String::new();
                        if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
                            break;
                        }
                        let trimmed = line.trim_end_matches(['\r', '\n']);
                        if trimmed.is_empty() {
                            break;
                        }
                        if let Some((k, v)) = trimmed.split_once(':') {
                            let kl = k.trim().to_ascii_lowercase();
                            let vl = v.trim().to_string();
                            if kl == "content-length" {
                                content_len = vl.parse().unwrap_or(0);
                            }
                            hdrs.insert(kl, vl);
                        }
                    }
                    let mut body_buf = vec![0u8; content_len];
                    if content_len > 0 {
                        let _ = reader.read_exact(&mut body_buf).await;
                    }
                    let resp_json = serde_json::json!({
                        "request_line": request_line.trim(),
                        "headers": hdrs,
                        "body": String::from_utf8_lossy(&body_buf),
                    })
                    .to_string();
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        resp_json.len(),
                        resp_json
                    );
                    let _ = write_half.write_all(resp.as_bytes()).await;
                    let _ = write_half.shutdown().await;
                });
            }
        });

        addr
    }

    async fn send_https_request(
        proxy_addr: SocketAddr,
        sni: &str,
        ca: &EphemeralCa,
        raw_http: &str,
    ) -> String {
        let client_cfg = Arc::new(
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(ca.root_cert_store().unwrap())
                .with_no_client_auth(),
        );
        let connector = TlsConnector::from(client_cfg);
        let tcp = TcpStream::connect(proxy_addr).await.unwrap();
        let server_name = ServerName::try_from(sni.to_string()).unwrap();
        let mut tls = connector.connect(server_name, tcp).await.unwrap();
        tls.write_all(raw_http.as_bytes()).await.unwrap();
        tls.flush().await.unwrap();
        let mut out = Vec::new();
        let _ = tls.read_to_end(&mut out).await;
        String::from_utf8_lossy(&out).into_owned()
    }

    #[tokio::test]
    async fn live_pingora_tls_mitm_auth_pinning_and_audit_end_to_end() {
        let upstream_addr = spawn_mock_upstream().await;
        let proxy_port = reserve_ephemeral_port();
        let proxy_addr: SocketAddr = format!("127.0.0.1:{proxy_port}").parse().unwrap();

        let ca = Arc::new(EphemeralCa::generate("sb-pingora-live").unwrap());
        let audit = Arc::new(MemoryAuditSink::new());
        let secrets = sample_secrets();

        let mut pinned = PinnedHostMap::new();
        pinned.insert("api.github.com".into(), vec![upstream_addr]);

        let mut cfg = HttpProxyConfig::new("sb-pingora-live", sample_rules(), pinned);
        // Mock upstream is local plaintext TCP; downstream Pingora listener is full TLS MITM!
        cfg.upstream_tls = false;
        cfg.verify_upstream_cert = false;

        let proxy = BlackwallHttpProxy::new(cfg, secrets, audit.clone());
        let mut service =
            build_pingora_http_service(proxy, &proxy_addr.to_string(), Some(ca.clone())).unwrap();

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let svc_task = tokio::spawn(async move {
            service.start_service(None, shutdown_rx, 1).await;
        });

        // Wait briefly for Pingora listener to bind
        for _ in 0..50 {
            if TcpStream::connect(proxy_addr).await.is_ok() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }

        // 1. Attacker sends BYO token -> 403 Forbidden + AuthMismatch audit event
        let resp_attacker = send_https_request(
            proxy_addr,
            "api.github.com",
            &ca,
            "POST /repos/my-org/my-repo/issues HTTP/1.1\r\nHost: api.github.com\r\nAuthorization: Bearer ghp_ATTACKER\r\nConnection: close\r\nContent-Length: 2\r\n\r\n{}",
        )
        .await;
        assert!(
            resp_attacker.starts_with("HTTP/1.1 403"),
            "expected 403 for attacker token, got: {resp_attacker}"
        );

        // 2. Guest sends valid placeholder + extra Cookie & X-Api-Key -> stripped & replaced with real secret
        let resp_ok = send_https_request(
            proxy_addr,
            "api.github.com",
            &ca,
            "POST /repos/my-org/my-repo/issues HTTP/1.1\r\nHost: api.github.com\r\nAuthorization: Bearer ghp_bw00_placeholder_token\r\nCookie: evil=cookie\r\nX-Api-Key: evil-key\r\nConnection: close\r\nContent-Length: 13\r\n\r\n{\"title\":\"x\"}",
        )
        .await;
        assert!(
            resp_ok.starts_with("HTTP/1.1 200"),
            "expected 200 for valid placeholder, got: {resp_ok}"
        );
        let body_part = resp_ok.split("\r\n\r\n").nth(1).unwrap();
        let echoed: serde_json::Value = serde_json::from_str(body_part).unwrap();
        assert_eq!(
            echoed["headers"]["authorization"],
            "Bearer ghp_REAL_GITHUB_SECRET"
        );
        assert!(echoed["headers"].get("cookie").is_none());
        assert!(echoed["headers"].get("x-api-key").is_none());
        assert_eq!(echoed["body"], "{\"title\":\"x\"}");

        // 3. Oversized request (> 128 bytes max_request_bytes) -> 413 Payload Too Large
        let big_body = "A".repeat(200);
        let resp_big = send_https_request(
            proxy_addr,
            "api.github.com",
            &ca,
            &format!(
                "POST /repos/my-org/my-repo/issues HTTP/1.1\r\nHost: api.github.com\r\nAuthorization: Bearer ghp_bw00_placeholder_token\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",
                big_body.len(),
                big_body
            ),
        )
        .await;
        assert!(
            resp_big.starts_with("HTTP/1.1 413"),
            "expected 413 for oversized body, got: {resp_big}"
        );

        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), svc_task).await;

        // Verify AuditSink recorded AuthMismatch AND HttpRequest events
        let events = audit.snapshot();
        assert!(
            events.iter().any(|e| matches!(
                &e.kind,
                AuditEventKind::AuthMismatch { host, .. } if host == "api.github.com"
            )),
            "expected AuthMismatch event in audit log: {events:?}"
        );
        assert!(
            events.iter().any(|e| matches!(
                &e.kind,
                AuditEventKind::HttpRequest {
                    host,
                    status: 200,
                    auth_injected: true,
                    ..
                } if host == "api.github.com"
            )),
            "expected successful HttpRequest with auth_injected=true in audit log: {events:?}"
        );
    }
}
