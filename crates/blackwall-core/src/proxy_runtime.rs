//! Per-VM proxy runtime hosting Pingora HTTP/1.1 & HTTP/2 TLS MITM, sibling
//! PostgreSQL `SCRAM-SHA-256` wire proxy, and the Port 1000 (`NET_MUX`) demultiplexer.
//!
//! In production (`ProxyLaunchMode::Auto` / `ProxyLaunchMode::JailedProcess`), each
//! `egress` sandbox spawns a dedicated, 100% rootless jailed `blackwall-proxy` child
//! process wrapped in `pasta` (`userns + netns + pidns`) with locked `nftables`,
//! zero Linux capabilities (`capset` v3), `PR_SET_DUMPABLE=0`, `PR_SET_NO_NEW_PRIVS=1`,
//! Landlock zero-fs, and `seccomp-bpf`. All secrets and the ephemeral CA private key
//! are handed over an anonymous in-memory pipe — NEVER host disk.

use crate::dns::collect_pinned_endpoints;
use crate::error::{CoreError, Result};
use crate::secrets_bridge::VmSecretTableBridge;
use blackwall_audit::{AuditEvent, AuditEventKind, AuditOrigin, AuditSink};
use blackwall_policy::SandboxSpec;
use blackwall_proxy::{
    build_pingora_http_service, BlackwallHttpProxy, EphemeralCa, HttpProxyConfig, PinnedHostMap,
    Port1000Muxer, PostgresProxyConfig, PostgresProxyServer, PostgresRouteTarget,
    ProxyBootstrapConfig, ProxyBootstrapSecret, ProxyError, ProxyJailConfig, ProxyReadyAck,
    SecretResolver, SyntheticDnsTable,
};
use pingora_core::services::Service;
use std::fs::File;
use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::PathBuf;
use std::process::Child;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::UnixStream as TokioUnixStream;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

/// Hard per-line cap for NDJSON audit events read from a jailed proxy's `audit_rx_fd` (64 KiB).
pub(crate) const MAX_PROXY_AUDIT_LINE_BYTES: usize = 65_536;

/// Hard per-line cap for the single `ProxyReadyAck` line returned over the anonymous bootstrap socket.
#[cfg(target_os = "linux")]
const MAX_READY_ACK_BYTES: usize = 16_384;

fn parent_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Strip ANSI CSI/OSC escape sequences and all control characters (`ch.is_control()`,
/// including `\x1b`, `\r`, `\n`, `\0`), then cap UTF-8 byte length to `max_bytes`.
fn sanitize_audit_str(input: &str, max_bytes: usize) -> String {
    let mut out = String::with_capacity(input.len().min(max_bytes));
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\x1b' {
            match chars.peek().copied() {
                Some('[') => {
                    chars.next();
                    // CSI sequence ends at final byte in 0x40..=0x7E ('@'..='~').
                    for c in chars.by_ref() {
                        if ('@'..='~').contains(&c) {
                            break;
                        }
                    }
                }
                Some(']') => {
                    chars.next();
                    // OSC sequence ends at BEL (\x07) or ST (\x1b\\).
                    while let Some(c) = chars.next() {
                        if c == '\x07' {
                            break;
                        }
                        if c == '\x1b' && chars.peek() == Some(&'\\') {
                            chars.next();
                            break;
                        }
                    }
                }
                _ => {}
            }
            continue;
        }
        if ch.is_control() {
            continue;
        }
        if out.len() + ch.len_utf8() > max_bytes {
            break;
        }
        out.push(ch);
    }
    out
}

/// Confused-deputy enforcement for `AuditEvent`s arriving over a jailed proxy's
/// `audit_rx_fd`:
/// - Strictly allowlists proxy-only `AuditEventKind` variants (`HttpRequest`, `DnsQuery`,
///   `AuthMismatch`, `PostgresQuery`) and drops all others with a warning.
/// - Unconditionally overwrites `sandbox_id`, `timestamp_ms`, and `origin = AuditOrigin::Proxy`.
/// - Strips control chars / ANSI escape sequences and caps string lengths.
pub(crate) fn sanitize_proxy_event(
    ev: AuditEvent,
    expected_sandbox_id: &str,
) -> Option<AuditEvent> {
    let sanitized_kind = match ev.kind {
        AuditEventKind::HttpRequest {
            host,
            method,
            path,
            status,
            request_bytes,
            response_bytes,
            auth_injected,
        } => AuditEventKind::HttpRequest {
            host: sanitize_audit_str(&host, 255),
            method: sanitize_audit_str(&method, 32),
            path: sanitize_audit_str(&path, 2048),
            status,
            request_bytes,
            response_bytes,
            auth_injected,
        },
        AuditEventKind::DnsQuery {
            fqdn,
            allowed,
            synthetic_ip,
        } => AuditEventKind::DnsQuery {
            fqdn: sanitize_audit_str(&fqdn, 255),
            allowed,
            synthetic_ip: synthetic_ip.map(|ip| sanitize_audit_str(&ip, 64)),
        },
        AuditEventKind::AuthMismatch { host, path, reason } => AuditEventKind::AuthMismatch {
            host: sanitize_audit_str(&host, 255),
            path: sanitize_audit_str(&path, 2048),
            reason: sanitize_audit_str(&reason, 2048),
        },
        AuditEventKind::PostgresQuery {
            host,
            port,
            message_type,
            statement,
        } => AuditEventKind::PostgresQuery {
            host: sanitize_audit_str(&host, 255),
            port,
            message_type: if message_type.is_control() {
                '?'
            } else {
                message_type
            },
            statement: sanitize_audit_str(&statement, 2048),
        },
        disallowed => {
            tracing::warn!(
                sandbox_id = %expected_sandbox_id,
                claimed_sandbox_id = %ev.sandbox_id,
                claimed_origin = ?ev.origin,
                disallowed_event = ?disallowed,
                "dropped disallowed AuditEventKind from jailed proxy pipe"
            );
            return None;
        }
    };

    Some(AuditEvent {
        timestamp_ms: parent_now_ms(),
        sandbox_id: expected_sandbox_id.to_string(),
        origin: AuditOrigin::Proxy,
        kind: sanitized_kind,
    })
}

#[derive(Debug, PartialEq, Eq)]
enum BoundedLineStatus {
    Eof,
    Line,
    Oversized,
}

/// Read a single newline-delimited line from `reader` without ever buffering more
/// than `max_bytes` in memory. If a line exceeds `max_bytes`, all remaining bytes
/// up to and including `\n` are discarded and `BoundedLineStatus::Oversized` is returned
/// so the caller can skip it and cleanly continue reading subsequent lines.
fn read_bounded_line<R: BufRead>(
    reader: &mut R,
    max_bytes: usize,
    out: &mut Vec<u8>,
) -> std::io::Result<BoundedLineStatus> {
    out.clear();
    let mut oversized = false;
    let mut saw_any = false;

    loop {
        let buf = match reader.fill_buf() {
            Ok(b) => b,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if buf.is_empty() {
            if !saw_any {
                return Ok(BoundedLineStatus::Eof);
            }
            if oversized {
                out.clear();
                return Ok(BoundedLineStatus::Oversized);
            }
            return Ok(BoundedLineStatus::Line);
        }
        saw_any = true;

        if let Some(nl_pos) = buf.iter().position(|&b| b == b'\n') {
            if !oversized {
                if out.len() + nl_pos > max_bytes {
                    oversized = true;
                    out.clear();
                } else {
                    out.extend_from_slice(&buf[..nl_pos]);
                }
            }
            reader.consume(nl_pos + 1);
            return if oversized {
                Ok(BoundedLineStatus::Oversized)
            } else {
                Ok(BoundedLineStatus::Line)
            };
        }

        let buf_len = buf.len();
        if !oversized {
            if out.len() + buf_len > max_bytes {
                oversized = true;
                out.clear();
            } else {
                out.extend_from_slice(buf);
            }
        }
        reader.consume(buf_len);
    }
}

/// Drain NDJSON `AuditEvent` lines from a proxy audit pipe with strict 64 KiB line
/// bounding and confused-deputy validation/sanitization.
pub(crate) fn drain_proxy_audit_reader<R: BufRead>(
    mut reader: R,
    expected_sandbox_id: &str,
    audit_sink: &dyn AuditSink,
) {
    let mut line_buf = Vec::with_capacity(1024);
    loop {
        match read_bounded_line(&mut reader, MAX_PROXY_AUDIT_LINE_BYTES, &mut line_buf) {
            Ok(BoundedLineStatus::Eof) => break,
            Ok(BoundedLineStatus::Oversized) => {
                tracing::warn!(
                    sandbox_id = %expected_sandbox_id,
                    max_bytes = MAX_PROXY_AUDIT_LINE_BYTES,
                    "dropped oversized NDJSON line from jailed proxy audit pipe"
                );
            }
            Ok(BoundedLineStatus::Line) => {
                let Ok(text) = std::str::from_utf8(&line_buf) else {
                    tracing::warn!(
                        sandbox_id = %expected_sandbox_id,
                        "dropped non-UTF-8 line from jailed proxy audit pipe"
                    );
                    continue;
                };
                let trimmed = text.trim();
                if trimmed.is_empty() {
                    continue;
                }
                match serde_json::from_str::<AuditEvent>(trimmed) {
                    Ok(ev) => {
                        if let Some(sanitized) = sanitize_proxy_event(ev, expected_sandbox_id) {
                            audit_sink.record(sanitized);
                        }
                    }
                    Err(err) => {
                        tracing::warn!(
                            sandbox_id = %expected_sandbox_id,
                            error = %err,
                            "failed to parse AuditEvent JSON from jailed proxy pipe"
                        );
                    }
                }
            }
            Err(_) => break,
        }
    }
}

/// Enable `SO_PASSCRED` on an anonymous `AF_UNIX` `socketpair` so the kernel attaches
/// host-namespace-translated `SCM_CREDENTIALS` (`ucred.pid`) to `ProxyReadyAck` writes
/// from the jailed `blackwall-proxy` child process inside `pasta`'s PID namespace.
#[cfg(target_os = "linux")]
fn enable_unix_passcred(sock: &StdUnixStream) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;

    const SOL_SOCKET: i32 = 1;
    const SO_PASSCRED: i32 = 16;

    extern "C" {
        fn setsockopt(
            sockfd: i32,
            level: i32,
            optname: i32,
            optval: *const core::ffi::c_void,
            optlen: u32,
        ) -> i32;
    }

    let enable: i32 = 1;
    let rc = unsafe {
        setsockopt(
            sock.as_raw_fd(),
            SOL_SOCKET,
            SO_PASSCRED,
            (&enable as *const i32).cast(),
            std::mem::size_of::<i32>() as u32,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Read the single newline-delimited `ProxyReadyAck` from `sock` while simultaneously
/// extracting the sender's kernel-authenticated host-namespace PID from `SCM_CREDENTIALS`.
#[cfg(target_os = "linux")]
fn recv_ready_ack_with_peer_pid(
    sock: &StdUnixStream,
) -> std::io::Result<(String, Option<u32>)> {
    use std::os::fd::AsRawFd;

    const SOL_SOCKET: i32 = 1;
    const SCM_CREDENTIALS: i32 = 2;

    #[repr(C)]
    struct IoVec {
        iov_base: *mut core::ffi::c_void,
        iov_len: usize,
    }

    #[repr(C)]
    struct MsgHdr {
        msg_name: *mut core::ffi::c_void,
        msg_namelen: u32,
        msg_iov: *mut IoVec,
        msg_iovlen: usize,
        msg_control: *mut core::ffi::c_void,
        msg_controllen: usize,
        msg_flags: i32,
    }

    #[repr(C)]
    struct CmsgHdr {
        cmsg_len: usize,
        cmsg_level: i32,
        cmsg_type: i32,
    }

    #[repr(C)]
    struct UCred {
        pid: i32,
        uid: u32,
        gid: u32,
    }

    extern "C" {
        fn recvmsg(sockfd: i32, msg: *mut MsgHdr, flags: i32) -> isize;
    }

    const fn cmsg_align(len: usize) -> usize {
        let align = std::mem::size_of::<usize>();
        (len + align - 1) & !(align - 1)
    }

    let mut acc = Vec::with_capacity(256);
    let mut chunk = [0u8; 1024];
    let mut cmsg_buf = [0u8; 128];
    let mut peer_pid: Option<u32> = None;

    loop {
        let mut iov = IoVec {
            iov_base: chunk.as_mut_ptr().cast(),
            iov_len: chunk.len(),
        };
        let mut msg = MsgHdr {
            msg_name: std::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: &mut iov,
            msg_iovlen: 1,
            msg_control: cmsg_buf.as_mut_ptr().cast(),
            msg_controllen: cmsg_buf.len(),
            msg_flags: 0,
        };

        let n = unsafe { recvmsg(sock.as_raw_fd(), &mut msg, 0) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }

        // Parse any SCM_CREDENTIALS control message to recover host-namespace peer PID.
        let hdr_size = cmsg_align(std::mem::size_of::<CmsgHdr>());
        let mut offset = 0usize;
        while offset + std::mem::size_of::<CmsgHdr>() <= msg.msg_controllen {
            let hdr = unsafe {
                std::ptr::read_unaligned(cmsg_buf.as_ptr().add(offset).cast::<CmsgHdr>())
            };
            if hdr.cmsg_len < std::mem::size_of::<CmsgHdr>()
                || offset + hdr.cmsg_len > msg.msg_controllen
            {
                break;
            }
            if hdr.cmsg_level == SOL_SOCKET
                && hdr.cmsg_type == SCM_CREDENTIALS
                && hdr.cmsg_len >= hdr_size + std::mem::size_of::<UCred>()
            {
                let cred = unsafe {
                    std::ptr::read_unaligned(cmsg_buf.as_ptr().add(offset + hdr_size).cast::<UCred>())
                };
                if cred.pid > 0 {
                    peer_pid = Some(cred.pid as u32);
                }
            }
            let step = cmsg_align(hdr.cmsg_len);
            if step == 0 {
                break;
            }
            offset += step;
        }

        if n == 0 {
            break;
        }
        let bytes = &chunk[..n as usize];
        if let Some(nl_pos) = bytes.iter().position(|&b| b == b'\n') {
            if acc.len() + nl_pos > MAX_READY_ACK_BYTES {
                return Err(std::io::Error::new(
                    ErrorKind::InvalidData,
                    "ProxyReadyAck exceeded maximum allowed length",
                ));
            }
            acc.extend_from_slice(&bytes[..nl_pos]);
            break;
        }
        if acc.len() + bytes.len() > MAX_READY_ACK_BYTES {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "ProxyReadyAck exceeded maximum allowed length",
            ));
        }
        acc.extend_from_slice(bytes);
    }

    let line = String::from_utf8(acc).map_err(|e| {
        std::io::Error::new(
            ErrorKind::InvalidData,
            format!("non-UTF-8 ProxyReadyAck: {e}"),
        )
    })?;
    Ok((line, peer_pid))
}

/// Controls whether per-VM egress proxies launch as a dedicated jailed `pasta` +
/// `blackwall-proxy` OS child process or in-process inside `blackwall-core`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProxyLaunchMode {
    /// Prefer a dedicated rootless jailed `pasta` + `blackwall-proxy` child process
    /// whenever `blackwall-proxy`, `pasta`, and `nft` are available; fall back to
    /// in-process Pingora if any host tool is absent.
    #[default]
    Auto,
    /// Require a dedicated rootless jailed `pasta` + `blackwall-proxy` child process
    /// (fail closed if `blackwall-proxy`, `pasta`, or `nft` is missing).
    JailedProcess,
    /// Run Pingora in-process inside `blackwall-core` (for mock/loopback unit tests).
    InProcess,
}

/// Detected host tool paths required to spawn a dedicated rootless jailed proxy process.
#[derive(Debug, Clone)]
pub struct DetectedProxyTools {
    pub blackwall_proxy: PathBuf,
    pub pasta: PathBuf,
    pub nft: PathBuf,
}

/// Optional tuning knobs for launching a jailed `blackwall-proxy` child process.
#[derive(Debug, Clone)]
pub struct JailedProxyOptions {
    /// Extra `pasta` arguments inserted before `--` (empty in production).
    pub extra_pasta_args: Vec<String>,
    /// Whether upstream HTTP connections use TLS (always `true` in production).
    pub upstream_tls: bool,
    /// Whether upstream HTTP TLS certificates/hostnames are verified (always `true` in production).
    pub verify_upstream_cert: bool,
    /// Apply `nftables` egress IP-pinning ruleset inside child `netns` (`true` in production).
    pub apply_nftables: bool,
    /// Apply capability drop + `PR_SET_DUMPABLE=0` + `PR_SET_NO_NEW_PRIVS=1` + Landlock + `seccomp-bpf` (`true` in production).
    pub apply_jail: bool,
}

impl Default for JailedProxyOptions {
    fn default() -> Self {
        Self {
            extra_pasta_args: Vec::new(),
            upstream_tls: true,
            verify_upstream_cert: true,
            apply_nftables: true,
            apply_jail: true,
        }
    }
}

/// Auto-detect `blackwall-proxy`, `pasta`, and `nft` on the host.
pub fn detect_proxy_tools() -> Option<DetectedProxyTools> {
    let blackwall_proxy = find_blackwall_proxy_bin()?;
    let pasta = std::env::var_os("BLACKWALL_PASTA_BIN")
        .map(PathBuf::from)
        .filter(|p| p.is_file())
        .or_else(|| find_in_path("pasta"))?;
    let nft = std::env::var_os("BLACKWALL_NFT_BIN")
        .map(PathBuf::from)
        .filter(|p| p.is_file())
        .or_else(|| find_in_path("nft"))
        .or_else(|| {
            ["/usr/sbin/nft", "/sbin/nft"]
                .iter()
                .map(PathBuf::from)
                .find(|p| p.is_file())
        })?;

    Some(DetectedProxyTools {
        blackwall_proxy,
        pasta,
        nft,
    })
}

fn find_blackwall_proxy_bin() -> Option<PathBuf> {
    if let Some(env_path) = std::env::var_os("BLACKWALL_PROXY_BIN") {
        let p = PathBuf::from(env_path);
        if p.is_file() {
            return Some(p);
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        // Walk up to 5 ancestors to cover `target/<profile>/<bin>`,
        // `target/<profile>/deps/<test>`, and `target/<profile>/build/<crate>/<hash>/out/<test>`.
        for ancestor in exe.ancestors().skip(1).take(5) {
            let candidate = ancestor.join("blackwall-proxy");
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    find_in_path("blackwall-proxy")
}

fn find_in_path(name: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

enum ProxyBackend {
    JailedProcess {
        pasta_child: Option<Child>,
        pasta_pid: u32,
        proxy_pid: u32,
        dumpable: Option<i32>,
        audit_thread: Option<thread::JoinHandle<()>>,
        stderr_thread: Option<thread::JoinHandle<()>>,
    },
    InProcess {
        shutdown_tx: watch::Sender<bool>,
        tasks: Vec<JoinHandle<()>>,
    },
}

/// Live handle to a sandbox's dedicated per-VM proxy (either a rootless jailed
/// `pasta` + `blackwall-proxy` OS child process or an in-process Pingora fallback).
pub struct VmProxyHandle {
    ca: Arc<EphemeralCa>,
    jail_config: ProxyJailConfig,
    http_listen_addr: SocketAddr,
    backend: ProxyBackend,
}

impl VmProxyHandle {
    /// Start the per-VM proxy using [`ProxyLaunchMode::Auto`].
    pub fn start(
        sandbox_id: &str,
        spec: &SandboxSpec,
        pinned_hosts: PinnedHostMap,
        ca: Arc<EphemeralCa>,
        secrets: Arc<VmSecretTableBridge>,
        audit_sink: Arc<dyn AuditSink>,
        net_mux: Option<StdUnixStream>,
    ) -> Result<Self> {
        Self::start_with_mode(
            sandbox_id,
            spec,
            pinned_hosts,
            ca,
            secrets,
            audit_sink,
            net_mux,
            ProxyLaunchMode::Auto,
        )
    }

    /// Start the per-VM proxy with an explicit [`ProxyLaunchMode`].
    #[allow(clippy::too_many_arguments)]
    pub fn start_with_mode(
        sandbox_id: &str,
        spec: &SandboxSpec,
        pinned_hosts: PinnedHostMap,
        ca: Arc<EphemeralCa>,
        secrets: Arc<VmSecretTableBridge>,
        audit_sink: Arc<dyn AuditSink>,
        net_mux: Option<StdUnixStream>,
        mode: ProxyLaunchMode,
    ) -> Result<Self> {
        let pinned_endpoints = collect_pinned_endpoints(&pinned_hosts);
        let jail_config = ProxyJailConfig::new(sandbox_id, pinned_endpoints);

        match mode {
            ProxyLaunchMode::InProcess => Self::start_in_process(
                sandbox_id,
                spec,
                pinned_hosts,
                ca,
                jail_config,
                secrets,
                audit_sink,
                net_mux,
            ),
            ProxyLaunchMode::JailedProcess => {
                let tools = detect_proxy_tools().ok_or_else(|| {
                    CoreError::Proxy(ProxyError::Jail(
                        "ProxyLaunchMode::JailedProcess requires `blackwall-proxy`, `pasta`, and `nft` on host"
                            .into(),
                    ))
                })?;
                let mux = net_mux.ok_or_else(|| {
                    CoreError::Proxy(ProxyError::Jail(
                        "ProxyLaunchMode::JailedProcess requires a connected Port 1000 net_mux stream"
                            .into(),
                    ))
                })?;
                Self::start_jailed_process(
                    sandbox_id,
                    spec,
                    pinned_hosts,
                    ca,
                    jail_config,
                    secrets,
                    audit_sink,
                    mux,
                    &tools,
                    &JailedProxyOptions::default(),
                )
            }
            ProxyLaunchMode::Auto => {
                #[cfg(target_os = "linux")]
                if let Some(tools) = detect_proxy_tools() {
                    if let Some(mux) = net_mux {
                        return Self::start_jailed_process(
                            sandbox_id,
                            spec,
                            pinned_hosts,
                            ca,
                            jail_config,
                            secrets,
                            audit_sink,
                            mux,
                            &tools,
                            &JailedProxyOptions::default(),
                        );
                    }
                    return Self::start_in_process(
                        sandbox_id,
                        spec,
                        pinned_hosts,
                        ca,
                        jail_config,
                        secrets,
                        audit_sink,
                        None,
                    );
                }
                tracing::debug!(
                    sandbox_id = %sandbox_id,
                    "falling back to in-process proxy (blackwall-proxy/pasta/nft unavailable)"
                );
                Self::start_in_process(
                    sandbox_id,
                    spec,
                    pinned_hosts,
                    ca,
                    jail_config,
                    secrets,
                    audit_sink,
                    net_mux,
                )
            }
        }
    }

    /// Launch a dedicated rootless jailed `pasta` + `blackwall-proxy` child process with
    /// custom [`JailedProxyOptions`] (also used by integration tests).
    #[cfg(target_os = "linux")]
    #[allow(clippy::too_many_arguments)]
    pub fn start_jailed_with_options(
        sandbox_id: &str,
        spec: &SandboxSpec,
        pinned_hosts: PinnedHostMap,
        ca: Arc<EphemeralCa>,
        secrets: Arc<dyn SecretResolver>,
        secret_names_and_placeholders: Vec<(String, String)>,
        audit_sink: Arc<dyn AuditSink>,
        net_mux: StdUnixStream,
        options: &JailedProxyOptions,
    ) -> Result<Self> {
        let tools = detect_proxy_tools().ok_or_else(|| {
            CoreError::Proxy(ProxyError::Jail(
                "jailed proxy requires `blackwall-proxy`, `pasta`, and `nft`".into(),
            ))
        })?;
        let pinned_endpoints = collect_pinned_endpoints(&pinned_hosts);
        let jail_config = ProxyJailConfig::new(sandbox_id, pinned_endpoints);
        Self::start_jailed_process_raw(
            sandbox_id,
            spec,
            pinned_hosts,
            ca,
            jail_config,
            secrets,
            secret_names_and_placeholders,
            audit_sink,
            net_mux,
            &tools,
            options,
        )
    }

    #[cfg(target_os = "linux")]
    #[allow(clippy::too_many_arguments)]
    fn start_jailed_process(
        sandbox_id: &str,
        spec: &SandboxSpec,
        pinned_hosts: PinnedHostMap,
        ca: Arc<EphemeralCa>,
        jail_config: ProxyJailConfig,
        secrets: Arc<VmSecretTableBridge>,
        audit_sink: Arc<dyn AuditSink>,
        net_mux: StdUnixStream,
        tools: &DetectedProxyTools,
        options: &JailedProxyOptions,
    ) -> Result<Self> {
        let pairs: Vec<(String, String)> = secrets.guest_placeholders().into_iter().collect();
        let resolver: Arc<dyn SecretResolver> = secrets;
        Self::start_jailed_process_raw(
            sandbox_id,
            spec,
            pinned_hosts,
            ca,
            jail_config,
            resolver,
            pairs,
            audit_sink,
            net_mux,
            tools,
            options,
        )
    }

    #[cfg(target_os = "linux")]
    #[allow(clippy::too_many_arguments)]
    fn start_jailed_process_raw(
        sandbox_id: &str,
        spec: &SandboxSpec,
        pinned_hosts: PinnedHostMap,
        ca: Arc<EphemeralCa>,
        mut jail_config: ProxyJailConfig,
        secrets: Arc<dyn SecretResolver>,
        secret_names_and_placeholders: Vec<(String, String)>,
        audit_sink: Arc<dyn AuditSink>,
        net_mux: StdUnixStream,
        tools: &DetectedProxyTools,
        options: &JailedProxyOptions,
    ) -> Result<Self> {
        use std::os::fd::{AsRawFd, OwnedFd};
        use std::os::unix::process::CommandExt;
        use std::process::{Command, Stdio};

        jail_config.pasta_binary = tools.pasta.clone();
        jail_config.nft_binary = tools.nft.clone();

        // 1. Create two anonymous in-memory pipes (`config` and `audit`).
        let (config_rx_fd, config_tx_fd) = blackwall_proxy::create_pipe_pair()?;
        let (audit_rx_fd, audit_tx_fd) = blackwall_proxy::create_pipe_pair()?;

        // 2. Create an anonymous `AF_UNIX` `socketpair` and pass the child end as `stdin` (`fd 0`).
        //    `pasta` preserves `fd 0` across its namespace setup, avoiding ANY filesystem UDS path!
        let (parent_sock, child_sock) = StdUnixStream::pair()?;
        enable_unix_passcred(&parent_sock)?;
        parent_sock.set_read_timeout(Some(Duration::from_secs(10)))?;
        parent_sock.set_write_timeout(Some(Duration::from_secs(5)))?;
        blackwall_proxy::clear_cloexec(child_sock.as_raw_fd())?;
        let child_stdin: OwnedFd = child_sock.into();

        // 3. Build `pasta` + `blackwall-proxy` command line (`--bootstrap-stdin`).
        let mut proxy_args = vec![
            "--bootstrap-stdin".to_string(),
            "--nft-bin".to_string(),
            tools.nft.to_string_lossy().into_owned(),
        ];
        if options.apply_nftables {
            proxy_args.push("--apply-nftables".to_string());
        }
        if options.apply_jail {
            proxy_args.push("--apply-jail".to_string());
        }

        let mut pasta_args = vec![
            "--config-net".to_string(),
            "--no-map-gw".to_string(),
            "--no-dhcp".to_string(),
            "--no-dhcpv6".to_string(),
            "--no-ndp".to_string(),
            "--no-ra".to_string(),
            "-t".to_string(),
            "none".to_string(),
            "-u".to_string(),
            "none".to_string(),
            "-T".to_string(),
            "none".to_string(),
            "-U".to_string(),
            "none".to_string(),
            "--quiet".to_string(),
        ];
        pasta_args.extend(options.extra_pasta_args.iter().cloned());
        pasta_args.push("--".to_string());
        pasta_args.push(tools.blackwall_proxy.to_string_lossy().into_owned());
        pasta_args.extend(proxy_args);

        let mut pasta_child = {
            let mut cmd = Command::new(&tools.pasta);
            cmd.args(&pasta_args)
                .stdin(Stdio::from(child_stdin))
                .stdout(Stdio::null())
                .stderr(Stdio::piped());

            // Put `pasta` + `blackwall-proxy` into their own process group for atomic cleanup.
            unsafe {
                cmd.pre_exec(blackwall_proxy::set_new_process_group);
            }

            cmd.spawn().map_err(|e| {
                CoreError::Proxy(ProxyError::Jail(format!(
                    "failed to spawn {} for jailed blackwall-proxy: {e}",
                    tools.pasta.display()
                )))
            })?
            // `cmd` (owning parent's copy of `child_stdin`) is dropped & closed right here!
        };
        let pasta_pid = pasta_child.id();

        // Drain stderr in background so child never blocks on a full pipe and errors are captured.
        let stderr_tail = Arc::new(Mutex::new(String::new()));
        let stderr_tail_clone = Arc::clone(&stderr_tail);
        let stderr_sid = sandbox_id.to_string();
        let stderr_thread = pasta_child
            .stderr
            .take()
            .and_then(|mut pipe| {
                thread::Builder::new()
                    .name(format!("bw-proxy-err-{sandbox_id}"))
                    .spawn(move || {
                        let mut buf = [0u8; 2048];
                        while let Ok(n) = pipe.read(&mut buf) {
                            if n == 0 {
                                break;
                            }
                            let chunk = String::from_utf8_lossy(&buf[..n]);
                            tracing::debug!(
                                sandbox_id = %stderr_sid,
                                msg = %chunk.trim(),
                                "blackwall-proxy stderr"
                            );
                            if let Ok(mut guard) = stderr_tail_clone.lock() {
                                guard.push_str(&chunk);
                                if guard.len() > 4096 {
                                    let drain_to = guard.len() - 4096;
                                    guard.drain(..drain_to);
                                }
                            }
                        }
                    })
                    .ok()
            });

        // 4. Pass `[config_rx_fd, audit_tx_fd, mux_fd]` over the anonymous `socketpair` via
        //    `SCM_RIGHTS` and close parent's copies immediately.
        let send_fds = [
            config_rx_fd.as_raw_fd(),
            audit_tx_fd.as_raw_fd(),
            net_mux.as_raw_fd(),
        ];
        if let Err(e) = blackwall_proxy::send_fds_over_unix(&parent_sock, &send_fds) {
            blackwall_proxy::kill_process_group(pasta_pid, None);
            let _ = pasta_child.wait();
            let err_text = stderr_tail
                .lock()
                .map(|g| g.trim().to_string())
                .unwrap_or_default();
            return Err(CoreError::Proxy(ProxyError::Jail(format!(
                "failed to send SCM_RIGHTS bootstrap fds over anonymous stdin socketpair: {e} ({err_text})"
            ))));
        }
        drop(config_rx_fd);
        drop(audit_tx_fd);
        drop(net_mux);

        // 5. Write `ProxyBootstrapConfig` (with secrets + CA private key in `Zeroizing`) to
        //    the anonymous memory pipe and close `config_tx_fd` immediately!
        let mut boot_secrets = Vec::with_capacity(secret_names_and_placeholders.len());
        for (name, placeholder) in secret_names_and_placeholders {
            if let Some(val) = secrets.resolve_secret(&name) {
                boot_secrets.push(ProxyBootstrapSecret {
                    name,
                    placeholder,
                    value: val,
                });
            }
        }

        let boot_cfg = ProxyBootstrapConfig {
            sandbox_id: sandbox_id.to_string(),
            http_rules: spec.network.http.clone(),
            postgres_rules: spec.network.postgres.clone(),
            pinned_hosts,
            ca_cert_pem: ca.ca_cert_pem().to_string(),
            ca_key_pem: ca.ca_key_pem(),
            secrets: boot_secrets,
            upstream_tls: options.upstream_tls,
            verify_upstream_cert: options.verify_upstream_cert,
        };
        let cfg_json = Zeroizing::new(
            serde_json::to_vec(&boot_cfg).map_err(|e| {
                CoreError::Proxy(ProxyError::Jail(format!(
                    "failed to serialize ProxyBootstrapConfig: {e}"
                )))
            })?,
        );
        drop(boot_cfg);

        {
            let mut tx_file = File::from(config_tx_fd);
            if let Err(e) = tx_file.write_all(&cfg_json).and_then(|_| tx_file.flush()) {
                blackwall_proxy::kill_process_group(pasta_pid, None);
                let _ = pasta_child.wait();
                let err_text = stderr_tail
                    .lock()
                    .map(|g| g.trim().to_string())
                    .unwrap_or_default();
                return Err(CoreError::Proxy(ProxyError::Jail(format!(
                    "failed writing ProxyBootstrapConfig to anonymous pipe: {e} ({err_text})"
                ))));
            }
        }
        drop(cfg_json);

        // 6. Start hardened audit reader thread draining bounded (<= 64 KiB) NDJSON `AuditEvent`s
        //    from `audit_rx_fd` with strict confused-deputy allowlist & sanitization.
        let audit_sid = sandbox_id.to_string();
        let audit_thread = thread::Builder::new()
            .name(format!("bw-proxy-audit-{sandbox_id}"))
            .spawn(move || {
                let reader = BufReader::new(File::from(audit_rx_fd));
                drain_proxy_audit_reader(reader, &audit_sid, audit_sink.as_ref());
            })
            .map_err(CoreError::Io)?;

        // 7. Wait for `ProxyReadyAck` (and kernel `SCM_CREDENTIALS` host-namespace `proxy_pid`)
        //    proving nftables + capability drop + Landlock + seccomp + Pingora are live.
        let (ack_line, cred_pid) = match recv_ready_ack_with_peer_pid(&parent_sock) {
            Ok(res) => res,
            Err(e) => {
                blackwall_proxy::kill_process_group(pasta_pid, None);
                let _ = pasta_child.wait();
                let err_text = stderr_tail
                    .lock()
                    .map(|g| g.trim().to_string())
                    .unwrap_or_default();
                return Err(CoreError::Proxy(ProxyError::Jail(format!(
                    "failed reading ProxyReadyAck from jailed blackwall-proxy: {e} ({err_text})"
                ))));
            }
        };
        drop(parent_sock);

        let proxy_pid = cred_pid.unwrap_or(pasta_pid);

        let ack: ProxyReadyAck = serde_json::from_str(ack_line.trim()).map_err(|e| {
            blackwall_proxy::kill_process_group(pasta_pid, Some(proxy_pid));
            let _ = pasta_child.wait();
            let err_text = stderr_tail
                .lock()
                .map(|g| g.trim().to_string())
                .unwrap_or_default();
            CoreError::Proxy(ProxyError::Jail(format!(
                "invalid ProxyReadyAck from jailed blackwall-proxy ({e}): raw={ack_line:?} stderr={err_text}"
            )))
        })?;

        if !ack.ok {
            blackwall_proxy::kill_process_group(pasta_pid, Some(proxy_pid));
            let _ = pasta_child.wait();
            let err_text = stderr_tail
                .lock()
                .map(|g| g.trim().to_string())
                .unwrap_or_default();
            return Err(CoreError::Proxy(ProxyError::Jail(format!(
                "jailed blackwall-proxy failed startup: {} ({err_text})",
                ack.error.unwrap_or_else(|| "unknown error".into())
            ))));
        }

        let http_listen_addr: SocketAddr = ack
            .http_listen_addr
            .as_deref()
            .unwrap_or("127.0.0.1:0")
            .parse()
            .unwrap_or_else(|_| SocketAddr::from(([127, 0, 0, 1], 0)));

        tracing::info!(
            sandbox_id = %sandbox_id,
            pasta_pid,
            proxy_pid,
            %http_listen_addr,
            dumpable = ?ack.dumpable,
            "started dedicated rootless jailed blackwall-proxy child process"
        );

        Ok(Self {
            ca,
            jail_config,
            http_listen_addr,
            backend: ProxyBackend::JailedProcess {
                pasta_child: Some(pasta_child),
                pasta_pid,
                proxy_pid,
                dumpable: ack.dumpable,
                audit_thread: Some(audit_thread),
                stderr_thread,
            },
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn start_in_process(
        sandbox_id: &str,
        spec: &SandboxSpec,
        pinned_hosts: PinnedHostMap,
        ca: Arc<EphemeralCa>,
        jail_config: ProxyJailConfig,
        secrets: Arc<VmSecretTableBridge>,
        audit_sink: Arc<dyn AuditSink>,
        net_mux: Option<StdUnixStream>,
    ) -> Result<Self> {
        let http_listen_addr = {
            let probe = StdTcpListener::bind("127.0.0.1:0")?;
            probe.local_addr()?
        };

        let http_cfg = HttpProxyConfig::new(
            sandbox_id,
            spec.network.http.clone(),
            pinned_hosts.clone(),
        );
        let http_proxy = BlackwallHttpProxy::new(http_cfg, secrets.clone(), audit_sink.clone());
        let mut pingora_service = build_pingora_http_service(
            http_proxy,
            &http_listen_addr.to_string(),
            Some(Arc::clone(&ca)),
        )?;

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let mut tasks = Vec::new();

        tasks.push(tokio::spawn(async move {
            pingora_service.start_service(None, shutdown_rx, 1).await;
        }));

        let pg_cfg = PostgresProxyConfig::new(
            sandbox_id,
            spec.network.postgres.clone(),
            pinned_hosts,
        );
        let pg_server = Arc::new(PostgresProxyServer::new(
            pg_cfg,
            Arc::clone(&ca),
            secrets,
            Arc::clone(&audit_sink),
        ));

        let dns_table = Arc::new(SyntheticDnsTable::from_allowlist(&spec.derived_dns_allow()));
        let muxer = Port1000Muxer::new(
            dns_table,
            http_listen_addr,
            Some(PostgresRouteTarget::Direct(pg_server)),
        )
        .with_audit(sandbox_id, audit_sink);

        if let Some(std_stream) = net_mux {
            std_stream.set_nonblocking(true)?;
            let tokio_stream = TokioUnixStream::from_std(std_stream).map_err(CoreError::Io)?;
            let sid = sandbox_id.to_string();
            tasks.push(tokio::spawn(async move {
                if let Err(err) = muxer.run(tokio_stream).await {
                    tracing::debug!(sandbox_id = %sid, error = %err, "Port 1000 muxer exited");
                }
            }));
        }

        Ok(Self {
            ca,
            jail_config,
            http_listen_addr,
            backend: ProxyBackend::InProcess { shutdown_tx, tasks },
        })
    }

    /// Ephemeral ECDSA P-256 MITM CA generated for this VM.
    pub fn ca(&self) -> &Arc<EphemeralCa> {
        &self.ca
    }

    /// Generated rootless proxy jail configuration (including exact `nftables` IP-pinning rules).
    pub fn jail_config(&self) -> &ProxyJailConfig {
        &self.jail_config
    }

    /// Local listener address of this VM's Pingora HTTP MITM service (inside the child netns when jailed).
    pub fn http_listen_addr(&self) -> SocketAddr {
        self.http_listen_addr
    }

    /// Host-namespace PID of the dedicated jailed `blackwall-proxy` child process, if isolated.
    pub fn proxy_pid(&self) -> Option<u32> {
        match &self.backend {
            ProxyBackend::JailedProcess { proxy_pid, .. } => Some(*proxy_pid),
            ProxyBackend::InProcess { .. } => None,
        }
    }

    /// Host-namespace PID of the `pasta` namespace bridge process, if isolated.
    pub fn pasta_pid(&self) -> Option<u32> {
        match &self.backend {
            ProxyBackend::JailedProcess { pasta_pid, .. } => Some(*pasta_pid),
            ProxyBackend::InProcess { .. } => None,
        }
    }

    /// Reported `PR_GET_DUMPABLE` value from the jailed child process (`Some(0)` when jailed).
    pub fn dumpable(&self) -> Option<i32> {
        match &self.backend {
            ProxyBackend::JailedProcess { dumpable, .. } => *dumpable,
            ProxyBackend::InProcess { .. } => None,
        }
    }

    /// `true` when this proxy is running inside a dedicated jailed OS child process.
    pub fn is_isolated(&self) -> bool {
        matches!(self.backend, ProxyBackend::JailedProcess { .. })
    }

    /// Cleanly terminate and reap the jailed proxy process group or in-process tasks.
    pub fn stop(&mut self) {
        match &mut self.backend {
            ProxyBackend::JailedProcess {
                pasta_child,
                pasta_pid,
                proxy_pid,
                audit_thread,
                stderr_thread,
                ..
            } => {
                #[cfg(target_os = "linux")]
                blackwall_proxy::kill_process_group(*pasta_pid, Some(*proxy_pid));

                if let Some(mut child) = pasta_child.take() {
                    let _ = child.kill();
                    let _ = child.wait();
                }
                if let Some(h) = audit_thread.take() {
                    let _ = h.join();
                }
                if let Some(h) = stderr_thread.take() {
                    let _ = h.join();
                }
            }
            ProxyBackend::InProcess { shutdown_tx, tasks } => {
                let _ = shutdown_tx.send(true);
                for task in tasks.drain(..) {
                    task.abort();
                }
            }
        }
    }
}

impl Drop for VmProxyHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::dns::StaticDnsResolver;
    use crate::manager::{CoreConfig, SandboxManager};
    use crate::mock::MockSessionVmmBackend;
    use blackwall_audit::MemoryAuditSink;
    use blackwall_policy::{AuthSpec, HttpRule, NetworkMode, NetworkPatch, ProfileDraft, SecretSpec};
    use blackwall_proto::{
        mux_flags, DnsQueryPayload, DnsRecordType, DnsResponsePayload, MuxFrame, MuxHeader,
        StreamType, MUX_HEADER_LEN,
    };
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn read_status_field(pid: u32, key: &str) -> Option<String> {
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix(key) {
                return Some(rest.trim().to_string());
            }
        }
        None
    }

    #[tokio::test]
    async fn jailed_pasta_proxy_lifecycle_namespaces_caps_seccomp_and_dns() {
        if detect_proxy_tools().is_none() {
            eprintln!(
                "[jailed_pasta_proxy_lifecycle] SKIPPING: blackwall-proxy, pasta, or nft not found"
            );
            return;
        }

        let tmp = tempfile::tempdir().unwrap();
        let sink = Arc::new(MemoryAuditSink::new());
        let mut cfg = CoreConfig::for_testing(tmp.path(), sink.clone());
        cfg.proxy_launch_mode = ProxyLaunchMode::JailedProcess;

        let mut dns = StaticDnsResolver::new();
        dns.insert_ips("api.github.com", vec![IpAddr::V4(Ipv4Addr::new(140, 82, 121, 6))]);

        let mock = MockSessionVmmBackend::new();
        let manager =
            SandboxManager::with_backend(cfg, Box::new(mock.clone()), Arc::new(dns)).unwrap();

        let mut draft = ProfileDraft {
            network: Some(NetworkPatch {
                mode: Some(NetworkMode::Egress),
                http: vec![HttpRule {
                    host: "api.github.com".into(),
                    port: 443,
                    methods: vec!["GET".into()],
                    path_prefixes: vec!["/repos/".into()],
                    max_request_bytes: None,
                    auth: Some(AuthSpec::Bearer {
                        secret: "GITHUB_TOKEN".into(),
                    }),
                }],
                postgres: vec![],
                restrict_hosts: None,
            }),
            ..ProfileDraft::default()
        };
        draft.secrets.insert(
            "GITHUB_TOKEN".into(),
            SecretSpec {
                placeholder_prefix: "ghp_bw00_".into(),
                sealed: None,
                ephemeral: Some("ghp_REAL_TOKEN_NEVER_ON_DISK".into()),
            },
        );

        let summary = manager.create_sandbox(draft).await.unwrap();
        assert!(summary.proxy_isolated, "egress sandbox must spawn isolated proxy");
        let proxy_pid = summary
            .proxy_pid
            .expect("isolated proxy must expose host-namespace proxy_pid");
        assert_ne!(proxy_pid, std::process::id());

        let detail = manager.get_sandbox(&summary.id).await.unwrap();
        assert!(detail.proxy_isolated);
        assert_eq!(detail.proxy_pid, Some(proxy_pid));

        // Verify kernel-level isolation directly via /proc/<proxy_pid>
        let parent_user_ns = std::fs::read_link("/proc/self/ns/user").unwrap();
        let child_user_ns = std::fs::read_link(format!("/proc/{proxy_pid}/ns/user")).unwrap();
        assert_ne!(
            parent_user_ns, child_user_ns,
            "blackwall-proxy must run in its own user namespace"
        );

        let parent_net_ns = std::fs::read_link("/proc/self/ns/net").unwrap();
        let child_net_ns = std::fs::read_link(format!("/proc/{proxy_pid}/ns/net")).unwrap();
        assert_ne!(
            parent_net_ns, child_net_ns,
            "blackwall-proxy must run in its own network namespace"
        );

        assert_eq!(
            read_status_field(proxy_pid, "CapEff:").as_deref(),
            Some("0000000000000000"),
            "all effective capabilities must be dropped"
        );
        assert_eq!(
            read_status_field(proxy_pid, "CapPrm:").as_deref(),
            Some("0000000000000000"),
            "all permitted capabilities must be dropped"
        );
        assert_eq!(
            read_status_field(proxy_pid, "CapInh:").as_deref(),
            Some("0000000000000000"),
            "all inheritable capabilities must be dropped"
        );
        assert_eq!(
            read_status_field(proxy_pid, "NoNewPrivs:").as_deref(),
            Some("1"),
            "PR_SET_NO_NEW_PRIVS must be 1"
        );
        assert_eq!(
            read_status_field(proxy_pid, "Seccomp:").as_deref(),
            Some("2"),
            "seccomp-bpf filter mode (2) must be active"
        );

        // Exercise Port 1000 DNS across the real OS process boundary.
        let guest_std = mock.take_guest_net_stream(&summary.id).unwrap();
        guest_std.set_nonblocking(true).unwrap();
        let mut guest = TokioUnixStream::from_std(guest_std).unwrap();

        let query = DnsQueryPayload {
            query_id: 7,
            fqdn: "api.github.com".into(),
            record_type: DnsRecordType::A,
        };
        let frame = MuxFrame::new(
            1,
            mux_flags::SYN | mux_flags::FIN,
            StreamType::DnsQuery,
            serde_json::to_vec(&query).unwrap(),
        )
        .unwrap();
        let mut wire = Vec::with_capacity(MUX_HEADER_LEN + frame.payload.len());
        wire.extend_from_slice(&frame.header.encode().unwrap());
        wire.extend_from_slice(&frame.payload);
        guest.write_all(&wire).await.unwrap();

        let mut hdr_buf = [0u8; MUX_HEADER_LEN];
        guest.read_exact(&mut hdr_buf).await.unwrap();
        let hdr = MuxHeader::decode(&hdr_buf).unwrap();
        assert_eq!(hdr.stream_type, StreamType::DnsResponse);
        let mut payload = vec![0u8; hdr.payload_len as usize];
        guest.read_exact(&mut payload).await.unwrap();
        let resp: DnsResponsePayload = serde_json::from_slice(&payload).unwrap();
        assert!(resp.allowed);
        assert!(
            resp.synthetic_ip
                .as_deref()
                .is_some_and(|ip| ip.starts_with("198.18.")),
            "expected RFC 2544 synthetic IP, got {:?}",
            resp.synthetic_ip
        );

        // Destroy sandbox and verify jailed proxy process is cleanly killed and reaped.
        manager.destroy_sandbox(&summary.id).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            !std::path::Path::new(&format!("/proc/{proxy_pid}")).exists(),
            "jailed blackwall-proxy process {proxy_pid} must be terminated on destroy"
        );
    }

    #[test]
    fn sanitize_proxy_event_overwrites_spoofed_identity_timestamp_and_origin() {
        let spoofed = AuditEvent {
            timestamp_ms: 42,
            sandbox_id: "bw-victim-sibling".into(),
            origin: AuditOrigin::Daemon,
            kind: AuditEventKind::DnsQuery {
                fqdn: "api.github.com".into(),
                allowed: true,
                synthetic_ip: Some("198.18.0.1".into()),
            },
        };

        let before = parent_now_ms();
        let cleaned = sanitize_proxy_event(spoofed, "bw-real-sandbox").expect("DnsQuery allowed");
        let after = parent_now_ms();

        assert_eq!(cleaned.sandbox_id, "bw-real-sandbox");
        assert_eq!(cleaned.origin, AuditOrigin::Proxy);
        assert!(
            cleaned.timestamp_ms >= before && cleaned.timestamp_ms <= after,
            "timestamp_ms must be overwritten with parent clock, got {}",
            cleaned.timestamp_ms
        );
    }

    #[test]
    fn sanitize_proxy_event_drops_disallowed_variants() {
        use blackwall_audit::TransferDirection;
        use blackwall_proto::GuestAuditFrame;

        let disallowed_kinds = vec![
            AuditEventKind::SandboxLifecycle {
                phase: "destroyed".into(),
                image_roothash: None,
                details: None,
            },
            AuditEventKind::ExecCommand {
                cmd: vec!["rm".into(), "-rf".into(), "/".into()],
                cwd: None,
                background: false,
                exit_code: Some(0),
                duration_ms: Some(1),
            },
            AuditEventKind::FileTransfer {
                direction: TransferDirection::Download,
                path: "/etc/shadow".into(),
                bytes: 100,
                files: 1,
            },
            AuditEventKind::UnpackerRejection {
                path: "x".into(),
                reason: "spoofed".into(),
            },
            AuditEventKind::VmmFatalExit {
                reason: "fake".into(),
                exit_detail: "fake".into(),
            },
            AuditEventKind::GuestPort1001 {
                frame: GuestAuditFrame {
                    timestamp_ns: 1,
                    source: "spoof".into(),
                    kind: "spoof".into(),
                    payload: serde_json::json!({}),
                },
            },
            AuditEventKind::IngressTunnel {
                guest_port: 8080,
                bytes_in: 1,
                bytes_out: 1,
                allowed: true,
            },
        ];

        for kind in disallowed_kinds {
            let ev = AuditEvent::now("bw-spoof", kind);
            assert!(
                sanitize_proxy_event(ev, "bw-real").is_none(),
                "proxy MUST NOT be allowed to emit non-proxy AuditEventKind variants"
            );
        }
    }

    #[test]
    fn sanitize_proxy_event_strips_ansi_and_control_chars_and_truncates_oversized_strings() {
        let evil_host = format!("\x1b[31m{}\x1b[0m\r\n\0", "a".repeat(400));
        let evil_method = format!("G\x00E\r\nT\x1b[1m{}", "X".repeat(64));
        let evil_path = format!("/v1/\x1b[31mred\x1b[0m\x07\r\n{}", "p".repeat(3000));

        let ev = AuditEvent::now(
            "bw-evil",
            AuditEventKind::HttpRequest {
                host: evil_host,
                method: evil_method,
                path: evil_path,
                status: 200,
                request_bytes: 10,
                response_bytes: 20,
                auth_injected: false,
            },
        );
        let cleaned = sanitize_proxy_event(ev, "bw-target").expect("HttpRequest allowed");
        match cleaned.kind {
            AuditEventKind::HttpRequest {
                host, method, path, ..
            } => {
                assert_eq!(host.len(), 255);
                assert!(!host.contains('\x1b'));
                assert!(!host.chars().any(|c| c.is_control()));
                assert!(host.chars().all(|c| c == 'a'));

                assert_eq!(method.len(), 32);
                assert!(method.starts_with("GET"));
                assert!(!method.chars().any(|c| c.is_control()));

                assert_eq!(path.len(), 2048);
                assert!(path.starts_with("/v1/red"));
                assert!(!path.contains("\x1b[31m"));
                assert!(!path.chars().any(|c| c.is_control()));
            }
            other => panic!("expected HttpRequest, got {other:?}"),
        }

        // Also check PostgresQuery control char sanitization & statement truncation.
        let pg_ev = AuditEvent::now(
            "bw-evil",
            AuditEventKind::PostgresQuery {
                host: "db.internal\r\n\x1b[32m".into(),
                port: 5432,
                message_type: '\x1b',
                statement: format!("SELECT \x1b[31m1\x1b[0m {}", "z".repeat(3000)),
            },
        );
        let pg_cleaned = sanitize_proxy_event(pg_ev, "bw-target").expect("PostgresQuery allowed");
        match pg_cleaned.kind {
            AuditEventKind::PostgresQuery {
                host,
                message_type,
                statement,
                ..
            } => {
                assert_eq!(host, "db.internal");
                assert_eq!(message_type, '?');
                assert_eq!(statement.len(), 2048);
                assert!(statement.starts_with("SELECT 1 "));
                assert!(!statement.chars().any(|c| c.is_control()));
            }
            other => panic!("expected PostgresQuery, got {other:?}"),
        }
    }

    #[test]
    fn drain_proxy_audit_reader_drops_oversized_lines_without_breaking_subsequent_valid_lines() {
        use std::io::Cursor;

        let valid1 = serde_json::to_string(&AuditEvent::now(
            "bw-spoofed",
            AuditEventKind::DnsQuery {
                fqdn: "first.example".into(),
                allowed: true,
                synthetic_ip: Some("198.18.0.1".into()),
            },
        ))
        .unwrap();

        // > 64 KiB malicious NDJSON line (100 KiB payload).
        let huge_payload = "A".repeat(MAX_PROXY_AUDIT_LINE_BYTES + 32_768);
        let oversized_line = format!(
            r#"{{"timestamp_ms":1,"sandbox_id":"bw-x","event":"dns_query","fqdn":"{huge_payload}","allowed":false,"synthetic_ip":null}}"#
        );
        assert!(oversized_line.len() > MAX_PROXY_AUDIT_LINE_BYTES);

        // Disallowed ExecCommand line interspersed.
        let disallowed = serde_json::to_string(&AuditEvent::now(
            "bw-spoofed",
            AuditEventKind::ExecCommand {
                cmd: vec!["id".into()],
                cwd: None,
                background: false,
                exit_code: Some(0),
                duration_ms: Some(1),
            },
        ))
        .unwrap();

        let valid2 = serde_json::to_string(&AuditEvent::now(
            "bw-spoofed",
            AuditEventKind::AuthMismatch {
                host: "api.example\x1b[31m".into(),
                path: "/secret\r\n".into(),
                reason: "bad host".into(),
            },
        ))
        .unwrap();

        let stream = format!("{valid1}\n{oversized_line}\n{disallowed}\n{valid2}\n");
        let sink = MemoryAuditSink::new();
        drain_proxy_audit_reader(Cursor::new(stream.into_bytes()), "bw-authoritative", &sink);

        let recorded = sink.snapshot();
        assert_eq!(recorded.len(), 2, "only the 2 valid allowlisted events should be recorded");
        assert_eq!(recorded[0].sandbox_id, "bw-authoritative");
        assert_eq!(recorded[0].origin, AuditOrigin::Proxy);
        assert!(matches!(
            &recorded[0].kind,
            AuditEventKind::DnsQuery { fqdn, .. } if fqdn == "first.example"
        ));

        assert_eq!(recorded[1].sandbox_id, "bw-authoritative");
        assert_eq!(recorded[1].origin, AuditOrigin::Proxy);
        assert!(matches!(
            &recorded[1].kind,
            AuditEventKind::AuthMismatch { host, path, reason }
            if host == "api.example" && path == "/secret" && reason == "bad host"
        ));
    }

    #[test]
    fn anonymous_socketpair_passcred_delivers_peer_pid_and_ready_ack() {
        let (parent, mut child) = StdUnixStream::pair().unwrap();
        enable_unix_passcred(&parent).unwrap();
        let ack = ProxyReadyAck {
            ok: true,
            http_listen_addr: Some("127.0.0.1:12345".into()),
            dumpable: Some(0),
            error: None,
        };
        let line = serde_json::to_string(&ack).unwrap();
        writeln!(child, "{line}").unwrap();
        child.flush().unwrap();
        drop(child);

        let (received_line, peer_pid) = recv_ready_ack_with_peer_pid(&parent).unwrap();
        assert_eq!(received_line, line);
        assert_eq!(peer_pid, Some(std::process::id()));
    }
}
