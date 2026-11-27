//! Pluggable observability and audit hooks for Blackwall.
//!
//! Provides the `AuditSink` trait, strongly typed `AuditEvent` structs,
//! Port 1001 unidirectional frame ingestion hook, and minimal default sinks
//! (`NoopAuditSink`, `JsonlAuditSink`, `MemoryAuditSink`).
//!
//! Intentionally excludes BPF LSM, RFC 6962 Merkle spooling, and `immudb`
//! backends—those plug into `AuditSink` in a future phase.

use blackwall_proto::GuestAuditFrame;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("audit sink lock poisoned")]
    Poisoned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransferDirection {
    Upload,
    Download,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum AuditEventKind {
    SandboxLifecycle {
        phase: String,
        image_roothash: Option<String>,
        details: Option<String>,
    },
    ExecCommand {
        cmd: Vec<String>,
        cwd: Option<String>,
        background: bool,
        exit_code: Option<i32>,
        duration_ms: Option<u64>,
    },
    FileTransfer {
        direction: TransferDirection,
        path: String,
        bytes: u64,
        files: u64,
    },
    HttpRequest {
        host: String,
        method: String,
        path: String,
        status: u16,
        request_bytes: u64,
        response_bytes: u64,
        auth_injected: bool,
    },
    AuthMismatch {
        host: String,
        path: String,
        reason: String,
    },
    PostgresQuery {
        host: String,
        port: u16,
        message_type: char,
        statement: String,
    },
    UnpackerRejection {
        path: String,
        reason: String,
    },
    VmmFatalExit {
        reason: String,
        exit_detail: String,
    },
    GuestPort1001 {
        frame: GuestAuditFrame,
    },
    IngressTunnel {
        guest_port: u16,
        bytes_in: u64,
        bytes_out: u64,
        allowed: bool,
    },
    HostServiceBridge {
        name: String,
        guest_port: u16,
        target: String,
        bytes_in: u64,
        bytes_out: u64,
        allowed: bool,
    },
    DnsQuery {
        fqdn: String,
        allowed: bool,
        synthetic_ip: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOrigin {
    #[default]
    Daemon,
    Proxy,
    Unpacker,
    Vmm,
    GuestUntrusted,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub timestamp_ms: u64,
    pub sandbox_id: String,
    #[serde(default)]
    pub origin: AuditOrigin,
    #[serde(flatten)]
    pub kind: AuditEventKind,
}

impl AuditEvent {
    pub fn now(sandbox_id: impl Into<String>, kind: AuditEventKind) -> Self {
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let origin = if matches!(kind, AuditEventKind::GuestPort1001 { .. }) {
            AuditOrigin::GuestUntrusted
        } else {
            AuditOrigin::Daemon
        };
        Self {
            timestamp_ms,
            sandbox_id: sandbox_id.into(),
            origin,
            kind,
        }
    }

    pub fn with_origin(mut self, origin: AuditOrigin) -> Self {
        self.origin = origin;
        self
    }
}

/// Core extension hook for all Blackwall audit & telemetry consumers.
pub trait AuditSink: Send + Sync {
    fn record(&self, event: AuditEvent);
    fn flush(&self) -> Result<(), AuditError> {
        Ok(())
    }
}

/// Default zero-overhead no-op sink.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopAuditSink;

impl AuditSink for NoopAuditSink {
    fn record(&self, _event: AuditEvent) {}
}

/// Minimal JSONL sink writing one `AuditEvent` per line to any writer or file.
pub struct JsonlAuditSink<W: Write + Send> {
    writer: Mutex<BufWriter<W>>,
}

impl<W: Write + Send> JsonlAuditSink<W> {
    pub fn new(writer: W) -> Self {
        Self {
            writer: Mutex::new(BufWriter::new(writer)),
        }
    }
}

impl JsonlAuditSink<File> {
    pub fn open_append(path: impl AsRef<Path>) -> Result<Self, AuditError> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self::new(file))
    }
}

impl<W: Write + Send> AuditSink for JsonlAuditSink<W> {
    fn record(&self, event: AuditEvent) {
        if let Ok(mut guard) = self.writer.lock() {
            if let Ok(line) = serde_json::to_string(&event) {
                let _ = writeln!(guard, "{line}");
                let _ = guard.flush();
            }
        }
    }

    fn flush(&self) -> Result<(), AuditError> {
        let mut guard = self.writer.lock().map_err(|_| AuditError::Poisoned)?;
        guard.flush()?;
        Ok(())
    }
}

/// In-memory sink useful for tests and embedded SDK inspection.
#[derive(Debug, Default, Clone)]
pub struct MemoryAuditSink {
    events: Arc<Mutex<Vec<AuditEvent>>>,
}

impl MemoryAuditSink {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn snapshot(&self) -> Vec<AuditEvent> {
        self.events.lock().map(|g| g.clone()).unwrap_or_default()
    }
}

impl AuditSink for MemoryAuditSink {
    fn record(&self, event: AuditEvent) {
        if let Ok(mut guard) = self.events.lock() {
            guard.push(event);
        }
    }
}

/// Ingest a unidirectional Port 1001 stream until EOF, forwarding each
/// `GuestAuditFrame` to `sink`.
const MAX_GUEST_AUDIT_FIELD_BYTES: usize = 128;
const MAX_GUEST_AUDIT_DETAILS_BYTES: usize = 4096;
const PORT1001_RATE_BURST: f64 = 64.0;
const PORT1001_RATE_PER_SEC: f64 = 20.0;

/// Strip ANSI CSI/OSC escape sequences and ASCII control characters, truncating to `max_bytes`
/// on a valid UTF-8 boundary.
fn sanitize_guest_string(input: &str, max_bytes: usize) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len().min(max_bytes));
    let mut i = 0;
    while i < bytes.len() && out.len() < max_bytes {
        if bytes[i] == 0x1b {
            // Skip CSI (`ESC [ ... final`) or OSC (`ESC ] ... BEL/ST`) sequences.
            i += 1;
            if i < bytes.len() && bytes[i] == b'[' {
                i += 1;
                while i < bytes.len() && !(0x40..=0x7e).contains(&bytes[i]) {
                    i += 1;
                }
                if i < bytes.len() {
                    i += 1;
                }
                continue;
            } else if i < bytes.len() && bytes[i] == b']' {
                i += 1;
                while i < bytes.len() && bytes[i] != 0x07 {
                    if bytes[i] == 0x1b && i + 1 < bytes.len() && bytes[i + 1] == b'\\' {
                        i += 2;
                        break;
                    }
                    i += 1;
                }
                if i < bytes.len() && bytes[i] == 0x07 {
                    i += 1;
                }
                continue;
            }
            continue;
        }
        let Some(ch) = input[i..].chars().next() else {
            break;
        };
        let ch_len = ch.len_utf8();
        i += ch_len;
        if ch.is_control() {
            if matches!(ch, '\n' | '\r' | '\t') && out.len() < max_bytes {
                out.push(' ');
            }
            continue;
        }
        if out.len() + ch_len > max_bytes {
            break;
        }
        out.push(ch);
    }
    out
}

fn sanitize_guest_json(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::String(s) => {
            serde_json::Value::String(sanitize_guest_string(&s, 1024))
        }
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.into_iter().take(64).map(sanitize_guest_json).collect())
        }
        serde_json::Value::Object(map) => {
            let clean = map
                .into_iter()
                .take(64)
                .map(|(k, v)| (sanitize_guest_string(&k, 64), sanitize_guest_json(v)))
                .collect();
            serde_json::Value::Object(clean)
        }
        other => other,
    }
}

/// Sanitize an untrusted Port 1001 [`GuestAuditFrame`] before recording it on the host.
pub fn sanitize_guest_audit_frame(frame: GuestAuditFrame) -> GuestAuditFrame {
    let source = sanitize_guest_string(&frame.source, MAX_GUEST_AUDIT_FIELD_BYTES);
    let kind = sanitize_guest_string(&frame.kind, MAX_GUEST_AUDIT_FIELD_BYTES);
    let sanitized_payload = sanitize_guest_json(frame.payload);
    let payload = match serde_json::to_string(&sanitized_payload) {
        Ok(encoded) if encoded.len() <= MAX_GUEST_AUDIT_DETAILS_BYTES => sanitized_payload,
        _ => serde_json::json!({ "truncated": true }),
    };
    GuestAuditFrame {
        timestamp_ns: frame.timestamp_ns,
        source,
        kind,
        payload,
    }
}

struct Port1001RateLimiter {
    tokens: f64,
    last_refill: Instant,
    throttled_notified: bool,
}

impl Port1001RateLimiter {
    fn new() -> Self {
        Self {
            tokens: PORT1001_RATE_BURST,
            last_refill: Instant::now(),
            throttled_notified: false,
        }
    }

    fn allow(&mut self) -> (bool, bool) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        if elapsed > 0.0 {
            self.tokens = (self.tokens + elapsed * PORT1001_RATE_PER_SEC).min(PORT1001_RATE_BURST);
            self.last_refill = now;
        }
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            if self.tokens > PORT1001_RATE_BURST / 2.0 {
                self.throttled_notified = false;
            }
            (true, false)
        } else {
            let emit_warning = !self.throttled_notified;
            self.throttled_notified = true;
            (false, emit_warning)
        }
    }
}

/// Drain unidirectional Port 1001 guest audit frames from `reader` into `sink`,
/// enforcing `AuditOrigin::GuestUntrusted`, ANSI/control-char sanitization, field caps,
/// and per-sandbox token-bucket rate limiting.
pub fn drain_port1001_stream<R: std::io::Read>(
    mut reader: R,
    sandbox_id: &str,
    sink: &dyn AuditSink,
) -> usize {
    let mut count = 0;
    let mut limiter = Port1001RateLimiter::new();
    while let Ok(frame) = blackwall_proto::read_audit_frame(&mut reader) {
        let (allowed, emit_warning) = limiter.allow();
        if !allowed {
            if emit_warning {
                sink.record(
                    AuditEvent::now(
                        sandbox_id,
                        AuditEventKind::SandboxLifecycle {
                            phase: "guest_audit_throttled".into(),
                            image_roothash: None,
                            details: Some(
                                "Port 1001 guest audit stream exceeded rate limit; excess frames dropped".into(),
                            ),
                        },
                    )
                    .with_origin(AuditOrigin::Daemon),
                );
            }
            continue;
        }
        let clean = sanitize_guest_audit_frame(frame);
        sink.record(
            AuditEvent::now(sandbox_id, AuditEventKind::GuestPort1001 { frame: clean })
                .with_origin(AuditOrigin::GuestUntrusted),
        );
        count += 1;
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn memory_and_jsonl_sinks_record_events() {
        let mem = MemoryAuditSink::new();
        mem.record(AuditEvent::now(
            "sb-1",
            AuditEventKind::PostgresQuery {
                host: "db.internal".into(),
                port: 5432,
                message_type: 'Q',
                statement: "SELECT 1".into(),
            },
        ));
        assert_eq!(mem.snapshot().len(), 1);

        let shared = Arc::new(Mutex::new(Vec::<u8>::new()));
        struct SharedBuf(Arc<Mutex<Vec<u8>>>);
        impl Write for SharedBuf {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let sink = JsonlAuditSink::new(SharedBuf(shared.clone()));
        sink.record(AuditEvent::now(
            "sb-2",
            AuditEventKind::UnpackerRejection {
                path: ".GitHub/workflows/ci.yml".into(),
                reason: "matched deny_touch_globs".into(),
            },
        ));
        sink.flush().unwrap();
        let text = String::from_utf8(shared.lock().unwrap().clone()).unwrap();
        let parsed: AuditEvent = serde_json::from_str(text.trim()).unwrap();
        assert_eq!(parsed.sandbox_id, "sb-2");
    }

    #[test]
    fn port1001_drain_forwards_guest_frames() {
        let mut wire = Vec::new();
        let frame = GuestAuditFrame {
            timestamp_ns: 42,
            source: "init".into(),
            kind: "boot".into(),
            payload: serde_json::json!({"ok": true}),
        };
        blackwall_proto::write_audit_frame(&mut wire, &frame).unwrap();
        let sink = MemoryAuditSink::new();
        let count = drain_port1001_stream(Cursor::new(wire), "sb-3", &sink);
        assert_eq!(count, 1);
        assert_eq!(sink.snapshot().len(), 1);
    }

    #[test]
    fn dns_query_event_serializes_with_dns_query_tag() {
        let allowed_ev = AuditEvent::now(
            "sb-dns",
            AuditEventKind::DnsQuery {
                fqdn: "api.github.com".into(),
                allowed: true,
                synthetic_ip: Some("198.18.1.2".into()),
            },
        );
        let val = serde_json::to_value(&allowed_ev).unwrap();
        assert_eq!(val["event"], "dns_query");
        assert_eq!(val["fqdn"], "api.github.com");
        assert_eq!(val["allowed"], true);
        assert_eq!(val["synthetic_ip"], "198.18.1.2");
        let roundtrip: AuditEvent = serde_json::from_value(val).unwrap();
        assert_eq!(roundtrip, allowed_ev);

        let blocked_ev = AuditEvent::now(
            "sb-dns",
            AuditEventKind::DnsQuery {
                fqdn: "google.com".into(),
                allowed: false,
                synthetic_ip: None,
            },
        );
        let val = serde_json::to_value(&blocked_ev).unwrap();
        assert_eq!(val["event"], "dns_query");
        assert_eq!(val["fqdn"], "google.com");
        assert_eq!(val["allowed"], false);
        assert!(val["synthetic_ip"].is_null());
        let roundtrip: AuditEvent = serde_json::from_value(val).unwrap();
        assert_eq!(roundtrip, blocked_ev);
    }

    #[test]
    fn audit_origin_defaults_and_serializes_in_snake_case() {
        let daemon_ev = AuditEvent::now(
            "sb-origin",
            AuditEventKind::SandboxLifecycle {
                phase: "running".into(),
                image_roothash: None,
                details: None,
            },
        );
        assert_eq!(daemon_ev.origin, AuditOrigin::Daemon);

        let proxy_ev = AuditEvent::now(
            "sb-origin",
            AuditEventKind::DnsQuery {
                fqdn: "api.github.com".into(),
                allowed: true,
                synthetic_ip: Some("198.18.0.1".into()),
            },
        )
        .with_origin(AuditOrigin::Proxy);
        assert_eq!(proxy_ev.origin, AuditOrigin::Proxy);
        assert_eq!(serde_json::to_value(&proxy_ev).unwrap()["origin"], "proxy");

        let guest_ev = AuditEvent::now(
            "sb-origin",
            AuditEventKind::GuestPort1001 {
                frame: GuestAuditFrame {
                    timestamp_ns: 1,
                    source: "init".into(),
                    kind: "boot".into(),
                    payload: serde_json::json!({}),
                },
            },
        );
        assert_eq!(guest_ev.origin, AuditOrigin::GuestUntrusted);
        assert_eq!(
            serde_json::to_value(&guest_ev).unwrap()["origin"],
            "guest_untrusted"
        );

        // Legacy JSON without `origin` deserializes with `AuditOrigin::Daemon`.
        let legacy_json = r#"{"timestamp_ms":123,"sandbox_id":"sb-legacy","event":"dns_query","fqdn":"a.test","allowed":false,"synthetic_ip":null}"#;
        let parsed: AuditEvent = serde_json::from_str(legacy_json).unwrap();
        assert_eq!(parsed.origin, AuditOrigin::Daemon);
    }

    #[test]
    fn host_service_bridge_event_serializes_roundtrip() {
        let ev = AuditEvent::now(
            "sb-bridge",
            AuditEventKind::HostServiceBridge {
                name: "local-pg".into(),
                guest_port: 5432,
                target: "127.0.0.1:5432".into(),
                bytes_in: 1024,
                bytes_out: 4096,
                allowed: true,
            },
        );
        let val = serde_json::to_value(&ev).unwrap();
        assert_eq!(val["event"], "host_service_bridge");
        assert_eq!(val["name"], "local-pg");
        assert_eq!(val["guest_port"], 5432);
        assert_eq!(val["target"], "127.0.0.1:5432");
        assert_eq!(val["bytes_in"], 1024);
        assert_eq!(val["bytes_out"], 4096);
        assert_eq!(val["allowed"], true);
        let roundtrip: AuditEvent = serde_json::from_value(val).unwrap();
        assert_eq!(roundtrip, ev);

        let denied = AuditEvent::now(
            "sb-bridge",
            AuditEventKind::HostServiceBridge {
                name: "sock-svc".into(),
                guest_port: 8080,
                target: "unix:///run/svc.sock".into(),
                bytes_in: 0,
                bytes_out: 0,
                allowed: false,
            },
        );
        let text = serde_json::to_string(&denied).unwrap();
        let parsed: AuditEvent = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed, denied);
    }

    #[test]
    fn port1001_drain_sanitizes_ansi_tags_guest_untrusted_and_rate_limits_floods() {
        let sink = MemoryAuditSink::new();
        let mut wire = Vec::new();
        // Frame 1: ANSI + control chars + oversized payload
        let dirty = GuestAuditFrame {
            timestamp_ns: 1,
            source: "\x1b[31mblackwall-init\x1b[0m\n".into(),
            kind: "boot\x1b]0;pwn\x07_ok".into(),
            payload: serde_json::json!({ "msg": "\x1b[1;31mfake\x1b[0m", "pad": "A".repeat(8000) }),
        };
        blackwall_proto::write_audit_frame(&mut wire, &dirty).unwrap();

        // Frames 2..=120: flood past burst cap (64)
        for i in 0..120 {
            let f = GuestAuditFrame {
                timestamp_ns: i + 2,
                source: "guest".into(),
                kind: "spam".into(),
                payload: serde_json::json!({ "i": i }),
            };
            blackwall_proto::write_audit_frame(&mut wire, &f).unwrap();
        }

        let accepted = drain_port1001_stream(Cursor::new(&wire), "bw-flood", &sink);
        assert!(accepted <= 65, "expected burst throttling, accepted {accepted}");

        let events = sink.snapshot();
        // First event must be GuestUntrusted with ANSI stripped and oversized payload truncated
        assert_eq!(events[0].origin, AuditOrigin::GuestUntrusted);
        match &events[0].kind {
            AuditEventKind::GuestPort1001 { frame } => {
                assert_eq!(frame.source, "blackwall-init ");
                assert_eq!(frame.kind, "boot_ok");
                assert!(!frame.source.contains('\x1b'));
                assert!(!frame.kind.contains('\x1b'));
            }
            other => panic!("expected GuestPort1001, got {other:?}"),
        }
        // Throttle warning emitted once with Daemon origin
        let throttle_warnings: Vec<_> = events
            .iter()
            .filter(|e| {
                e.origin == AuditOrigin::Daemon
                    && matches!(
                        &e.kind,
                        AuditEventKind::SandboxLifecycle { phase, .. } if phase == "guest_audit_throttled"
                    )
            })
            .collect();
        assert_eq!(throttle_warnings.len(), 1);
    }
}
