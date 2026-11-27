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
use std::time::{SystemTime, UNIX_EPOCH};
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
pub fn drain_port1001_stream<R: std::io::Read>(
    mut reader: R,
    sandbox_id: &str,
    sink: &dyn AuditSink,
) -> usize {
    let mut count = 0;
    while let Ok(frame) = blackwall_proto::read_audit_frame(&mut reader) {
        sink.record(AuditEvent::now(
            sandbox_id,
            AuditEventKind::GuestPort1001 { frame },
        ));
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
}
