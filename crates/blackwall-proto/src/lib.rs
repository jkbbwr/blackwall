//! Wire protocol definitions for Blackwall's host-initiated `AF_VSOCK` channels:
//! - Port 1000 (`NET_MUX`): 12-byte big-endian length-prefixed stream multiplexer
//! - Port 1001 (`AUDIT_UNI`): Guest -> Host unidirectional audit frames
//! - Port 1002 (`CTRL_SESSION`): Boot config + interactive exec/bg-proc/PTY/file RPCs

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use thiserror::Error;

pub const PORT_NET_MUX: u32 = 1000;
pub const PORT_AUDIT_UNI: u32 = 1001;
pub const PORT_CTRL_SESSION: u32 = 1002;

pub const MUX_HEADER_LEN: usize = 12;
pub const MAX_MUX_PAYLOAD: u32 = 65_536; // 64 KiB
pub const MAX_AUDIT_FRAME: u32 = 256 * 1024; // 256 KiB
pub const MAX_CTRL_FRAME: u32 = 1024 * 1024; // 1 MiB

#[derive(Debug, Error)]
pub enum ProtoError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("payload length {len} exceeds maximum {max}")]
    PayloadTooLarge { len: u32, max: u32 },
    #[error("unknown stream type: {0}")]
    UnknownStreamType(u8),
    #[error("invalid mux flags: 0x{0:02x}")]
    InvalidFlags(u8),
    #[error("non-zero reserved field in mux header: 0x{0:04x}")]
    NonZeroReserved(u16),
    #[error("invalid vsock handshake line: {0}")]
    InvalidHandshake(String),
    #[error("truncated frame")]
    Truncated,
}

pub type Result<T> = std::result::Result<T, ProtoError>;

// ---------------------------------------------------------------------------
// Host-initiated Cloud Hypervisor / Firecracker hybrid vsock handshake
// ---------------------------------------------------------------------------

/// Format the host -> VMM connect line for a guest vsock port.
pub fn format_connect_handshake(port: u32) -> String {
    format!("CONNECT {port}\n")
}

/// Parse the VMM -> host response line (`OK <local_port>\n`) returning `<local_port>`.
pub fn parse_ok_handshake(line: &str) -> Result<u32> {
    let trimmed = line.trim_end_matches(['\r', '\n']);
    let rest = trimmed
        .strip_prefix("OK ")
        .ok_or_else(|| ProtoError::InvalidHandshake(trimmed.to_string()))?;
    rest.parse::<u32>()
        .map_err(|_| ProtoError::InvalidHandshake(trimmed.to_string()))
}

// ---------------------------------------------------------------------------
// Port 1000: 12-byte big-endian stream multiplexer framing
// ---------------------------------------------------------------------------

pub mod mux_flags {
    pub const SYN: u8 = 0x01;
    pub const DATA: u8 = 0x02;
    pub const FIN: u8 = 0x04;
    pub const RST: u8 = 0x08;
    pub const ACK: u8 = 0x10;
    pub const VALID_MASK: u8 = SYN | DATA | FIN | RST | ACK;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum StreamType {
    Tcp = 1,
    DnsQuery = 2,
    DnsResponse = 3,
    Postgres = 4,
}

impl TryFrom<u8> for StreamType {
    type Error = ProtoError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Tcp),
            2 => Ok(Self::DnsQuery),
            3 => Ok(Self::DnsResponse),
            4 => Ok(Self::Postgres),
            other => Err(ProtoError::UnknownStreamType(other)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MuxHeader {
    pub stream_id: u32,
    pub payload_len: u32,
    pub flags: u8,
    pub stream_type: StreamType,
    pub reserved: u16,
}

impl MuxHeader {
    pub fn new(stream_id: u32, payload_len: u32, flags: u8, stream_type: StreamType) -> Result<Self> {
        if payload_len > MAX_MUX_PAYLOAD {
            return Err(ProtoError::PayloadTooLarge {
                len: payload_len,
                max: MAX_MUX_PAYLOAD,
            });
        }
        if flags == 0 || (flags & !mux_flags::VALID_MASK) != 0 {
            return Err(ProtoError::InvalidFlags(flags));
        }
        Ok(Self {
            stream_id,
            payload_len,
            flags,
            stream_type,
            reserved: 0,
        })
    }

    pub fn encode(&self) -> Result<[u8; MUX_HEADER_LEN]> {
        if self.payload_len > MAX_MUX_PAYLOAD {
            return Err(ProtoError::PayloadTooLarge {
                len: self.payload_len,
                max: MAX_MUX_PAYLOAD,
            });
        }
        if self.flags == 0 || (self.flags & !mux_flags::VALID_MASK) != 0 {
            return Err(ProtoError::InvalidFlags(self.flags));
        }
        if self.reserved != 0 {
            return Err(ProtoError::NonZeroReserved(self.reserved));
        }
        let mut buf = [0u8; MUX_HEADER_LEN];
        buf[0..4].copy_from_slice(&self.stream_id.to_be_bytes());
        buf[4..8].copy_from_slice(&self.payload_len.to_be_bytes());
        buf[8] = self.flags;
        buf[9] = self.stream_type as u8;
        buf[10..12].copy_from_slice(&self.reserved.to_be_bytes());
        Ok(buf)
    }

    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < MUX_HEADER_LEN {
            return Err(ProtoError::Truncated);
        }
        let stream_id = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let payload_len = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        if payload_len > MAX_MUX_PAYLOAD {
            return Err(ProtoError::PayloadTooLarge {
                len: payload_len,
                max: MAX_MUX_PAYLOAD,
            });
        }
        let flags = buf[8];
        if flags == 0 || (flags & !mux_flags::VALID_MASK) != 0 {
            return Err(ProtoError::InvalidFlags(flags));
        }
        let stream_type = StreamType::try_from(buf[9])?;
        let reserved = u16::from_be_bytes([buf[10], buf[11]]);
        if reserved != 0 {
            return Err(ProtoError::NonZeroReserved(reserved));
        }
        Ok(Self {
            stream_id,
            payload_len,
            flags,
            stream_type,
            reserved,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MuxFrame {
    pub header: MuxHeader,
    pub payload: Vec<u8>,
}

impl MuxFrame {
    pub fn new(stream_id: u32, flags: u8, stream_type: StreamType, payload: Vec<u8>) -> Result<Self> {
        let payload_len = u32::try_from(payload.len()).map_err(|_| ProtoError::PayloadTooLarge {
            len: u32::MAX,
            max: MAX_MUX_PAYLOAD,
        })?;
        let header = MuxHeader::new(stream_id, payload_len, flags, stream_type)?;
        Ok(Self { header, payload })
    }

    pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        if self.payload.len() != self.header.payload_len as usize {
            return Err(ProtoError::PayloadTooLarge {
                len: self.payload.len() as u32,
                max: self.header.payload_len,
            });
        }
        let hdr = self.header.encode()?;
        writer.write_all(&hdr)?;
        if !self.payload.is_empty() {
            writer.write_all(&self.payload)?;
        }
        Ok(())
    }

    pub fn read_from<R: Read>(reader: &mut R) -> Result<Self> {
        let mut hdr_buf = [0u8; MUX_HEADER_LEN];
        reader.read_exact(&mut hdr_buf)?;
        let header = MuxHeader::decode(&hdr_buf)?;
        let mut payload = vec![0u8; header.payload_len as usize];
        if !payload.is_empty() {
            reader.read_exact(&mut payload)?;
        }
        Ok(Self { header, payload })
    }
}

/// Payload for `StreamType::Tcp` / `StreamType::Postgres` `SYN` frames opening a stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamOpenPayload {
    pub dst_ip: String,
    pub dst_port: u16,
    pub hostname: Option<String>,
}

/// Payload for `StreamType::DnsQuery` frames.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsQueryPayload {
    pub query_id: u16,
    pub fqdn: String,
    pub record_type: DnsRecordType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum DnsRecordType {
    A,
    AAAA,
}

/// Payload for `StreamType::DnsResponse` frames.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsResponsePayload {
    pub query_id: u16,
    pub fqdn: String,
    pub synthetic_ip: Option<String>,
    pub allowed: bool,
    pub ttl_sec: u32,
}

// ---------------------------------------------------------------------------
// Port 1001: Unidirectional guest -> host audit frame
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GuestAuditFrame {
    pub timestamp_ns: u64,
    pub source: String,
    pub kind: String,
    pub payload: serde_json::Value,
}

pub fn write_audit_frame<W: Write>(writer: &mut W, frame: &GuestAuditFrame) -> Result<()> {
    write_length_prefixed_json(writer, frame, MAX_AUDIT_FRAME)
}

pub fn read_audit_frame<R: Read>(reader: &mut R) -> Result<GuestAuditFrame> {
    read_length_prefixed_json(reader, MAX_AUDIT_FRAME)
}

// ---------------------------------------------------------------------------
// Port 1002: Session control, exec, background procs, PTY, upload/download
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GuestNetMode {
    None,
    Loopback,
    Egress,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DmVerityConfig {
    pub roothash_hex: String,
    pub salt_hex: String,
    pub data_blocks: u64,
    pub hash_start_block: u64,
    pub data_block_size: u32,
    pub hash_block_size: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootConfig {
    pub vda_verity: Option<DmVerityConfig>,
    pub network_mode: GuestNetMode,
    pub mitm_ca_pem: Option<String>,
    pub env: BTreeMap<String, String>,
    pub secret_placeholders: BTreeMap<String, String>,
    pub workspace_mount: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputStream {
    Stdout,
    Stderr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum SignalKind {
    Sigterm,
    Sigkill,
    Sigint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UploadKind {
    Raw,
    Tar,
    TarGz,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DownloadFormat {
    Raw,
    TarGz,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessState {
    Running,
    Exited,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub proc_id: String,
    pub pid: u32,
    pub cmd: Vec<String>,
    pub state: ProcessState,
    pub exit_code: Option<i32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CtrlErrorCode {
    InvalidRequest,
    NotFound,
    PermissionDenied,
    PathViolation,
    LimitExceeded,
    Timeout,
    Internal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CtrlRequest {
    BootConfigure {
        req_id: u64,
        config: BootConfig,
    },
    ExecStart {
        req_id: u64,
        cmd: Vec<String>,
        cwd: Option<String>,
        env: BTreeMap<String, String>,
        stdin: Option<Vec<u8>>,
        timeout_sec: Option<u64>,
        background: bool,
    },
    ProcessList {
        req_id: u64,
    },
    ProcessLogs {
        req_id: u64,
        proc_id: String,
        tail: Option<usize>,
        follow: bool,
    },
    ProcessSignal {
        req_id: u64,
        proc_id: String,
        signal: SignalKind,
    },
    ProcessDelete {
        req_id: u64,
        proc_id: String,
    },
    PtyOpen {
        req_id: u64,
        session_id: String,
        cmd: Option<Vec<String>>,
        cwd: Option<String>,
        env: BTreeMap<String, String>,
        cols: u16,
        rows: u16,
    },
    PtyInput {
        session_id: String,
        data: Vec<u8>,
    },
    PtyResize {
        session_id: String,
        cols: u16,
        rows: u16,
    },
    PtyClose {
        session_id: String,
    },
    UploadBegin {
        req_id: u64,
        path: String,
        kind: UploadKind,
    },
    FileChunk {
        req_id: u64,
        data: Vec<u8>,
        eof: bool,
    },
    DownloadBegin {
        req_id: u64,
        path: String,
        format: DownloadFormat,
    },
    TcpConnect {
        req_id: u64,
        stream_id: String,
        guest_port: u16,
    },
    TcpData {
        stream_id: String,
        data: Vec<u8>,
    },
    TcpClose {
        stream_id: String,
    },
    HostBridgeBind {
        req_id: u64,
        guest_port: u16,
    },
    HostBridgeUnbind {
        req_id: u64,
        guest_port: u16,
    },
    HostBridgeAccepted {
        stream_id: String,
    },
    HostBridgeRejected {
        stream_id: String,
        reason: String,
    },
    Shutdown {
        req_id: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CtrlResponse {
    BootReady {
        req_id: u64,
        version: String,
        workspace_mounted: bool,
        netbridge_ready: bool,
    },
    ExecOutput {
        req_id: u64,
        stream: OutputStream,
        data: Vec<u8>,
    },
    ExecExit {
        req_id: u64,
        exit_code: i32,
        timed_out: bool,
        duration_ms: u64,
    },
    ProcessSpawned {
        req_id: u64,
        proc_id: String,
        pid: u32,
    },
    ProcessListResult {
        req_id: u64,
        processes: Vec<ProcessInfo>,
    },
    ProcessLogsEnd {
        req_id: u64,
    },
    PtyOpened {
        req_id: u64,
        session_id: String,
    },
    PtyOutput {
        session_id: String,
        data: Vec<u8>,
    },
    PtyExited {
        session_id: String,
        exit_code: i32,
    },
    UploadComplete {
        req_id: u64,
        bytes_written: u64,
        files_written: u64,
    },
    FileChunk {
        req_id: u64,
        data: Vec<u8>,
        eof: bool,
    },
    TcpConnected {
        req_id: u64,
        stream_id: String,
    },
    TcpData {
        stream_id: String,
        data: Vec<u8>,
    },
    TcpClosed {
        stream_id: String,
        reason: Option<String>,
    },
    HostBridgeOpen {
        stream_id: String,
        guest_port: u16,
    },
    Ack {
        req_id: u64,
    },
    Error {
        req_id: u64,
        code: CtrlErrorCode,
        message: String,
    },
}

pub fn write_ctrl_request<W: Write>(writer: &mut W, req: &CtrlRequest) -> Result<()> {
    write_length_prefixed_json(writer, req, MAX_CTRL_FRAME)
}

pub fn read_ctrl_request<R: Read>(reader: &mut R) -> Result<CtrlRequest> {
    read_length_prefixed_json(reader, MAX_CTRL_FRAME)
}

pub fn write_ctrl_response<W: Write>(writer: &mut W, resp: &CtrlResponse) -> Result<()> {
    write_length_prefixed_json(writer, resp, MAX_CTRL_FRAME)
}

pub fn read_ctrl_response<R: Read>(reader: &mut R) -> Result<CtrlResponse> {
    read_length_prefixed_json(reader, MAX_CTRL_FRAME)
}

fn write_length_prefixed_json<W: Write, T: Serialize>(
    writer: &mut W,
    msg: &T,
    max_len: u32,
) -> Result<()> {
    let bytes = serde_json::to_vec(msg)?;
    let len = u32::try_from(bytes.len()).map_err(|_| ProtoError::PayloadTooLarge {
        len: u32::MAX,
        max: max_len,
    })?;
    if len > max_len {
        return Err(ProtoError::PayloadTooLarge { len, max: max_len });
    }
    writer.write_all(&len.to_be_bytes())?;
    writer.write_all(&bytes)?;
    Ok(())
}

fn read_length_prefixed_json<R: Read, T: for<'de> Deserialize<'de>>(
    reader: &mut R,
    max_len: u32,
) -> Result<T> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf);
    if len == 0 {
        return Err(ProtoError::Truncated);
    }
    if len > max_len {
        return Err(ProtoError::PayloadTooLarge { len, max: max_len });
    }
    let mut body = vec![0u8; len as usize];
    reader.read_exact(&mut body)?;
    Ok(serde_json::from_slice(&body)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn vsock_handshake_roundtrip() {
        assert_eq!(format_connect_handshake(PORT_NET_MUX), "CONNECT 1000\n");
        assert_eq!(parse_ok_handshake("OK 1073741824\n").unwrap(), 1073741824);
        assert_eq!(parse_ok_handshake("OK 42\r\n").unwrap(), 42);
        assert!(parse_ok_handshake("ERR 1\n").is_err());
        assert!(parse_ok_handshake("OK nope\n").is_err());
    }

    #[test]
    fn mux_frame_roundtrip_and_bounds() {
        let frame = MuxFrame::new(
            7,
            mux_flags::SYN | mux_flags::DATA,
            StreamType::Tcp,
            b"hello world".to_vec(),
        )
        .unwrap();
        let mut buf = Vec::new();
        frame.write_to(&mut buf).unwrap();
        assert_eq!(buf.len(), MUX_HEADER_LEN + 11);

        let decoded = MuxFrame::read_from(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn mux_header_rejects_malformed_inputs() {
        // Too short
        assert!(matches!(MuxHeader::decode(&[0u8; 11]), Err(ProtoError::Truncated)));

        // Payload > 64 KiB
        let mut oversized = [0u8; 12];
        oversized[4..8].copy_from_slice(&(MAX_MUX_PAYLOAD + 1).to_be_bytes());
        oversized[8] = mux_flags::DATA;
        oversized[9] = StreamType::Tcp as u8;
        assert!(matches!(
            MuxHeader::decode(&oversized),
            Err(ProtoError::PayloadTooLarge { .. })
        ));

        // Unknown stream type
        let mut bad_type = [0u8; 12];
        bad_type[8] = mux_flags::DATA;
        bad_type[9] = 99;
        assert!(matches!(
            MuxHeader::decode(&bad_type),
            Err(ProtoError::UnknownStreamType(99))
        ));

        // Invalid flags (0 or unknown bit)
        let mut bad_flags = [0u8; 12];
        bad_flags[8] = 0x80;
        bad_flags[9] = StreamType::Tcp as u8;
        assert!(matches!(
            MuxHeader::decode(&bad_flags),
            Err(ProtoError::InvalidFlags(0x80))
        ));

        // Non-zero reserved
        let mut bad_res = [0u8; 12];
        bad_res[8] = mux_flags::FIN;
        bad_res[9] = StreamType::Postgres as u8;
        bad_res[10..12].copy_from_slice(&1u16.to_be_bytes());
        assert!(matches!(
            MuxHeader::decode(&bad_res),
            Err(ProtoError::NonZeroReserved(1))
        ));
    }

    #[test]
    fn audit_frame_roundtrip_and_oversized_rejection() {
        let frame = GuestAuditFrame {
            timestamp_ns: 123_456_789,
            source: "blackwall-init".into(),
            kind: "exec".into(),
            payload: serde_json::json!({"pid": 42}),
        };
        let mut buf = Vec::new();
        write_audit_frame(&mut buf, &frame).unwrap();
        let decoded = read_audit_frame(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(decoded, frame);

        let mut bad = Vec::new();
        bad.extend_from_slice(&(MAX_AUDIT_FRAME + 1).to_be_bytes());
        assert!(matches!(
            read_audit_frame(&mut Cursor::new(&bad)),
            Err(ProtoError::PayloadTooLarge { .. })
        ));
    }

    #[test]
    fn ctrl_rpc_roundtrip_and_zero_length_rejection() {
        let req = CtrlRequest::ExecStart {
            req_id: 99,
            cmd: vec!["cargo".into(), "test".into()],
            cwd: Some("/workspace".into()),
            env: BTreeMap::from([("RUST_BACKTRACE".into(), "1".into())]),
            stdin: None,
            timeout_sec: Some(30),
            background: false,
        };
        let mut buf = Vec::new();
        write_ctrl_request(&mut buf, &req).unwrap();
        let decoded = read_ctrl_request(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(decoded, req);

        let resp = CtrlResponse::ExecExit {
            req_id: 99,
            exit_code: 0,
            timed_out: false,
            duration_ms: 412,
        };
        buf.clear();
        write_ctrl_response(&mut buf, &resp).unwrap();
        let decoded_resp = read_ctrl_response(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(decoded_resp, resp);

        assert!(matches!(
            read_ctrl_request(&mut Cursor::new(&0u32.to_be_bytes())),
            Err(ProtoError::Truncated)
        ));

        // TCP ingress tunnel control frames round-trip cleanly
        for tcp_req in [
            CtrlRequest::TcpConnect {
                req_id: 100,
                stream_id: "tcp-abc".into(),
                guest_port: 5173,
            },
            CtrlRequest::TcpData {
                stream_id: "tcp-abc".into(),
                data: b"GET / HTTP/1.1\r\n\r\n".to_vec(),
            },
            CtrlRequest::TcpClose {
                stream_id: "tcp-abc".into(),
            },
        ] {
            buf.clear();
            write_ctrl_request(&mut buf, &tcp_req).unwrap();
            assert_eq!(read_ctrl_request(&mut Cursor::new(&buf)).unwrap(), tcp_req);
        }

        for tcp_resp in [
            CtrlResponse::TcpConnected {
                req_id: 100,
                stream_id: "tcp-abc".into(),
            },
            CtrlResponse::TcpData {
                stream_id: "tcp-abc".into(),
                data: b"HTTP/1.1 200 OK\r\n\r\n".to_vec(),
            },
            CtrlResponse::TcpClosed {
                stream_id: "tcp-abc".into(),
                reason: Some("eof".into()),
            },
        ] {
            buf.clear();
            write_ctrl_response(&mut buf, &tcp_resp).unwrap();
            assert_eq!(read_ctrl_response(&mut Cursor::new(&buf)).unwrap(), tcp_resp);
        }
    }

    #[test]
    fn host_bridge_ctrl_rpc_roundtrip() {
        let mut buf = Vec::new();

        for (req, expected_tag) in [
            (
                CtrlRequest::HostBridgeBind {
                    req_id: 201,
                    guest_port: 5432,
                },
                "host_bridge_bind",
            ),
            (
                CtrlRequest::HostBridgeUnbind {
                    req_id: 202,
                    guest_port: 5432,
                },
                "host_bridge_unbind",
            ),
            (
                CtrlRequest::HostBridgeAccepted {
                    stream_id: "hb-1".into(),
                },
                "host_bridge_accepted",
            ),
            (
                CtrlRequest::HostBridgeRejected {
                    stream_id: "hb-2".into(),
                    reason: "connection refused".into(),
                },
                "host_bridge_rejected",
            ),
        ] {
            let val = serde_json::to_value(&req).unwrap();
            assert_eq!(val["type"], expected_tag);
            buf.clear();
            write_ctrl_request(&mut buf, &req).unwrap();
            assert_eq!(read_ctrl_request(&mut Cursor::new(&buf)).unwrap(), req);
        }

        let resp = CtrlResponse::HostBridgeOpen {
            stream_id: "hb-1".into(),
            guest_port: 5432,
        };
        let val = serde_json::to_value(&resp).unwrap();
        assert_eq!(val["type"], "host_bridge_open");
        buf.clear();
        write_ctrl_response(&mut buf, &resp).unwrap();
        assert_eq!(read_ctrl_response(&mut Cursor::new(&buf)).unwrap(), resp);
    }
}
