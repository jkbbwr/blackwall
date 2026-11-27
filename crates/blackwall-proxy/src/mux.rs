//! Port 1000 (`NET_MUX`) stream demultiplexer and deterministic RFC 2544 (`198.18.x.y`)
//! synthetic DNS responder.
//!
//! Reads 12-byte big-endian [`MuxFrame`]s from the pre-connected Port 1000 `UnixStream`:
//! - [`StreamType::DnsQuery`] -> [`StreamType::DnsResponse`]: maps allowlisted FQDNs
//!   deterministically to `198.18.x.y` and rejects non-allowlisted FQDNs (`allowed = false`).
//! - [`StreamType::Tcp`]: bridges allowlisted synthetic streams to the local Pingora listener.
//! - [`StreamType::Postgres`]: bridges allowlisted synthetic streams to the sibling
//!   [`PostgresProxyServer`] (either directly in-process or via local TCP listener).

use crate::error::{ProxyError, Result};
use crate::postgres_proxy::PostgresProxyServer;
use blackwall_audit::{AuditEvent, AuditEventKind, AuditSink};
use blackwall_proto::{
    mux_flags, DnsQueryPayload, DnsRecordType, DnsResponsePayload, MuxFrame, MuxHeader,
    StreamOpenPayload, StreamType, MAX_MUX_PAYLOAD, MUX_HEADER_LEN,
};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// Deterministic RFC 2544 (`198.18.1.1` .. `198.19.255.254`) synthetic IP table
/// derived from a sandbox's allowlisted FQDNs.
#[derive(Debug, Clone)]
pub struct SyntheticDnsTable {
    fqdn_to_ip: BTreeMap<String, Ipv4Addr>,
    ip_to_fqdn: BTreeMap<Ipv4Addr, String>,
    ttl_sec: u32,
}

impl SyntheticDnsTable {
    /// Build a deterministic synthetic DNS table from allowlisted FQDNs.
    ///
    /// Reserves `198.18.0.x` (used by guest `tun0` at `198.18.0.1` and synthetic DNS
    /// server at `198.18.0.53`) and allocates allowlisted FQDNs deterministically starting
    /// at `198.18.1.1`.
    pub fn from_allowlist(allowed_fqdns: &BTreeSet<String>) -> Self {
        let mut normalized: BTreeSet<String> = BTreeSet::new();
        for host in allowed_fqdns {
            let h = normalize_fqdn(host);
            if !h.is_empty() {
                normalized.insert(h);
            }
        }

        let mut fqdn_to_ip = BTreeMap::new();
        let mut ip_to_fqdn = BTreeMap::new();

        // Start at 198.18.1.1 (0xC6120101), staying within 198.18.0.0/15.
        for (idx, host) in normalized.into_iter().enumerate() {
            let offset = (idx as u32) + 1;
            let third = 1 + (offset / 254);
            let fourth = 1 + (offset % 254);
            let second = 18 + (third / 256);
            let ip = Ipv4Addr::new(198, second as u8, (third % 256) as u8, fourth as u8);
            fqdn_to_ip.insert(host.clone(), ip);
            ip_to_fqdn.insert(ip, host);
        }

        Self {
            fqdn_to_ip,
            ip_to_fqdn,
            ttl_sec: 60,
        }
    }

    pub fn lookup_ip(&self, fqdn: &str) -> Option<Ipv4Addr> {
        self.fqdn_to_ip.get(&normalize_fqdn(fqdn)).copied()
    }

    pub fn lookup_fqdn(&self, ip: Ipv4Addr) -> Option<&str> {
        self.ip_to_fqdn.get(&ip).map(String::as_str)
    }

    pub fn lookup_fqdn_str(&self, ip_str: &str) -> Option<&str> {
        let ip: Ipv4Addr = ip_str.parse().ok()?;
        self.lookup_fqdn(ip)
    }

    pub fn is_allowed_fqdn(&self, fqdn: &str) -> bool {
        self.fqdn_to_ip.contains_key(&normalize_fqdn(fqdn))
    }

    /// Answer a [`DnsQueryPayload`] strictly against the allowlist.
    pub fn resolve(&self, query: &DnsQueryPayload) -> DnsResponsePayload {
        let norm = normalize_fqdn(&query.fqdn);
        if let Some(ip) = self.fqdn_to_ip.get(&norm) {
            let synthetic_ip = match query.record_type {
                DnsRecordType::A => Some(ip.to_string()),
                // Allowlisted host, NODATA for AAAA so dual-stack clients use the synthetic A IP.
                DnsRecordType::AAAA => None,
            };
            DnsResponsePayload {
                query_id: query.query_id,
                fqdn: query.fqdn.clone(),
                synthetic_ip,
                allowed: true,
                ttl_sec: self.ttl_sec,
            }
        } else {
            DnsResponsePayload {
                query_id: query.query_id,
                fqdn: query.fqdn.clone(),
                synthetic_ip: None,
                allowed: false,
                ttl_sec: 0,
            }
        }
    }
}

fn normalize_fqdn(fqdn: &str) -> String {
    fqdn.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Routing target for `StreamType::Postgres` streams arriving on Port 1000.
#[derive(Clone)]
pub enum PostgresRouteTarget {
    /// Route directly into an in-process [`PostgresProxyServer`] over a duplex stream,
    /// preserving the exact resolved `(hostname, dst_port)` for every connection.
    Direct(Arc<PostgresProxyServer>),
    /// Connect to a local TCP listener hosting the sibling Postgres proxy.
    Tcp(SocketAddr),
}

const MAX_ACTIVE_MUX_STREAMS: usize = 256;
const MAX_DNS_FQDN_LEN: usize = 253;

/// Port 1000 (`NET_MUX`) stream demultiplexer bridging `blackwall-netbridge` streams
/// to synthetic DNS, the local Pingora HTTP proxy, and the sibling Postgres proxy.
pub struct Port1000Muxer {
    dns_table: Arc<SyntheticDnsTable>,
    http_proxy_addr: SocketAddr,
    postgres_target: Option<PostgresRouteTarget>,
    audit: Option<(String, Arc<dyn AuditSink>)>,
}

impl Port1000Muxer {
    pub fn new(
        dns_table: Arc<SyntheticDnsTable>,
        http_proxy_addr: SocketAddr,
        postgres_target: Option<PostgresRouteTarget>,
    ) -> Self {
        Self {
            dns_table,
            http_proxy_addr,
            postgres_target,
            audit: None,
        }
    }

    /// Attach an audit sink so synthetic DNS queries processed by this muxer emit
    /// [`AuditEventKind::DnsQuery`] events tagged with `sandbox_id`.
    pub fn with_audit(
        mut self,
        sandbox_id: impl Into<String>,
        audit_sink: Arc<dyn AuditSink>,
    ) -> Self {
        self.audit = Some((sandbox_id.into(), audit_sink));
        self
    }

    pub fn dns_table(&self) -> &SyntheticDnsTable {
        &self.dns_table
    }

    /// Run the Port 1000 multiplexer loop over a pre-connected `UnixStream` (or any
    /// `AsyncRead + AsyncWrite` transport) until EOF.
    pub async fn run<S>(&self, stream: S) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (mut reader, mut writer) = tokio::io::split(stream);
        let (out_tx, mut out_rx) = mpsc::channel::<MuxFrame>(256);

        // Writer task serializing outbound MuxFrames onto Port 1000.
        let writer_task = tokio::spawn(async move {
            while let Some(frame) = out_rx.recv().await {
                if write_mux_frame_async(&mut writer, &frame).await.is_err() {
                    break;
                }
            }
            let _ = writer.shutdown().await;
        });

        let mut active_streams: HashMap<u32, mpsc::Sender<Vec<u8>>> = HashMap::new();

        while let Some(frame) = read_mux_frame_async(&mut reader).await? {
            let sid = frame.header.stream_id;
            let flags = frame.header.flags;

            match frame.header.stream_type {
                StreamType::DnsQuery => {
                    let query: DnsQueryPayload = match serde_json::from_slice(&frame.payload) {
                        Ok(q) => q,
                        Err(_) => {
                            let _ = send_rst(&out_tx, sid, StreamType::DnsResponse).await;
                            continue;
                        }
                    };
                    if query.fqdn.len() > MAX_DNS_FQDN_LEN {
                        let _ = send_rst(&out_tx, sid, StreamType::DnsResponse).await;
                        continue;
                    }
                    let resp = self.dns_table.resolve(&query);
                    if let Some((sandbox_id, audit_sink)) = &self.audit {
                        audit_sink.record(AuditEvent::now(
                            sandbox_id,
                            AuditEventKind::DnsQuery {
                                fqdn: resp.fqdn.clone(),
                                allowed: resp.allowed,
                                synthetic_ip: resp.synthetic_ip.clone(),
                            },
                        ));
                    }
                    let Ok(resp_bytes) = serde_json::to_vec(&resp) else {
                        let _ = send_rst(&out_tx, sid, StreamType::DnsResponse).await;
                        continue;
                    };
                    match MuxFrame::new(
                        sid,
                        mux_flags::DATA | mux_flags::FIN,
                        StreamType::DnsResponse,
                        resp_bytes,
                    ) {
                        Ok(reply) => {
                            let _ = out_tx.send(reply).await;
                        }
                        Err(_) => {
                            let _ = send_rst(&out_tx, sid, StreamType::DnsResponse).await;
                        }
                    }
                }
                StreamType::Tcp => {
                    if (flags & mux_flags::SYN) != 0 {
                        active_streams.retain(|_, tx| !tx.is_closed());
                        if active_streams.contains_key(&sid)
                            || active_streams.len() >= MAX_ACTIVE_MUX_STREAMS
                        {
                            let _ = send_rst(&out_tx, sid, StreamType::Tcp).await;
                            continue;
                        }
                        let open: StreamOpenPayload = match serde_json::from_slice(&frame.payload) {
                            Ok(o) => o,
                            Err(_) => {
                                let _ = send_rst(&out_tx, sid, StreamType::Tcp).await;
                                continue;
                            }
                        };
                        if self.resolve_allowed_host(&open).is_none() {
                            let _ = send_rst(&out_tx, sid, StreamType::Tcp).await;
                            continue;
                        }
                        match TcpStream::connect(self.http_proxy_addr).await {
                            Ok(backend) => {
                                let tx = spawn_stream_bridge(
                                    sid,
                                    StreamType::Tcp,
                                    backend,
                                    out_tx.clone(),
                                );
                                active_streams.insert(sid, tx);
                                let ack = MuxFrame::new(sid, mux_flags::ACK, StreamType::Tcp, vec![])?;
                                let _ = out_tx.send(ack).await;
                            }
                            Err(_) => {
                                let _ = send_rst(&out_tx, sid, StreamType::Tcp).await;
                            }
                        }
                    } else if (flags & mux_flags::DATA) != 0 {
                        let mut stalled = false;
                        if let Some(tx) = active_streams.get(&sid) {
                            if tx.try_send(frame.payload).is_err() {
                                stalled = true;
                            }
                        } else {
                            let _ = send_rst(&out_tx, sid, StreamType::Tcp).await;
                        }
                        if stalled {
                            active_streams.remove(&sid);
                            let _ = send_rst(&out_tx, sid, StreamType::Tcp).await;
                        } else if (flags & mux_flags::FIN) != 0 {
                            active_streams.remove(&sid);
                        }
                    } else if (flags & (mux_flags::FIN | mux_flags::RST)) != 0 {
                        active_streams.remove(&sid);
                    }
                }
                StreamType::Postgres => {
                    if (flags & mux_flags::SYN) != 0 {
                        active_streams.retain(|_, tx| !tx.is_closed());
                        if active_streams.contains_key(&sid)
                            || active_streams.len() >= MAX_ACTIVE_MUX_STREAMS
                        {
                            let _ = send_rst(&out_tx, sid, StreamType::Postgres).await;
                            continue;
                        }
                        let open: StreamOpenPayload = match serde_json::from_slice(&frame.payload) {
                            Ok(o) => o,
                            Err(_) => {
                                let _ = send_rst(&out_tx, sid, StreamType::Postgres).await;
                                continue;
                            }
                        };
                        let Some(host) = self.resolve_allowed_host(&open) else {
                            let _ = send_rst(&out_tx, sid, StreamType::Postgres).await;
                            continue;
                        };
                        match &self.postgres_target {
                            Some(PostgresRouteTarget::Tcp(addr)) => {
                                match TcpStream::connect(*addr).await {
                                    Ok(backend) => {
                                        let tx = spawn_stream_bridge(
                                            sid,
                                            StreamType::Postgres,
                                            backend,
                                            out_tx.clone(),
                                        );
                                        active_streams.insert(sid, tx);
                                        let ack = MuxFrame::new(
                                            sid,
                                            mux_flags::ACK,
                                            StreamType::Postgres,
                                            vec![],
                                        )?;
                                        let _ = out_tx.send(ack).await;
                                    }
                                    Err(_) => {
                                        let _ = send_rst(&out_tx, sid, StreamType::Postgres).await;
                                    }
                                }
                            }
                            Some(PostgresRouteTarget::Direct(pg_server)) => {
                                let (mux_side, pg_side) = tokio::io::duplex(64 * 1024);
                                let server = Arc::clone(pg_server);
                                let dst_port = open.dst_port;
                                tokio::spawn(async move {
                                    let _ = server.handle_connection(pg_side, &host, dst_port).await;
                                });
                                let tx = spawn_stream_bridge(
                                    sid,
                                    StreamType::Postgres,
                                    mux_side,
                                    out_tx.clone(),
                                );
                                active_streams.insert(sid, tx);
                                let ack = MuxFrame::new(
                                    sid,
                                    mux_flags::ACK,
                                    StreamType::Postgres,
                                    vec![],
                                )?;
                                let _ = out_tx.send(ack).await;
                            }
                            None => {
                                let _ = send_rst(&out_tx, sid, StreamType::Postgres).await;
                            }
                        }
                    } else if (flags & mux_flags::DATA) != 0 {
                        let mut stalled = false;
                        if let Some(tx) = active_streams.get(&sid) {
                            if tx.try_send(frame.payload).is_err() {
                                stalled = true;
                            }
                        } else {
                            let _ = send_rst(&out_tx, sid, StreamType::Postgres).await;
                        }
                        if stalled {
                            active_streams.remove(&sid);
                            let _ = send_rst(&out_tx, sid, StreamType::Postgres).await;
                        } else if (flags & mux_flags::FIN) != 0 {
                            active_streams.remove(&sid);
                        }
                    } else if (flags & (mux_flags::FIN | mux_flags::RST)) != 0 {
                        active_streams.remove(&sid);
                    }
                }
                StreamType::DnsResponse => {
                    // Guest must not send DnsResponse to host; ignore.
                }
            }
        }

        drop(active_streams);
        drop(out_tx);
        let _ = writer_task.await;
        Ok(())
    }

    fn resolve_allowed_host(&self, open: &StreamOpenPayload) -> Option<String> {
        if let Some(h) = self.dns_table.lookup_fqdn_str(&open.dst_ip) {
            return Some(h.to_string());
        }
        if let Some(h) = &open.hostname {
            if self.dns_table.is_allowed_fqdn(h) {
                return Some(normalize_fqdn(h));
            }
        }
        None
    }
}

fn spawn_stream_bridge<T>(
    stream_id: u32,
    stream_type: StreamType,
    backend: T,
    out_tx: mpsc::Sender<MuxFrame>,
) -> mpsc::Sender<Vec<u8>>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut back_read, mut back_write) = tokio::io::split(backend);
    let (in_tx, mut in_rx) = mpsc::channel::<Vec<u8>>(64);

    // Guest -> Backend writer task
    tokio::spawn(async move {
        while let Some(chunk) = in_rx.recv().await {
            if back_write.write_all(&chunk).await.is_err() {
                break;
            }
        }
        let _ = back_write.shutdown().await;
    });

    // Backend -> Guest reader task
    tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_MUX_PAYLOAD as usize];
        loop {
            match back_read.read(&mut buf).await {
                Ok(0) => {
                    if let Ok(fin) = MuxFrame::new(stream_id, mux_flags::FIN, stream_type, vec![]) {
                        let _ = out_tx.send(fin).await;
                    }
                    break;
                }
                Ok(n) => {
                    if let Ok(data) = MuxFrame::new(
                        stream_id,
                        mux_flags::DATA,
                        stream_type,
                        buf[..n].to_vec(),
                    ) {
                        if out_tx.send(data).await.is_err() {
                            break;
                        }
                    }
                }
                Err(_) => {
                    let _ = send_rst(&out_tx, stream_id, stream_type).await;
                    break;
                }
            }
        }
    });

    in_tx
}

async fn send_rst(
    out_tx: &mpsc::Sender<MuxFrame>,
    stream_id: u32,
    stream_type: StreamType,
) -> Result<()> {
    let rst = MuxFrame::new(stream_id, mux_flags::RST, stream_type, vec![])?;
    let _ = out_tx.send(rst).await;
    Ok(())
}

/// Read a single [`MuxFrame`] asynchronously; returns `Ok(None)` on clean EOF.
pub async fn read_mux_frame_async<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Option<MuxFrame>> {
    let mut hdr_buf = [0u8; MUX_HEADER_LEN];
    match reader.read_exact(&mut hdr_buf[0..1]).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(ProxyError::Io(e)),
    }
    reader.read_exact(&mut hdr_buf[1..MUX_HEADER_LEN]).await?;
    let header = MuxHeader::decode(&hdr_buf)?;
    let mut payload = vec![0u8; header.payload_len as usize];
    if !payload.is_empty() {
        reader.read_exact(&mut payload).await?;
    }
    Ok(Some(MuxFrame { header, payload }))
}

/// Write a single [`MuxFrame`] asynchronously.
pub async fn write_mux_frame_async<W: AsyncWrite + Unpin>(
    writer: &mut W,
    frame: &MuxFrame,
) -> Result<()> {
    let hdr = frame.header.encode()?;
    writer.write_all(&hdr).await?;
    if !frame.payload.is_empty() {
        writer.write_all(&frame.payload).await?;
    }
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn muxer_dns_allow_deny_and_tcp_postgres_routing() {
        // Spawn simple echo servers standing in for Pingora TCP and sibling Postgres TCP.
        let http_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let http_addr = http_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = http_listener.accept().await.unwrap();
            let mut buf = [0u8; 32];
            let n = s.read(&mut buf).await.unwrap();
            s.write_all(b"HTTP_BACKEND:").await.unwrap();
            s.write_all(&buf[..n]).await.unwrap();
            let _ = s.shutdown().await;
        });

        let pg_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let pg_addr = pg_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = pg_listener.accept().await.unwrap();
            let mut buf = [0u8; 32];
            let n = s.read(&mut buf).await.unwrap();
            s.write_all(b"PG_BACKEND:").await.unwrap();
            s.write_all(&buf[..n]).await.unwrap();
            let _ = s.shutdown().await;
        });

        let allowlist = BTreeSet::from(["api.github.com".to_string(), "db.internal".to_string()]);
        let dns_table = Arc::new(SyntheticDnsTable::from_allowlist(&allowlist));
        let muxer = Arc::new(Port1000Muxer::new(
            dns_table.clone(),
            http_addr,
            Some(PostgresRouteTarget::Tcp(pg_addr)),
        ));

        let (mut guest_side, host_side) = tokio::io::duplex(64 * 1024);
        let mux_task = tokio::spawn(async move { muxer.run(host_side).await.unwrap() });

        // 1. DNS query for allowlisted host -> deterministic 198.18.x.y
        let q1 = DnsQueryPayload {
            query_id: 1,
            fqdn: "api.github.com".into(),
            record_type: DnsRecordType::A,
        };
        let f1 = MuxFrame::new(
            1,
            mux_flags::DATA | mux_flags::FIN,
            StreamType::DnsQuery,
            serde_json::to_vec(&q1).unwrap(),
        )
        .unwrap();
        write_mux_frame_async(&mut guest_side, &f1).await.unwrap();
        let r1 = read_mux_frame_async(&mut guest_side)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(r1.header.stream_type, StreamType::DnsResponse);
        let dns_r1: DnsResponsePayload = serde_json::from_slice(&r1.payload).unwrap();
        assert!(dns_r1.allowed);
        let github_ip = dns_r1.synthetic_ip.unwrap();
        assert!(github_ip.starts_with("198.18."));

        // 2. DNS query for non-allowlisted host -> allowed = false
        let q2 = DnsQueryPayload {
            query_id: 2,
            fqdn: "exfil.evil.com".into(),
            record_type: DnsRecordType::A,
        };
        let f2 = MuxFrame::new(
            2,
            mux_flags::DATA | mux_flags::FIN,
            StreamType::DnsQuery,
            serde_json::to_vec(&q2).unwrap(),
        )
        .unwrap();
        write_mux_frame_async(&mut guest_side, &f2).await.unwrap();
        let r2 = read_mux_frame_async(&mut guest_side)
            .await
            .unwrap()
            .unwrap();
        let dns_r2: DnsResponsePayload = serde_json::from_slice(&r2.payload).unwrap();
        assert!(!dns_r2.allowed);
        assert!(dns_r2.synthetic_ip.is_none());

        // 3. TCP stream to non-allowlisted IP -> immediate RST
        let bad_syn = MuxFrame::new(
            10,
            mux_flags::SYN,
            StreamType::Tcp,
            serde_json::to_vec(&StreamOpenPayload {
                dst_ip: "169.254.169.254".into(),
                dst_port: 80,
                hostname: None,
            })
            .unwrap(),
        )
        .unwrap();
        write_mux_frame_async(&mut guest_side, &bad_syn)
            .await
            .unwrap();
        let bad_reply = read_mux_frame_async(&mut guest_side)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(bad_reply.header.stream_id, 10);
        assert_eq!(bad_reply.header.flags, mux_flags::RST);

        // 4. TCP stream to allowlisted synthetic IP -> routed to HTTP proxy backend
        let tcp_syn = MuxFrame::new(
            11,
            mux_flags::SYN,
            StreamType::Tcp,
            serde_json::to_vec(&StreamOpenPayload {
                dst_ip: github_ip,
                dst_port: 443,
                hostname: Some("api.github.com".into()),
            })
            .unwrap(),
        )
        .unwrap();
        write_mux_frame_async(&mut guest_side, &tcp_syn)
            .await
            .unwrap();
        let ack = read_mux_frame_async(&mut guest_side)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(ack.header.flags, mux_flags::ACK);

        let data = MuxFrame::new(11, mux_flags::DATA, StreamType::Tcp, b"ping".to_vec()).unwrap();
        write_mux_frame_async(&mut guest_side, &data).await.unwrap();
        let resp = read_mux_frame_async(&mut guest_side)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(resp.payload, b"HTTP_BACKEND:ping");
        // Drain FIN
        let fin = read_mux_frame_async(&mut guest_side)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fin.header.flags, mux_flags::FIN);

        // 5. Postgres stream to allowlisted db.internal -> routed to Postgres backend
        let db_ip = dns_table.lookup_ip("db.internal").unwrap().to_string();
        let pg_syn = MuxFrame::new(
            12,
            mux_flags::SYN,
            StreamType::Postgres,
            serde_json::to_vec(&StreamOpenPayload {
                dst_ip: db_ip,
                dst_port: 5432,
                hostname: Some("db.internal".into()),
            })
            .unwrap(),
        )
        .unwrap();
        write_mux_frame_async(&mut guest_side, &pg_syn)
            .await
            .unwrap();
        let pg_ack = read_mux_frame_async(&mut guest_side)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(pg_ack.header.flags, mux_flags::ACK);

        let pg_data =
            MuxFrame::new(12, mux_flags::DATA, StreamType::Postgres, b"sql".to_vec()).unwrap();
        write_mux_frame_async(&mut guest_side, &pg_data)
            .await
            .unwrap();
        let pg_resp = read_mux_frame_async(&mut guest_side)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(pg_resp.payload, b"PG_BACKEND:sql");

        drop(guest_side);
        mux_task.await.unwrap();
    }

    #[tokio::test]
    async fn muxer_with_audit_emits_dns_query_events_for_allowed_and_blocked_fqdns() {
        use blackwall_audit::MemoryAuditSink;

        let allowlist = BTreeSet::from(["api.github.com".to_string()]);
        let dns_table = Arc::new(SyntheticDnsTable::from_allowlist(&allowlist));
        let audit_sink = Arc::new(MemoryAuditSink::new());
        let dummy_http_addr: SocketAddr = "127.0.0.1:1".parse().unwrap();

        let muxer = Arc::new(
            Port1000Muxer::new(dns_table, dummy_http_addr, None)
                .with_audit("sb-dns-audit", audit_sink.clone()),
        );

        let (mut guest_side, host_side) = tokio::io::duplex(64 * 1024);
        let mux_task = tokio::spawn(async move { muxer.run(host_side).await.unwrap() });

        // 1. Allowlisted FQDN -> allowed: true + synthetic 198.18.x.y IP
        let q_allowed = DnsQueryPayload {
            query_id: 101,
            fqdn: "api.github.com".into(),
            record_type: DnsRecordType::A,
        };
        let f_allowed = MuxFrame::new(
            1,
            mux_flags::DATA | mux_flags::FIN,
            StreamType::DnsQuery,
            serde_json::to_vec(&q_allowed).unwrap(),
        )
        .unwrap();
        write_mux_frame_async(&mut guest_side, &f_allowed)
            .await
            .unwrap();
        let r_allowed = read_mux_frame_async(&mut guest_side)
            .await
            .unwrap()
            .unwrap();
        let dns_allowed: DnsResponsePayload = serde_json::from_slice(&r_allowed.payload).unwrap();
        assert!(dns_allowed.allowed);
        let expected_ip = dns_allowed.synthetic_ip.clone();
        assert!(expected_ip
            .as_deref()
            .is_some_and(|ip| ip.starts_with("198.18.")));

        // 2. Blocked FQDN (`google.com`) -> allowed: false + synthetic_ip: None
        let q_blocked = DnsQueryPayload {
            query_id: 102,
            fqdn: "google.com".into(),
            record_type: DnsRecordType::A,
        };
        let f_blocked = MuxFrame::new(
            2,
            mux_flags::DATA | mux_flags::FIN,
            StreamType::DnsQuery,
            serde_json::to_vec(&q_blocked).unwrap(),
        )
        .unwrap();
        write_mux_frame_async(&mut guest_side, &f_blocked)
            .await
            .unwrap();
        let r_blocked = read_mux_frame_async(&mut guest_side)
            .await
            .unwrap()
            .unwrap();
        let dns_blocked: DnsResponsePayload = serde_json::from_slice(&r_blocked.payload).unwrap();
        assert!(!dns_blocked.allowed);
        assert!(dns_blocked.synthetic_ip.is_none());

        drop(guest_side);
        mux_task.await.unwrap();

        let events = audit_sink.snapshot();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].sandbox_id, "sb-dns-audit");
        assert_eq!(
            events[0].kind,
            AuditEventKind::DnsQuery {
                fqdn: "api.github.com".into(),
                allowed: true,
                synthetic_ip: expected_ip,
            }
        );
        assert_eq!(events[1].sandbox_id, "sb-dns-audit");
        assert_eq!(
            events[1].kind,
            AuditEventKind::DnsQuery {
                fqdn: "google.com".into(),
                allowed: false,
                synthetic_ip: None,
            }
        );
    }
}
