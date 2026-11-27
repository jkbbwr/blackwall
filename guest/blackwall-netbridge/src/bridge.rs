//! `smoltcp` userspace TCP/UDP packet engine terminating guest connections to
//! synthetic `198.18.0.0/15` destinations and multiplexing `SYN`/`DATA`/`FIN`/`RST`
//! `MuxFrame`s over `Port 1000` (`StreamType::Tcp`, `StreamType::Postgres`,
//! `StreamType::DnsQuery`, `StreamType::DnsResponse`).

use crate::dns::{
    build_dns_error_response, build_dns_response, parse_dns_query, ParsedDnsQuery,
    SyntheticIpTable, RCODE_NOTIMP,
};
use crate::tun::{TUN_DNS_IP, TUN_LOCAL_IP, TUN_MTU};
use blackwall_proto::{
    mux_flags, DnsResponsePayload, MuxFrame, StreamOpenPayload, StreamType, MAX_MUX_PAYLOAD,
};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::socket::udp::{self, PacketBuffer, PacketMetadata, UdpMetadata};
use smoltcp::time::{Duration, Instant};
use smoltcp::wire::{
    HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint, IpProtocol, Ipv4Address,
    Ipv4Packet, TcpPacket,
};
use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;

pub const POSTGRES_PORT: u16 = 5432;
pub const DNS_PORT: u16 = 53;

const TCP_RX_BUF_BYTES: usize = 64 * 1024;
const TCP_TX_BUF_BYTES: usize = 64 * 1024;
const UDP_META_SLOTS: usize = 64;
const UDP_PAYLOAD_BYTES: usize = 32 * 1024;

/// In-memory IP-layer `smoltcp::phy::Device` bridging raw IPv4 packets between
/// `tun0` (or unit tests) and the `smoltcp` stack.
pub struct VirtualIpDevice {
    rx_queue: VecDeque<Vec<u8>>,
    tx_queue: VecDeque<Vec<u8>>,
    mtu: usize,
}

impl VirtualIpDevice {
    pub fn new(mtu: usize) -> Self {
        Self {
            rx_queue: VecDeque::new(),
            tx_queue: VecDeque::new(),
            mtu,
        }
    }

    pub fn push_rx(&mut self, packet: Vec<u8>) {
        self.rx_queue.push_back(packet);
    }

    pub fn drain_tx(&mut self) -> Vec<Vec<u8>> {
        self.tx_queue.drain(..).collect()
    }
}

pub struct VirtualRxToken {
    packet: Vec<u8>,
}

impl RxToken for VirtualRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.packet)
    }
}

pub struct VirtualTxToken<'a> {
    tx_queue: &'a mut VecDeque<Vec<u8>>,
}

impl TxToken for VirtualTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let res = f(&mut buf);
        self.tx_queue.push_back(buf);
        res
    }
}

impl Device for VirtualIpDevice {
    type RxToken<'a> = VirtualRxToken where Self: 'a;
    type TxToken<'a> = VirtualTxToken<'a> where Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.rx_queue.pop_front()?;
        Some((
            VirtualRxToken { packet },
            VirtualTxToken {
                tx_queue: &mut self.tx_queue,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(VirtualTxToken {
            tx_queue: &mut self.tx_queue,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct TcpTuple {
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
}

struct ActiveTcpStream {
    handle: SocketHandle,
    tuple: TcpTuple,
    stream_type: StreamType,
    tx_to_guest: VecDeque<u8>,
    host_fin: bool,
    local_closed: bool,
    guest_fin_sent: bool,
}

struct PendingDnsQuery {
    client_endpoint: IpEndpoint,
    query: ParsedDnsQuery,
}

/// Core userspace TCP/UDP/DNS <-> `Port 1000` `MuxFrame` bridge.
pub struct NetBridge {
    device: VirtualIpDevice,
    iface: Interface,
    sockets: SocketSet<'static>,
    dns_socket: SocketHandle,
    ip_table: SyntheticIpTable,
    next_stream_id: u32,
    tcp_streams: HashMap<u32, ActiveTcpStream>,
    tuple_to_stream: HashMap<TcpTuple, u32>,
    pending_dns: HashMap<u32, PendingDnsQuery>,
    outbound_mux: VecDeque<MuxFrame>,
}

impl NetBridge {
    pub fn new(now: Instant, random_seed: u64) -> Self {
        let mut device = VirtualIpDevice::new(TUN_MTU as usize);
        let mut cfg = Config::new(HardwareAddress::Ip);
        cfg.random_seed = random_seed;

        let mut iface = Interface::new(cfg, &mut device, now);
        iface.set_any_ip(true);
        iface.update_ip_addrs(|addrs| {
            let [a, b, c, d] = TUN_LOCAL_IP.octets();
            let _ = addrs.push(IpCidr::new(IpAddress::v4(a, b, c, d), 15));
        });
        let [a, b, c, d] = TUN_LOCAL_IP.octets();
        let _ = iface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Address::new(a, b, c, d));

        let mut sockets = SocketSet::new(vec![]);
        let udp_rx = PacketBuffer::new(
            vec![PacketMetadata::EMPTY; UDP_META_SLOTS],
            vec![0u8; UDP_PAYLOAD_BYTES],
        );
        let udp_tx = PacketBuffer::new(
            vec![PacketMetadata::EMPTY; UDP_META_SLOTS],
            vec![0u8; UDP_PAYLOAD_BYTES],
        );
        let mut dns_sock = udp::Socket::new(udp_rx, udp_tx);
        let [da, db, dc, dd] = TUN_DNS_IP.octets();
        dns_sock
            .bind(IpListenEndpoint {
                addr: Some(IpAddress::v4(da, db, dc, dd)),
                port: DNS_PORT,
            })
            .expect("bind synthetic DNS UDP socket");
        let dns_socket = sockets.add(dns_sock);

        Self {
            device,
            iface,
            sockets,
            dns_socket,
            ip_table: SyntheticIpTable::new(),
            next_stream_id: 1,
            tcp_streams: HashMap::new(),
            tuple_to_stream: HashMap::new(),
            pending_dns: HashMap::new(),
            outbound_mux: VecDeque::new(),
        }
    }

    pub fn ip_table(&self) -> &SyntheticIpTable {
        &self.ip_table
    }

    pub fn ip_table_mut(&mut self) -> &mut SyntheticIpTable {
        &mut self.ip_table
    }

    fn alloc_stream_id(&mut self) -> u32 {
        let id = self.next_stream_id;
        self.next_stream_id = self.next_stream_id.wrapping_add(1).max(1);
        id
    }

    /// Classify destination port into `StreamType::Postgres` (`:5432`) or `StreamType::Tcp`.
    pub fn stream_type_for_port(dst_port: u16) -> StreamType {
        if dst_port == POSTGRES_PORT {
            StreamType::Postgres
        } else {
            StreamType::Tcp
        }
    }

    /// Feed a raw IPv4 packet read from `tun0` into the `smoltcp` bridge.
    ///
    /// Inspects incoming TCP SYNs for synthetic `198.18.0.0/15` destinations to
    /// dynamically spawn a listening `smoltcp` TCP socket and emit a `SYN`
    /// `MuxFrame` carrying `StreamOpenPayload` on Port 1000.
    pub fn ingest_guest_packet(&mut self, packet: &[u8]) {
        if let Ok(ip_pkt) = Ipv4Packet::new_checked(packet) {
            if ip_pkt.next_header() == IpProtocol::Tcp {
                if let Ok(tcp_pkt) = TcpPacket::new_checked(ip_pkt.payload()) {
                    if tcp_pkt.syn() && !tcp_pkt.ack() {
                        let src_ip = Ipv4Addr::from(ip_pkt.src_addr().octets());
                        let dst_ip = Ipv4Addr::from(ip_pkt.dst_addr().octets());
                        let tuple = TcpTuple {
                            src_ip,
                            src_port: tcp_pkt.src_port(),
                            dst_ip,
                            dst_port: tcp_pkt.dst_port(),
                        };
                        self.maybe_open_tcp_stream(tuple);
                    }
                }
            }
        }
        self.device.push_rx(packet.to_vec());
    }

    fn maybe_open_tcp_stream(&mut self, tuple: TcpTuple) {
        if self.tuple_to_stream.contains_key(&tuple) {
            return;
        }
        if !SyntheticIpTable::is_in_synthetic_subnet(tuple.dst_ip) {
            return;
        }
        // Do not proxy direct TCP connections to the synthetic DNS IP itself on port 53.
        if tuple.dst_ip == TUN_DNS_IP && tuple.dst_port == DNS_PORT {
            return;
        }

        let rx_buf = tcp::SocketBuffer::new(vec![0u8; TCP_RX_BUF_BYTES]);
        let tx_buf = tcp::SocketBuffer::new(vec![0u8; TCP_TX_BUF_BYTES]);
        let mut sock = tcp::Socket::new(rx_buf, tx_buf);
        let [a, b, c, d] = tuple.dst_ip.octets();
        let listen_ep = IpListenEndpoint {
            addr: Some(IpAddress::v4(a, b, c, d)),
            port: tuple.dst_port,
        };
        if sock.listen(listen_ep).is_err() {
            return;
        }
        let handle = self.sockets.add(sock);
        let stream_id = self.alloc_stream_id();
        let stream_type = Self::stream_type_for_port(tuple.dst_port);
        let hostname = self.ip_table.lookup_fqdn(tuple.dst_ip).map(str::to_string);

        let open_payload = StreamOpenPayload {
            dst_ip: tuple.dst_ip.to_string(),
            dst_port: tuple.dst_port,
            hostname,
        };
        if let Ok(payload_bytes) = serde_json::to_vec(&open_payload) {
            if let Ok(frame) = MuxFrame::new(stream_id, mux_flags::SYN, stream_type, payload_bytes) {
                self.outbound_mux.push_back(frame);
            }
        }

        self.tuple_to_stream.insert(tuple, stream_id);
        self.tcp_streams.insert(
            stream_id,
            ActiveTcpStream {
                handle,
                tuple,
                stream_type,
                tx_to_guest: VecDeque::new(),
                host_fin: false,
                local_closed: false,
                guest_fin_sent: false,
            },
        );
    }

    /// Process a `Port 1000` `MuxFrame` received from `blackwall-proxy` on the host.
    pub fn ingest_mux_frame(&mut self, frame: MuxFrame) {
        let sid = frame.header.stream_id;
        let flags = frame.header.flags;

        match frame.header.stream_type {
            StreamType::DnsResponse => {
                if let Some(pending) = self.pending_dns.remove(&sid) {
                    if let Ok(resp) = serde_json::from_slice::<DnsResponsePayload>(&frame.payload) {
                        let wire = build_dns_response(&pending.query, &resp, &mut self.ip_table);
                        self.send_dns_udp_reply(pending.client_endpoint, &wire);
                    }
                }
            }
            StreamType::Tcp | StreamType::Postgres => {
                if (flags & mux_flags::RST) != 0 {
                    if let Some(stream) = self.tcp_streams.get_mut(&sid) {
                        self.tuple_to_stream.remove(&stream.tuple);
                        stream.guest_fin_sent = true;
                        let sock = self.sockets.get_mut::<tcp::Socket>(stream.handle);
                        sock.abort();
                    }
                    return;
                }
                if let Some(stream) = self.tcp_streams.get_mut(&sid) {
                    if (flags & mux_flags::DATA) != 0 && !frame.payload.is_empty() {
                        stream.tx_to_guest.extend(frame.payload);
                    }
                    if (flags & mux_flags::FIN) != 0 {
                        stream.host_fin = true;
                    }
                }
            }
            StreamType::DnsQuery => {
                // Host does not send DNS queries to guest.
            }
        }
    }

    fn send_dns_udp_reply(&mut self, client_ep: IpEndpoint, wire: &[u8]) {
        let [a, b, c, d] = TUN_DNS_IP.octets();
        let meta = UdpMetadata {
            endpoint: client_ep,
            local_address: Some(IpAddress::v4(a, b, c, d)),
            meta: Default::default(),
        };
        let sock = self.sockets.get_mut::<udp::Socket>(self.dns_socket);
        let _ = sock.send_slice(wire, meta);
    }

    /// Drive `smoltcp` state machines, handle UDP DNS queries, and pump bidirectional
    /// TCP <-> `MuxFrame` streams.
    pub fn poll(&mut self, now: Instant) {
        self.iface.poll(now, &mut self.device, &mut self.sockets);

        // 1. Drain incoming guest DNS queries on 198.18.0.53:53.
        let mut incoming_dns = Vec::new();
        {
            let sock = self.sockets.get_mut::<udp::Socket>(self.dns_socket);
            while sock.can_recv() {
                if let Ok((data, meta)) = sock.recv() {
                    incoming_dns.push((meta.endpoint, data.to_vec()));
                }
            }
        }
        for (client_ep, raw_query) in incoming_dns {
            match parse_dns_query(&raw_query) {
                Ok(parsed) => match parsed.to_proto_query() {
                    Some(proto_query) => {
                        let sid = self.alloc_stream_id();
                        if let Ok(payload) = serde_json::to_vec(&proto_query) {
                            if let Ok(frame) = MuxFrame::new(
                                sid,
                                mux_flags::SYN | mux_flags::DATA,
                                StreamType::DnsQuery,
                                payload,
                            ) {
                                self.pending_dns.insert(
                                    sid,
                                    PendingDnsQuery {
                                        client_endpoint: client_ep,
                                        query: parsed,
                                    },
                                );
                                self.outbound_mux.push_back(frame);
                            }
                        }
                    }
                    None => {
                        let reply = build_dns_error_response(&parsed, RCODE_NOTIMP);
                        self.send_dns_udp_reply(client_ep, &reply);
                    }
                },
                Err(_) => {
                    // Drop malformed DNS queries silently.
                }
            }
        }

        // 2. Pump TCP sockets <-> MuxFrames.
        let stream_ids: Vec<u32> = self.tcp_streams.keys().copied().collect();
        let mut closed_ids = Vec::new();

        for sid in stream_ids {
            let Some(stream) = self.tcp_streams.get_mut(&sid) else {
                continue;
            };
            let sock = self.sockets.get_mut::<tcp::Socket>(stream.handle);

            // Guest -> Host data
            while sock.can_recv() {
                let mut chunk = vec![0u8; MAX_MUX_PAYLOAD as usize];
                match sock.recv_slice(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => {
                        chunk.truncate(n);
                        if let Ok(frame) =
                            MuxFrame::new(sid, mux_flags::DATA, stream.stream_type, chunk)
                        {
                            self.outbound_mux.push_back(frame);
                        }
                    }
                    Err(_) => break,
                }
            }

            // Host -> Guest data
            while !stream.tx_to_guest.is_empty() && sock.can_send() {
                let (front, _) = stream.tx_to_guest.as_slices();
                if front.is_empty() {
                    stream.tx_to_guest.make_contiguous();
                    continue;
                }
                match sock.send_slice(front) {
                    Ok(0) => break,
                    Ok(n) => {
                        stream.tx_to_guest.drain(..n);
                    }
                    Err(_) => break,
                }
            }

            // Host FIN -> close guest socket once pending host data is flushed.
            if stream.host_fin && stream.tx_to_guest.is_empty() && !stream.local_closed {
                sock.close();
                stream.local_closed = true;
            }

            // Guest FIN / Close -> emit FIN to host once.
            let state = sock.state();
            let guest_closed = matches!(
                state,
                tcp::State::CloseWait
                    | tcp::State::Closing
                    | tcp::State::LastAck
                    | tcp::State::TimeWait
                    | tcp::State::Closed
            );
            if guest_closed && !stream.guest_fin_sent {
                if let Ok(frame) =
                    MuxFrame::new(sid, mux_flags::FIN, stream.stream_type, Vec::new())
                {
                    self.outbound_mux.push_back(frame);
                }
                stream.guest_fin_sent = true;
            }

            if state == tcp::State::Closed {
                closed_ids.push(sid);
            }
        }

        for sid in closed_ids {
            if let Some(stream) = self.tcp_streams.remove(&sid) {
                self.tuple_to_stream.remove(&stream.tuple);
                self.sockets.remove(stream.handle);
            }
        }

        // Flush any newly generated TX IP packets.
        self.iface.poll(now, &mut self.device, &mut self.sockets);
    }

    pub fn drain_guest_packets(&mut self) -> Vec<Vec<u8>> {
        self.device.drain_tx()
    }

    pub fn drain_mux_frames(&mut self) -> Vec<MuxFrame> {
        self.outbound_mux.drain(..).collect()
    }

    pub fn poll_delay(&mut self, now: Instant) -> Option<Duration> {
        self.iface.poll_delay(now, &self.sockets)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::{encode_dns_query, QTYPE_A};
    use blackwall_proto::{DnsQueryPayload, DnsRecordType};
    use smoltcp::phy::ChecksumCapabilities;
    use smoltcp::wire::{Ipv4Repr, TcpRepr, TcpSeqNumber, UdpPacket, UdpRepr};

    fn build_ipv4_udp_packet(
        src_ip: Ipv4Addr,
        src_port: u16,
        dst_ip: Ipv4Addr,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let udp_repr = UdpRepr {
            src_port,
            dst_port,
        };
        let ip_repr = Ipv4Repr {
            src_addr: Ipv4Address::from(src_ip),
            dst_addr: Ipv4Address::from(dst_ip),
            next_header: IpProtocol::Udp,
            payload_len: udp_repr.header_len() + payload.len(),
            hop_limit: 64,
        };
        let mut buf = vec![0u8; ip_repr.buffer_len() + ip_repr.payload_len];
        let mut ip_pkt = Ipv4Packet::new_unchecked(&mut buf);
        ip_repr.emit(&mut ip_pkt, &ChecksumCapabilities::default());
        let mut udp_pkt = UdpPacket::new_unchecked(ip_pkt.payload_mut());
        udp_repr.emit(
            &mut udp_pkt,
            &ip_repr.src_addr.into(),
            &ip_repr.dst_addr.into(),
            payload.len(),
            |b| b.copy_from_slice(payload),
            &ChecksumCapabilities::default(),
        );
        buf
    }

    fn build_ipv4_tcp_packet(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        tcp_repr: &TcpRepr<'_>,
    ) -> Vec<u8> {
        let ip_repr = Ipv4Repr {
            src_addr: Ipv4Address::from(src_ip),
            dst_addr: Ipv4Address::from(dst_ip),
            next_header: IpProtocol::Tcp,
            payload_len: tcp_repr.buffer_len(),
            hop_limit: 64,
        };
        let mut buf = vec![0u8; ip_repr.buffer_len() + ip_repr.payload_len];
        let mut ip_pkt = Ipv4Packet::new_unchecked(&mut buf);
        ip_repr.emit(&mut ip_pkt, &ChecksumCapabilities::default());
        let mut tcp_pkt = TcpPacket::new_unchecked(ip_pkt.payload_mut());
        tcp_repr.emit(
            &mut tcp_pkt,
            &ip_repr.src_addr.into(),
            &ip_repr.dst_addr.into(),
            &ChecksumCapabilities::default(),
        );
        buf
    }

    #[test]
    fn bridge_dns_query_and_response_over_port_1000() {
        let now = Instant::from_millis(1000);
        let mut bridge = NetBridge::new(now, 42);

        let dns_wire = encode_dns_query(0x55AA, "api.github.com", QTYPE_A);
        let udp_pkt = build_ipv4_udp_packet(TUN_LOCAL_IP, 40001, TUN_DNS_IP, DNS_PORT, &dns_wire);

        bridge.ingest_guest_packet(&udp_pkt);
        bridge.poll(now);

        let frames = bridge.drain_mux_frames();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].header.stream_type, StreamType::DnsQuery);
        let q: DnsQueryPayload = serde_json::from_slice(&frames[0].payload).unwrap();
        assert_eq!(q.query_id, 0x55AA);
        assert_eq!(q.fqdn, "api.github.com");
        assert_eq!(q.record_type, DnsRecordType::A);

        // Host responds with allowed synthetic IP.
        let resp_payload = DnsResponsePayload {
            query_id: 0x55AA,
            fqdn: "api.github.com".into(),
            synthetic_ip: Some("198.18.1.10".into()),
            allowed: true,
            ttl_sec: 60,
        };
        let resp_frame = MuxFrame::new(
            frames[0].header.stream_id,
            mux_flags::DATA | mux_flags::FIN,
            StreamType::DnsResponse,
            serde_json::to_vec(&resp_payload).unwrap(),
        )
        .unwrap();
        bridge.ingest_mux_frame(resp_frame);
        bridge.poll(Instant::from_millis(1010));

        let tx_pkts = bridge.drain_guest_packets();
        assert_eq!(tx_pkts.len(), 1);
        let ip = Ipv4Packet::new_checked(&tx_pkts[0]).unwrap();
        assert_eq!(Ipv4Addr::from(ip.src_addr().octets()), TUN_DNS_IP);
        assert_eq!(Ipv4Addr::from(ip.dst_addr().octets()), TUN_LOCAL_IP);
        let udp = UdpPacket::new_checked(ip.payload()).unwrap();
        assert_eq!(udp.src_port(), DNS_PORT);
        assert_eq!(udp.dst_port(), 40001);
        let reply_dns = udp.payload();
        assert_eq!(u16::from_be_bytes([reply_dns[0], reply_dns[1]]), 0x55AA);
        assert_eq!(&reply_dns[reply_dns.len() - 4..], &[198, 18, 1, 10]);
        assert_eq!(
            bridge.ip_table().lookup_fqdn(Ipv4Addr::new(198, 18, 1, 10)),
            Some("api.github.com")
        );
    }

    #[test]
    fn bridge_tcp_syn_data_fin_rst_and_postgres_detection() {
        let mut now = Instant::from_millis(2000);
        let mut bridge = NetBridge::new(now, 99);

        let api_ip = Ipv4Addr::new(198, 18, 1, 20);
        let db_ip = Ipv4Addr::new(198, 18, 1, 21);
        bridge.ip_table_mut().register_mapping("api.github.com", api_ip);
        bridge.ip_table_mut().register_mapping("db.internal", db_ip);

        // 1. Guest opens HTTPS TCP connection (port 443 -> StreamType::Tcp)
        let syn = TcpRepr {
            src_port: 50000,
            dst_port: 443,
            control: smoltcp::wire::TcpControl::Syn,
            seq_number: TcpSeqNumber(1000),
            ack_number: None,
            window_len: 65535,
            window_scale: None,
            max_seg_size: Some(1460),
            sack_permitted: false,
            sack_ranges: [None, None, None],
            timestamp: None,
            payload: &[],
        };
        bridge.ingest_guest_packet(&build_ipv4_tcp_packet(TUN_LOCAL_IP, api_ip, &syn));
        bridge.poll(now);

        let frames = bridge.drain_mux_frames();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].header.flags, mux_flags::SYN);
        assert_eq!(frames[0].header.stream_type, StreamType::Tcp);
        let tcp_sid = frames[0].header.stream_id;
        let open: StreamOpenPayload = serde_json::from_slice(&frames[0].payload).unwrap();
        assert_eq!(open.dst_ip, "198.18.1.20");
        assert_eq!(open.dst_port, 443);
        assert_eq!(open.hostname.as_deref(), Some("api.github.com"));

        // Capture smoltcp SYN-ACK to get its seq number.
        let tx = bridge.drain_guest_packets();
        assert_eq!(tx.len(), 1);
        let syn_ack_ip = Ipv4Packet::new_checked(&tx[0]).unwrap();
        let syn_ack_tcp = TcpPacket::new_checked(syn_ack_ip.payload()).unwrap();
        assert!(syn_ack_tcp.syn() && syn_ack_tcp.ack());
        let server_isn = syn_ack_tcp.seq_number();

        // Guest sends ACK + payload "GET / HTTP/1.1\r\n"
        now = Instant::from_millis(2010);
        let data_pkt = TcpRepr {
            src_port: 50000,
            dst_port: 443,
            control: smoltcp::wire::TcpControl::None,
            seq_number: TcpSeqNumber(1001),
            ack_number: Some(server_isn + 1),
            window_len: 65535,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None, None, None],
            timestamp: None,
            payload: b"GET / HTTP/1.1\r\n",
        };
        bridge.ingest_guest_packet(&build_ipv4_tcp_packet(TUN_LOCAL_IP, api_ip, &data_pkt));
        bridge.poll(now);

        let data_frames = bridge.drain_mux_frames();
        assert_eq!(data_frames.len(), 1);
        assert_eq!(data_frames[0].header.stream_id, tcp_sid);
        assert_eq!(data_frames[0].header.flags, mux_flags::DATA);
        assert_eq!(data_frames[0].payload, b"GET / HTTP/1.1\r\n");
        let _ = bridge.drain_guest_packets(); // ACK

        // Host replies with DATA + FIN over Port 1000
        now = Instant::from_millis(2020);
        bridge.ingest_mux_frame(
            MuxFrame::new(
                tcp_sid,
                mux_flags::DATA | mux_flags::FIN,
                StreamType::Tcp,
                b"HTTP/1.1 200 OK\r\n".to_vec(),
            )
            .unwrap(),
        );
        bridge.poll(now);
        let host_tx = bridge.drain_guest_packets();
        assert!(!host_tx.is_empty());
        let mut saw_payload = false;
        for pkt in &host_tx {
            let ip = Ipv4Packet::new_checked(pkt).unwrap();
            let tp = TcpPacket::new_checked(ip.payload()).unwrap();
            if tp.payload() == b"HTTP/1.1 200 OK\r\n" {
                saw_payload = true;
            }
        }
        assert!(saw_payload, "expected host DATA payload transmitted to guest");

        // Guest sends FIN -> verify FIN MuxFrame emitted
        now = Instant::from_millis(2030);
        let fin = TcpRepr {
            src_port: 50000,
            dst_port: 443,
            control: smoltcp::wire::TcpControl::Fin,
            seq_number: TcpSeqNumber(1001 + 16),
            ack_number: Some(server_isn + 1 + 17 + 1),
            window_len: 65535,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None, None, None],
            timestamp: None,
            payload: &[],
        };
        bridge.ingest_guest_packet(&build_ipv4_tcp_packet(TUN_LOCAL_IP, api_ip, &fin));
        bridge.poll(now);
        let fin_frames = bridge.drain_mux_frames();
        assert!(fin_frames
            .iter()
            .any(|f| f.header.stream_id == tcp_sid && (f.header.flags & mux_flags::FIN) != 0));

        // 2. Guest opens Postgres TCP connection on port 5432 -> StreamType::Postgres
        now = Instant::from_millis(2040);
        let pg_syn = TcpRepr {
            src_port: 50001,
            dst_port: POSTGRES_PORT,
            control: smoltcp::wire::TcpControl::Syn,
            seq_number: TcpSeqNumber(5000),
            ack_number: None,
            window_len: 65535,
            window_scale: None,
            max_seg_size: Some(1460),
            sack_permitted: false,
            sack_ranges: [None, None, None],
            timestamp: None,
            payload: &[],
        };
        bridge.ingest_guest_packet(&build_ipv4_tcp_packet(TUN_LOCAL_IP, db_ip, &pg_syn));
        bridge.poll(now);

        let pg_frames = bridge.drain_mux_frames();
        assert_eq!(pg_frames.len(), 1);
        assert_eq!(pg_frames[0].header.flags, mux_flags::SYN);
        assert_eq!(pg_frames[0].header.stream_type, StreamType::Postgres);
        let pg_sid = pg_frames[0].header.stream_id;
        let pg_open: StreamOpenPayload = serde_json::from_slice(&pg_frames[0].payload).unwrap();
        assert_eq!(pg_open.dst_port, 5432);
        assert_eq!(pg_open.hostname.as_deref(), Some("db.internal"));

        // 3. Host sends RST -> TCP RST is emitted to guest and stream is torn down cleanly
        now = Instant::from_millis(2050);
        bridge.ingest_mux_frame(
            MuxFrame::new(pg_sid, mux_flags::RST, StreamType::Postgres, Vec::new()).unwrap(),
        );
        bridge.poll(now);
        assert!(!bridge.tcp_streams.contains_key(&pg_sid));
    }
}
