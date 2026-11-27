//! Lightweight RFC 1035 DNS wire parser & responder for `198.18.0.53:53` plus
//! deterministic RFC 2544 (`198.18.0.0/15`) synthetic IP allocator and reverse cache.

use blackwall_proto::{DnsQueryPayload, DnsRecordType, DnsResponsePayload};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use thiserror::Error;

pub const DNS_HEADER_LEN: usize = 12;
pub const QTYPE_A: u16 = 1;
pub const QTYPE_AAAA: u16 = 28;
pub const QCLASS_IN: u16 = 1;

pub const RCODE_NOERROR: u8 = 0;
pub const RCODE_FORMERR: u8 = 1;
pub const RCODE_NXDOMAIN: u8 = 3;
pub const RCODE_NOTIMP: u8 = 4;
pub const RCODE_REFUSED: u8 = 5;

/// First allocatable synthetic IP (`198.18.1.1`) in RFC 2544 `198.18.0.0/15`,
/// reserving `198.18.0.0/24` for local `tun0` (`198.18.0.1`) and DNS (`198.18.0.53`).
const SYNTHETIC_RANGE_START: u32 = u32::from_be_bytes([198, 18, 1, 1]);
const SYNTHETIC_RANGE_END: u32 = u32::from_be_bytes([198, 19, 255, 254]);

#[derive(Debug, Error)]
pub enum DnsError {
    #[error("DNS packet too short ({0} bytes)")]
    TooShort(usize),
    #[error("DNS packet is not a query")]
    NotAQuery,
    #[error("DNS query has zero questions")]
    NoQuestions,
    #[error("malformed DNS domain name: {0}")]
    MalformedName(String),
}

/// Bidirectional cache mapping `fqdn <-> synthetic_ip` inside `198.18.0.0/15`.
#[derive(Debug, Default)]
pub struct SyntheticIpTable {
    fqdn_to_ip: HashMap<String, Ipv4Addr>,
    ip_to_fqdn: HashMap<Ipv4Addr, String>,
    next_host: u32,
}

impl SyntheticIpTable {
    pub fn new() -> Self {
        Self {
            fqdn_to_ip: HashMap::new(),
            ip_to_fqdn: HashMap::new(),
            next_host: SYNTHETIC_RANGE_START,
        }
    }

    pub fn normalize_fqdn(fqdn: &str) -> String {
        fqdn.trim_end_matches('.').to_ascii_lowercase()
    }

    pub fn is_in_synthetic_subnet(ip: Ipv4Addr) -> bool {
        let [a, b, _, _] = ip.octets();
        a == 198 && (b == 18 || b == 19)
    }

    /// Record an explicit host-supplied `fqdn <-> synthetic_ip` mapping.
    pub fn register_mapping(&mut self, fqdn: &str, ip: Ipv4Addr) {
        let norm = Self::normalize_fqdn(fqdn);
        if let Some(old_ip) = self.fqdn_to_ip.insert(norm.clone(), ip) {
            if old_ip != ip {
                self.ip_to_fqdn.remove(&old_ip);
            }
        }
        self.ip_to_fqdn.insert(ip, norm);
    }

    /// Return the cached synthetic IP for `fqdn`, or allocate a fresh IP in `198.18.1.1..=198.19.255.254`.
    pub fn allocate_for_fqdn(&mut self, fqdn: &str) -> Ipv4Addr {
        let norm = Self::normalize_fqdn(fqdn);
        if let Some(&existing) = self.fqdn_to_ip.get(&norm) {
            return existing;
        }
        if self.next_host < SYNTHETIC_RANGE_START {
            self.next_host = SYNTHETIC_RANGE_START;
        }
        let range_len = SYNTHETIC_RANGE_END - SYNTHETIC_RANGE_START + 1;
        for _ in 0..range_len {
            let candidate = Ipv4Addr::from(self.next_host);
            self.next_host = if self.next_host >= SYNTHETIC_RANGE_END {
                SYNTHETIC_RANGE_START
            } else {
                self.next_host + 1
            };
            let octets = candidate.octets();
            // Skip .0 and .255 host addresses for broad client compatibility.
            if octets[3] == 0 || octets[3] == 255 {
                continue;
            }
            if !self.ip_to_fqdn.contains_key(&candidate) {
                self.fqdn_to_ip.insert(norm.clone(), candidate);
                self.ip_to_fqdn.insert(candidate, norm);
                return candidate;
            }
        }
        // Fallback if table is completely exhausted (130k+ unique domains): wrap & reuse.
        let fallback = Ipv4Addr::from(SYNTHETIC_RANGE_START);
        self.register_mapping(&norm, fallback);
        fallback
    }

    pub fn lookup_fqdn(&self, ip: Ipv4Addr) -> Option<&str> {
        self.ip_to_fqdn.get(&ip).map(String::as_str)
    }

    pub fn lookup_ip(&self, fqdn: &str) -> Option<Ipv4Addr> {
        let norm = Self::normalize_fqdn(fqdn);
        self.fqdn_to_ip.get(&norm).copied()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedDnsQuery {
    pub id: u16,
    pub flags: u16,
    pub fqdn: String,
    pub qtype: u16,
    pub qclass: u16,
    /// Raw RFC 1035 question section bytes (QNAME + QTYPE + QCLASS) to echo in response.
    pub raw_question: Vec<u8>,
}

impl ParsedDnsQuery {
    /// Convert supported `A`/`AAAA` queries into `blackwall_proto::DnsQueryPayload`.
    pub fn to_proto_query(&self) -> Option<DnsQueryPayload> {
        let record_type = match self.qtype {
            QTYPE_A => DnsRecordType::A,
            QTYPE_AAAA => DnsRecordType::AAAA,
            _ => return None,
        };
        Some(DnsQueryPayload {
            query_id: self.id,
            fqdn: self.fqdn.clone(),
            record_type,
        })
    }
}

/// Parse an RFC 1035 DNS query packet (UDP payload).
pub fn parse_dns_query(packet: &[u8]) -> Result<ParsedDnsQuery, DnsError> {
    if packet.len() < DNS_HEADER_LEN {
        return Err(DnsError::TooShort(packet.len()));
    }
    let id = u16::from_be_bytes([packet[0], packet[1]]);
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]);

    // QR bit (MSB of flags) must be 0 for a query.
    if (flags & 0x8000) != 0 {
        return Err(DnsError::NotAQuery);
    }
    if qdcount == 0 {
        return Err(DnsError::NoQuestions);
    }

    let (fqdn, name_end) = decode_qname(packet, DNS_HEADER_LEN)?;
    if name_end + 4 > packet.len() {
        return Err(DnsError::TooShort(packet.len()));
    }
    let qtype = u16::from_be_bytes([packet[name_end], packet[name_end + 1]]);
    let qclass = u16::from_be_bytes([packet[name_end + 2], packet[name_end + 3]]);
    let raw_question = packet[DNS_HEADER_LEN..name_end + 4].to_vec();

    Ok(ParsedDnsQuery {
        id,
        flags,
        fqdn,
        qtype,
        qclass,
        raw_question,
    })
}

fn decode_qname(packet: &[u8], start: usize) -> Result<(String, usize), DnsError> {
    let mut labels = Vec::new();
    let mut offset = start;
    let mut end_offset: Option<usize> = None;
    let mut jumps = 0u8;
    let mut total_len = 0usize;

    loop {
        if offset >= packet.len() {
            return Err(DnsError::MalformedName("unexpected EOF in QNAME".into()));
        }
        let len_byte = packet[offset];
        if len_byte == 0 {
            let final_end = end_offset.unwrap_or(offset + 1);
            return Ok((labels.join("."), final_end));
        }
        if (len_byte & 0xC0) == 0xC0 {
            // Compression pointer
            if offset + 1 >= packet.len() {
                return Err(DnsError::MalformedName("truncated pointer".into()));
            }
            jumps += 1;
            if jumps > 16 {
                return Err(DnsError::MalformedName("compression pointer loop".into()));
            }
            if end_offset.is_none() {
                end_offset = Some(offset + 2);
            }
            let ptr = (((len_byte & 0x3F) as usize) << 8) | (packet[offset + 1] as usize);
            if ptr >= packet.len() {
                return Err(DnsError::MalformedName("pointer out of bounds".into()));
            }
            offset = ptr;
            continue;
        }
        if (len_byte & 0xC0) != 0 {
            return Err(DnsError::MalformedName("invalid label prefix bits".into()));
        }
        let label_len = len_byte as usize;
        offset += 1;
        if offset + label_len > packet.len() {
            return Err(DnsError::MalformedName("label exceeds packet length".into()));
        }
        total_len += label_len + 1;
        if total_len > 255 {
            return Err(DnsError::MalformedName("domain exceeds 255 bytes".into()));
        }
        let label_bytes = &packet[offset..offset + label_len];
        let label = std::str::from_utf8(label_bytes)
            .map_err(|_| DnsError::MalformedName("non-UTF8 label".into()))?;
        labels.push(label.to_ascii_lowercase());
        offset += label_len;
    }
}

/// Build an RFC 1035 DNS wire response from a host `DnsResponsePayload`.
///
/// - If `!resp.allowed`, returns `NXDOMAIN` (`RCODE=3`) with `ANCOUNT=0`.
/// - If `resp.allowed` and `query.qtype == A`: resolves/caches synthetic IPv4 in
///   `198.18.0.0/15` and returns `NOERROR` with 1 `A` answer RR.
/// - If `resp.allowed` and `query.qtype == AAAA`: returns `NOERROR` with `ANCOUNT=0`
///   (NODATA) so dual-stack resolvers fall back cleanly to the `A` record.
pub fn build_dns_response(
    query: &ParsedDnsQuery,
    resp: &DnsResponsePayload,
    table: &mut SyntheticIpTable,
) -> Vec<u8> {
    if !resp.allowed {
        return build_dns_error_response(query, RCODE_NXDOMAIN);
    }

    if query.qtype != QTYPE_A {
        // Allowed domain, but IPv6/non-A record -> NOERROR empty answer (NODATA).
        return build_dns_error_response(query, RCODE_NOERROR);
    }

    let ip = match resp
        .synthetic_ip
        .as_deref()
        .and_then(|s| s.parse::<Ipv4Addr>().ok())
    {
        Some(parsed) if SyntheticIpTable::is_in_synthetic_subnet(parsed) => {
            table.register_mapping(&resp.fqdn, parsed);
            parsed
        }
        _ => table.allocate_for_fqdn(&resp.fqdn),
    };

    let rd = query.flags & 0x0100;
    // QR=1 (0x8000), AA=1 (0x0400), RD preserved, RA=1 (0x0080), RCODE=0
    let resp_flags: u16 = 0x8480 | rd;

    let mut out = Vec::with_capacity(DNS_HEADER_LEN + query.raw_question.len() + 16);
    out.extend_from_slice(&query.id.to_be_bytes());
    out.extend_from_slice(&resp_flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
    out.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT = 1
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT = 0
    out.extend_from_slice(&query.raw_question);

    // Answer RR: pointer to QNAME at offset 12 (0xC00C)
    out.extend_from_slice(&0xC00Cu16.to_be_bytes());
    out.extend_from_slice(&QTYPE_A.to_be_bytes());
    out.extend_from_slice(&QCLASS_IN.to_be_bytes());
    let ttl = if resp.ttl_sec == 0 { 60 } else { resp.ttl_sec };
    out.extend_from_slice(&ttl.to_be_bytes());
    out.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH = 4
    out.extend_from_slice(&ip.octets());
    out
}

/// Build an RFC 1035 DNS wire response with zero answers and the given `rcode`
/// (e.g., `RCODE_NXDOMAIN`, `RCODE_REFUSED`, `RCODE_NOERROR`, `RCODE_NOTIMP`).
pub fn build_dns_error_response(query: &ParsedDnsQuery, rcode: u8) -> Vec<u8> {
    let rd = query.flags & 0x0100;
    let resp_flags: u16 = 0x8480 | rd | ((rcode & 0x0F) as u16);

    let mut out = Vec::with_capacity(DNS_HEADER_LEN + query.raw_question.len());
    out.extend_from_slice(&query.id.to_be_bytes());
    out.extend_from_slice(&resp_flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
    out.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT = 0
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT = 0
    out.extend_from_slice(&query.raw_question);
    out
}

/// Helper to build a standard RFC 1035 DNS query wire packet (useful for tests).
pub fn encode_dns_query(id: u16, fqdn: &str, qtype: u16) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(DNS_HEADER_LEN + fqdn.len() + 6);
    pkt.extend_from_slice(&id.to_be_bytes());
    pkt.extend_from_slice(&0x0100u16.to_be_bytes()); // Standard query, RD=1
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT = 0
    pkt.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT = 0
    for label in fqdn.trim_end_matches('.').split('.') {
        if !label.is_empty() {
            pkt.push(label.len() as u8);
            pkt.extend_from_slice(label.as_bytes());
        }
    }
    pkt.push(0); // Root label
    pkt.extend_from_slice(&qtype.to_be_bytes());
    pkt.extend_from_slice(&QCLASS_IN.to_be_bytes());
    pkt
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_query_parse_and_a_response_roundtrip() {
        let wire = encode_dns_query(0x1234, "API.GitHub.com", QTYPE_A);
        let parsed = parse_dns_query(&wire).unwrap();
        assert_eq!(parsed.id, 0x1234);
        assert_eq!(parsed.fqdn, "api.github.com");
        assert_eq!(parsed.qtype, QTYPE_A);
        assert_eq!(parsed.qclass, QCLASS_IN);

        let proto_q = parsed.to_proto_query().unwrap();
        assert_eq!(proto_q.query_id, 0x1234);
        assert_eq!(proto_q.fqdn, "api.github.com");
        assert_eq!(proto_q.record_type, DnsRecordType::A);

        let mut table = SyntheticIpTable::new();
        let resp_payload = DnsResponsePayload {
            query_id: 0x1234,
            fqdn: "api.github.com".into(),
            synthetic_ip: Some("198.18.2.42".into()),
            allowed: true,
            ttl_sec: 120,
        };
        let resp_wire = build_dns_response(&parsed, &resp_payload, &mut table);

        // Verify RFC 1035 header
        assert_eq!(u16::from_be_bytes([resp_wire[0], resp_wire[1]]), 0x1234);
        let flags = u16::from_be_bytes([resp_wire[2], resp_wire[3]]);
        assert_ne!(flags & 0x8000, 0); // QR=1
        assert_eq!(flags & 0x000F, RCODE_NOERROR as u16);
        assert_eq!(u16::from_be_bytes([resp_wire[4], resp_wire[5]]), 1); // QDCOUNT
        assert_eq!(u16::from_be_bytes([resp_wire[6], resp_wire[7]]), 1); // ANCOUNT

        // Verify Answer RR tail
        let ans = &resp_wire[DNS_HEADER_LEN + parsed.raw_question.len()..];
        assert_eq!(ans.len(), 16);
        assert_eq!(&ans[0..2], &[0xC0, 0x0C]);
        assert_eq!(u16::from_be_bytes([ans[2], ans[3]]), QTYPE_A);
        assert_eq!(u16::from_be_bytes([ans[4], ans[5]]), QCLASS_IN);
        assert_eq!(u32::from_be_bytes([ans[6], ans[7], ans[8], ans[9]]), 120);
        assert_eq!(u16::from_be_bytes([ans[10], ans[11]]), 4);
        assert_eq!(&ans[12..16], &[198, 18, 2, 42]);

        // Verify reverse lookup cache
        assert_eq!(
            table.lookup_fqdn(Ipv4Addr::new(198, 18, 2, 42)),
            Some("api.github.com")
        );
    }

    #[test]
    fn dns_denied_returns_nxdomain_and_refused_helper_works() {
        let wire = encode_dns_query(0xBEEF, "evil.example", QTYPE_A);
        let parsed = parse_dns_query(&wire).unwrap();
        let mut table = SyntheticIpTable::new();

        let denied = DnsResponsePayload {
            query_id: 0xBEEF,
            fqdn: "evil.example".into(),
            synthetic_ip: None,
            allowed: false,
            ttl_sec: 0,
        };
        let resp = build_dns_response(&parsed, &denied, &mut table);
        assert_eq!(u16::from_be_bytes([resp[0], resp[1]]), 0xBEEF);
        let flags = u16::from_be_bytes([resp[2], resp[3]]);
        assert_eq!(flags & 0x000F, RCODE_NXDOMAIN as u16);
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 0); // ANCOUNT = 0
        assert!(table.lookup_ip("evil.example").is_none());

        let refused = build_dns_error_response(&parsed, RCODE_REFUSED);
        assert_eq!(
            u16::from_be_bytes([refused[2], refused[3]]) & 0x000F,
            RCODE_REFUSED as u16
        );
    }

    #[test]
    fn synthetic_ip_allocation_and_reverse_lookup() {
        let mut table = SyntheticIpTable::new();
        let ip1 = table.allocate_for_fqdn("crates.io");
        let ip2 = table.allocate_for_fqdn("static.crates.io.");
        let ip1_again = table.allocate_for_fqdn("CRATES.IO");

        assert!(SyntheticIpTable::is_in_synthetic_subnet(ip1));
        assert!(SyntheticIpTable::is_in_synthetic_subnet(ip2));
        assert_eq!(ip1, ip1_again);
        assert_ne!(ip1, ip2);
        assert_eq!(table.lookup_fqdn(ip1), Some("crates.io"));
        assert_eq!(table.lookup_fqdn(ip2), Some("static.crates.io"));
        assert_eq!(table.lookup_ip("static.crates.io"), Some(ip2));
    }
}
