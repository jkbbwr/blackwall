//! Out-of-process host DNS resolver for Blackwall.
//!
//! Resolves all hostnames derived from `spec.derived_dns_allow()` strictly on the
//! host (outside the jailed `blackwall-proxy`) into a [`PinnedHostMap`], filtering
//! out loopback (`127.0.0.0/8`, `::1`), link-local / cloud metadata
//! (`169.254.0.0/16`, `fe80::/10`), and RFC1918 / ULA private ranges unless
//! explicitly permitted in local/test configuration.

use crate::error::{CoreError, Result};
use blackwall_policy::{NetworkMode, SandboxSpec};
use blackwall_proxy::PinnedHostMap;
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};

/// Pluggable host DNS resolver interface (injectable for deterministic tests).
pub trait DnsResolver: Send + Sync {
    /// Resolve `(host, port)` into one or more upstream [`SocketAddr`]s.
    fn resolve_host(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>>;
}

/// Default host OS resolver backed by `std::net::ToSocketAddrs`.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemDnsResolver;

impl DnsResolver for SystemDnsResolver {
    fn resolve_host(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>> {
        let iter = (host, port)
            .to_socket_addrs()
            .map_err(|e| CoreError::DnsResolution {
                host: host.to_string(),
                reason: e.to_string(),
            })?;
        let addrs: Vec<SocketAddr> = iter.collect();
        if addrs.is_empty() {
            return Err(CoreError::DnsResolution {
                host: host.to_string(),
                reason: "resolver returned zero addresses".into(),
            });
        }
        Ok(addrs)
    }
}

/// Deterministic in-memory [`DnsResolver`] for tests and static pinning.
#[derive(Debug, Default, Clone)]
pub struct StaticDnsResolver {
    /// Maps lowercase `host` -> IP addresses (combined with the requested port).
    host_ips: BTreeMap<String, Vec<IpAddr>>,
    /// Maps lowercase `host:port` -> exact `SocketAddr` overrides (e.g., local test ports).
    exact_addrs: BTreeMap<String, Vec<SocketAddr>>,
}

impl StaticDnsResolver {
    pub fn new() -> Self {
        Self::default()
    }

    /// Map `host` to one or more IP addresses (paired with whichever port the rule uses).
    pub fn insert_ips(&mut self, host: impl Into<String>, ips: Vec<IpAddr>) -> &mut Self {
        let key = normalize_host(&host.into());
        self.host_ips.insert(key, ips);
        self
    }

    /// Map `(host, port)` to exact upstream `SocketAddr`s (useful when routing a rule
    /// like `api.github.com:443` to a local mock server on an ephemeral port in tests).
    pub fn insert_exact(
        &mut self,
        host: impl Into<String>,
        port: u16,
        addrs: Vec<SocketAddr>,
    ) -> &mut Self {
        let key = format!("{}:{port}", normalize_host(&host.into()));
        self.exact_addrs.insert(key, addrs);
        self
    }
}

impl DnsResolver for StaticDnsResolver {
    fn resolve_host(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>> {
        let norm = normalize_host(host);
        let exact_key = format!("{norm}:{port}");
        if let Some(addrs) = self.exact_addrs.get(&exact_key) {
            if !addrs.is_empty() {
                return Ok(addrs.clone());
            }
        }
        if let Some(ips) = self.host_ips.get(&norm) {
            if !ips.is_empty() {
                return Ok(ips.iter().map(|&ip| SocketAddr::new(ip, port)).collect());
            }
        }
        Err(CoreError::DnsResolution {
            host: host.to_string(),
            reason: "no static DNS entry configured".into(),
        })
    }
}

/// IP filtering controls for out-of-process DNS resolution.
///
/// Defaults to fail-closed (`allow_loopback = false`, `allow_private = false`,
/// `allow_link_local = false`), rejecting loopback, cloud metadata / link-local,
/// and RFC1918 / IPv6 ULA targets.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DnsResolveOptions {
    /// Permit `127.0.0.0/8` and `::1`. Must remain `false` in production.
    pub allow_loopback: bool,
    /// Permit RFC1918 (`10/8`, `172.16/12`, `192.168/16`), CGNAT (`100.64/10`), and IPv6 ULA (`fc00::/7`).
    pub allow_private: bool,
    /// Permit link-local / cloud metadata (`169.254.0.0/16`, `fe80::/10`). Must remain `false` in production.
    pub allow_link_local: bool,
}

impl DnsResolveOptions {
    /// Fail-closed production policy: rejects loopback, link-local/metadata, and private ranges.
    pub const fn strict() -> Self {
        Self {
            allow_loopback: false,
            allow_private: false,
            allow_link_local: false,
        }
    }

    /// Local integration test helper: allows loopback and private RFC1918, still blocks metadata/link-local.
    pub const fn allow_local_for_testing() -> Self {
        Self {
            allow_loopback: true,
            allow_private: true,
            allow_link_local: false,
        }
    }
}

/// Check whether `ip` is permitted by `opts`.
///
/// Unwraps IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) so attackers cannot bypass
/// IPv4 loopback/metadata/RFC1918 blocks via mapped IPv6 representations.
pub fn check_ip_allowed(ip: IpAddr, opts: DnsResolveOptions) -> std::result::Result<(), &'static str> {
    match ip {
        IpAddr::V4(v4) => check_ipv4_allowed(v4, opts),
        IpAddr::V6(v6) => {
            if let Some(mapped_v4) = v6.to_ipv4_mapped() {
                return check_ipv4_allowed(mapped_v4, opts);
            }
            check_ipv6_allowed(v6, opts)
        }
    }
}

fn check_ipv4_allowed(v4: Ipv4Addr, opts: DnsResolveOptions) -> std::result::Result<(), &'static str> {
    let octets = v4.octets();
    if octets[0] == 0 {
        return Err("unspecified 0.0.0.0/8 address is forbidden");
    }
    if v4.is_loopback() {
        return if opts.allow_loopback {
            Ok(())
        } else {
            Err("loopback 127.0.0.0/8 address is forbidden")
        };
    }
    if v4.is_link_local() {
        return if opts.allow_link_local {
            Ok(())
        } else {
            Err("link-local / cloud metadata 169.254.0.0/16 address is forbidden")
        };
    }
    if v4.is_private() {
        return if opts.allow_private {
            Ok(())
        } else {
            Err("RFC1918 private address is forbidden")
        };
    }
    // RFC 6598 CGNAT / shared address space (100.64.0.0/10)
    if octets[0] == 100 && (octets[1] & 0b1100_0000) == 64 {
        return if opts.allow_private {
            Ok(())
        } else {
            Err("shared/CGNAT 100.64.0.0/10 address is forbidden")
        };
    }
    if v4.is_multicast() || v4.is_broadcast() {
        return Err("multicast/broadcast address is forbidden");
    }
    Ok(())
}

fn check_ipv6_allowed(v6: Ipv6Addr, opts: DnsResolveOptions) -> std::result::Result<(), &'static str> {
    if v6.is_unspecified() {
        return Err("unspecified :: address is forbidden");
    }
    if v6.is_loopback() {
        return if opts.allow_loopback {
            Ok(())
        } else {
            Err("IPv6 loopback ::1 is forbidden")
        };
    }
    let seg0 = v6.segments()[0];
    // fe80::/10 link-local unicast
    if (seg0 & 0xffc0) == 0xfe80 {
        return if opts.allow_link_local {
            Ok(())
        } else {
            Err("IPv6 link-local fe80::/10 address is forbidden")
        };
    }
    // fc00::/7 Unique Local Addresses (RFC 4193)
    if (seg0 & 0xfe00) == 0xfc00 {
        return if opts.allow_private {
            Ok(())
        } else {
            Err("IPv6 private ULA fc00::/7 address is forbidden")
        };
    }
    if v6.is_multicast() {
        return Err("IPv6 multicast address is forbidden");
    }
    Ok(())
}

/// Resolve all allowlisted FQDNs in `spec` using the host OS DNS resolver with
/// strict fail-closed IP filtering (blocks loopback, metadata/link-local, RFC1918).
pub fn resolve_allowlisted_hosts(spec: &SandboxSpec) -> Result<PinnedHostMap> {
    resolve_allowlisted_hosts_with(spec, &SystemDnsResolver, DnsResolveOptions::strict())
}

/// Resolve all allowlisted FQDNs in `spec` using an injectable [`DnsResolver`] and
/// [`DnsResolveOptions`].
///
/// Returns an empty [`PinnedHostMap`] when `spec.network.mode != NetworkMode::Egress`.
pub fn resolve_allowlisted_hosts_with(
    spec: &SandboxSpec,
    resolver: &dyn DnsResolver,
    opts: DnsResolveOptions,
) -> Result<PinnedHostMap> {
    if spec.network.mode != NetworkMode::Egress {
        return Ok(PinnedHostMap::new());
    }

    // Collect every unique (host, port) pair from HTTP and Postgres rules.
    let mut host_ports: BTreeMap<String, BTreeSet<u16>> = BTreeMap::new();
    for rule in &spec.network.http {
        let h = normalize_host(&rule.host);
        if !h.is_empty() {
            host_ports.entry(h).or_default().insert(rule.port);
        }
    }
    for rule in &spec.network.postgres {
        let h = normalize_host(&rule.host);
        if !h.is_empty() {
            host_ports.entry(h).or_default().insert(rule.port);
        }
    }

    // Ensure every hostname in `spec.derived_dns_allow()` is accounted for.
    for derived in spec.derived_dns_allow() {
        let h = normalize_host(&derived);
        host_ports.entry(h).or_insert_with(|| BTreeSet::from([443]));
    }

    let mut pinned = PinnedHostMap::new();

    for (host, ports) in host_ports {
        let multi_port = ports.len() > 1;
        let mut combined_for_host: Vec<SocketAddr> = Vec::new();

        for port in ports {
            let raw_addrs = resolver.resolve_host(&host, port)?;
            let mut filtered: Vec<SocketAddr> = Vec::new();
            let mut first_rejected: Option<(IpAddr, &'static str)> = None;

            for addr in raw_addrs {
                match check_ip_allowed(addr.ip(), opts) {
                    Ok(()) => {
                        if !filtered.contains(&addr) {
                            filtered.push(addr);
                        }
                    }
                    Err(reason) => {
                        if first_rejected.is_none() {
                            first_rejected = Some((addr.ip(), reason));
                        }
                    }
                }
            }

            if filtered.is_empty() {
                if let Some((ip, reason)) = first_rejected {
                    return Err(CoreError::ForbiddenResolvedIp {
                        host,
                        ip,
                        reason: reason.to_string(),
                    });
                }
                return Err(CoreError::DnsResolution {
                    host,
                    reason: format!("no valid IP addresses resolved for port {port}"),
                });
            }

            let port_remapped = filtered.iter().any(|a| a.port() != port);
            if multi_port || port_remapped {
                pinned.insert(format!("{host}:{port}"), filtered.clone());
            }
            for addr in filtered {
                if !combined_for_host.contains(&addr) {
                    combined_for_host.push(addr);
                }
            }
        }

        pinned.insert(host, combined_for_host);
    }

    Ok(pinned)
}

/// Extract a deduplicated list of pinned upstream [`SocketAddr`]s for `nftables` IP-sets.
pub fn collect_pinned_endpoints(map: &PinnedHostMap) -> Vec<SocketAddr> {
    let mut set = BTreeSet::new();
    for addrs in map.values() {
        for &addr in addrs {
            set.insert(addr);
        }
    }
    set.into_iter().collect()
}

fn normalize_host(host: &str) -> String {
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use blackwall_policy::{HttpRule, PostgresRule};
    use blackwall_proxy::http_proxy::lookup_pinned_addr;

    fn egress_spec() -> SandboxSpec {
        let mut spec = SandboxSpec::base();
        spec.network.mode = NetworkMode::Egress;
        spec.network.http.push(HttpRule {
            host: "api.github.com".into(),
            port: 443,
            methods: vec!["GET".into()],
            path_prefixes: vec!["/".into()],
            max_request_bytes: None,
            auth: None,
        });
        spec.network.postgres.push(PostgresRule {
            host: "db.example.com".into(),
            port: 5432,
            secret: "PGPASSWORD".into(),
            require_upstream_tls: true,
        });
        spec
    }

    #[test]
    fn resolves_http_and_postgres_ports_and_filters_forbidden_ips() {
        let spec = egress_spec();
        let mut resolver = StaticDnsResolver::new();
        resolver.insert_ips(
            "api.github.com",
            vec![
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),      // filtered
                IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)), // filtered
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),        // filtered
                IpAddr::V4(Ipv4Addr::new(140, 82, 121, 6)),    // allowed
            ],
        );
        resolver.insert_ips(
            "db.example.com",
            vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10))],
        );

        let pinned =
            resolve_allowlisted_hosts_with(&spec, &resolver, DnsResolveOptions::strict()).unwrap();
        assert_eq!(
            lookup_pinned_addr(&pinned, "api.github.com", 443),
            Some("140.82.121.6:443".parse().unwrap())
        );
        assert_eq!(
            lookup_pinned_addr(&pinned, "db.example.com", 5432),
            Some("198.51.100.10:5432".parse().unwrap())
        );
    }

    #[test]
    fn rejects_hosts_resolving_exclusively_to_loopback_metadata_or_rfc1918() {
        let mut spec = SandboxSpec::base();
        spec.network.mode = NetworkMode::Egress;
        spec.network.http.push(HttpRule {
            host: "rebind.evil.test".into(),
            port: 443,
            methods: vec!["GET".into()],
            path_prefixes: vec!["/".into()],
            max_request_bytes: None,
            auth: None,
        });

        for bad_ip in [
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
            IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)),
            IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6("fe80::1".parse().unwrap()),
            IpAddr::V6("fc00::1".parse().unwrap()),
            // IPv4-mapped IPv6 bypass attempt for AWS metadata
            IpAddr::V6("::ffff:169.254.169.254".parse().unwrap()),
        ] {
            let mut resolver = StaticDnsResolver::new();
            resolver.insert_ips("rebind.evil.test", vec![bad_ip]);
            let err =
                resolve_allowlisted_hosts_with(&spec, &resolver, DnsResolveOptions::strict())
                    .unwrap_err();
            assert!(
                matches!(err, CoreError::ForbiddenResolvedIp { .. }),
                "expected ForbiddenResolvedIp for {bad_ip}, got {err:?}"
            );
        }

        // Explicitly allowing local in test config permits loopback but still blocks metadata.
        let mut local_resolver = StaticDnsResolver::new();
        local_resolver.insert_ips("rebind.evil.test", vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);
        assert!(resolve_allowlisted_hosts_with(
            &spec,
            &local_resolver,
            DnsResolveOptions::allow_local_for_testing()
        )
        .is_ok());
    }

    #[test]
    fn non_egress_modes_resolve_zero_hosts() {
        let spec = SandboxSpec::base(); // Loopback mode
        let resolver = StaticDnsResolver::new();
        let pinned =
            resolve_allowlisted_hosts_with(&spec, &resolver, DnsResolveOptions::strict()).unwrap();
        assert!(pinned.is_empty());
    }
}
