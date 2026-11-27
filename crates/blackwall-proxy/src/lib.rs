//! Per-VM rootless Pingora HTTP/1.1 & HTTP/2 TLS MITM proxy, sibling PostgreSQL
//! `SCRAM-SHA-256` wire proxy, Port 1000 stream demultiplexer, and Linux jail helpers.

pub mod ca;
pub mod error;
pub mod http_proxy;
pub mod jail;
pub mod mux;
pub mod postgres_proxy;
pub mod secrets;

pub use ca::EphemeralCa;
pub use error::{ProxyError, Result};
pub use http_proxy::{
    apply_auth_rewrite, build_pingora_http_service, evaluate_http_request, BlackwallHttpProxy,
    HttpProxyConfig, PinnedHostMap, PolicyDecision, PolicyRejection, STRIPPED_AUTH_HEADERS,
};
pub use jail::{
    generate_nftables_rules, generate_nftables_rules_with_local_loopback, ProxyBootstrapConfig,
    ProxyBootstrapSecret, ProxyJailConfig, ProxyReadyAck,
};
#[cfg(target_os = "linux")]
pub use jail::{
    build_proxy_seccomp_filter, clear_cloexec, create_pipe_pair, drop_all_capabilities,
    get_dumpable, kill_process_group, recv_fds_over_unix, send_fds_over_unix,
    set_new_process_group, unix_peer_pid,
};
pub use mux::{Port1000Muxer, PostgresRouteTarget, SyntheticDnsTable};
pub use postgres_proxy::{PostgresProxyConfig, PostgresProxyServer};
pub use secrets::{constant_time_str_eq, InMemorySecretResolver, SecretResolver};
