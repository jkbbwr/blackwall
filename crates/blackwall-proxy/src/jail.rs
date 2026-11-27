//! Rootless per-VM jail setup, `nftables` egress IP-pinning ruleset generation,
//! `pasta` bridge arguments, Landlock filesystem lockdown, and `seccomp-bpf` filter.
//!
//! Enforces Scenario D of `docs/THREAT_MODEL.md`:
//! - Out-of-process DNS resolves allowlisted FQDNs before jail lockdown.
//! - `nftables` inside the proxy's `CLONE_NEWUSER + CLONE_NEWNET` drops ALL outbound traffic
//!   by default (explicitly blocking `127.0.0.0/8`, `169.254.169.254`, RFC1918, link-local,
//!   and arbitrary public IPs) and permits ONLY `tcp dport <port> ip daddr <ip> accept`
//!   (and IPv6 equivalents) for the exact pinned endpoints.
//! - Before running Pingora/Postgres proxy code, the process sets `PR_SET_DUMPABLE=0`,
//!   `PR_SET_NO_NEW_PRIVS=1`, applies Landlock zero-fs access, and installs a `seccomp-bpf`
//!   filter explicitly blocking `SYS_unshare`, `SYS_setns`, `SYS_mount`, `SYS_ptrace`, and
//!   `socket(AF_NETLINK, ...)` so a compromised proxy CANNOT modify its own `nftables`.

use crate::error::{ProxyError, Result};
use crate::http_proxy::PinnedHostMap;
use blackwall_policy::{HttpRule, PostgresRule};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

mod zeroizing_string_serde {
    use serde::{Deserialize, Deserializer, Serializer};
    use zeroize::Zeroizing;

    pub fn serialize<S: Serializer>(val: &Zeroizing<String>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(val.as_str())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Zeroizing<String>, D::Error> {
        let raw = String::deserialize(d)?;
        Ok(Zeroizing::new(raw))
    }
}

/// Secret entry handed from `blackwall-core` to a dedicated jailed `blackwall-proxy`
/// child over an anonymous in-memory pipe (NEVER written to host disk).
#[derive(Clone, Serialize, Deserialize)]
pub struct ProxyBootstrapSecret {
    pub name: String,
    pub placeholder: String,
    #[serde(with = "zeroizing_string_serde")]
    pub value: Zeroizing<String>,
}

impl fmt::Debug for ProxyBootstrapSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyBootstrapSecret")
            .field("name", &self.name)
            .field("placeholder", &self.placeholder)
            .field("value", &"<redacted>")
            .finish()
    }
}

/// Complete per-VM bootstrap payload sent once over an anonymous memory pipe (`config_rx_fd`)
/// from `blackwall-core` to the jailed `blackwall-proxy` child process before jail lockdown.
#[derive(Clone, Serialize, Deserialize)]
pub struct ProxyBootstrapConfig {
    pub sandbox_id: String,
    #[serde(default)]
    pub http_rules: Vec<HttpRule>,
    #[serde(default)]
    pub postgres_rules: Vec<PostgresRule>,
    #[serde(default)]
    pub pinned_hosts: PinnedHostMap,
    pub ca_cert_pem: String,
    #[serde(with = "zeroizing_string_serde")]
    pub ca_key_pem: Zeroizing<String>,
    #[serde(default)]
    pub secrets: Vec<ProxyBootstrapSecret>,
    #[serde(default = "default_true")]
    pub upstream_tls: bool,
    #[serde(default = "default_true")]
    pub verify_upstream_cert: bool,
}

impl fmt::Debug for ProxyBootstrapConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyBootstrapConfig")
            .field("sandbox_id", &self.sandbox_id)
            .field("http_rules", &self.http_rules.len())
            .field("postgres_rules", &self.postgres_rules.len())
            .field("pinned_hosts", &self.pinned_hosts.len())
            .field("secrets", &self.secrets.len())
            .field("ca_key_pem", &"<redacted>")
            .field("upstream_tls", &self.upstream_tls)
            .field("verify_upstream_cert", &self.verify_upstream_cert)
            .finish()
    }
}

/// Readiness acknowledgement sent by the jailed `blackwall-proxy` child back to its parent
/// immediately after `nftables`, capability drop, Landlock, `seccomp-bpf`, and Pingora
/// listener startup have all completed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyReadyAck {
    pub ok: bool,
    #[serde(default)]
    pub http_listen_addr: Option<String>,
    #[serde(default)]
    pub dumpable: Option<i32>,
    #[serde(default)]
    pub error: Option<String>,
}

/// Generate a strict fail-closed `nftables` ruleset for a per-VM `blackwall-proxy` netns.
///
/// Explicitly blocks loopback (`127.0.0.0/8`, `::1`), cloud metadata & link-local
/// (`169.254.0.0/16` including `169.254.169.254`, `fe80::/10`), and private RFC1918/ULA
/// ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`), and allows
/// ONLY exact `tcp dport <port> ip[6] daddr <ip> accept` rules for `pinned_endpoints`.
pub fn generate_nftables_rules(pinned_endpoints: &[SocketAddr]) -> String {
    generate_nftables_rules_with_local_loopback(pinned_endpoints, None)
}

/// Generate the fail-closed `nftables` ruleset for a per-VM `blackwall-proxy` netns,
/// optionally permitting ONLY the single internal `lo` hop (`127.0.0.1:<pingora_local_port>`)
/// used by `Port1000Muxer -> Pingora` inside the child's isolated network namespace.
pub fn generate_nftables_rules_with_local_loopback(
    pinned_endpoints: &[SocketAddr],
    pingora_local_port: Option<u16>,
) -> String {
    let mut v4_rules: BTreeSet<(std::net::Ipv4Addr, u16)> = BTreeSet::new();
    let mut v6_rules: BTreeSet<(std::net::Ipv6Addr, u16)> = BTreeSet::new();

    for ep in pinned_endpoints {
        match ep.ip() {
            IpAddr::V4(ip) => {
                v4_rules.insert((ip, ep.port()));
            }
            IpAddr::V6(ip) => {
                v6_rules.insert((ip, ep.port()));
            }
        }
    }

    let mut out = String::new();
    out.push_str("flush ruleset\n");
    out.push_str("table inet blackwall_proxy {\n");
    out.push_str("    chain input {\n");
    out.push_str("        type filter hook input priority 0; policy drop;\n");
    out.push_str("        ct state established,related accept\n");
    if let Some(port) = pingora_local_port {
        out.push_str(&format!(
            "        iifname \"lo\" tcp dport {port} ip daddr 127.0.0.1 accept\n"
        ));
    }
    out.push_str("    }\n");
    out.push_str("    chain forward {\n");
    out.push_str("        type filter hook forward priority 0; policy drop;\n");
    out.push_str("    }\n");
    out.push_str("    chain output {\n");
    out.push_str("        type filter hook output priority 0; policy drop;\n");
    out.push_str("        ct state established,related accept\n");
    if let Some(port) = pingora_local_port {
        out.push_str(&format!(
            "        oifname \"lo\" tcp dport {port} ip daddr 127.0.0.1 accept\n"
        ));
    }
    // Hard-block all other loopback, metadata (169.254.169.254), link-local, and RFC1918 / ULA.
    out.push_str("        ip daddr 127.0.0.0/8 drop\n");
    out.push_str("        ip daddr 169.254.169.254/32 drop\n");
    out.push_str("        ip daddr 169.254.0.0/16 drop\n");
    out.push_str("        ip daddr 10.0.0.0/8 drop\n");
    out.push_str("        ip daddr 172.16.0.0/12 drop\n");
    out.push_str("        ip daddr 192.168.0.0/16 drop\n");
    out.push_str("        ip6 daddr ::1/128 drop\n");
    out.push_str("        ip6 daddr fe80::/10 drop\n");
    out.push_str("        ip6 daddr fc00::/7 drop\n");

    for (ip, port) in v4_rules {
        out.push_str(&format!("        tcp dport {port} ip daddr {ip} accept\n"));
    }
    for (ip, port) in v6_rules {
        out.push_str(&format!("        tcp dport {port} ip6 daddr {ip} accept\n"));
    }

    out.push_str("    }\n");
    out.push_str("}\n");
    out
}

/// Configuration for launching and locking down a rootless per-VM `blackwall-proxy` jail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyJailConfig {
    pub sandbox_id: String,
    pub pinned_endpoints: Vec<SocketAddr>,
    #[serde(default = "default_pasta_bin")]
    pub pasta_binary: PathBuf,
    #[serde(default = "default_nft_bin")]
    pub nft_binary: PathBuf,
    #[serde(default = "default_true")]
    pub enable_namespaces: bool,
    #[serde(default = "default_true")]
    pub enable_nftables: bool,
    #[serde(default = "default_true")]
    pub enable_landlock: bool,
    #[serde(default = "default_true")]
    pub enable_seccomp: bool,
}

fn default_pasta_bin() -> PathBuf {
    PathBuf::from("pasta")
}

fn default_nft_bin() -> PathBuf {
    PathBuf::from("nft")
}

fn default_true() -> bool {
    true
}

impl ProxyJailConfig {
    pub fn new(sandbox_id: impl Into<String>, pinned_endpoints: Vec<SocketAddr>) -> Self {
        Self {
            sandbox_id: sandbox_id.into(),
            pinned_endpoints,
            pasta_binary: default_pasta_bin(),
            nft_binary: default_nft_bin(),
            enable_namespaces: true,
            enable_nftables: true,
            enable_landlock: true,
            enable_seccomp: true,
        }
    }

    /// Generate the `nftables` ruleset for this jail's pinned endpoints.
    pub fn nftables_ruleset(&self) -> String {
        generate_nftables_rules(&self.pinned_endpoints)
    }

    /// Generate the `nftables` ruleset permitting the single internal loopback hop
    /// (`127.0.0.1:<pingora_local_port>`) inside the child proxy's isolated netns.
    pub fn nftables_ruleset_with_local_loopback(&self, pingora_local_port: Option<u16>) -> String {
        generate_nftables_rules_with_local_loopback(&self.pinned_endpoints, pingora_local_port)
    }

    /// Build rootless `pasta` CLI arguments to bridge the target proxy PID's `CLONE_NEWNET`
    /// without host gateway mapping (`--no-map-gw`) and with no inbound port forwarding.
    pub fn pasta_args(&self, proxy_pid: u32) -> Vec<String> {
        vec![
            "--config-net".into(),
            "--no-map-gw".into(),
            "--no-dhcp".into(),
            "--no-dhcpv6".into(),
            "--no-ndp".into(),
            "--no-ra".into(),
            "--quiet".into(),
            proxy_pid.to_string(),
        ]
    }

    /// Build rootless `pasta` CLI arguments to spawn `proxy_bin` inside a fresh
    /// `userns + netns + pidns` with `--no-map-gw`, no inbound/outbound port forwarding,
    /// and no DHCP/NDP/RA daemons.
    pub fn pasta_spawn_args(&self, proxy_bin: &Path, proxy_args: &[String]) -> Vec<String> {
        let mut args = vec![
            "--config-net".into(),
            "--no-map-gw".into(),
            "--no-dhcp".into(),
            "--no-dhcpv6".into(),
            "--no-ndp".into(),
            "--no-ra".into(),
            "-t".into(),
            "none".into(),
            "-u".into(),
            "none".into(),
            "-T".into(),
            "none".into(),
            "-U".into(),
            "none".into(),
            "--quiet".into(),
            "--".into(),
            proxy_bin.to_string_lossy().into_owned(),
        ];
        args.extend(proxy_args.iter().cloned());
        args
    }

    /// Pipe the fail-closed `nftables` ruleset (with optional single internal loopback hop
    /// for `Port1000Muxer -> Pingora`) into `nft -f -` inside the current `netns`.
    #[cfg(target_os = "linux")]
    pub fn apply_nftables_rules(&self, pingora_local_port: Option<u16>) -> Result<()> {
        use std::io::Write;
        use std::process::{Command, Stdio};

        if !self.enable_nftables {
            return Ok(());
        }

        let ruleset = self.nftables_ruleset_with_local_loopback(pingora_local_port);
        let mut child = Command::new(&self.nft_binary)
            .args(["-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| {
                ProxyError::Jail(format!(
                    "failed to spawn {} -f -: {e}",
                    self.nft_binary.display()
                ))
            })?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(ruleset.as_bytes()).map_err(|e| {
                ProxyError::Jail(format!("failed to pipe ruleset into nft: {e}"))
            })?;
        }

        let output = child
            .wait_with_output()
            .map_err(|e| ProxyError::Jail(format!("failed waiting on nft: {e}")))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(ProxyError::Jail(format!(
                "nft -f - exited with {}: {}",
                output.status,
                stderr.trim()
            )));
        }

        Ok(())
    }

    /// Setup rootless `CLONE_NEWUSER + CLONE_NEWNET` namespaces, write UID/GID mappings,
    /// and install `nftables` rules via `nft -f -`.
    ///
    /// Must be called **before** [`Self::apply_pre_exec_lockdown`] drops capabilities and
    /// blocks `AF_NETLINK` / `unshare` / `setns`.
    #[cfg(target_os = "linux")]
    pub fn setup_rootless_netns_and_nftables(&self) -> Result<()> {
        self.setup_rootless_netns_and_nftables_with_loopback(None)
    }

    /// Variant of [`Self::setup_rootless_netns_and_nftables`] allowing the internal
    /// `lo` hop `127.0.0.1:<pingora_local_port>`.
    #[cfg(target_os = "linux")]
    pub fn setup_rootless_netns_and_nftables_with_loopback(
        &self,
        pingora_local_port: Option<u16>,
    ) -> Result<()> {
        if self.enable_namespaces {
            let uid = unsafe { libc::getuid() };
            let gid = unsafe { libc::getgid() };

            let rc = unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET) };
            if rc != 0 {
                return Err(ProxyError::Jail(format!(
                    "unshare(CLONE_NEWUSER | CLONE_NEWNET) failed: {}",
                    std::io::Error::last_os_error()
                )));
            }

            // Disable setgroups before writing gid_map (kernel requirement in rootless userns)
            std::fs::write("/proc/self/setgroups", "deny\n").map_err(|e| {
                ProxyError::Jail(format!("failed to write /proc/self/setgroups: {e}"))
            })?;
            std::fs::write("/proc/self/uid_map", format!("0 {uid} 1\n")).map_err(|e| {
                ProxyError::Jail(format!("failed to write /proc/self/uid_map: {e}"))
            })?;
            std::fs::write("/proc/self/gid_map", format!("0 {gid} 1\n")).map_err(|e| {
                ProxyError::Jail(format!("failed to write /proc/self/gid_map: {e}"))
            })?;
        }

        self.apply_nftables_rules(pingora_local_port)
    }

    /// Apply irrevocable process-level lockdown before handling untrusted guest bytes:
    /// 1. Drop ALL Linux capabilities (bounding + ambient + `capset` v3 effective/permitted/inheritable = 0)
    /// 2. `PR_SET_DUMPABLE = 0` (blocks ptrace / `/proc/pid/mem` inspection & core dumps)
    /// 3. `PR_SET_NO_NEW_PRIVS = 1` (prevents privilege gain on any subsequent exec)
    /// 4. Landlock filesystem lockdown (denies all host filesystem access)
    /// 5. `seccomp-bpf` filter blocking `SYS_unshare`, `SYS_setns`, `SYS_mount`,
    ///    `SYS_ptrace`, and `socket(AF_NETLINK, ...)` so compromised proxy code cannot
    ///    modify its own `nftables` or escape its namespaces.
    ///
    /// IMPORTANT: Call while the process is **single-threaded** (before creating the Tokio
    /// runtime) so capabilities, `PR_SET_NO_NEW_PRIVS`, and Landlock are inherited by EVERY
    /// worker thread!
    #[cfg(target_os = "linux")]
    pub fn apply_pre_exec_lockdown(&self) -> Result<()> {
        // 1. Drop all Linux capabilities (including CAP_NET_ADMIN inside userns!).
        drop_all_capabilities()?;

        // 2. PR_SET_DUMPABLE = 0
        let rc = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
        if rc != 0 {
            return Err(ProxyError::Jail(format!(
                "prctl(PR_SET_DUMPABLE, 0) failed: {}",
                std::io::Error::last_os_error()
            )));
        }

        // 3. PR_SET_NO_NEW_PRIVS = 1
        let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if rc != 0 {
            return Err(ProxyError::Jail(format!(
                "prctl(PR_SET_NO_NEW_PRIVS, 1) failed: {}",
                std::io::Error::last_os_error()
            )));
        }

        // 4. Landlock zero-fs access restriction
        if self.enable_landlock {
            apply_landlock_zero_fs()?;
        }

        // 5. seccomp-bpf filter across all threads
        if self.enable_seccomp {
            let bpf = build_proxy_seccomp_filter()?;
            seccompiler::apply_filter_all_threads(&bpf).map_err(|e| {
                ProxyError::Jail(format!("seccompiler::apply_filter_all_threads failed: {e}"))
            })?;
        }

        Ok(())
    }
}

/// Drop ALL Linux capabilities (bounding set, ambient set, and `capset` version 3
/// effective/permitted/inheritable masks all cleared to 0).
#[cfg(target_os = "linux")]
pub fn drop_all_capabilities() -> Result<()> {
    #[repr(C)]
    struct CapUserHeader {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct CapUserData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

    // Best-effort drop bounding set while CAP_SETPCAP may still be held inside userns.
    for cap in 0u64..=63 {
        let _ = unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) };
    }
    // Clear ambient capabilities.
    let _ = unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        )
    };

    let mut hdr = CapUserHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data = [CapUserData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];

    let rc = unsafe {
        libc::syscall(
            libc::SYS_capset,
            &mut hdr as *mut CapUserHeader,
            data.as_mut_ptr(),
        )
    };
    if rc != 0 {
        return Err(ProxyError::Jail(format!(
            "capset(LINUX_CAPABILITY_VERSION_3, all=0) failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

/// Query `PR_GET_DUMPABLE` for the current process (`0` = non-dumpable).
#[cfg(target_os = "linux")]
pub fn get_dumpable() -> i32 {
    unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) }
}

/// Create an anonymous pipe pair `(read_end, write_end)` with `O_CLOEXEC` set.
#[cfg(target_os = "linux")]
pub fn create_pipe_pair() -> Result<(std::os::fd::OwnedFd, std::os::fd::OwnedFd)> {
    use std::os::fd::{FromRawFd, OwnedFd};
    let mut fds = [-1i32; 2];
    let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    if rc != 0 {
        return Err(ProxyError::Jail(format!(
            "pipe2(O_CLOEXEC) failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    let rx = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    let tx = unsafe { OwnedFd::from_raw_fd(fds[1]) };
    Ok((rx, tx))
}

/// Clear `FD_CLOEXEC` on `fd` (for direct exec inheritance without an intermediate launcher).
#[cfg(target_os = "linux")]
pub fn clear_cloexec(fd: std::os::fd::RawFd) -> Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(ProxyError::Jail(format!(
            "fcntl(F_GETFD) failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) };
    if rc < 0 {
        return Err(ProxyError::Jail(format!(
            "fcntl(F_SETFD) failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

/// Send `fds` across a connected Unix domain socket using `SCM_RIGHTS`.
#[cfg(target_os = "linux")]
pub fn send_fds_over_unix(
    sock: &std::os::unix::net::UnixStream,
    fds: &[std::os::fd::RawFd],
) -> Result<()> {
    use std::os::fd::AsRawFd;

    let mut marker: [u8; 1] = [0x42];
    let mut iov = libc::iovec {
        iov_base: marker.as_mut_ptr().cast(),
        iov_len: marker.len(),
    };

    let fds_bytes = std::mem::size_of_val(fds);
    let cmsg_space = unsafe { libc::CMSG_SPACE(fds_bytes as u32) } as usize;
    let mut cmsg_buf = vec![0u8; cmsg_space];

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr().cast();
    msg.msg_controllen = cmsg_space as _;

    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() {
            return Err(ProxyError::Jail("CMSG_FIRSTHDR returned null".into()));
        }
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(fds_bytes as u32) as _;
        std::ptr::copy_nonoverlapping(fds.as_ptr().cast::<u8>(), libc::CMSG_DATA(cmsg), fds_bytes);
    }

    loop {
        let rc = unsafe { libc::sendmsg(sock.as_raw_fd(), &msg, libc::MSG_NOSIGNAL) };
        if rc >= 0 {
            return Ok(());
        }
        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        return Err(ProxyError::Jail(format!(
            "sendmsg(SCM_RIGHTS) failed: {err}"
        )));
    }
}

/// Receive exactly `expected` file descriptors sent via `SCM_RIGHTS` over a Unix domain socket.
#[cfg(target_os = "linux")]
pub fn recv_fds_over_unix(
    sock: &std::os::unix::net::UnixStream,
    expected: usize,
) -> Result<Vec<std::os::fd::OwnedFd>> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

    let mut marker: [u8; 1] = [0];
    let mut iov = libc::iovec {
        iov_base: marker.as_mut_ptr().cast(),
        iov_len: marker.len(),
    };

    let fds_bytes = expected * std::mem::size_of::<RawFd>();
    let cmsg_space = unsafe { libc::CMSG_SPACE(fds_bytes as u32) } as usize;
    let mut cmsg_buf = vec![0u8; cmsg_space];

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr().cast();
    msg.msg_controllen = cmsg_space as _;

    let rc = loop {
        let n = unsafe { libc::recvmsg(sock.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC) };
        if n >= 0 {
            break n;
        }
        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        return Err(ProxyError::Jail(format!(
            "recvmsg(SCM_RIGHTS) failed: {err}"
        )));
    };

    if rc == 0 {
        return Err(ProxyError::Jail(
            "bootstrap Unix socket closed before SCM_RIGHTS fds arrived".into(),
        ));
    }
    if (msg.msg_flags & libc::MSG_CTRUNC) != 0 {
        return Err(ProxyError::Jail(
            "SCM_RIGHTS control message was truncated".into(),
        ));
    }

    let mut received: Vec<OwnedFd> = Vec::with_capacity(expected);
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                let header_len = libc::CMSG_LEN(0) as usize;
                let total_len = (*cmsg).cmsg_len as usize;
                if total_len >= header_len {
                    let data_len = total_len - header_len;
                    let count = data_len / std::mem::size_of::<RawFd>();
                    let data_ptr = libc::CMSG_DATA(cmsg);
                    for i in 0..count {
                        let fd = std::ptr::read_unaligned(
                            data_ptr
                                .add(i * std::mem::size_of::<RawFd>())
                                .cast::<RawFd>(),
                        );
                        received.push(OwnedFd::from_raw_fd(fd));
                    }
                }
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }

    if received.len() != expected {
        return Err(ProxyError::Jail(format!(
            "expected {expected} SCM_RIGHTS fds, received {}",
            received.len()
        )));
    }
    Ok(received)
}

/// Read the host-namespace PID of the peer connected to a Unix domain socket via `SO_PEERCRED`.
#[cfg(target_os = "linux")]
pub fn unix_peer_pid(sock: &std::os::unix::net::UnixStream) -> Result<u32> {
    use std::os::fd::AsRawFd;

    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(ProxyError::Jail(format!(
            "getsockopt(SO_PEERCRED) failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    if cred.pid <= 0 {
        return Err(ProxyError::Jail(format!(
            "invalid SO_PEERCRED pid: {}",
            cred.pid
        )));
    }
    Ok(cred.pid as u32)
}

/// Place the current child process into its own process group (`setpgid(0, 0)`)
/// so the parent can atomically `SIGKILL` both `pasta` and `blackwall-proxy`.
#[cfg(target_os = "linux")]
pub fn set_new_process_group() -> std::io::Result<()> {
    let rc = unsafe { libc::setpgid(0, 0) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Send `SIGKILL` to an entire process group (`-pgid`) and optionally an explicit child PID.
#[cfg(target_os = "linux")]
pub fn kill_process_group(pgid: u32, extra_pid: Option<u32>) {
    if pgid > 0 {
        let p = pgid as libc::pid_t;
        unsafe {
            libc::kill(-p, libc::SIGKILL);
            libc::kill(p, libc::SIGKILL);
        }
    }
    if let Some(pid) = extra_pid {
        if pid > 0 && pid != pgid {
            unsafe {
                libc::kill(pid as libc::pid_t, libc::SIGKILL);
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn apply_landlock_zero_fs() -> Result<()> {
    use landlock::{Access, AccessFs, Ruleset, RulesetAttr, ABI};

    let status = Ruleset::default()
        .handle_access(AccessFs::from_all(ABI::V1))
        .map_err(|e| ProxyError::Jail(format!("landlock handle_access failed: {e}")))?
        .create()
        .map_err(|e| ProxyError::Jail(format!("landlock create failed: {e}")))?
        .restrict_self()
        .map_err(|e| ProxyError::Jail(format!("landlock restrict_self failed: {e}")))?;

    tracing::debug!(?status.ruleset, "Landlock zero-fs restriction applied to blackwall-proxy");
    Ok(())
}

/// Build the `seccompiler` BPF filter for `blackwall-proxy`.
///
/// Explicitly returns `EPERM` on:
/// - `SYS_unshare`, `SYS_setns` (cannot enter or create new netns/userns)
/// - `SYS_mount`, `SYS_umount2`, `SYS_pivot_root` (cannot alter mount tree)
/// - `SYS_ptrace`, `SYS_process_vm_readv`, `SYS_process_vm_writev` (cannot inspect peers)
/// - `SYS_bpf`, `SYS_io_uring_setup`, `SYS_init_module`, `SYS_finit_module`, `SYS_kexec_load`
/// - `socket(AF_NETLINK, ...)` and `socket(AF_PACKET, ...)` (cannot talk to netfilter/nftables!)
#[cfg(target_os = "linux")]
pub fn build_proxy_seccomp_filter() -> Result<seccompiler::BpfProgram> {
    use seccompiler::{
        BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition,
        SeccompFilter, SeccompRule, TargetArch,
    };
    use std::collections::BTreeMap;

    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();

    // Unconditionally blocked syscalls (empty rule vec matches all calls to that syscall).
    for &nr in &[
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_bpf,
        libc::SYS_kexec_load,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_perf_event_open,
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
    ] {
        rules.insert(nr, vec![]);
    }

    // Block socket(AF_NETLINK, ...) and socket(AF_PACKET, ...) so compromised Pingora
    // cannot send netlink commands to modify or flush its own nftables ruleset.
    let netlink_rule = SeccompRule::new(vec![SeccompCondition::new(
        0,
        SeccompCmpArgLen::Dword,
        SeccompCmpOp::Eq,
        libc::AF_NETLINK as u64,
    )
    .map_err(|e| ProxyError::Jail(format!("seccomp AF_NETLINK cond error: {e}")))?])
    .map_err(|e| ProxyError::Jail(format!("seccomp AF_NETLINK rule error: {e}")))?;

    let packet_rule = SeccompRule::new(vec![SeccompCondition::new(
        0,
        SeccompCmpArgLen::Dword,
        SeccompCmpOp::Eq,
        libc::AF_PACKET as u64,
    )
    .map_err(|e| ProxyError::Jail(format!("seccomp AF_PACKET cond error: {e}")))?])
    .map_err(|e| ProxyError::Jail(format!("seccomp AF_PACKET rule error: {e}")))?;

    rules.insert(libc::SYS_socket, vec![netlink_rule, packet_rule]);

    let arch: TargetArch = std::env::consts::ARCH
        .try_into()
        .map_err(|e| ProxyError::Jail(format!("unsupported seccomp target arch: {e}")))?;

    let filter = SeccompFilter::new(
        rules,
        // Default action for non-matching syscalls: Allow
        SeccompAction::Allow,
        // Match action for blocked syscalls: EPERM
        SeccompAction::Errno(libc::EPERM as u32),
        arch,
    )
    .map_err(|e| ProxyError::Jail(format!("SeccompFilter::new failed: {e}")))?;

    let bpf: BpfProgram = filter
        .try_into()
        .map_err(|e| ProxyError::Jail(format!("seccomp BPF compilation failed: {e}")))?;

    Ok(bpf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn nftables_ruleset_blocks_internal_ranges_and_allows_only_pinned_endpoints() {
        let endpoints = vec![
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(140, 82, 121, 6)), 443),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(140, 82, 121, 6)), 443), // duplicate deduped
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(104, 18, 32, 7)), 5432),
            SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 1)),
                443,
            ),
        ];

        let rules = generate_nftables_rules(&endpoints);
        assert!(rules.contains("table inet blackwall_proxy"));
        assert!(rules.contains("policy drop;"));
        assert!(rules.contains("ip daddr 127.0.0.0/8 drop"));
        assert!(rules.contains("ip daddr 169.254.169.254/32 drop"));
        assert!(rules.contains("ip daddr 169.254.0.0/16 drop"));
        assert!(rules.contains("ip daddr 10.0.0.0/8 drop"));
        assert!(rules.contains("ip daddr 172.16.0.0/12 drop"));
        assert!(rules.contains("ip daddr 192.168.0.0/16 drop"));
        assert!(rules.contains("ip6 daddr ::1/128 drop"));
        assert!(rules.contains("ip6 daddr fe80::/10 drop"));
        assert!(rules.contains("ip6 daddr fc00::/7 drop"));

        assert!(rules.contains("tcp dport 443 ip daddr 140.82.121.6 accept"));
        assert!(rules.contains("tcp dport 5432 ip daddr 104.18.32.7 accept"));
        assert!(rules.contains("tcp dport 443 ip6 daddr 2606:4700::1 accept"));

        // Deduplicated
        assert_eq!(
            rules.matches("tcp dport 443 ip daddr 140.82.121.6 accept").count(),
            1
        );

        let cfg = ProxyJailConfig::new("sb-jail", endpoints);
        let pasta = cfg.pasta_args(12345);
        assert!(pasta.contains(&"--no-map-gw".to_string()));
        assert_eq!(pasta.last().map(String::as_str), Some("12345"));

        // Variant with internal Pingora loopback port permits ONLY that exact 127.0.0.1:<port> hop
        // before dropping all other 127.0.0.0/8 traffic.
        let rules_lo = generate_nftables_rules_with_local_loopback(&cfg.pinned_endpoints, Some(18443));
        assert!(rules_lo.contains("iifname \"lo\" tcp dport 18443 ip daddr 127.0.0.1 accept"));
        assert!(rules_lo.contains("oifname \"lo\" tcp dport 18443 ip daddr 127.0.0.1 accept"));
        let allow_pos = rules_lo
            .find("oifname \"lo\" tcp dport 18443 ip daddr 127.0.0.1 accept")
            .unwrap();
        let drop_pos = rules_lo.find("ip daddr 127.0.0.0/8 drop").unwrap();
        assert!(
            allow_pos < drop_pos,
            "single Pingora loopback accept must precede 127.0.0.0/8 drop"
        );

        // ProxyBootstrapConfig Debug never leaks secrets or CA key PEM.
        let boot = ProxyBootstrapConfig {
            sandbox_id: "sb-redact".into(),
            http_rules: vec![],
            postgres_rules: vec![],
            pinned_hosts: PinnedHostMap::new(),
            ca_cert_pem: "CERT".into(),
            ca_key_pem: Zeroizing::new("SUPER_SECRET_CA_KEY_MATERIAL".into()),
            secrets: vec![ProxyBootstrapSecret {
                name: "TOKEN".into(),
                placeholder: "ph_123".into(),
                value: Zeroizing::new("REAL_SECRET_VALUE_999".into()),
            }],
            upstream_tls: true,
            verify_upstream_cert: true,
        };
        let dbg = format!("{boot:?}");
        assert!(!dbg.contains("SUPER_SECRET_CA_KEY_MATERIAL"));
        assert!(!dbg.contains("REAL_SECRET_VALUE_999"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn seccomp_filter_compiles_and_denies_unshare_setns_and_netlink() {
        let bpf = build_proxy_seccomp_filter().expect("seccomp BPF must compile");
        assert!(!bpf.is_empty());

        // Verify the compiled BPF instructions explicitly reference SYS_unshare,
        // SYS_setns, SYS_mount, SYS_ptrace, SYS_socket, and AF_NETLINK.
        let k_values: Vec<u32> = bpf.iter().map(|ins| ins.k).collect();
        assert!(k_values.contains(&(libc::SYS_unshare as u32)));
        assert!(k_values.contains(&(libc::SYS_setns as u32)));
        assert!(k_values.contains(&(libc::SYS_mount as u32)));
        assert!(k_values.contains(&(libc::SYS_ptrace as u32)));
        assert!(k_values.contains(&(libc::SYS_socket as u32)));
        assert!(k_values.contains(&(libc::AF_NETLINK as u32)));

        // Fork a short-lived child process to prove the kernel actually enforces EPERM
        // on unshare(), setns(), and socket(AF_NETLINK, ...) once the BPF is installed!
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
            if rc != 0 {
                unsafe { libc::_exit(10) };
            }
            if seccompiler::apply_filter(&bpf).is_err() {
                unsafe { libc::_exit(11) };
            }

            // 1. unshare(CLONE_NEWNET) must fail with EPERM
            let u_rc = unsafe { libc::unshare(libc::CLONE_NEWNET) };
            let u_err = std::io::Error::last_os_error().raw_os_error();
            if u_rc != -1 || u_err != Some(libc::EPERM) {
                unsafe { libc::_exit(12) };
            }

            // 2. setns(-1, 0) must fail with EPERM (intercepted before EBADF!)
            let s_rc = unsafe { libc::setns(-1, 0) };
            let s_err = std::io::Error::last_os_error().raw_os_error();
            if s_rc != -1 || s_err != Some(libc::EPERM) {
                unsafe { libc::_exit(13) };
            }

            // 3. socket(AF_NETLINK, SOCK_RAW, 0) must fail with EPERM
            let nl_rc = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, 0) };
            let nl_err = std::io::Error::last_os_error().raw_os_error();
            if nl_rc != -1 || nl_err != Some(libc::EPERM) {
                unsafe { libc::_exit(14) };
            }

            // 4. Normal TCP socket(AF_INET, SOCK_STREAM, 0) must still succeed!
            let tcp_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
            if tcp_fd < 0 {
                unsafe { libc::_exit(15) };
            }
            unsafe { libc::close(tcp_fd) };

            unsafe { libc::_exit(0) };
        } else {
            let mut status: libc::c_int = 0;
            let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
            assert_eq!(waited, pid);
            assert!(
                libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
                "child seccomp verification failed with status={status} exit={}",
                libc::WEXITSTATUS(status)
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn live_jailed_pasta_proxy_enforces_http_policy_secret_injection_and_audit_pipe() {
        use crate::ca::EphemeralCa;
        use blackwall_audit::{AuditEvent, AuditEventKind, AuditSink, MemoryAuditSink};
        use blackwall_policy::{AuthSpec, HttpRule};
        use blackwall_proto::{
            mux_flags, DnsQueryPayload, DnsRecordType, DnsResponsePayload, MuxFrame, MuxHeader,
            StreamOpenPayload, StreamType, MUX_HEADER_LEN,
        };
        use rustls::crypto::ring;
        use rustls::pki_types::ServerName;
        use rustls::ClientConfig;
        use std::io::{BufRead, BufReader, Write};
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::net::{UnixListener as StdUnixListener, UnixStream as StdUnixStream};
        use std::os::unix::process::CommandExt;
        use std::process::{Command, Stdio};
        use std::sync::Arc;
        use std::time::{Duration, Instant};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, UnixStream as TokioUnixStream};
        use tokio_rustls::TlsConnector;

        fn find_bin(name: &str) -> Option<PathBuf> {
            let path_var = std::env::var_os("PATH")?;
            for dir in std::env::split_paths(&path_var) {
                let p = dir.join(name);
                if p.is_file() {
                    return Some(p);
                }
            }
            None
        }

        let proxy_bin = std::env::var_os("BLACKWALL_PROXY_BIN")
            .map(PathBuf::from)
            .filter(|p| p.is_file())
            .or_else(|| {
                std::env::current_exe().ok().and_then(|exe| {
                    exe.ancestors()
                        .skip(1)
                        .take(5)
                        .map(|d| d.join("blackwall-proxy"))
                        .find(|p| p.is_file())
                })
            })
            .or_else(|| find_bin("blackwall-proxy"));
        let pasta_bin = find_bin("pasta");
        let nft_bin = find_bin("nft").or_else(|| {
            ["/usr/sbin/nft", "/sbin/nft"]
                .iter()
                .map(PathBuf::from)
                .find(|p| p.is_file())
        });

        let (Some(proxy_bin), Some(pasta_bin), Some(nft_bin)) = (proxy_bin, pasta_bin, nft_bin)
        else {
            eprintln!(
                "[live_jailed_pasta_proxy] SKIPPING: blackwall-proxy, pasta, or nft not found"
            );
            return;
        };

        // 1. Start a local upstream HTTP/1.1 server on host 127.0.0.1:0.
        //    We map RFC 5737 TEST-NET-2 (198.51.100.1) via pasta `--map-host-loopback` so the
        //    child runs the EXACT production nftables ruleset (dropping 127.0.0.0/8, metadata,
        //    and RFC1918 while permitting ONLY 198.51.100.1:<upstream_port> + internal lo hop)!
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_port = upstream_listener.local_addr().unwrap().port();
        let upstream_seen = Arc::new(std::sync::Mutex::new(String::new()));
        let upstream_seen_task = Arc::clone(&upstream_seen);
        let upstream_task = tokio::spawn(async move {
            if let Ok((mut conn, _)) = upstream_listener.accept().await {
                let mut req_buf = vec![0u8; 4096];
                let n = conn.read(&mut req_buf).await.unwrap_or(0);
                let req_str = String::from_utf8_lossy(&req_buf[..n]).to_string();
                *upstream_seen_task.lock().unwrap() = req_str;
                let resp = "HTTP/1.1 200 OK\r\nContent-Length: 14\r\nConnection: close\r\n\r\nJAILED_HTTP_OK";
                let _ = conn.write_all(resp.as_bytes()).await;
                let _ = conn.shutdown().await;
            }
        });

        // 2. Mint ephemeral CA, pipes, Port 1000 socketpair, and 0700 1-shot bootstrap UDS.
        let ca = Arc::new(EphemeralCa::generate("sb-jailed-e2e").unwrap());
        let (config_rx_fd, config_tx_fd) = create_pipe_pair().unwrap();
        let (audit_rx_fd, audit_tx_fd) = create_pipe_pair().unwrap();
        let (guest_mux_std, proxy_mux_std) = StdUnixStream::pair().unwrap();

        let boot_dir = std::env::temp_dir().join(format!(
            "bw-proxy-test-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&boot_dir).unwrap();
        std::fs::set_permissions(&boot_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let sock_path = boot_dir.join("bootstrap.sock");
        let boot_listener = StdUnixListener::bind(&sock_path).unwrap();
        std::fs::set_permissions(&sock_path, std::fs::Permissions::from_mode(0o600)).unwrap();

        // 3. Spawn REAL `pasta` + `blackwall-proxy --apply-nftables --apply-jail`!
        let mut cmd = Command::new(&pasta_bin);
        cmd.args([
            "--config-net",
            "--no-map-gw",
            "--no-dhcp",
            "--no-dhcpv6",
            "--no-ndp",
            "--no-ra",
            "-t",
            "none",
            "-u",
            "none",
            "-T",
            "none",
            "-U",
            "none",
            "--map-host-loopback",
            "198.51.100.1",
            "--quiet",
            "--",
        ])
        .arg(&proxy_bin)
        .args([
            "--bootstrap-uds",
            &sock_path.to_string_lossy(),
            "--nft-bin",
            &nft_bin.to_string_lossy(),
            "--apply-nftables",
            "--apply-jail",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
        unsafe {
            cmd.pre_exec(set_new_process_group);
        }

        let mut pasta_child = cmd.spawn().expect("pasta spawn must succeed");
        let pasta_pid = pasta_child.id();

        let (boot_stream, _) = boot_listener.accept().expect("child must connect to bootstrap UDS");
        drop(boot_listener);
        let _ = std::fs::remove_file(&sock_path);
        let _ = std::fs::remove_dir(&boot_dir);

        let proxy_pid = unix_peer_pid(&boot_stream).expect("SO_PEERCRED must return child pid");
        send_fds_over_unix(
            &boot_stream,
            &[
                config_rx_fd.as_raw_fd(),
                audit_tx_fd.as_raw_fd(),
                proxy_mux_std.as_raw_fd(),
            ],
        )
        .unwrap();
        drop(config_rx_fd);
        drop(audit_tx_fd);
        drop(proxy_mux_std);

        // 4. Write ProxyBootstrapConfig to anonymous memory pipe and close write end immediately.
        let mut pinned_hosts = PinnedHostMap::new();
        pinned_hosts.insert(
            "api.example.test".into(),
            vec![SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
                upstream_port,
            )],
        );
        let boot_cfg = ProxyBootstrapConfig {
            sandbox_id: "sb-jailed-e2e".into(),
            http_rules: vec![HttpRule {
                host: "api.example.test".into(),
                port: 443,
                methods: vec!["GET".into()],
                path_prefixes: vec!["/repos/".into()],
                max_request_bytes: None,
                auth: Some(AuthSpec::Bearer {
                    secret: "API_TOKEN".into(),
                }),
            }],
            postgres_rules: vec![],
            pinned_hosts,
            ca_cert_pem: ca.ca_cert_pem().to_string(),
            ca_key_pem: ca.ca_key_pem(),
            secrets: vec![ProxyBootstrapSecret {
                name: "API_TOKEN".into(),
                placeholder: "ghp_bw00_placeholder_token".into(),
                value: Zeroizing::new("ghp_REAL_PIPE_SECRET_999".into()),
            }],
            upstream_tls: false,
            verify_upstream_cert: false,
        };
        {
            let mut tx = std::fs::File::from(config_tx_fd);
            let payload = Zeroizing::new(serde_json::to_vec(&boot_cfg).unwrap());
            tx.write_all(&payload).unwrap();
            tx.flush().unwrap();
        }
        drop(boot_cfg);

        // 5. Start audit reader thread feeding MemoryAuditSink from `audit_rx_fd`.
        let audit_sink = Arc::new(MemoryAuditSink::new());
        let audit_sink_thread = Arc::clone(&audit_sink);
        let audit_thread = std::thread::spawn(move || {
            let reader = BufReader::new(std::fs::File::from(audit_rx_fd));
            for line in reader.lines().map_while(std::result::Result::ok) {
                if let Ok(ev) = serde_json::from_str::<AuditEvent>(&line) {
                    audit_sink_thread.record(ev);
                }
            }
        });

        // 6. Wait for ProxyReadyAck proving nftables + caps=0 + dumpable=0 + Landlock + seccomp + Pingora are live.
        let mut ack_line = String::new();
        BufReader::new(&boot_stream).read_line(&mut ack_line).unwrap();
        drop(boot_stream);
        let ack: ProxyReadyAck = serde_json::from_str(ack_line.trim())
            .unwrap_or_else(|e| panic!("bad ack ({e}): {ack_line:?}"));
        assert!(ack.ok, "jailed proxy failed startup: {:?}", ack.error);
        assert_eq!(ack.dumpable, Some(0), "PR_GET_DUMPABLE inside child must be 0");

        // 7. Verify kernel-enforced jail properties via `/proc/<proxy_pid>`.
        let status = std::fs::read_to_string(format!("/proc/{proxy_pid}/status")).unwrap();
        assert!(status.contains("CapEff:\t0000000000000000"), "status:\n{status}");
        assert!(status.contains("CapPrm:\t0000000000000000"), "status:\n{status}");
        assert!(status.contains("CapInh:\t0000000000000000"), "status:\n{status}");
        assert!(status.contains("NoNewPrivs:\t1"), "status:\n{status}");
        assert!(status.contains("Seccomp:\t2"), "status:\n{status}");
        assert_ne!(
            std::fs::read_link("/proc/self/ns/user").unwrap(),
            std::fs::read_link(format!("/proc/{proxy_pid}/ns/user")).unwrap()
        );
        assert_ne!(
            std::fs::read_link("/proc/self/ns/net").unwrap(),
            std::fs::read_link(format!("/proc/{proxy_pid}/ns/net")).unwrap()
        );

        // 8. Drive real Port 1000 DNS + TLS MITM HTTP requests over `guest_mux_std`!
        guest_mux_std.set_nonblocking(true).unwrap();
        let mut guest_mux = TokioUnixStream::from_std(guest_mux_std).unwrap();

        fn encode_mux_frame(frame: &MuxFrame) -> Vec<u8> {
            let mut out = Vec::with_capacity(MUX_HEADER_LEN + frame.payload.len());
            out.extend_from_slice(&frame.header.encode().unwrap());
            out.extend_from_slice(&frame.payload);
            out
        }

        // 8a. DNS query for allowlisted host -> synthetic 198.18.1.1
        let dns_q = DnsQueryPayload {
            query_id: 1,
            fqdn: "api.example.test".into(),
            record_type: DnsRecordType::A,
        };
        guest_mux
            .write_all(&encode_mux_frame(
                &MuxFrame::new(
                    1,
                    mux_flags::SYN | mux_flags::FIN,
                    StreamType::DnsQuery,
                    serde_json::to_vec(&dns_q).unwrap(),
                )
                .unwrap(),
            ))
            .await
            .unwrap();

        let mut hdr_buf = [0u8; MUX_HEADER_LEN];
        guest_mux.read_exact(&mut hdr_buf).await.unwrap();
        let hdr = MuxHeader::decode(&hdr_buf).unwrap();
        assert_eq!(hdr.stream_type, StreamType::DnsResponse);
        let mut body = vec![0u8; hdr.payload_len as usize];
        guest_mux.read_exact(&mut body).await.unwrap();
        let dns_resp: DnsResponsePayload = serde_json::from_slice(&body).unwrap();
        assert!(dns_resp.allowed);
        let synth_ip = dns_resp.synthetic_ip.unwrap();
        assert!(
            synth_ip.starts_with("198.18."),
            "expected RFC 2544 synthetic IP, got {synth_ip}"
        );

        // Helper to tunnel a single TLS 1.3 HTTP/1.1 request over Port 1000 mux stream_id.
        async fn send_mux_https_request(
            mux: &mut TokioUnixStream,
            ca: &EphemeralCa,
            stream_id: u32,
            dst_ip: &str,
            http_request: &str,
        ) -> String {
            let open = StreamOpenPayload {
                dst_ip: dst_ip.to_string(),
                dst_port: 443,
                hostname: Some("api.example.test".into()),
            };
            mux.write_all(&encode_mux_frame(
                &MuxFrame::new(
                    stream_id,
                    mux_flags::SYN,
                    StreamType::Tcp,
                    serde_json::to_vec(&open).unwrap(),
                )
                .unwrap(),
            ))
            .await
            .unwrap();

            // Bridge duplex <-> mux frames for this stream_id so TlsConnector can speak TLS over mux!
            let (client_side, mut bridge_side) = tokio::io::duplex(64 * 1024);
            let client_cfg = Arc::new(
                ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
                    .with_safe_default_protocol_versions()
                    .unwrap()
                    .with_root_certificates(ca.root_cert_store().unwrap())
                    .with_no_client_auth(),
            );
            let connector = TlsConnector::from(client_cfg);
            let req_bytes = http_request.as_bytes().to_vec();

            let tls_task = tokio::spawn(async move {
                let sni = ServerName::try_from("api.example.test".to_string()).unwrap();
                let mut tls = connector.connect(sni, client_side).await.unwrap();
                tls.write_all(&req_bytes).await.unwrap();
                let mut resp = Vec::new();
                let mut tmp = [0u8; 4096];
                loop {
                    match tls.read(&mut tmp).await {
                        Ok(0) => break,
                        Ok(n) => {
                            resp.extend_from_slice(&tmp[..n]);
                            if let Ok(s) = std::str::from_utf8(&resp) {
                                if s.contains("JAILED_HTTP_OK")
                                    || (s.starts_with("HTTP/1.1 403") && s.contains("\r\n\r\n"))
                                {
                                    break;
                                }
                            }
                        }
                        Err(_) => break,
                    }
                }
                String::from_utf8_lossy(&resp).to_string()
            });

            let mut bridge_buf = [0u8; 16 * 1024];
            let mut mux_hdr_buf = [0u8; MUX_HEADER_LEN];
            let mut tls_handle = tls_task;

            loop {
                tokio::select! {
                    res = &mut tls_handle => {
                        return res.unwrap();
                    }
                    n = bridge_side.read(&mut bridge_buf) => {
                        let n = n.unwrap_or(0);
                        if n == 0 {
                            let _ = mux.write_all(&encode_mux_frame(&MuxFrame::new(stream_id, mux_flags::FIN, StreamType::Tcp, Vec::new()).unwrap())).await;
                        } else {
                            mux.write_all(&encode_mux_frame(&MuxFrame::new(stream_id, mux_flags::DATA, StreamType::Tcp, bridge_buf[..n].to_vec()).unwrap())).await.unwrap();
                        }
                    }
                    r = mux.read_exact(&mut mux_hdr_buf) => {
                        if r.is_err() {
                            break;
                        }
                        let h = MuxHeader::decode(&mux_hdr_buf).unwrap();
                        let mut p = vec![0u8; h.payload_len as usize];
                        if !p.is_empty() {
                            mux.read_exact(&mut p).await.unwrap();
                        }
                        if h.stream_id == stream_id && !p.is_empty() {
                            let _ = bridge_side.write_all(&p).await;
                        }
                        if h.stream_id == stream_id && (h.flags & (mux_flags::FIN | mux_flags::RST)) != 0 {
                            let _ = bridge_side.shutdown().await;
                        }
                    }
                }
            }
            tls_handle.await.unwrap()
        }

        // 8b. Allowlisted GET /repos/org/repo with valid placeholder -> 200 OK + real secret injected!
        let ok_resp = send_mux_https_request(
            &mut guest_mux,
            &ca,
            10,
            &synth_ip,
            "GET /repos/org/repo HTTP/1.1\r\nHost: api.example.test\r\nAuthorization: Bearer ghp_bw00_placeholder_token\r\nCookie: session=evil\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(ok_resp.contains("200 OK"), "unexpected allowlisted resp: {ok_resp}");
        assert!(ok_resp.contains("JAILED_HTTP_OK"), "unexpected body: {ok_resp}");

        let _ = tokio::time::timeout(Duration::from_secs(3), upstream_task).await;
        let seen = upstream_seen.lock().unwrap().clone();
        assert!(
            seen.contains("ghp_REAL_PIPE_SECRET_999"),
            "upstream must receive real secret injected from pipe; got: {seen}"
        );
        assert!(
            !seen.contains("ghp_bw00_placeholder_token"),
            "placeholder must never leak upstream; got: {seen}"
        );
        assert!(
            !seen.to_ascii_lowercase().contains("cookie:"),
            "guest cookies must be stripped; got: {seen}"
        );

        // 8c. Disallowed path GET /admin/secret -> 403 Forbidden!
        let deny_resp = send_mux_https_request(
            &mut guest_mux,
            &ca,
            11,
            &synth_ip,
            "GET /admin/secret HTTP/1.1\r\nHost: api.example.test\r\nAuthorization: Bearer ghp_bw00_placeholder_token\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(
            deny_resp.contains("403 Forbidden"),
            "disallowed path must be rejected with 403; got: {deny_resp}"
        );

        // 9. Verify AuditEvent JSON streamed back over `audit_tx_fd` into MemoryAuditSink!
        let wait_deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let events = audit_sink.snapshot();
            let has_200 = events.iter().any(|e| {
                matches!(
                    &e.kind,
                    AuditEventKind::HttpRequest { status: 200, auth_injected: true, .. }
                )
            });
            let has_403 = events.iter().any(|e| {
                matches!(&e.kind, AuditEventKind::HttpRequest { status: 403, .. })
            });
            if has_200 && has_403 {
                break;
            }
            if Instant::now() >= wait_deadline {
                panic!("expected 200 + 403 HttpRequest audit events from pipe, got: {events:?}");
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }

        // 10. Cleanly kill & reap pasta + blackwall-proxy process group.
        drop(guest_mux);
        kill_process_group(pasta_pid, Some(proxy_pid));
        let _ = pasta_child.kill();
        let _ = pasta_child.wait();
        let _ = audit_thread.join();
    }
}
