//! Standalone per-VM jailed `blackwall-proxy` binary entrypoint.
//!
//! Startup ordering (strictly single-threaded until after jail lockdown so capabilities,
//! `PR_SET_DUMPABLE=0`, `PR_SET_NO_NEW_PRIVS=1`, Landlock, and `seccomp-bpf` are inherited
//! by EVERY Tokio & Pingora thread):
//! 1. Receive `[config_rx_fd, audit_tx_fd, mux_fd]` over a 1-shot private `0700` Unix socket
//!    (`--bootstrap-uds <path>`, via `SCM_RIGHTS`) or inherited fds (`--config-fd` / `--audit-fd`
//!    / `--mux-fd`). Read [`ProxyBootstrapConfig`] from `config_rx_fd` into `Zeroizing` memory
//!    and close `config_rx_fd` immediately (secrets & CA key NEVER touch host disk!).
//! 2. Reserve the internal Pingora loopback port (`127.0.0.1:0`) inside the isolated `netns`.
//! 3. (`--apply-nftables`) Pipe `generate_nftables_rules_with_local_loopback(...)` into `nft -f -`
//!    so ONLY `lo -> 127.0.0.1:<pingora_port>` and exact resolver-pinned upstream endpoints are
//!    reachable; all other loopback, metadata (`169.254.169.254`), and RFC1918/ULA are dropped.
//! 4. (`--apply-jail`) Irreversibly drop ALL Linux capabilities (`capset` v3 + bounding + ambient),
//!    set `PR_SET_DUMPABLE=0`, set `PR_SET_NO_NEW_PRIVS=1`, apply Landlock zero-fs lockdown,
//!    and install `seccomp-bpf` blocking `unshare`/`setns`/`mount`/`ptrace`/`AF_NETLINK`/`AF_PACKET`.
//! 5. Start the Tokio runtime, Pingora (`rustls`), sibling Tokio Postgres wire proxy, emit
//!    [`ProxyReadyAck`] back to the parent, close the bootstrap socket, and run `Port1000Muxer`.

use blackwall_audit::{AuditSink, JsonlAuditSink};
use blackwall_proxy::{
    build_pingora_http_service, BlackwallHttpProxy, EphemeralCa, HttpProxyConfig,
    InMemorySecretResolver, Port1000Muxer, PostgresProxyConfig, PostgresProxyServer,
    PostgresRouteTarget, ProxyBootstrapConfig, ProxyJailConfig, ProxyReadyAck, SyntheticDnsTable,
};
use pingora_core::services::Service;
use std::collections::BTreeSet;
use std::fs::File;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::os::fd::{FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use zeroize::Zeroizing;

struct CliArgs {
    bootstrap_stdin: bool,
    bootstrap_uds: Option<PathBuf>,
    config_fd: Option<RawFd>,
    audit_fd: Option<RawFd>,
    mux_fd: Option<RawFd>,
    apply_nftables: bool,
    apply_jail: bool,
    unshare_netns: bool,
    nft_bin: PathBuf,
}

fn parse_args() -> Result<CliArgs, String> {
    let mut cli = CliArgs {
        bootstrap_stdin: false,
        bootstrap_uds: None,
        config_fd: None,
        audit_fd: None,
        mux_fd: None,
        apply_nftables: false,
        apply_jail: false,
        unshare_netns: false,
        nft_bin: PathBuf::from("nft"),
    };

    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--bootstrap-stdin" => cli.bootstrap_stdin = true,
            "--bootstrap-uds" => {
                i += 1;
                let path = args
                    .get(i)
                    .ok_or_else(|| "missing path after --bootstrap-uds".to_string())?;
                cli.bootstrap_uds = Some(PathBuf::from(path));
            }
            "--config-fd" => {
                i += 1;
                let fd: RawFd = args
                    .get(i)
                    .ok_or_else(|| "missing fd after --config-fd".to_string())?
                    .parse()
                    .map_err(|e| format!("invalid --config-fd: {e}"))?;
                cli.config_fd = Some(fd);
            }
            "--audit-fd" => {
                i += 1;
                let fd: RawFd = args
                    .get(i)
                    .ok_or_else(|| "missing fd after --audit-fd".to_string())?
                    .parse()
                    .map_err(|e| format!("invalid --audit-fd: {e}"))?;
                cli.audit_fd = Some(fd);
            }
            "--mux-fd" => {
                i += 1;
                let fd: RawFd = args
                    .get(i)
                    .ok_or_else(|| "missing fd after --mux-fd".to_string())?
                    .parse()
                    .map_err(|e| format!("invalid --mux-fd: {e}"))?;
                cli.mux_fd = Some(fd);
            }
            "--nft-bin" => {
                i += 1;
                let path = args
                    .get(i)
                    .ok_or_else(|| "missing path after --nft-bin".to_string())?;
                cli.nft_bin = PathBuf::from(path);
            }
            "--apply-nftables" => cli.apply_nftables = true,
            "--apply-jail" => cli.apply_jail = true,
            "--unshare-netns" => cli.unshare_netns = true,
            other => return Err(format!("unknown argument: {other}")),
        }
        i += 1;
    }

    Ok(cli)
}

fn write_ready_ack(sock: &mut Option<StdUnixStream>, ack: &ProxyReadyAck) {
    if let Some(mut s) = sock.take() {
        if let Ok(line) = serde_json::to_string(ack) {
            let _ = writeln!(s, "{line}");
            let _ = s.flush();
        }
    }
}

#[cfg(target_os = "linux")]
fn take_bootstrap_stdin_socket() -> Result<StdUnixStream, Box<dyn std::error::Error>> {
    use std::os::fd::AsRawFd;

    // Duplicate fd 0 onto a private O_CLOEXEC fd so child processes (e.g. `nft`) never
    // inherit the bootstrap socket, then immediately rebind fd 0 to `/dev/null` before
    // Landlock zero-fs lockdown so nothing accidentally reads or writes fd 0 later.
    let dup_fd = unsafe { libc::fcntl(libc::STDIN_FILENO, libc::F_DUPFD_CLOEXEC, 3) };
    if dup_fd < 0 {
        return Err(format!(
            "fcntl(0, F_DUPFD_CLOEXEC) failed: {}",
            std::io::Error::last_os_error()
        )
        .into());
    }
    let sock = unsafe { StdUnixStream::from_raw_fd(dup_fd) };

    match File::open("/dev/null") {
        Ok(devnull) => {
            let rc = unsafe { libc::dup2(devnull.as_raw_fd(), libc::STDIN_FILENO) };
            if rc < 0 {
                let _ = unsafe { libc::close(libc::STDIN_FILENO) };
            }
        }
        Err(_) => {
            let _ = unsafe { libc::close(libc::STDIN_FILENO) };
        }
    }

    Ok(sock)
}

fn run_proxy(
    cli: CliArgs,
    bootstrap_sock: &mut Option<StdUnixStream>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Step 1: Acquire (config_rx_fd, audit_tx_fd, mux_fd) without touching disk.
    let (config_fd, audit_fd, mux_fd): (OwnedFd, OwnedFd, OwnedFd) = if cli.bootstrap_stdin {
        #[cfg(target_os = "linux")]
        let sock = take_bootstrap_stdin_socket()?;
        #[cfg(target_os = "linux")]
        let mut fds = blackwall_proxy::recv_fds_over_unix(&sock, 3)?;
        #[cfg(not(target_os = "linux"))]
        let mut fds: Vec<OwnedFd> = return Err("SCM_RIGHTS requires Linux".into());

        #[cfg(target_os = "linux")]
        {
            *bootstrap_sock = Some(sock);
        }
        let mux_fd = fds.pop().ok_or("missing mux_fd")?;
        let audit_fd = fds.pop().ok_or("missing audit_tx_fd")?;
        let config_fd = fds.pop().ok_or("missing config_rx_fd")?;
        (config_fd, audit_fd, mux_fd)
    } else if let Some(ref uds_path) = cli.bootstrap_uds {
        let sock = StdUnixStream::connect(uds_path)?;
        #[cfg(target_os = "linux")]
        let mut fds = blackwall_proxy::recv_fds_over_unix(&sock, 3)?;
        #[cfg(not(target_os = "linux"))]
        let mut fds: Vec<OwnedFd> = return Err("SCM_RIGHTS requires Linux".into());

        *bootstrap_sock = Some(sock);
        let mux_fd = fds.pop().ok_or("missing mux_fd")?;
        let audit_fd = fds.pop().ok_or("missing audit_tx_fd")?;
        let config_fd = fds.pop().ok_or("missing config_rx_fd")?;
        (config_fd, audit_fd, mux_fd)
    } else if let (Some(c), Some(a), Some(m)) = (cli.config_fd, cli.audit_fd, cli.mux_fd) {
        unsafe {
            (
                OwnedFd::from_raw_fd(c),
                OwnedFd::from_raw_fd(a),
                OwnedFd::from_raw_fd(m),
            )
        }
    } else {
        return Err(
            "must pass --bootstrap-stdin, --bootstrap-uds <path>, or --config-fd/--audit-fd/--mux-fd"
                .into(),
        );
    };

    // Read JSON bootstrap payload from the anonymous pipe into a Zeroizing buffer and close immediately.
    let mut raw_cfg = Zeroizing::new(Vec::<u8>::new());
    {
        let mut config_file = File::from(config_fd);
        config_file.read_to_end(&mut raw_cfg)?;
    }

    let boot: ProxyBootstrapConfig = serde_json::from_slice(&raw_cfg)?;
    drop(raw_cfg);

    let sandbox_id = boot.sandbox_id.clone();
    let http_rules = boot.http_rules.clone();
    let postgres_rules = boot.postgres_rules.clone();
    let pinned_hosts = boot.pinned_hosts.clone();
    let upstream_tls = boot.upstream_tls;
    let verify_upstream_cert = boot.verify_upstream_cert;

    let ca = Arc::new(EphemeralCa::from_pem_pair(
        &sandbox_id,
        &boot.ca_cert_pem,
        &boot.ca_key_pem,
    )?);

    let mut secret_store = InMemorySecretResolver::new();
    for s in &boot.secrets {
        secret_store.insert(s.name.clone(), s.placeholder.clone(), (*s.value).clone());
    }
    let secrets = Arc::new(secret_store);

    // Wipe the deserialized bootstrap config (including CA key PEM & plaintext secrets) right away.
    drop(boot);

    let audit_file = File::from(audit_fd);
    let audit: Arc<dyn AuditSink> = Arc::new(JsonlAuditSink::new(audit_file));

    let mut allowlist = BTreeSet::new();
    for r in &http_rules {
        allowlist.insert(r.host.to_ascii_lowercase());
    }
    for r in &postgres_rules {
        allowlist.insert(r.host.to_ascii_lowercase());
    }
    let dns_table = Arc::new(SyntheticDnsTable::from_allowlist(&allowlist));

    // Step 2: Reserve internal loopback port (`127.0.0.1:0`) and pre-build the Pingora
    // service & TLS root store in memory BEFORE Landlock locks the filesystem to zero-fs.
    let http_addr: SocketAddr = {
        let probe = std::net::TcpListener::bind("127.0.0.1:0")?;
        probe.local_addr()?
    };

    let mut http_cfg = HttpProxyConfig::new(&sandbox_id, http_rules, pinned_hosts.clone());
    http_cfg.upstream_tls = upstream_tls;
    http_cfg.verify_upstream_cert = verify_upstream_cert;
    let http_proxy = BlackwallHttpProxy::new(http_cfg, secrets.clone(), audit.clone());
    let mut pingora_service =
        build_pingora_http_service(http_proxy, &http_addr.to_string(), Some(ca.clone()))?;

    let pg_cfg = PostgresProxyConfig::new(&sandbox_id, postgres_rules, pinned_hosts.clone());
    let pg_server = Arc::new(PostgresProxyServer::new(
        pg_cfg,
        ca,
        secrets,
        audit.clone(),
    ));

    // Step 3: Apply fail-closed nftables ruleset inside isolated netns BEFORE dropping capabilities!
    #[cfg(target_os = "linux")]
    if cli.apply_nftables || cli.unshare_netns {
        let pinned_endpoints: Vec<SocketAddr> = pinned_hosts
            .values()
            .flat_map(|v| v.iter().copied())
            .collect();
        let mut jail = ProxyJailConfig::new(&sandbox_id, pinned_endpoints);
        jail.nft_binary = cli.nft_bin.clone();
        jail.enable_namespaces = cli.unshare_netns;
        jail.enable_nftables = cli.apply_nftables;

        if cli.unshare_netns {
            jail.setup_rootless_netns_and_nftables_with_loopback(Some(http_addr.port()))?;
        } else {
            jail.apply_nftables_rules(Some(http_addr.port()))?;
        }
    }

    // Step 4: Irreversibly lock down the process WHILE STILL SINGLE-THREADED:
    // drop ALL caps (capset v3) -> PR_SET_DUMPABLE=0 -> PR_SET_NO_NEW_PRIVS=1 -> Landlock -> seccomp-bpf!
    #[cfg(target_os = "linux")]
    if cli.apply_jail {
        let jail = ProxyJailConfig::new(&sandbox_id, Vec::new());
        jail.apply_pre_exec_lockdown()?;
    }

    #[cfg(target_os = "linux")]
    let dumpable_val = Some(blackwall_proxy::get_dumpable());
    #[cfg(not(target_os = "linux"))]
    let dumpable_val = None;

    // Step 5: Construct the multi-threaded Tokio runtime AFTER jail lockdown so every worker
    // thread inherits CapEff=0, NoNewPrivs=1, Dumpable=0, Landlock, and Seccomp!
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;

    let std_mux_stream = unsafe { StdUnixStream::from_raw_fd(mux_fd.into_raw_fd()) };
    std_mux_stream.set_nonblocking(true)?;

    runtime.block_on(async move {
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        tokio::spawn(async move {
            pingora_service.start_service(None, shutdown_rx, 1).await;
        });

        // Wait until Pingora's loopback listener is accepting connections before signaling ready.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            match tokio::net::TcpStream::connect(http_addr).await {
                Ok(s) => {
                    drop(s);
                    break;
                }
                Err(e) => {
                    if tokio::time::Instant::now() >= deadline {
                        return Err(format!(
                            "Pingora listener at {http_addr} did not become ready: {e}"
                        )
                        .into());
                    }
                    tokio::time::sleep(Duration::from_millis(15)).await;
                }
            }
        }

        let mux_stream = tokio::net::UnixStream::from_std(std_mux_stream)?;

        // Notify parent that nftables + capability drop + Landlock + seccomp + Pingora are ALL live,
        // and immediately close the bootstrap socket.
        write_ready_ack(
            bootstrap_sock,
            &ProxyReadyAck {
                ok: true,
                http_listen_addr: Some(http_addr.to_string()),
                dumpable: dumpable_val,
                error: None,
            },
        );

        let muxer = Port1000Muxer::new(
            dns_table,
            http_addr,
            Some(PostgresRouteTarget::Direct(pg_server)),
        )
        .with_audit(sandbox_id, audit);
        let res = muxer.run(mux_stream).await;
        let _ = shutdown_tx.send(true);
        res.map_err(|e| -> Box<dyn std::error::Error> { Box::new(e) })
    })
}

fn main() {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = match parse_args() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("blackwall-proxy: {e}");
            std::process::exit(2);
        }
    };

    let mut bootstrap_sock: Option<StdUnixStream> = None;
    if let Err(err) = run_proxy(cli, &mut bootstrap_sock) {
        let msg = err.to_string();
        write_ready_ack(
            &mut bootstrap_sock,
            &ProxyReadyAck {
                ok: false,
                http_listen_addr: None,
                dumpable: None,
                error: Some(msg.clone()),
            },
        );
        eprintln!("blackwall-proxy error: {msg}");
        std::process::exit(1);
    }
}
