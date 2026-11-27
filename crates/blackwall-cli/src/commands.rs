//! Subcommand execution and formatting for `blackwall-cli`.

use crate::cli::{
    resolve_socket_path, AuditArgs, BridgeArgs, Cli, Command, CreateArgs, DownloadArgs,
    DownloadFormatArg, ExecArgs, ImageBuildArgs, ImageCommand, ImageListArgs, IngressArgs,
    KeepaliveArgs, KillArgs, LogsArgs, ProfilesArgs, ProfilesCommand, SecretCommand, UploadArgs,
};
use crate::client::{NdjsonFrame, NdjsonStream, UdsClient};
use crate::error::{CliError, Result};
use crate::forward::run_forward;
use crate::pty::run_pty_shell;
use crate::secret::seal_secret_from_args;
use crate::upload_filter::{build_upload_tar, should_exclude_path};
use blackwall_audit::{AuditEvent, AuditEventKind, NoopAuditSink, TransferDirection};
use blackwall_core::{
    ComputePatch, CoreConfig, ExecRequest, ImageBuilder, ImageSpec, ProfileDraft, ProfileRegistry,
    SandboxDetail, SandboxSummary,
};
use blackwall_policy::{
    validate_host_service, AuthSpec, ExportSpec, HostServiceSpec, HttpRule, IngressPatch,
    NetworkMode, NetworkPatch, SecretSpec,
};
use blackwall_proto::{DownloadFormat, ProcessInfo, SignalKind};
use blackwall_secrets::SEAL1_PREFIX;
use blackwall_unpacker::{unpack_raw_to_dir, unpack_to_dir};
use bytes::Bytes;
use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Cursor, Write};
use std::path::Path;

/// Execute a parsed [`Cli`] command, returning the process exit code (0 on normal success,
/// or the guest command's exit code for `exec` / `shell`).
pub async fn run_cli(cli: Cli) -> Result<i32> {
    let socket_path = resolve_socket_path(cli.socket.as_deref());
    let client = UdsClient::new(socket_path);
    let json_out = cli.json;

    match cli.command {
        Command::Create(args) => cmd_create(&client, &args, json_out).await.map(|()| 0),
        Command::List => cmd_list(&client, json_out).await.map(|()| 0),
        Command::Inspect(args) => cmd_inspect(&client, &args.id, json_out).await.map(|()| 0),
        Command::Destroy(args) => cmd_destroy(&client, &args.id, json_out).await.map(|()| 0),
        Command::Exec(args) => cmd_exec(&client, &args, json_out).await,
        Command::Ps(args) => cmd_ps(&client, &args.id, json_out).await.map(|()| 0),
        Command::Logs(args) => cmd_logs(&client, &args, json_out).await.map(|()| 0),
        Command::Kill(args) => cmd_kill(&client, &args, json_out).await.map(|()| 0),
        Command::Shell(args) => run_pty_shell(&client, &args).await,
        Command::Forward(args) => run_forward(&client, &args, json_out).await,
        Command::Ingress(args) => cmd_ingress(&client, &args, json_out).await.map(|()| 0),
        Command::Bridge(args) => cmd_bridge(&client, &args, json_out).await.map(|()| 0),
        Command::Upload(args) => cmd_upload(&client, &args, json_out).await.map(|()| 0),
        Command::Download(args) => cmd_download(&client, &args, json_out).await.map(|()| 0),
        Command::Audit(args) => cmd_audit(&client, &args, json_out).await.map(|()| 0),
        Command::Keepalive(args) => cmd_keepalive(&client, &args, json_out).await.map(|()| 0),
        Command::Image(args) => match args.command {
            ImageCommand::Build(b) => cmd_image_build(&b, json_out).map(|()| 0),
            ImageCommand::List(l) => cmd_image_list(&client, &l, json_out).await.map(|()| 0),
        },
        Command::Secret(args) => match args.command {
            SecretCommand::Seal(s) => {
                let output = seal_secret_from_args(&s, io::stdin().lock())?;
                if s.raw {
                    println!("{}", output.sealed);
                } else if json_out {
                    println!("{}", serde_json::to_string_pretty(&output)?);
                } else {
                    print!("{}", output.to_toml_snippet());
                }
                Ok(0)
            }
        },
        Command::Profiles(args) => cmd_profiles(&client, &args, json_out).await.map(|()| 0),
    }
}

/// Resolve a full sandbox ID or unique prefix against `GET /v1/sandboxes`.
///
/// Matches exact IDs first; otherwise matches any sandbox whose full ID starts with `query`,
/// or whose suffix after stripping `bw-` or `sb-` starts with `query`.
/// Returns an error if ambiguous, or returns `query` verbatim if no running sandbox matches
/// (allowing the daemon to return its standard 404).
pub async fn resolve_sandbox_id(client: &UdsClient, query: &str) -> Result<String> {
    if query.is_empty() {
        return Ok(String::new());
    }
    let sandboxes = client.list_sandboxes().await?;
    if sandboxes.iter().any(|sb| sb.id == query) {
        return Ok(query.to_string());
    }
    let matches: Vec<&str> = sandboxes
        .iter()
        .filter(|sb| {
            sb.id.starts_with(query)
                || sb
                    .id
                    .strip_prefix("bw-")
                    .is_some_and(|rest| rest.starts_with(query))
                || sb
                    .id
                    .strip_prefix("sb-")
                    .is_some_and(|rest| rest.starts_with(query))
        })
        .map(|sb| sb.id.as_str())
        .collect();
    match matches.len() {
        1 => Ok(matches[0].to_string()),
        0 => Ok(query.to_string()),
        _ => Err(CliError::InvalidArgument(format!(
            "ambiguous sandbox ID prefix '{query}': matches {}",
            matches.join(", ")
        ))),
    }
}

/// Build a [`ProfileDraft`] from `blackwall create` flags.
pub fn build_create_draft(args: &CreateArgs) -> Result<ProfileDraft> {
    let mut draft = if let Some(path) = &args.file {
        let raw = fs::read_to_string(path)?;
        if path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
        {
            ProfileDraft::from_json_str(&raw)?
        } else {
            ProfileDraft::from_toml_str(&raw)?
        }
    } else {
        ProfileDraft::default()
    };

    if !args.profiles.is_empty() {
        for p in &args.profiles {
            if !draft.extends.contains(p) {
                draft.extends.push(p.clone());
            }
        }
    }

    if args.vcpus.is_some()
        || args.memory_mib.is_some()
        || args.workspace_mib.is_some()
        || args.idle_timeout_sec.is_some()
        || args.max_wall_time_sec.is_some()
    {
        let compute = draft.compute.get_or_insert_with(ComputePatch::default);
        if let Some(v) = args.vcpus {
            compute.vcpus = Some(v);
        }
        if let Some(m) = args.memory_mib {
            compute.memory_mib = Some(m);
        }
        if let Some(w) = args.workspace_mib {
            compute.workspace_mib = Some(w);
        }
        if let Some(i) = args.idle_timeout_sec {
            compute.idle_timeout_sec = Some(i);
        }
        if let Some(w) = args.max_wall_time_sec {
            compute.max_wall_time_sec = Some(w);
        }
    }

    if args.network.is_some() || !args.allow_http.is_empty() {
        let network = draft.network.get_or_insert_with(NetworkPatch::default);
        if let Some(mode) = args.network {
            network.mode = Some(mode.into());
        } else if !args.allow_http.is_empty() {
            network.mode = Some(NetworkMode::Egress);
        }
        for raw_rule in &args.allow_http {
            let rule = parse_allow_http_rule(raw_rule)?;
            network.http.push(rule);
        }
    }

    if !args.ports.is_empty() {
        let ingress = draft.ingress.get_or_insert_with(IngressPatch::default);
        for &port in &args.ports {
            if port == 0 {
                return Err(CliError::InvalidArgument("--port must be >= 1".into()));
            }
            if !ingress.allow_ports.contains(&port) {
                ingress.allow_ports.push(port);
            }
        }
    }

    if !args.bridges.is_empty() {
        let host_services = draft.host_services.get_or_insert_with(Vec::new);
        for raw_bridge in &args.bridges {
            let spec = parse_bridge_spec(raw_bridge, None)?;
            host_services.push(spec);
        }
    }

    for raw_secret in &args.secrets {
        let (name, spec) = parse_secret_flag(raw_secret)?;
        draft.secrets.insert(name, spec);
    }

    for kv in &args.env {
        let (k, v) = parse_env_pair(kv)?;
        draft.env.insert(k, v);
    }

    Ok(draft)
}

/// Parse `--secret NAME=seal1_...` into `(NAME, SecretSpec)`.
pub fn parse_secret_flag(raw: &str) -> Result<(String, SecretSpec)> {
    let Some((name, value)) = raw.split_once('=') else {
        return Err(CliError::InvalidArgument(format!(
            "invalid --secret '{raw}': expected NAME=seal1_..."
        )));
    };
    if name.is_empty()
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        return Err(CliError::InvalidArgument(format!(
            "invalid --secret name '{name}': must be non-empty and contain only ASCII letters, digits, and '_'"
        )));
    }
    if !value.starts_with(SEAL1_PREFIX) {
        return Err(CliError::InvalidArgument(format!(
            "plaintext secrets are not allowed via --secret '{name}'; seal the secret first with `blackwall secret seal --raw` so the value starts with '{SEAL1_PREFIX}'"
        )));
    }
    Ok((
        name.to_string(),
        SecretSpec {
            placeholder_prefix: format!("bw_{}_", name.to_ascii_lowercase()),
            sealed: Some(value.to_string()),
            ephemeral: None,
        },
    ))
}

/// Parse `--allow-http METHOD:HOST/PATH[:SECRET]` into an [`HttpRule`].
pub fn parse_allow_http_rule(raw: &str) -> Result<HttpRule> {
    let Some((methods_part, rest)) = raw.split_once(':') else {
        return Err(CliError::InvalidArgument(format!(
            "invalid --allow-http '{raw}': expected METHOD:HOST/PATH[:SECRET]"
        )));
    };

    let methods: Vec<String> = methods_part
        .split(',')
        .map(|m| m.trim().to_ascii_uppercase())
        .collect();
    if methods.is_empty() || methods.iter().any(|m| m.is_empty()) {
        return Err(CliError::InvalidArgument(format!(
            "invalid --allow-http '{raw}': methods must be non-empty (e.g. GET or GET,POST)"
        )));
    }

    if rest.trim().is_empty() {
        return Err(CliError::InvalidArgument(format!(
            "invalid --allow-http '{raw}': missing HOST/PATH"
        )));
    }

    let (host_and_path, secret) = match rest.rsplit_once(':') {
        Some((before_last, after_last)) => {
            if after_last.is_empty() {
                return Err(CliError::InvalidArgument(format!(
                    "invalid --allow-http '{raw}': trailing ':' with empty secret name"
                )));
            }
            if !after_last.contains('/') && !after_last.bytes().all(|b| b.is_ascii_digit()) {
                (before_last, Some(after_last.to_string()))
            } else {
                (rest, None)
            }
        }
        None => (rest, None),
    };

    let (host_port, path_prefix) = match host_and_path.find('/') {
        Some(idx) => (&host_and_path[..idx], host_and_path[idx..].to_string()),
        None => (host_and_path, "/".to_string()),
    };

    let (host, port) = match host_port.rsplit_once(':') {
        Some((h, port_str)) => {
            let port: u16 = port_str.parse().map_err(|_| {
                CliError::InvalidArgument(format!(
                    "invalid --allow-http '{raw}': invalid port '{port_str}'"
                ))
            })?;
            if port == 0 {
                return Err(CliError::InvalidArgument(format!(
                    "invalid --allow-http '{raw}': port must be >= 1"
                )));
            }
            (h.trim(), port)
        }
        None => (host_port.trim(), 443u16),
    };

    if host.is_empty() || host.bytes().any(|b| b.is_ascii_whitespace()) {
        return Err(CliError::InvalidArgument(format!(
            "invalid --allow-http '{raw}': host must be non-empty"
        )));
    }

    Ok(HttpRule {
        host: host.to_string(),
        port,
        methods,
        path_prefixes: vec![path_prefix],
        max_request_bytes: None,
        auth: secret.map(|secret| AuthSpec::Bearer { secret }),
    })
}

pub fn parse_env_pair(kv: &str) -> Result<(String, String)> {
    let Some((k, v)) = kv.split_once('=') else {
        return Err(CliError::InvalidArgument(format!(
            "invalid --env '{kv}': expected KEY=VAL"
        )));
    };
    if k.is_empty() {
        return Err(CliError::InvalidArgument(format!(
            "invalid --env '{kv}': key must not be empty"
        )));
    }
    Ok((k.to_string(), v.to_string()))
}

/// Parse a host service bridge spec `<GUEST_PORT>:<TARGET>` (or `<NAME>=<GUEST_PORT>:<TARGET>`)
/// into a validated [`HostServiceSpec`].
///
/// `<TARGET>` must be a loopback TCP address (`127.0.0.1:<port>` or `[::1]:<port>`)
/// or an absolute Unix socket URI (`unix:///abs/path.sock`).
/// If `name_override` is provided it takes precedence over any inline `<NAME>=` prefix;
/// otherwise the name defaults to `bridge-<guest_port>`.
pub fn parse_bridge_spec(raw: &str, name_override: Option<&str>) -> Result<HostServiceSpec> {
    let trimmed = raw.trim();
    let (inline_name, port_and_target) = match (trimmed.find('='), trimmed.find(':')) {
        (Some(eq_idx), Some(colon_idx)) if eq_idx < colon_idx => {
            let (n, rest) = trimmed.split_at(eq_idx);
            let n = n.trim();
            if n.is_empty() {
                return Err(CliError::InvalidArgument(format!(
                    "invalid bridge spec '{raw}': empty name before '='"
                )));
            }
            (Some(n), &rest[1..])
        }
        _ => (None, trimmed),
    };

    let Some((port_str, target_str)) = port_and_target.split_once(':') else {
        return Err(CliError::InvalidArgument(format!(
            "invalid bridge spec '{raw}': expected <GUEST_PORT>:<TARGET> (e.g. 5435:127.0.0.1:5435 or 5432:unix:///run/pg.sock)"
        )));
    };

    let guest_port: u16 = port_str.trim().parse().map_err(|_| {
        CliError::InvalidArgument(format!(
            "invalid bridge spec '{raw}': invalid guest port '{port_str}'"
        ))
    })?;
    if guest_port == 0 {
        return Err(CliError::InvalidArgument(format!(
            "invalid bridge spec '{raw}': guest port must be >= 1"
        )));
    }

    let target = target_str.trim();
    if target.is_empty() {
        return Err(CliError::InvalidArgument(format!(
            "invalid bridge spec '{raw}': missing target after '{guest_port}:'"
        )));
    }

    let name = match name_override.map(str::trim) {
        Some(explicit) => explicit.to_string(),
        None => match inline_name {
            Some(n) => n.to_string(),
            None => format!("bridge-{guest_port}"),
        },
    };

    let spec = HostServiceSpec {
        name,
        guest_port,
        target: target.to_string(),
    };
    validate_host_service(&spec).map_err(|e| CliError::InvalidArgument(e.to_string()))?;
    Ok(spec)
}

async fn cmd_ingress(client: &UdsClient, args: &IngressArgs, json_out: bool) -> Result<()> {
    let id = resolve_sandbox_id(client, &args.id).await?;

    if let Some(port) = args.close {
        if port == 0 {
            return Err(CliError::InvalidArgument(
                "--close port must be >= 1".into(),
            ));
        }
        client.close_ingress_port(&id, port).await?;
        if json_out {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "id": id,
                    "closed_port": port,
                }))?
            );
        } else {
            println!("closed ingress port {port} on {id}");
        }
        return Ok(());
    }

    if let Some(port) = args.allow.or(args.port) {
        if port == 0 {
            return Err(CliError::InvalidArgument(
                "ingress port must be >= 1".into(),
            ));
        }
        let ports = client.allow_ingress_port(&id, port).await?;
        if json_out {
            println!("{}", serde_json::to_string_pretty(&ports)?);
        } else {
            let formatted = if ports.is_empty() {
                "(none)".to_string()
            } else {
                ports
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            println!("allowed ingress port {port} on {id} (ports: {formatted})");
        }
        return Ok(());
    }

    let ports = client.list_ingress_ports(&id).await?;
    if json_out {
        println!("{}", serde_json::to_string_pretty(&ports)?);
    } else if ports.is_empty() {
        println!("(none)");
    } else {
        for port in &ports {
            println!("{port}");
        }
    }
    Ok(())
}

async fn cmd_bridge(client: &UdsClient, args: &BridgeArgs, json_out: bool) -> Result<()> {
    let id = resolve_sandbox_id(client, &args.id).await?;

    if let Some(guest_port) = args.remove {
        if guest_port == 0 {
            return Err(CliError::InvalidArgument(
                "--remove guest_port must be >= 1".into(),
            ));
        }
        client.detach_bridge(&id, guest_port).await?;
        if json_out {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "sandbox_id": id,
                    "guest_port": guest_port,
                    "detached": true,
                }))?
            );
        } else {
            println!("detached bridge on {id} :{guest_port}");
        }
        return Ok(());
    }

    if args.list || args.spec.is_none() {
        let bridges = client.list_bridges(&id).await?;
        if json_out {
            println!("{}", serde_json::to_string_pretty(&bridges)?);
        } else {
            print_bridge_table(&bridges);
        }
        return Ok(());
    }

    let raw_spec = args.spec.as_deref().unwrap_or_default();
    let spec = parse_bridge_spec(raw_spec, args.name.as_deref())?;
    let attached = client.attach_bridge(&id, &spec).await?;
    if json_out {
        println!("{}", serde_json::to_string_pretty(&attached)?);
    } else {
        println!(
            "attached bridge '{}' on {} (127.0.0.1:{} -> {})",
            attached.name, id, attached.guest_port, attached.target
        );
    }
    Ok(())
}

fn print_bridge_table(bridges: &[HostServiceSpec]) {
    if bridges.is_empty() {
        println!("(no active host service bridges)");
        return;
    }
    println!("{:<20} {:<12} {}", "NAME", "GUEST_PORT", "TARGET");
    for b in bridges {
        println!("{:<20} {:<12} {}", b.name, b.guest_port, b.target);
    }
}

async fn cmd_create(client: &UdsClient, args: &CreateArgs, json_out: bool) -> Result<()> {
    let draft = build_create_draft(args)?;
    let summary = client.create_sandbox(&draft).await?;
    if json_out {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        println!("{}", summary.id);
    }
    Ok(())
}

async fn cmd_list(client: &UdsClient, json_out: bool) -> Result<()> {
    let sandboxes = client.list_sandboxes().await?;
    if json_out {
        println!("{}", serde_json::to_string_pretty(&sandboxes)?);
    } else {
        print_sandbox_table(&sandboxes);
    }
    Ok(())
}

fn print_sandbox_table(sandboxes: &[SandboxSummary]) {
    if sandboxes.is_empty() {
        println!("(no active sandboxes)");
        return;
    }
    println!(
        "{:<18} {:<18} {:<10} {:<10} {:<14} {:<14}",
        "ID", "PROFILE", "STATE", "NETWORK", "IDLE_UNTIL", "EXPIRES_AT"
    );
    for sb in sandboxes {
        println!(
            "{:<18} {:<18} {:<10} {:<10} {:<14} {:<14}",
            sb.id,
            sb.profile,
            format!("{:?}", sb.state).to_ascii_lowercase(),
            format!("{:?}", sb.network_mode).to_ascii_lowercase(),
            sb.idle_deadline_at,
            sb.expires_at,
        );
    }
}

async fn cmd_inspect(client: &UdsClient, raw_id: &str, json_out: bool) -> Result<()> {
    let id = resolve_sandbox_id(client, raw_id).await?;
    let detail = client.inspect_sandbox(&id).await?;
    if json_out {
        println!("{}", serde_json::to_string_pretty(&detail)?);
    } else {
        print_sandbox_detail(&detail);
    }
    Ok(())
}

fn print_sandbox_detail(detail: &SandboxDetail) {
    println!("id:               {}", detail.id);
    println!("profile:          {}", detail.profile);
    println!("state:            {:?}", detail.state);
    println!("image_roothash:   {}", detail.image_roothash);
    println!("network_mode:     {:?}", detail.network_mode);
    println!("vmm_pid:          {}", detail.vmm_pid);
    println!(
        "compute:          {} vCPUs, {} MiB RAM, {} MiB workspace",
        detail.compute.vcpus, detail.compute.memory_mib, detail.compute.workspace_mib
    );
    println!(
        "timers:           created={}, idle_deadline={}, expires={}",
        detail.created_at, detail.idle_deadline_at, detail.expires_at
    );
    if !detail.allowed_hosts.is_empty() {
        println!("allowed_hosts:    {}", detail.allowed_hosts.join(", "));
    }
    if !detail.ingress_allow_ports.is_empty() {
        let ports: Vec<String> = detail
            .ingress_allow_ports
            .iter()
            .map(ToString::to_string)
            .collect();
        println!("ingress_ports:    {}", ports.join(", "));
    }
    println!("processes:        {}", detail.processes.len());
}

async fn cmd_destroy(client: &UdsClient, raw_id: &str, json_out: bool) -> Result<()> {
    let id = resolve_sandbox_id(client, raw_id).await?;
    client.destroy_sandbox(&id).await?;
    if json_out {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "id": id,
                "destroyed": true
            }))?
        );
    } else {
        println!("destroyed {id}");
    }
    Ok(())
}

async fn cmd_exec(client: &UdsClient, args: &ExecArgs, json_out: bool) -> Result<i32> {
    let id = resolve_sandbox_id(client, &args.id).await?;
    let mut env = BTreeMap::new();
    for kv in &args.env {
        let (k, v) = parse_env_pair(kv)?;
        env.insert(k, v);
    }

    let req = ExecRequest {
        cmd: args.cmd.clone(),
        cwd: args.cwd.clone(),
        env,
        stdin: None,
        timeout_sec: args.timeout_sec,
        background: args.background,
    };

    if args.background {
        let proc = client.exec_background(&id, &req).await?;
        if json_out {
            println!("{}", serde_json::to_string_pretty(&proc)?);
        } else {
            println!("{}", proc.proc_id);
        }
        return Ok(0);
    }

    if args.stream {
        let stream = client.exec_stream(&id, &req).await?;
        return drain_ndjson_stream(stream, json_out).await;
    }

    let res = client.exec_sync(&id, &req).await?;
    if json_out {
        println!("{}", serde_json::to_string_pretty(&res)?);
    } else {
        if !res.stdout.is_empty() {
            let mut out = io::stdout().lock();
            out.write_all(res.stdout.as_bytes())?;
            out.flush()?;
        }
        if !res.stderr.is_empty() {
            let mut err = io::stderr().lock();
            err.write_all(res.stderr.as_bytes())?;
            err.flush()?;
        }
    }
    Ok(res.exit_code)
}

async fn drain_ndjson_stream(mut stream: NdjsonStream, json_out: bool) -> Result<i32> {
    let mut exit_code = 0;
    while let Some((raw_line, frame)) = stream.next_frame().await? {
        if json_out {
            println!("{raw_line}");
            if let NdjsonFrame::Exit { exit_code: code, .. } = frame {
                exit_code = code;
            } else if let NdjsonFrame::Error { code, message } = frame {
                return Err(CliError::StreamError { code, message });
            }
            continue;
        }

        match frame {
            NdjsonFrame::Stdout(s) => {
                let mut out = io::stdout().lock();
                out.write_all(s.as_bytes())?;
                out.flush()?;
            }
            NdjsonFrame::Stderr(s) => {
                let mut err = io::stderr().lock();
                err.write_all(s.as_bytes())?;
                err.flush()?;
            }
            NdjsonFrame::Exit {
                exit_code: code, ..
            } => {
                exit_code = code;
            }
            NdjsonFrame::End => break,
            NdjsonFrame::Error { code, message } => {
                return Err(CliError::StreamError { code, message });
            }
            NdjsonFrame::Raw(_) => {}
        }
    }
    Ok(exit_code)
}

async fn cmd_ps(client: &UdsClient, raw_id: &str, json_out: bool) -> Result<()> {
    let id = resolve_sandbox_id(client, raw_id).await?;
    let procs = client.list_processes(&id).await?;
    if json_out {
        println!("{}", serde_json::to_string_pretty(&procs)?);
    } else {
        print_process_table(&procs);
    }
    Ok(())
}

fn print_process_table(procs: &[ProcessInfo]) {
    if procs.is_empty() {
        println!("(no tracked background processes)");
        return;
    }
    println!(
        "{:<18} {:<8} {:<10} {:<10} {}",
        "PROC_ID", "PID", "STATE", "EXIT_CODE", "CMD"
    );
    for p in procs {
        let code = p
            .exit_code
            .map(|c| c.to_string())
            .unwrap_or_else(|| "-".to_string());
        println!(
            "{:<18} {:<8} {:<10} {:<10} {}",
            p.proc_id,
            p.pid,
            format!("{:?}", p.state).to_ascii_lowercase(),
            code,
            p.cmd.join(" "),
        );
    }
}

async fn cmd_logs(client: &UdsClient, args: &LogsArgs, json_out: bool) -> Result<()> {
    let id = resolve_sandbox_id(client, &args.id).await?;
    let stream = client
        .process_logs(&id, &args.proc_id, args.tail, args.follow)
        .await?;
    let _ = drain_ndjson_stream(stream, json_out).await?;
    Ok(())
}

async fn cmd_kill(client: &UdsClient, args: &KillArgs, json_out: bool) -> Result<()> {
    let id = resolve_sandbox_id(client, &args.id).await?;
    if let Some(sig_arg) = args.signal {
        let sig: SignalKind = sig_arg.into();
        client.signal_process(&id, &args.proc_id, sig).await?;
        if json_out {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "sandbox_id": id,
                    "proc_id": args.proc_id,
                    "signal": sig,
                }))?
            );
        } else {
            println!("signaled {} with {:?}", args.proc_id, sig);
        }
    } else {
        client.delete_process(&id, &args.proc_id).await?;
        if json_out {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "sandbox_id": id,
                    "proc_id": args.proc_id,
                    "killed": true,
                }))?
            );
        } else {
            println!("killed {}", args.proc_id);
        }
    }
    Ok(())
}

async fn cmd_upload(client: &UdsClient, args: &UploadArgs, json_out: bool) -> Result<()> {
    let id = resolve_sandbox_id(client, &args.id).await?;
    let meta = fs::metadata(&args.local_path)?;
    let (content_type, payload, excluded_count) = if meta.is_file() {
        if args.exclude_secrets {
            if let Some(name) = args.local_path.file_name() {
                if should_exclude_path(Path::new(name)) {
                    return Err(CliError::InvalidArgument(format!(
                        "refusing to upload '{}' because --exclude-secrets matched it",
                        args.local_path.display()
                    )));
                }
            }
        }
        let bytes = fs::read(&args.local_path)?;
        ("application/octet-stream", Bytes::from(bytes), 0u64)
    } else if meta.is_dir() {
        let (tar_bytes, stats) = build_upload_tar(&args.local_path, args.exclude_secrets)?;
        (
            "application/x-tar",
            Bytes::from(tar_bytes),
            stats.entries_excluded,
        )
    } else {
        return Err(CliError::InvalidArgument(format!(
            "'{}' must be a regular file or directory",
            args.local_path.display()
        )));
    };

    let result = client
        .upload_files(&id, &args.remote_path, content_type, payload)
        .await?;

    if json_out {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "bytes_written": result.bytes_written,
                "files_written": result.files_written,
                "entries_excluded": excluded_count,
                "remote_path": args.remote_path,
            }))?
        );
    } else {
        println!(
            "uploaded {} file(s) ({} bytes) to {}",
            result.files_written, result.bytes_written, args.remote_path
        );
    }
    Ok(())
}

async fn cmd_download(client: &UdsClient, args: &DownloadArgs, json_out: bool) -> Result<()> {
    let id = resolve_sandbox_id(client, &args.id).await?;
    let format_arg = args.format.unwrap_or({
        if args.unpack_dir.is_some() {
            DownloadFormatArg::TarGz
        } else {
            DownloadFormatArg::Raw
        }
    });

    let data = client
        .download_files(&id, &args.remote_path, format_arg.as_query_str())
        .await?;

    if let Some(unpack_dir) = &args.unpack_dir {
        let spec = ExportSpec::default();
        let format: DownloadFormat = format_arg.into();
        let summary = match format {
            DownloadFormat::TarGz => unpack_to_dir(
                Cursor::new(data.as_ref()),
                unpack_dir,
                &spec,
                &id,
                &NoopAuditSink,
            )?,
            DownloadFormat::Raw => {
                let rel_name = Path::new(&args.remote_path)
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("file");
                unpack_raw_to_dir(
                    Cursor::new(data.as_ref()),
                    unpack_dir,
                    rel_name,
                    &spec,
                    &id,
                    &NoopAuditSink,
                )?
            }
        };

        if json_out {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "unpack_dir": unpack_dir,
                    "bytes_written": summary.bytes_written,
                    "files_written": summary.files_written,
                    "dirs_written": summary.dirs_written,
                }))?
            );
        } else {
            println!(
                "unpacked {} file(s), {} dir(s) ({} bytes) into {}",
                summary.files_written,
                summary.dirs_written,
                summary.bytes_written,
                unpack_dir.display()
            );
        }
        return Ok(());
    }

    if let Some(out_path) = &args.output {
        if let Some(parent) = out_path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        fs::write(out_path, &data)?;
        if json_out {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "output": out_path,
                    "bytes": data.len(),
                    "format": format_arg.as_query_str(),
                }))?
            );
        } else {
            println!("wrote {} bytes to {}", data.len(), out_path.display());
        }
        return Ok(());
    }

    let mut stdout = io::stdout().lock();
    stdout.write_all(&data)?;
    stdout.flush()?;
    Ok(())
}

async fn cmd_keepalive(client: &UdsClient, args: &KeepaliveArgs, json_out: bool) -> Result<()> {
    let id = resolve_sandbox_id(client, &args.id).await?;
    let resp = client.keepalive_sandbox(&id).await?;
    if json_out {
        println!("{}", serde_json::to_string_pretty(&resp)?);
    } else {
        println!(
            "{id}: idle_remaining_sec={} wall_remaining_sec={}",
            resp.idle_remaining_sec, resp.wall_remaining_sec
        );
    }
    Ok(())
}

async fn cmd_audit(client: &UdsClient, args: &AuditArgs, json_out: bool) -> Result<()> {
    let resolved_id = match args.id.as_deref() {
        Some(raw_id) => Some(resolve_sandbox_id(client, raw_id).await?),
        None => None,
    };

    if args.follow {
        let mut stream = client
            .audit_stream(resolved_id.as_deref(), args.limit)
            .await?;
        loop {
            let next = tokio::select! {
                _ = tokio::signal::ctrl_c() => break,
                line = stream.next_line() => line?,
            };
            let Some(raw_line) = next else {
                break;
            };
            let mut stdout = io::stdout().lock();
            if json_out {
                writeln!(stdout, "{raw_line}")?;
            } else {
                match serde_json::from_str::<AuditEvent>(&raw_line) {
                    Ok(ev) => writeln!(stdout, "{}", format_audit_event(&ev))?,
                    Err(_) => writeln!(stdout, "{raw_line}")?,
                }
            }
            stdout.flush()?;
        }
        return Ok(());
    }

    let events = client
        .audit_events(resolved_id.as_deref(), args.limit)
        .await?;
    if json_out {
        println!("{}", serde_json::to_string_pretty(&events)?);
    } else if events.is_empty() {
        println!("(no audit events)");
    } else {
        let mut stdout = io::stdout().lock();
        for ev in &events {
            writeln!(stdout, "{}", format_audit_event(ev))?;
        }
        stdout.flush()?;
    }
    Ok(())
}

/// Format a Unix epoch millisecond timestamp as UTC `HH:MM:SS.mmm`.
pub fn format_timestamp_hms_ms(timestamp_ms: u64) -> String {
    let total_secs = timestamp_ms / 1000;
    let ms = timestamp_ms % 1000;
    let secs_in_day = total_secs % 86_400;
    let hours = secs_in_day / 3600;
    let mins = (secs_in_day % 3600) / 60;
    let secs = secs_in_day % 60;
    format!("{hours:02}:{mins:02}:{secs:02}.{ms:03}")
}

fn short_sandbox_id(id: &str) -> String {
    if id.len() > 12 {
        format!("{}...", &id[..9])
    } else {
        id.to_string()
    }
}

fn join_host_path(host: &str, path: &str) -> String {
    if path.starts_with('/') {
        format!("{host}{path}")
    } else {
        format!("{host}/{path}")
    }
}

/// Format an [`AuditEvent`] as a single scannable human-readable line.
pub fn format_audit_event(ev: &AuditEvent) -> String {
    let ts = format_timestamp_hms_ms(ev.timestamp_ms);
    let sb = short_sandbox_id(&ev.sandbox_id);

    let (tag, detail): (String, String) = match &ev.kind {
        AuditEventKind::HttpRequest {
            host,
            method,
            path,
            status,
            request_bytes,
            response_bytes,
            auth_injected,
        } => {
            let bytes = if *response_bytes > 0 {
                *response_bytes
            } else {
                *request_bytes
            };
            let auth = if *auth_injected {
                " [auth injected]"
            } else {
                ""
            };
            (
                format!("HTTP {status}"),
                format!(
                    "{} {} ({} B){auth}",
                    method,
                    join_host_path(host, path),
                    bytes
                ),
            )
        }
        AuditEventKind::DnsQuery {
            fqdn,
            allowed,
            synthetic_ip,
        } => {
            if *allowed {
                (
                    "DNS ALLOW".into(),
                    format!("{fqdn} -> {}", synthetic_ip.as_deref().unwrap_or("ok")),
                )
            } else {
                ("DNS DENY".into(), format!("{fqdn} -> NXDOMAIN"))
            }
        }
        AuditEventKind::AuthMismatch { host, path, reason } => (
            "AUTH MISMATCH".into(),
            format!("{} ({reason})", join_host_path(host, path)),
        ),
        AuditEventKind::IngressTunnel {
            guest_port,
            bytes_in,
            bytes_out,
            allowed,
        } => {
            if *allowed {
                (
                    "INGRESS".into(),
                    format!("port {guest_port} (in {bytes_in} B, out {bytes_out} B)"),
                )
            } else {
                ("INGRESS DENY".into(), format!("port {guest_port} denied"))
            }
        }
        AuditEventKind::HostServiceBridge {
            name,
            guest_port,
            target,
            bytes_in,
            bytes_out,
            allowed,
        } => {
            if *allowed {
                (
                    "BRIDGE".into(),
                    format!("{name} :{guest_port} -> {target} (in {bytes_in} B / out {bytes_out} B)"),
                )
            } else {
                (
                    "BRIDGE DENY".into(),
                    format!("{name} :{guest_port} -> {target} (blocked)"),
                )
            }
        }
        AuditEventKind::SandboxLifecycle {
            phase,
            image_roothash,
            details,
        } => {
            let extra = match (details.as_deref(), image_roothash.as_deref()) {
                (Some(d), _) if !d.is_empty() => format!(" ({d})"),
                (_, Some(h)) if !h.is_empty() => {
                    format!(" (roothash {}...)", &h[..h.len().min(12)])
                }
                _ => String::new(),
            };
            ("LIFECYCLE".into(), format!("{phase}{extra}"))
        }
        AuditEventKind::ExecCommand {
            cmd,
            cwd,
            background,
            exit_code,
            duration_ms,
        } => {
            let tag = if *background { "EXEC BG" } else { "EXEC" };
            let mut parts = vec![cmd.join(" ")];
            if let Some(dir) = cwd {
                parts.push(format!("cwd={dir}"));
            }
            if let Some(code) = exit_code {
                parts.push(format!("exit={code}"));
            }
            if let Some(ms) = duration_ms {
                parts.push(format!("{ms}ms"));
            }
            (tag.into(), parts.join(" "))
        }
        AuditEventKind::FileTransfer {
            direction,
            path,
            bytes,
            files,
        } => {
            let tag = match direction {
                TransferDirection::Upload => "UPLOAD",
                TransferDirection::Download => "DOWNLOAD",
            };
            (tag.into(), format!("{path} ({files} file(s), {bytes} B)"))
        }
        AuditEventKind::PostgresQuery {
            host,
            port,
            message_type,
            statement,
        } => (
            "POSTGRES".into(),
            format!("{host}:{port} [{message_type}] {statement}"),
        ),
        AuditEventKind::UnpackerRejection { path, reason } => {
            ("UNPACK DENY".into(), format!("{path} ({reason})"))
        }
        AuditEventKind::VmmFatalExit {
            reason,
            exit_detail,
        } => ("VMM FATAL".into(), format!("{reason}: {exit_detail}")),
        AuditEventKind::GuestPort1001 { frame } => (
            "GUEST AUDIT".into(),
            format!("{}/{} {}", frame.source, frame.kind, frame.payload),
        ),
    };

    format!("{ts}  {tag:<13}  {sb:<12}  {detail}")
}

/// Resolve an `image build` target (either a profile `.toml` file or an OCI image ref)
/// into an [`ImageSpec`].
pub fn resolve_image_spec(target: &str) -> Result<ImageSpec> {
    let path = Path::new(target);
    let looks_like_toml = path
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("toml"));

    if looks_like_toml || path.is_file() {
        let raw = fs::read_to_string(path)?;
        let draft = ProfileDraft::from_toml_str(&raw)?;
        let cfg = CoreConfig::default();
        let registry = ProfileRegistry::load_dir(&cfg.profile_dir).unwrap_or_default();
        if let Ok(resolved) = registry.resolve_api_request(&draft) {
            return Ok(resolved.image);
        }
        // Fallback: construct ImageSpec directly from the TOML's [image] patch.
        let mut spec = ImageSpec::default();
        if let Some(img) = draft.image {
            if let Some(r) = img.image_ref {
                spec.image_ref = Some(r);
            }
            if let Some(b) = img.base {
                spec.base = Some(b);
            }
            spec.packages = img.packages;
            spec.run = img.run;
        }
        return Ok(spec);
    }

    Ok(ImageSpec {
        image_ref: Some(target.to_string()),
        base: None,
        packages: Vec::new(),
        run: Vec::new(),
    })
}

fn cmd_image_build(args: &ImageBuildArgs, json_out: bool) -> Result<()> {
    let spec = resolve_image_spec(&args.target)?;
    let cache_dir = args
        .cache_dir
        .clone()
        .unwrap_or_else(|| CoreConfig::default().image_cache_dir);
    let builder = ImageBuilder::new(cache_dir);
    let built = builder.build(&spec)?;

    if json_out {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "tag": args.tag,
                "content_hash": built.content_hash,
                "erofs_path": built.erofs_path,
                "verity": built.verity,
            }))?
        );
    } else {
        if let Some(tag) = &args.tag {
            println!("tag:          {tag}");
        }
        println!("content_hash: {}", built.content_hash);
        println!("roothash:     {}", built.verity.roothash_hex);
        println!("erofs_path:   {}", built.erofs_path.display());
    }
    Ok(())
}

async fn cmd_image_list(client: &UdsClient, args: &ImageListArgs, json_out: bool) -> Result<()> {
    let images = if args.local {
        let cache_dir = args
            .cache_dir
            .clone()
            .unwrap_or_else(|| CoreConfig::default().image_cache_dir);
        ImageBuilder::new(cache_dir).list_cached()?
    } else {
        client.list_images().await?
    };

    if json_out {
        println!("{}", serde_json::to_string_pretty(&images)?);
    } else if images.is_empty() {
        println!("(no cached images)");
    } else {
        println!("{:<18} {:<66} {}", "CONTENT_HASH", "ROOTHASH", "EROFS_PATH");
        for img in &images {
            let short_hash = &img.content_hash[..img.content_hash.len().min(16)];
            println!(
                "{:<18} {:<66} {}",
                short_hash,
                img.verity.roothash_hex,
                img.erofs_path.display()
            );
        }
    }
    Ok(())
}

async fn cmd_profiles(client: &UdsClient, args: &ProfilesArgs, json_out: bool) -> Result<()> {
    match &args.command {
        None | Some(ProfilesCommand::List) => {
            let names = client.list_profiles().await?;
            if json_out {
                println!("{}", serde_json::to_string_pretty(&names)?);
            } else {
                for name in &names {
                    println!("{name}");
                }
            }
        }
        Some(ProfilesCommand::Show { name }) => {
            let spec = client.get_profile(name).await?;
            if json_out {
                println!("{}", serde_json::to_string_pretty(&spec)?);
            } else {
                println!(
                    "{}",
                    toml::to_string_pretty(&spec)
                        .unwrap_or_else(|_| format!("{spec:#?}"))
                );
            }
        }
    }
    Ok(())
}
