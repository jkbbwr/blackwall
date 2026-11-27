//! `blackwall-cli` — Command-line client library for Blackwall interactive sandboxes.

pub mod cli;
pub mod client;
pub mod commands;
pub mod error;
pub mod forward;
pub mod pty;
pub mod secret;
pub mod upload_filter;

pub use cli::{resolve_socket_path, BridgeArgs, Cli, Command, IngressArgs, NetworkModeArg};
pub use client::{KeepaliveResponse, NdjsonFrame, NdjsonStream, UdsClient};
pub use commands::{
    build_create_draft, format_audit_event, format_timestamp_hms_ms, parse_allow_http_rule,
    parse_bridge_spec, parse_env_pair, parse_secret_flag, resolve_image_spec, resolve_sandbox_id,
    run_cli,
};
pub use error::{CliError, Result};
pub use forward::{parse_local_addr, relay_tcp_to_tunnel_ws, run_forward};
pub use pty::{format_resize_frame, query_terminal_size, RawTerminalGuard};
pub use secret::{seal_secret_from_args, SealedSecretOutput};
pub use upload_filter::{build_upload_tar, should_exclude_path, UploadTarStats};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{
        DownloadFormatArg, ImageCommand, ProfilesCommand, SecretCommand, SecretSealArgs, SignalArg,
    };
    use blackwall_core::{
        BackgroundProcess, BuiltImage, ComputeSpec, ExecRequest, ExecResult, ExportSpec,
        NetworkMode, ProcessInfo, ProcessState, ProfileDraft, SandboxDetail, SandboxSpec,
        SandboxState, SandboxSummary, SignalKind, UploadResult,
    };
    use blackwall_proto::DmVerityConfig;
    use blackwall_secrets::{current_unix_sec, HostKeyPair, SEAL1_PREFIX};
    use bytes::Bytes;
    use clap::Parser;
    use http::{header, Method, Request, Response, StatusCode};
    use http_body_util::{BodyExt, Full};
    use hyper::body::Incoming;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use std::collections::BTreeSet;
    use std::fs;
    use std::io::Cursor;
    use std::path::Path;
    use std::sync::{Arc, Mutex};
    use tokio::net::UnixListener;

    // -----------------------------------------------------------------------
    // 1. CLI clap parsing tests covering every single subcommand
    // -----------------------------------------------------------------------

    #[test]
    fn clap_parses_all_subcommands_and_global_flags() {
        // create
        let cli = Cli::try_parse_from([
            "blackwall",
            "--socket",
            "/tmp/bw.sock",
            "--json",
            "create",
            "--profile",
            "my-repo-agent",
            "--file",
            "sandbox.toml",
            "--workspace-mib",
            "4096",
            "--vcpus",
            "4",
            "--memory-mib",
            "8192",
            "--idle-timeout-sec",
            "300",
            "--max-wall-time-sec",
            "1800",
            "--network",
            "egress",
            "--port",
            "3000",
            "--port",
            "5173",
            "--secret",
            "HTTPBIN_API_KEY=seal1_deadbeef",
            "--allow-http",
            "POST:httpbin.org/anything:HTTPBIN_API_KEY",
            "--allow-http",
            "GET:registry.npmjs.org/",
            "--env",
            "RUST_LOG=debug",
            "--env",
            "FOO=bar=baz",
        ])
        .unwrap();
        assert_eq!(cli.socket.as_deref(), Some(Path::new("/tmp/bw.sock")));
        assert!(cli.json);
        match cli.command {
            Command::Create(args) => {
                assert_eq!(args.profiles, vec!["my-repo-agent"]);
                assert_eq!(args.file.as_deref(), Some(Path::new("sandbox.toml")));
                assert_eq!(args.workspace_mib, Some(4096));
                assert_eq!(args.vcpus, Some(4));
                assert_eq!(args.memory_mib, Some(8192));
                assert_eq!(args.idle_timeout_sec, Some(300));
                assert_eq!(args.max_wall_time_sec, Some(1800));
                assert_eq!(args.network, Some(NetworkModeArg::Egress));
                assert_eq!(args.ports, vec![3000, 5173]);
                assert_eq!(args.secrets, vec!["HTTPBIN_API_KEY=seal1_deadbeef"]);
                assert_eq!(
                    args.allow_http,
                    vec![
                        "POST:httpbin.org/anything:HTTPBIN_API_KEY",
                        "GET:registry.npmjs.org/",
                    ]
                );
                assert_eq!(args.env, vec!["RUST_LOG=debug", "FOO=bar=baz"]);
            }
            other => panic!("expected Create, got {other:?}"),
        }

        // list & ls alias
        let cli = Cli::try_parse_from(["blackwall", "list"]).unwrap();
        assert!(matches!(cli.command, Command::List));
        let cli = Cli::try_parse_from(["blackwall", "ls"]).unwrap();
        assert!(matches!(cli.command, Command::List));

        // inspect
        let cli = Cli::try_parse_from(["blackwall", "inspect", "bw-123"]).unwrap();
        match cli.command {
            Command::Inspect(a) => assert_eq!(a.id, "bw-123"),
            other => panic!("expected Inspect, got {other:?}"),
        }

        // destroy & rm alias
        let cli = Cli::try_parse_from(["blackwall", "destroy", "bw-123"]).unwrap();
        match cli.command {
            Command::Destroy(a) => assert_eq!(a.id, "bw-123"),
            other => panic!("expected Destroy, got {other:?}"),
        }
        let cli = Cli::try_parse_from(["blackwall", "rm", "bw-123"]).unwrap();
        match cli.command {
            Command::Destroy(a) => assert_eq!(a.id, "bw-123"),
            other => panic!("expected Destroy via rm alias, got {other:?}"),
        }

        // exec (sync, stream, background, -d, --bg)
        let cli = Cli::try_parse_from([
            "blackwall",
            "exec",
            "bw-123",
            "--cwd",
            "/workspace",
            "--timeout-sec",
            "60",
            "--env",
            "A=1",
            "--stream",
            "--",
            "cargo",
            "test",
            "--nocapture",
        ])
        .unwrap();
        match cli.command {
            Command::Exec(a) => {
                assert_eq!(a.id, "bw-123");
                assert_eq!(a.cwd.as_deref(), Some("/workspace"));
                assert_eq!(a.timeout_sec, Some(60));
                assert_eq!(a.env, vec!["A=1"]);
                assert!(a.stream);
                assert!(!a.background);
                assert_eq!(a.cmd, vec!["cargo", "test", "--nocapture"]);
            }
            other => panic!("expected Exec, got {other:?}"),
        }

        for bg_flag in ["--background", "-d", "--bg"] {
            let cli = Cli::try_parse_from([
                "blackwall",
                "exec",
                "bw-123",
                bg_flag,
                "--",
                "cargo",
                "run",
                "--bin",
                "server",
            ])
            .unwrap();
            match cli.command {
                Command::Exec(a) => {
                    assert!(a.background, "expected background=true for {bg_flag}");
                    assert_eq!(a.cmd, vec!["cargo", "run", "--bin", "server"]);
                }
                other => panic!("expected Exec, got {other:?}"),
            }
        }

        // ps
        let cli = Cli::try_parse_from(["blackwall", "ps", "bw-123"]).unwrap();
        match cli.command {
            Command::Ps(a) => assert_eq!(a.id, "bw-123"),
            other => panic!("expected Ps, got {other:?}"),
        }

        // logs
        let cli = Cli::try_parse_from([
            "blackwall",
            "logs",
            "bw-123",
            "proc-1",
            "--tail",
            "200",
            "--follow",
        ])
        .unwrap();
        match cli.command {
            Command::Logs(a) => {
                assert_eq!(a.id, "bw-123");
                assert_eq!(a.proc_id, "proc-1");
                assert_eq!(a.tail, Some(200));
                assert!(a.follow);
            }
            other => panic!("expected Logs, got {other:?}"),
        }

        // kill
        let cli = Cli::try_parse_from([
            "blackwall",
            "kill",
            "bw-123",
            "proc-1",
            "--signal",
            "SIGKILL",
        ])
        .unwrap();
        match cli.command {
            Command::Kill(a) => {
                assert_eq!(a.id, "bw-123");
                assert_eq!(a.proc_id, "proc-1");
                assert_eq!(a.signal, Some(SignalArg::Sigkill));
            }
            other => panic!("expected Kill, got {other:?}"),
        }

        // shell
        let cli = Cli::try_parse_from([
            "blackwall",
            "shell",
            "bw-123",
            "--cols",
            "100",
            "--rows",
            "30",
            "--cwd",
            "/workspace",
            "--",
            "/bin/bash",
            "-l",
        ])
        .unwrap();
        match cli.command {
            Command::Shell(a) => {
                assert_eq!(a.id, "bw-123");
                assert_eq!(a.cols, Some(100));
                assert_eq!(a.rows, Some(30));
                assert_eq!(a.cwd.as_deref(), Some("/workspace"));
                assert_eq!(a.cmd, vec!["/bin/bash", "-l"]);
            }
            other => panic!("expected Shell, got {other:?}"),
        }

        // forward (default local and explicit --local)
        let cli = Cli::try_parse_from(["blackwall", "forward", "bw-123", "5173"]).unwrap();
        match cli.command {
            Command::Forward(a) => {
                assert_eq!(a.id, "bw-123");
                assert_eq!(a.guest_port, 5173);
                assert!(a.local.is_none());
                assert_eq!(
                    parse_local_addr(a.local.as_deref(), a.guest_port).unwrap(),
                    "127.0.0.1:5173".parse().unwrap()
                );
            }
            other => panic!("expected Forward, got {other:?}"),
        }

        let cli = Cli::try_parse_from([
            "blackwall",
            "forward",
            "bw-123",
            "3000",
            "--local",
            "127.0.0.1:9000",
        ])
        .unwrap();
        match cli.command {
            Command::Forward(a) => {
                assert_eq!(a.id, "bw-123");
                assert_eq!(a.guest_port, 3000);
                assert_eq!(a.local.as_deref(), Some("127.0.0.1:9000"));
                assert_eq!(
                    parse_local_addr(a.local.as_deref(), a.guest_port).unwrap(),
                    "127.0.0.1:9000".parse().unwrap()
                );
            }
            other => panic!("expected Forward, got {other:?}"),
        }

        // upload
        let cli = Cli::try_parse_from([
            "blackwall",
            "upload",
            "bw-123",
            "./my-project",
            "/workspace",
            "--exclude-secrets",
        ])
        .unwrap();
        match cli.command {
            Command::Upload(a) => {
                assert_eq!(a.id, "bw-123");
                assert_eq!(a.local_path, Path::new("./my-project"));
                assert_eq!(a.remote_path, "/workspace");
                assert!(a.exclude_secrets);
            }
            other => panic!("expected Upload, got {other:?}"),
        }

        // download (-o & --format)
        let cli = Cli::try_parse_from([
            "blackwall",
            "download",
            "bw-123",
            "/workspace",
            "--format",
            "tar.gz",
            "-o",
            "./result.tar.gz",
        ])
        .unwrap();
        match cli.command {
            Command::Download(a) => {
                assert_eq!(a.id, "bw-123");
                assert_eq!(a.remote_path, "/workspace");
                assert_eq!(a.format, Some(DownloadFormatArg::TarGz));
                assert_eq!(a.output.as_deref(), Some(Path::new("./result.tar.gz")));
                assert!(a.unpack_dir.is_none());
            }
            other => panic!("expected Download, got {other:?}"),
        }

        // download (--unpack-dir)
        let cli = Cli::try_parse_from([
            "blackwall",
            "download",
            "bw-123",
            "/workspace",
            "--unpack-dir",
            "./out-dir",
        ])
        .unwrap();
        match cli.command {
            Command::Download(a) => {
                assert_eq!(a.unpack_dir.as_deref(), Some(Path::new("./out-dir")));
            }
            other => panic!("expected Download, got {other:?}"),
        }

        // audit (global default, scoped with --limit & -f)
        let cli = Cli::try_parse_from(["blackwall", "audit"]).unwrap();
        match cli.command {
            Command::Audit(a) => {
                assert!(a.id.is_none());
                assert_eq!(a.limit, 100);
                assert!(!a.follow);
            }
            other => panic!("expected Audit, got {other:?}"),
        }
        let cli = Cli::try_parse_from([
            "blackwall",
            "audit",
            "bw-123",
            "--limit",
            "50",
            "-f",
        ])
        .unwrap();
        match cli.command {
            Command::Audit(a) => {
                assert_eq!(a.id.as_deref(), Some("bw-123"));
                assert_eq!(a.limit, 50);
                assert!(a.follow);
            }
            other => panic!("expected Audit, got {other:?}"),
        }

        // keepalive
        let cli = Cli::try_parse_from(["blackwall", "keepalive", "bw-123"]).unwrap();
        match cli.command {
            Command::Keepalive(a) => assert_eq!(a.id, "bw-123"),
            other => panic!("expected Keepalive, got {other:?}"),
        }

        // image build & image list
        let cli = Cli::try_parse_from([
            "blackwall",
            "image",
            "build",
            "ghcr.io/org/rust-dev:latest",
            "--tag",
            "blackwall/rust-dev:latest",
        ])
        .unwrap();
        match cli.command {
            Command::Image(a) => match a.command {
                ImageCommand::Build(b) => {
                    assert_eq!(b.target, "ghcr.io/org/rust-dev:latest");
                    assert_eq!(b.tag.as_deref(), Some("blackwall/rust-dev:latest"));
                }
                other => panic!("expected Image Build, got {other:?}"),
            },
            other => panic!("expected Image, got {other:?}"),
        }

        let cli = Cli::try_parse_from(["blackwall", "image", "list"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Image(a) if matches!(a.command, ImageCommand::List(_))
        ));

        // secret seal (and confirm no --value CLI flag exists!)
        let cli = Cli::try_parse_from([
            "blackwall",
            "secret",
            "seal",
            "--name",
            "GITHUB_TOKEN",
            "--hosts",
            "api.github.com,github.com",
            "--paths",
            "/repos/my-org/my-repo/,/my-org/my-repo.git/",
            "--policy-tag",
            "prod",
            "--exp-sec",
            "3600",
            "--key-path",
            "/tmp/host.key",
            "--value-env",
            "MY_TOKEN",
            "--raw",
        ])
        .unwrap();
        match cli.command {
            Command::Secret(a) => match a.command {
                SecretCommand::Seal(s) => {
                    assert_eq!(s.name, "GITHUB_TOKEN");
                    assert_eq!(s.hosts, vec!["api.github.com", "github.com"]);
                    assert_eq!(
                        s.paths,
                        vec!["/repos/my-org/my-repo/", "/my-org/my-repo.git/"]
                    );
                    assert_eq!(s.policy_tag, "prod");
                    assert_eq!(s.exp_sec, Some(3600));
                    assert_eq!(s.key_path.as_deref(), Some(Path::new("/tmp/host.key")));
                    assert_eq!(s.value_env.as_deref(), Some("MY_TOKEN"));
                    assert!(s.raw);
                }
            },
            other => panic!("expected Secret, got {other:?}"),
        }
        assert!(
            Cli::try_parse_from([
                "blackwall",
                "secret",
                "seal",
                "--name",
                "GITHUB_TOKEN",
                "--value",
                "leaked_in_ps",
            ])
            .is_err(),
            "--value CLI flag must NOT exist to prevent argv secret leakage"
        );

        // profiles & profiles show
        let cli = Cli::try_parse_from(["blackwall", "profiles"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Profiles(a) if a.command.is_none()
        ));

        let cli = Cli::try_parse_from(["blackwall", "profiles", "show", "rust-dev"]).unwrap();
        match cli.command {
            Command::Profiles(a) => match a.command {
                Some(ProfilesCommand::Show { name }) => assert_eq!(name, "rust-dev"),
                other => panic!("expected Profiles Show, got {other:?}"),
            },
            other => panic!("expected Profiles, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // 2. --exclude-secrets tar builder test
    // -----------------------------------------------------------------------

    #[test]
    fn exclude_secrets_tar_filters_sensitive_and_build_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();

        let files = [
            // Normal source files that MUST be included
            ("Cargo.toml", "[package]\nname = \"demo\"\n"),
            ("src/main.rs", "fn main() {}\n"),
            ("src/env_loader.rs", "// normal rust file\n"),
            ("README.md", "# Demo\n"),
            // Secrets & sensitive files that MUST be excluded
            (".env", "SECRET=1\n"),
            (".env.local", "SECRET=2\n"),
            ("sub/.env.production", "SECRET=3\n"),
            (".npmrc", "//registry.npmjs.org/:_authToken=secret\n"),
            (".yarnrc.yml", "npmAuthToken: secret\n"),
            (".pypirc", "[pypi]\npassword = secret\n"),
            (".netrc", "machine github.com password secret\n"),
            (".docker/config.json", "{\"auths\":{}}\n"),
            (".git/config", "[core]\n"),
            (".git/credentials", "https://user:pass@github.com\n"),
            (".git/hooks/pre-commit", "#!/bin/sh\n"),
            ("certs/server.pem", "-----BEGIN CERTIFICATE-----\n"),
            ("priv.key", "-----BEGIN PRIVATE KEY-----\n"),
            (".ssh/id_rsa", "RSA KEY\n"),
            (".ssh/id_ed25519", "ED25519 KEY\n"),
            // Heavy build directories that MUST be excluded
            ("target/debug/bin", "ELF\n"),
            ("node_modules/pkg/index.js", "module.exports = {};\n"),
            (".venv/bin/python", "py\n"),
        ];

        for (rel, body) in files {
            let p = root.join(rel);
            if let Some(parent) = p.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(&p, body).unwrap();
        }

        let (tar_bytes, stats) = build_upload_tar(root, true).unwrap();
        assert_eq!(stats.files_included, 4);

        let mut archive = tar::Archive::new(Cursor::new(&tar_bytes));
        let mut entry_paths = BTreeSet::new();
        for entry in archive.entries().unwrap() {
            let entry = entry.unwrap();
            let p = entry.path().unwrap().to_string_lossy().into_owned();
            entry_paths.insert(p);
        }

        // Included normal source files
        assert!(entry_paths.contains("Cargo.toml"));
        assert!(entry_paths.contains("src/main.rs"));
        assert!(entry_paths.contains("src/env_loader.rs"));
        assert!(entry_paths.contains("README.md"));

        // Excluded secret & build paths
        for forbidden in [
            ".env",
            ".env.local",
            "sub/.env.production",
            ".npmrc",
            ".yarnrc.yml",
            ".pypirc",
            ".netrc",
            ".docker/config.json",
            ".git/config",
            ".git/credentials",
            ".git/hooks/pre-commit",
            "certs/server.pem",
            "priv.key",
            ".ssh/id_rsa",
            ".ssh/id_ed25519",
            "target/debug/bin",
            "node_modules/pkg/index.js",
            ".venv/bin/python",
        ] {
            assert!(
                !entry_paths.contains(forbidden),
                "forbidden path '{forbidden}' leaked into upload tar!"
            );
        }
    }

    // -----------------------------------------------------------------------
    // 3. secret seal test (stdin & --value-env)
    // -----------------------------------------------------------------------

    #[test]
    fn secret_seal_via_stdin_and_env_opens_cleanly_with_host_keypair() {
        let tmp = tempfile::tempdir().unwrap();
        let key_path = tmp.path().join("host.key");

        // 1. Seal from stdin (trailing newline stripped)
        let args = SecretSealArgs {
            name: "GITHUB_TOKEN".into(),
            hosts: vec!["api.github.com".into(), "github.com".into()],
            paths: vec!["/repos/my-org/my-repo/".into()],
            policy_tag: "ci-agent".into(),
            exp_sec: Some(3600),
            key_path: Some(key_path.clone()),
            value_env: None,
            placeholder_prefix: None,
            raw: false,
        };

        let out = seal_secret_from_args(&args, Cursor::new(b"ghp_REAL_SECRET_VALUE\n")).unwrap();
        assert!(out.sealed.starts_with(SEAL1_PREFIX));
        assert_eq!(out.placeholder_prefix, "ghp_bw00_");
        let snippet = out.to_toml_snippet();
        assert!(snippet.contains("[secrets.GITHUB_TOKEN]"));
        assert!(snippet.contains(&out.sealed));

        // Open with HostKeyPair loaded from disk and verify binding + plaintext
        let kp = HostKeyPair::load_or_generate(&key_path).unwrap();
        let opened = kp.open(&out.sealed, current_unix_sec()).unwrap();
        assert_eq!(opened.secret.as_bytes(), b"ghp_REAL_SECRET_VALUE");
        assert_eq!(
            opened.binding.allow_hosts,
            vec!["api.github.com".to_string(), "github.com".to_string()]
        );
        assert_eq!(
            opened.binding.allow_path_templates,
            vec!["/repos/my-org/my-repo/".to_string()]
        );
        assert_eq!(opened.binding.policy_tag, "ci-agent");
        assert!(opened.binding.exp_unix_sec.is_some());

        // 2. Seal via --value-env
        let env_var = "BLACKWALL_CLI_TEST_SECRET_TOKEN";
        std::env::set_var(env_var, "sk-env-secret-999");
        let env_args = SecretSealArgs {
            name: "API_TOKEN".into(),
            hosts: vec!["api.example.com".into()],
            paths: vec!["/v1/*".into()],
            policy_tag: "dev".into(),
            exp_sec: None,
            key_path: Some(key_path.clone()),
            value_env: Some(env_var.into()),
            placeholder_prefix: Some("sk_bw_".into()),
            raw: true,
        };
        let env_out = seal_secret_from_args(&env_args, Cursor::new(b"")).unwrap();
        std::env::remove_var(env_var);

        assert!(env_out.sealed.starts_with(SEAL1_PREFIX));
        assert_eq!(env_out.placeholder_prefix, "sk_bw_");
        let opened_env = kp.open(&env_out.sealed, current_unix_sec()).unwrap();
        assert_eq!(opened_env.secret.as_bytes(), b"sk-env-secret-999");
        assert_eq!(opened_env.binding.allow_hosts, vec!["api.example.com"]);
        assert_eq!(opened_env.binding.allow_path_templates, vec!["/v1/*"]);
    }

    // -----------------------------------------------------------------------
    // 4. UDS HTTP client round-trip test against local mock UDS HTTP server
    // -----------------------------------------------------------------------

    #[derive(Default)]
    struct MockState {
        uploaded_path: Option<String>,
        uploaded_content_type: Option<String>,
        uploaded_body: Vec<u8>,
        destroyed_ids: Vec<String>,
        signaled: Vec<(String, String, SignalKind)>,
    }

    async fn spawn_mock_uds_server(
        sock_path: &Path,
        state: Arc<Mutex<MockState>>,
    ) -> tokio::task::JoinHandle<()> {
        let listener = UnixListener::bind(sock_path).unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let svc = service_fn(move |req: Request<Incoming>| {
                        let state = Arc::clone(&state);
                        async move { handle_mock_request(req, state).await }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, svc)
                        .await;
                });
            }
        })
    }

    async fn handle_mock_request(
        req: Request<Incoming>,
        state: Arc<Mutex<MockState>>,
    ) -> std::result::Result<Response<Full<Bytes>>, std::convert::Infallible> {
        let method = req.method().clone();
        let path = req.uri().path().to_string();
        let query = req.uri().query().unwrap_or("").to_string();
        let content_type = req
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(ToOwned::to_owned);
        let body = req
            .into_body()
            .collect()
            .await
            .map(|c| c.to_bytes())
            .unwrap_or_default();

        let resp = match (method, path.as_str()) {
            (Method::POST, "/v1/sandboxes") => {
                let draft: ProfileDraft = serde_json::from_slice(&body).unwrap();
                let profile = draft
                    .extends
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "base".into());
                let summary: SandboxSummary = serde_json::from_value(serde_json::json!({
                    "id": "sb-mock0001",
                    "profile": profile,
                    "state": SandboxState::Running,
                    "image_roothash": "deadbeef",
                    "image_content_hash": "cafebabe",
                    "kernel_profile": "vmlinux-lo",
                    "vmm_backend": "mock",
                    "vmm_pid": 4242,
                    "proxy_pid": null,
                    "proxy_isolated": false,
                    "boot_duration_ms": 42,
                    "guest_init_version": "0.1.0",
                    "workspace_mounted": true,
                    "netbridge_ready": false,
                    "compute": ComputeSpec::default(),
                    "network_mode": NetworkMode::Loopback,
                    "allowed_hosts": [],
                    "ingress_allow_ports": [],
                    "created_at": 1000,
                    "expires_at": 4600,
                    "idle_deadline_at": 1600,
                    "uptime_sec": 1,
                    "idle_remaining_sec": 599,
                    "wall_remaining_sec": 3599,
                }))
                .unwrap();
                json_response(StatusCode::CREATED, &summary)
            }
            (Method::GET, "/v1/sandboxes") => {
                let summary: SandboxSummary = serde_json::from_value(serde_json::json!({
                    "id": "sb-mock0001",
                    "profile": "base",
                    "state": SandboxState::Running,
                    "image_roothash": "deadbeef",
                    "image_content_hash": "cafebabe",
                    "kernel_profile": "vmlinux-lo",
                    "vmm_backend": "mock",
                    "vmm_pid": 4242,
                    "proxy_pid": null,
                    "proxy_isolated": false,
                    "boot_duration_ms": 42,
                    "guest_init_version": "0.1.0",
                    "workspace_mounted": true,
                    "netbridge_ready": false,
                    "compute": ComputeSpec::default(),
                    "network_mode": NetworkMode::Loopback,
                    "allowed_hosts": [],
                    "ingress_allow_ports": [],
                    "created_at": 1000,
                    "expires_at": 4600,
                    "idle_deadline_at": 1600,
                    "uptime_sec": 1,
                    "idle_remaining_sec": 599,
                    "wall_remaining_sec": 3599,
                }))
                .unwrap();
                json_response(StatusCode::OK, &vec![summary])
            }
            (Method::GET, "/v1/sandboxes/sb-mock0001") => {
                let detail: SandboxDetail = serde_json::from_value(serde_json::json!({
                    "id": "sb-mock0001",
                    "profile": "base",
                    "state": SandboxState::Running,
                    "image_roothash": "deadbeef",
                    "image_content_hash": "cafebabe",
                    "kernel_profile": "vmlinux-lo",
                    "vmm_backend": "mock",
                    "boot_duration_ms": 42,
                    "guest_init_version": "0.1.0",
                    "workspace_mounted": true,
                    "netbridge_ready": false,
                    "created_at": 1000,
                    "expires_at": 4600,
                    "idle_deadline_at": 1600,
                    "uptime_sec": 1,
                    "idle_remaining_sec": 599,
                    "wall_remaining_sec": 3599,
                    "compute": ComputeSpec::default(),
                    "network_mode": NetworkMode::Loopback,
                    "allowed_hosts": [],
                    "ingress_allow_ports": [],
                    "pinned_dns": {},
                    "configured_secrets": [],
                    "export": ExportSpec::default(),
                    "processes": [],
                    "vmm_pid": 4242,
                    "proxy_pid": null,
                    "proxy_isolated": false,
                    "stats": blackwall_core::SandboxRunStats::default(),
                }))
                .unwrap();
                json_response(StatusCode::OK, &detail)
            }
            (Method::POST, "/v1/sandboxes/sb-mock0001/exec") => {
                let exec_req: ExecRequest = serde_json::from_slice(&body).unwrap();
                if query.contains("stream=true") {
                    let ndjson = concat!(
                        "{\"type\":\"stdout\",\"data\":\"stream-hello\\n\"}\n",
                        "{\"type\":\"stderr\",\"data\":\"stream-warn\\n\"}\n",
                        "{\"type\":\"exit\",\"exit_code\":0,\"timed_out\":false,\"duration_ms\":12}\n"
                    );
                    Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "application/x-ndjson")
                        .body(Full::new(Bytes::from_static(ndjson.as_bytes())))
                        .unwrap()
                } else if exec_req.background {
                    let bg = BackgroundProcess {
                        sandbox_id: "sb-mock0001".into(),
                        proc_id: "proc-bg1".into(),
                        pid: 777,
                        cmd: exec_req.cmd.clone(),
                        cwd: "/workspace".into(),
                        started_at_ms: 1000,
                    };
                    json_response(StatusCode::ACCEPTED, &bg)
                } else {
                    let stdout = format!("ran: {}", exec_req.cmd.join(" "));
                    let stdout_bytes_len = stdout.len();
                    let res = ExecResult {
                        sandbox_id: "sb-mock0001".into(),
                        cmd: exec_req.cmd.clone(),
                        cwd: "/workspace".into(),
                        exit_code: 0,
                        success: true,
                        stdout,
                        stderr: String::new(),
                        stdout_bytes: Vec::new(),
                        stderr_bytes: Vec::new(),
                        stdout_bytes_len,
                        stderr_bytes_len: 0,
                        timed_out: false,
                        duration_ms: 5,
                        started_at_ms: 1000,
                        finished_at_ms: 1005,
                    };
                    json_response(StatusCode::OK, &res)
                }
            }
            (Method::GET, "/v1/sandboxes/sb-mock0001/processes") => {
                let procs = vec![ProcessInfo {
                    proc_id: "proc-bg1".into(),
                    pid: 777,
                    cmd: vec!["sleep".into(), "10".into()],
                    state: ProcessState::Running,
                    exit_code: None,
                }];
                json_response(StatusCode::OK, &procs)
            }
            (Method::POST, "/v1/sandboxes/sb-mock0001/processes/proc-bg1/signal") => {
                let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
                let sig: SignalKind = serde_json::from_value(v["signal"].clone()).unwrap();
                state
                    .lock()
                    .unwrap()
                    .signaled
                    .push(("sb-mock0001".into(), "proc-bg1".into(), sig));
                Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body(Full::new(Bytes::new()))
                    .unwrap()
            }
            (Method::PUT, "/v1/sandboxes/sb-mock0001/files") => {
                let mut st = state.lock().unwrap();
                st.uploaded_path = Some(query);
                st.uploaded_content_type = content_type;
                st.uploaded_body = body.to_vec();
                let res = UploadResult {
                    sandbox_id: "sb-mock0001".into(),
                    path: "/workspace/file".into(),
                    kind: blackwall_core::UploadKind::Raw,
                    bytes_written: body.len() as u64,
                    files_written: 1,
                    duration_ms: 1,
                };
                json_response(StatusCode::OK, &res)
            }
            (Method::GET, "/v1/sandboxes/sb-mock0001/files") => {
                let data = state.lock().unwrap().uploaded_body.clone();
                Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "application/octet-stream")
                    .body(Full::new(Bytes::from(data)))
                    .unwrap()
            }
            (Method::DELETE, "/v1/sandboxes/sb-mock0001") => {
                state
                    .lock()
                    .unwrap()
                    .destroyed_ids
                    .push("sb-mock0001".into());
                Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body(Full::new(Bytes::new()))
                    .unwrap()
            }
            (Method::GET, "/v1/profiles") => {
                json_response(StatusCode::OK, &vec!["base", "rust-dev"])
            }
            (Method::GET, "/v1/profiles/base") => {
                json_response(StatusCode::OK, &SandboxSpec::base())
            }
            (Method::GET, "/v1/images") => {
                let imgs = vec![BuiltImage {
                    content_hash: "0123456789abcdef".into(),
                    erofs_path: "/cache/vda.erofs".into(),
                    verity: DmVerityConfig {
                        roothash_hex: "aa".repeat(32),
                        salt_hex: "bb".repeat(16),
                        data_blocks: 10,
                        hash_start_block: 10,
                        data_block_size: 4096,
                        hash_block_size: 4096,
                    },
                }];
                json_response(StatusCode::OK, &imgs)
            }
            _ => Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Full::new(Bytes::from_static(
                    br#"{"error":"not found"}"#,
                )))
                .unwrap(),
        };

        Ok(resp)
    }

    fn json_response<T: serde::Serialize>(status: StatusCode, val: &T) -> Response<Full<Bytes>> {
        let bytes = serde_json::to_vec(val).unwrap();
        Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(bytes)))
            .unwrap()
    }

    #[tokio::test]
    async fn uds_http_client_round_trip_create_exec_stream_upload_download_destroy() {
        let tmp = tempfile::tempdir().unwrap();
        let sock_path = tmp.path().join("mock-blackwall.sock");
        let state = Arc::new(Mutex::new(MockState::default()));
        let server_task = spawn_mock_uds_server(&sock_path, Arc::clone(&state)).await;

        let client = UdsClient::new(&sock_path);

        // 1. Create
        let draft = ProfileDraft {
            extends: vec!["rust-dev".into()],
            ..ProfileDraft::default()
        };
        let created = client.create_sandbox(&draft).await.unwrap();
        assert_eq!(created.id, "sb-mock0001");
        assert_eq!(created.profile, "rust-dev");

        // List & Inspect
        let listed = client.list_sandboxes().await.unwrap();
        assert_eq!(listed.len(), 1);
        let detail = client.inspect_sandbox(&created.id).await.unwrap();
        assert_eq!(detail.vmm_pid, 4242);

        // 2. Sync exec
        let sync_res = client
            .exec_sync(&created.id, &ExecRequest::new(["echo", "hello"]))
            .await
            .unwrap();
        assert_eq!(sync_res.exit_code, 0);
        assert_eq!(sync_res.stdout, "ran: echo hello");

        // 3. Streaming NDJSON exec
        let mut stream = client
            .exec_stream(&created.id, &ExecRequest::new(["echo", "stream"]))
            .await
            .unwrap();
        let mut frames = Vec::new();
        while let Some((_raw, frame)) = stream.next_frame().await.unwrap() {
            frames.push(frame);
        }
        assert_eq!(
            frames,
            vec![
                NdjsonFrame::Stdout("stream-hello\n".into()),
                NdjsonFrame::Stderr("stream-warn\n".into()),
                NdjsonFrame::Exit {
                    exit_code: 0,
                    timed_out: false,
                    duration_ms: 12,
                },
            ]
        );

        // Background exec, ps, signal
        let bg = client
            .exec_background(&created.id, &ExecRequest::new(["sleep", "10"]))
            .await
            .unwrap();
        assert_eq!(bg.proc_id, "proc-bg1");
        let procs = client.list_processes(&created.id).await.unwrap();
        assert_eq!(procs.len(), 1);
        client
            .signal_process(&created.id, &bg.proc_id, SignalKind::Sigterm)
            .await
            .unwrap();
        assert_eq!(state.lock().unwrap().signaled.len(), 1);

        // 4. Upload & Download
        let upload_payload = Bytes::from_static(b"hello over uds!\n");
        let up_res = client
            .upload_files(
                &created.id,
                "/workspace/hello.txt",
                "application/octet-stream",
                upload_payload.clone(),
            )
            .await
            .unwrap();
        assert_eq!(up_res.bytes_written, upload_payload.len() as u64);
        assert_eq!(
            state.lock().unwrap().uploaded_content_type.as_deref(),
            Some("application/octet-stream")
        );

        let dl_bytes = client
            .download_files(&created.id, "/workspace/hello.txt", "raw")
            .await
            .unwrap();
        assert_eq!(dl_bytes, upload_payload);

        // Profiles & Images
        let profiles = client.list_profiles().await.unwrap();
        assert!(profiles.contains(&"base".to_string()));
        let base_spec = client.get_profile("base").await.unwrap();
        assert_eq!(base_spec.name, "base");
        let images = client.list_images().await.unwrap();
        assert_eq!(images.len(), 1);

        // 5. Destroy
        client.destroy_sandbox(&created.id).await.unwrap();
        assert_eq!(state.lock().unwrap().destroyed_ids, vec!["sb-mock0001"]);

        server_task.abort();
    }

    #[test]
    fn build_create_draft_and_resolve_image_spec() {
        let tmp = tempfile::tempdir().unwrap();
        let profile_path = tmp.path().join("custom.toml");
        fs::write(
            &profile_path,
            r#"
version = 1
name = "custom"
extends = ["base"]

[image]
base = "debian:bookworm-slim"
packages = ["git", "curl"]

[compute]
vcpus = 2
memory_mib = 1024

[env]
FROM_FILE = "yes"
"#,
        )
        .unwrap();

        let cli = Cli::try_parse_from([
            "blackwall",
            "create",
            "--file",
            profile_path.to_str().unwrap(),
            "--profile",
            "rust-dev",
            "--vcpus",
            "4",
            "--workspace-mib",
            "2048",
            "--env",
            "EXTRA=1",
        ])
        .unwrap();

        let Command::Create(args) = cli.command else {
            unreachable!()
        };
        let draft = build_create_draft(&args).unwrap();
        assert_eq!(draft.extends, vec!["base", "rust-dev"]);
        let compute = draft.compute.unwrap();
        assert_eq!(compute.vcpus, Some(4));
        assert_eq!(compute.memory_mib, Some(1024));
        assert_eq!(compute.workspace_mib, Some(2048));
        assert_eq!(draft.env.get("FROM_FILE").map(String::as_str), Some("yes"));
        assert_eq!(draft.env.get("EXTRA").map(String::as_str), Some("1"));

        let from_toml = resolve_image_spec(profile_path.to_str().unwrap()).unwrap();
        assert_eq!(from_toml.base.as_deref(), Some("debian:bookworm-slim"));
        assert_eq!(from_toml.packages, vec!["git", "curl"]);

        let from_oci = resolve_image_spec("ghcr.io/org/rust-dev:latest").unwrap();
        assert_eq!(
            from_oci.image_ref.as_deref(),
            Some("ghcr.io/org/rust-dev:latest")
        );
    }

    #[tokio::test]
    async fn download_unpack_dir_enforces_unpacker_deny_touch_globs() {
        use flate2::write::GzEncoder;
        use flate2::Compression;

        fn make_targz(files: &[(&str, &[u8])]) -> Vec<u8> {
            let mut gz = GzEncoder::new(Vec::new(), Compression::default());
            {
                let mut builder = tar::Builder::new(&mut gz);
                for &(path, data) in files {
                    let mut hdr = tar::Header::new_gnu();
                    hdr.set_entry_type(tar::EntryType::Regular);
                    hdr.set_size(data.len() as u64);
                    hdr.set_mode(0o644);
                    hdr.set_uid(0);
                    hdr.set_gid(0);
                    hdr.set_mtime(0);
                    hdr.set_cksum();
                    builder.append_data(&mut hdr, path, data).unwrap();
                }
                builder.finish().unwrap();
            }
            gz.finish().unwrap()
        }

        let tmp = tempfile::tempdir().unwrap();
        let sock_path = tmp.path().join("unpack-test.sock");
        let state = Arc::new(Mutex::new(MockState::default()));
        let server_task = spawn_mock_uds_server(&sock_path, Arc::clone(&state)).await;

        // 1. Safe archive unpacks cleanly
        state.lock().unwrap().uploaded_body =
            make_targz(&[("src/hello.rs", b"pub fn hi() {}\n")]);
        let good_dir = tmp.path().join("good-out");
        let cli = Cli::try_parse_from([
            "blackwall",
            "--socket",
            sock_path.to_str().unwrap(),
            "download",
            "sb-mock0001",
            "/workspace",
            "--unpack-dir",
            good_dir.to_str().unwrap(),
        ])
        .unwrap();
        assert_eq!(run_cli(cli).await.unwrap(), 0);
        assert_eq!(
            fs::read_to_string(good_dir.join("src/hello.rs")).unwrap(),
            "pub fn hi() {}\n"
        );

        // 2. Archive containing case-bypass `.GitHub/workflows/ci.yml` is rejected!
        state.lock().unwrap().uploaded_body =
            make_targz(&[(".GitHub/workflows/ci.yml", b"name: pwn\n")]);
        let bad_dir = tmp.path().join("bad-out");
        let cli = Cli::try_parse_from([
            "blackwall",
            "--socket",
            sock_path.to_str().unwrap(),
            "download",
            "sb-mock0001",
            "/workspace",
            "--unpack-dir",
            bad_dir.to_str().unwrap(),
        ])
        .unwrap();
        let err = run_cli(cli).await.unwrap_err();
        assert!(
            matches!(err, CliError::Unpacker(_)),
            "expected Unpacker rejection for .GitHub/workflows/ci.yml, got {err:?}"
        );

        server_task.abort();
    }

    #[tokio::test]
    async fn pty_websocket_over_uds_exchanges_binary_and_resize_frames() {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::Message;

        let tmp = tempfile::tempdir().unwrap();
        let sock_path = tmp.path().join("pty-ws.sock");
        let listener = UnixListener::bind(&sock_path).unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();

            // Expect binary input frame from client
            let msg = ws.next().await.unwrap().unwrap();
            assert_eq!(msg, Message::Binary(b"echo ok\n".to_vec()));

            // Expect resize JSON text frame
            let resize = ws.next().await.unwrap().unwrap();
            let Message::Text(txt) = resize else {
                panic!("expected resize text frame, got {resize:?}");
            };
            let v: serde_json::Value = serde_json::from_str(&txt).unwrap();
            assert_eq!(v["type"], "resize");
            assert_eq!(v["cols"], 132);
            assert_eq!(v["rows"], 50);

            // Send binary output and exit frame back
            ws.send(Message::Binary(b"ok\r\n".to_vec())).await.unwrap();
            ws.send(Message::Text(r#"{"type":"exit","code":0}"#.into()))
                .await
                .unwrap();
        });

        let client = UdsClient::new(&sock_path);
        let mut ws = client
            .connect_pty_ws("sb-1", 120, 40, Some("/workspace"), &["/bin/sh".into()])
            .await
            .unwrap();
        ws.send(Message::Binary(b"echo ok\n".to_vec())).await.unwrap();
        ws.send(Message::Text(format_resize_frame(132, 50)))
            .await
            .unwrap();

        let out = ws.next().await.unwrap().unwrap();
        assert_eq!(out, Message::Binary(b"ok\r\n".to_vec()));
        let exit = ws.next().await.unwrap().unwrap();
        assert_eq!(exit, Message::Text(r#"{"type":"exit","code":0}"#.into()));

        server.await.unwrap();
    }

    #[test]
    fn create_flags_build_network_ports_secrets_and_http_rules() {
        use blackwall_policy::AuthSpec;

        // --allow-http auto-enables egress mode when --network is omitted
        let cli = Cli::try_parse_from([
            "blackwall",
            "create",
            "--port",
            "3000",
            "--port",
            "5173",
            "--secret",
            "HTTPBIN_API_KEY=seal1_abc123",
            "--allow-http",
            "POST:httpbin.org/anything:HTTPBIN_API_KEY",
            "--allow-http",
            "GET:registry.npmjs.org/",
            "--allow-http",
            "get,post:api.example.com:8443/v1:HTTPBIN_API_KEY",
            "--allow-http",
            "GET:internal.example.com:8443",
            "--allow-http",
            "GET:plain.example.com",
        ])
        .unwrap();
        let Command::Create(args) = cli.command else {
            unreachable!()
        };
        let draft = build_create_draft(&args).unwrap();

        let ingress = draft.ingress.expect("ingress patch should be populated");
        assert_eq!(ingress.allow_ports, vec![3000, 5173]);

        let sec = draft
            .secrets
            .get("HTTPBIN_API_KEY")
            .expect("secret should be populated");
        assert_eq!(sec.sealed.as_deref(), Some("seal1_abc123"));
        assert!(sec.ephemeral.is_none());
        assert_eq!(sec.placeholder_prefix, "bw_httpbin_api_key_");

        let net = draft.network.expect("network patch should be populated");
        assert_eq!(net.mode, Some(NetworkMode::Egress));
        assert_eq!(net.http.len(), 5);

        assert_eq!(net.http[0].host, "httpbin.org");
        assert_eq!(net.http[0].port, 443);
        assert_eq!(net.http[0].methods, vec!["POST"]);
        assert_eq!(net.http[0].path_prefixes, vec!["/anything"]);
        assert_eq!(
            net.http[0].auth,
            Some(AuthSpec::Bearer {
                secret: "HTTPBIN_API_KEY".into()
            })
        );

        assert_eq!(net.http[1].host, "registry.npmjs.org");
        assert_eq!(net.http[1].port, 443);
        assert_eq!(net.http[1].methods, vec!["GET"]);
        assert_eq!(net.http[1].path_prefixes, vec!["/"]);
        assert_eq!(net.http[1].auth, None);

        assert_eq!(net.http[2].host, "api.example.com");
        assert_eq!(net.http[2].port, 8443);
        assert_eq!(net.http[2].methods, vec!["GET", "POST"]);
        assert_eq!(net.http[2].path_prefixes, vec!["/v1"]);
        assert_eq!(
            net.http[2].auth,
            Some(AuthSpec::Bearer {
                secret: "HTTPBIN_API_KEY".into()
            })
        );

        assert_eq!(net.http[3].host, "internal.example.com");
        assert_eq!(net.http[3].port, 8443);
        assert_eq!(net.http[3].path_prefixes, vec!["/"]);
        assert_eq!(net.http[3].auth, None);

        assert_eq!(net.http[4].host, "plain.example.com");
        assert_eq!(net.http[4].port, 443);
        assert_eq!(net.http[4].path_prefixes, vec!["/"]);
        assert_eq!(net.http[4].auth, None);

        // Plaintext secret via --secret is rejected with guidance to use `blackwall secret seal --raw`
        let err = parse_secret_flag("API_KEY=sk_live_plaintext").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("blackwall secret seal --raw"), "got: {msg}");

        // Explicit --network none is respected
        let cli_none =
            Cli::try_parse_from(["blackwall", "create", "--network", "none"]).unwrap();
        let Command::Create(args_none) = cli_none.command else {
            unreachable!()
        };
        let draft_none = build_create_draft(&args_none).unwrap();
        assert_eq!(draft_none.network.unwrap().mode, Some(NetworkMode::None));

        // Invalid --allow-http rules fail cleanly
        assert!(parse_allow_http_rule("no-colon").is_err());
        assert!(parse_allow_http_rule(":host/path").is_err());
        assert!(parse_allow_http_rule("GET:host/path:").is_err());
        assert!(parse_allow_http_rule("GET::443/path").is_err());
    }

    #[test]
    fn format_audit_event_covers_key_event_types() {
        use blackwall_audit::{AuditEvent, AuditEventKind, AuditOrigin, TransferDirection};

        // 12:34:56.789 UTC
        let ts = ((12 * 3600 + 34 * 60 + 56) * 1000) + 789;

        let http_ev = AuditEvent {
            timestamp_ms: ts,
            sandbox_id: "bw-2ca91234".into(),
            origin: AuditOrigin::Proxy,
            kind: AuditEventKind::HttpRequest {
                host: "httpbin.org".into(),
                method: "POST".into(),
                path: "/anything".into(),
                status: 200,
                request_bytes: 120,
                response_bytes: 466,
                auth_injected: true,
            },
        };
        let http_line = format_audit_event(&http_ev);
        assert!(http_line.starts_with("12:34:56.789"));
        assert!(http_line.contains("HTTP 200"));
        assert!(http_line.contains("bw-2ca91234"));
        assert!(http_line.contains("POST httpbin.org/anything (466 B) [auth injected]"));

        let dns_deny = AuditEvent {
            timestamp_ms: ts,
            sandbox_id: "bw-2ca91234".into(),
            origin: AuditOrigin::Proxy,
            kind: AuditEventKind::DnsQuery {
                fqdn: "google.com".into(),
                allowed: false,
                synthetic_ip: None,
            },
        };
        let dns_line = format_audit_event(&dns_deny);
        assert!(dns_line.contains("DNS DENY"));
        assert!(dns_line.contains("google.com -> NXDOMAIN"));

        let auth_mismatch = AuditEvent {
            timestamp_ms: ts,
            sandbox_id: "bw-2ca91234".into(),
            origin: AuditOrigin::Proxy,
            kind: AuditEventKind::AuthMismatch {
                host: "evil.example".into(),
                path: "/steal".into(),
                reason: "host not bound".into(),
            },
        };
        let auth_line = format_audit_event(&auth_mismatch);
        assert!(auth_line.contains("AUTH MISMATCH"));
        assert!(auth_line.contains("evil.example/steal (host not bound)"));

        let ingress = AuditEvent {
            timestamp_ms: ts,
            sandbox_id: "bw-2ca91234".into(),
            origin: AuditOrigin::Daemon,
            kind: AuditEventKind::IngressTunnel {
                guest_port: 3000,
                bytes_in: 100,
                bytes_out: 250,
                allowed: true,
            },
        };
        let ingress_line = format_audit_event(&ingress);
        assert!(ingress_line.contains("INGRESS"));
        assert!(ingress_line.contains("port 3000"));

        let transfer = AuditEvent {
            timestamp_ms: ts,
            sandbox_id: "bw-2ca91234".into(),
            origin: AuditOrigin::Daemon,
            kind: AuditEventKind::FileTransfer {
                direction: TransferDirection::Upload,
                path: "/workspace/app".into(),
                bytes: 2048,
                files: 3,
            },
        };
        let transfer_line = format_audit_event(&transfer);
        assert!(transfer_line.contains("UPLOAD"));
        assert!(transfer_line.contains("/workspace/app"));

        let bridge_allow = AuditEvent {
            timestamp_ms: ts,
            sandbox_id: "bw-2ca91234".into(),
            origin: AuditOrigin::Daemon,
            kind: AuditEventKind::HostServiceBridge {
                name: "pg".into(),
                guest_port: 5432,
                target: "127.0.0.1:5435".into(),
                bytes_in: 512,
                bytes_out: 2048,
                allowed: true,
            },
        };
        let bridge_allow_line = format_audit_event(&bridge_allow);
        assert!(bridge_allow_line.contains("BRIDGE"));
        assert!(!bridge_allow_line.contains("BRIDGE DENY"));
        assert!(
            bridge_allow_line.contains("pg :5432 -> 127.0.0.1:5435 (in 512 B / out 2048 B)"),
            "got: {bridge_allow_line}"
        );

        let bridge_deny = AuditEvent {
            timestamp_ms: ts,
            sandbox_id: "bw-2ca91234".into(),
            origin: AuditOrigin::Daemon,
            kind: AuditEventKind::HostServiceBridge {
                name: "sock".into(),
                guest_port: 9000,
                target: "unix:///run/svc.sock".into(),
                bytes_in: 0,
                bytes_out: 0,
                allowed: false,
            },
        };
        let bridge_deny_line = format_audit_event(&bridge_deny);
        assert!(bridge_deny_line.contains("BRIDGE DENY"));
        assert!(
            bridge_deny_line.contains("sock :9000 -> unix:///run/svc.sock (blocked)"),
            "got: {bridge_deny_line}"
        );
    }

    #[tokio::test]
    async fn resolve_sandbox_id_audit_and_keepalive_over_uds() {
        use blackwall_audit::{AuditEvent, AuditEventKind, AuditOrigin};

        fn sample_summary(id: &str) -> SandboxSummary {
            serde_json::from_value(serde_json::json!({
                "id": id,
                "profile": "base",
                "state": SandboxState::Running,
                "image_roothash": "deadbeef",
                "image_content_hash": "cafebabe",
                "kernel_profile": "vmlinux-lo",
                "vmm_backend": "mock",
                "vmm_pid": 1001,
                "proxy_pid": null,
                "proxy_isolated": false,
                "boot_duration_ms": 20,
                "guest_init_version": "0.1.0",
                "workspace_mounted": true,
                "netbridge_ready": false,
                "compute": ComputeSpec::default(),
                "network_mode": NetworkMode::Egress,
                "allowed_hosts": ["httpbin.org"],
                "ingress_allow_ports": [3000],
                "created_at": 1000,
                "expires_at": 4600,
                "idle_deadline_at": 1600,
                "uptime_sec": 10,
                "idle_remaining_sec": 590,
                "wall_remaining_sec": 3590,
            }))
            .unwrap()
        }

        let tmp = tempfile::tempdir().unwrap();
        let sock_path = tmp.path().join("prefix-audit-keepalive.sock");
        let listener = UnixListener::bind(&sock_path).unwrap();
        let keepalive_hits = Arc::new(Mutex::new(Vec::<String>::new()));
        let audit_paths = Arc::new(Mutex::new(Vec::<String>::new()));

        let kh = Arc::clone(&keepalive_hits);
        let ap = Arc::clone(&audit_paths);
        let server = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let kh = Arc::clone(&kh);
                let ap = Arc::clone(&ap);
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let svc = service_fn(move |req: Request<Incoming>| {
                        let kh = Arc::clone(&kh);
                        let ap = Arc::clone(&ap);
                        async move {
                            let method = req.method().clone();
                            let uri = req.uri().to_string();
                            let path = req.uri().path().to_string();
                            let query = req.uri().query().unwrap_or("").to_string();

                            let ev1 = AuditEvent {
                                timestamp_ms: 1_700_000_000_123,
                                sandbox_id: "bw-2ca91111".into(),
                                origin: AuditOrigin::Proxy,
                                kind: AuditEventKind::DnsQuery {
                                    fqdn: "google.com".into(),
                                    allowed: false,
                                    synthetic_ip: None,
                                },
                            };
                            let ev2 = AuditEvent {
                                timestamp_ms: 1_700_000_001_456,
                                sandbox_id: "bw-2ca91111".into(),
                                origin: AuditOrigin::Proxy,
                                kind: AuditEventKind::HttpRequest {
                                    host: "httpbin.org".into(),
                                    method: "POST".into(),
                                    path: "/anything".into(),
                                    status: 200,
                                    request_bytes: 64,
                                    response_bytes: 466,
                                    auth_injected: true,
                                },
                            };

                            let resp = match (method, path.as_str()) {
                                (Method::GET, "/v1/sandboxes") => json_response(
                                    StatusCode::OK,
                                    &vec![
                                        sample_summary("bw-2ca91111"),
                                        sample_summary("bw-2ca92222"),
                                        sample_summary("bw-99ff0000"),
                                        sample_summary("sb-legacy01"),
                                    ],
                                ),
                                (Method::POST, "/v1/sandboxes/bw-99ff0000/keepalive") => {
                                    kh.lock().unwrap().push("bw-99ff0000".into());
                                    json_response(
                                        StatusCode::OK,
                                        &serde_json::json!({
                                            "id": "bw-99ff0000",
                                            "idle_deadline_at": 2200,
                                            "expires_at": 4600,
                                            "idle_remaining_sec": 600,
                                            "wall_remaining_sec": 3000,
                                        }),
                                    )
                                }
                                (Method::GET, "/v1/audit")
                                | (Method::GET, "/v1/sandboxes/bw-2ca91111/audit") => {
                                    ap.lock().unwrap().push(uri);
                                    if query.contains("follow=true") {
                                        let body = format!(
                                            "{}\n{}\n",
                                            serde_json::to_string(&ev1).unwrap(),
                                            serde_json::to_string(&ev2).unwrap(),
                                        );
                                        Response::builder()
                                            .status(StatusCode::OK)
                                            .header(header::CONTENT_TYPE, "application/x-ndjson")
                                            .body(Full::new(Bytes::from(body)))
                                            .unwrap()
                                    } else {
                                        json_response(StatusCode::OK, &vec![ev1, ev2])
                                    }
                                }
                                _ => Response::builder()
                                    .status(StatusCode::NOT_FOUND)
                                    .body(Full::new(Bytes::from_static(
                                        br#"{"error":"not found"}"#,
                                    )))
                                    .unwrap(),
                            };
                            Ok::<_, std::convert::Infallible>(resp)
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, svc)
                        .await;
                });
            }
        });

        let client = UdsClient::new(&sock_path);

        // 1. Prefix resolution tests
        assert_eq!(
            resolve_sandbox_id(&client, "bw-2ca91111").await.unwrap(),
            "bw-2ca91111"
        );
        assert_eq!(
            resolve_sandbox_id(&client, "bw-99").await.unwrap(),
            "bw-99ff0000"
        );
        assert_eq!(
            resolve_sandbox_id(&client, "99ff").await.unwrap(),
            "bw-99ff0000"
        );
        assert_eq!(
            resolve_sandbox_id(&client, "legacy").await.unwrap(),
            "sb-legacy01"
        );
        assert_eq!(
            resolve_sandbox_id(&client, "unknown-xyz").await.unwrap(),
            "unknown-xyz"
        );
        let ambig_err = resolve_sandbox_id(&client, "2ca9").await.unwrap_err();
        let ambig_msg = ambig_err.to_string();
        assert!(ambig_msg.contains("bw-2ca91111"), "got: {ambig_msg}");
        assert!(ambig_msg.contains("bw-2ca92222"), "got: {ambig_msg}");

        // 2. Keepalive via short prefix via run_cli
        let cli = Cli::try_parse_from([
            "blackwall",
            "--socket",
            sock_path.to_str().unwrap(),
            "keepalive",
            "99ff",
        ])
        .unwrap();
        assert_eq!(run_cli(cli).await.unwrap(), 0);
        assert_eq!(*keepalive_hits.lock().unwrap(), vec!["bw-99ff0000"]);

        // 3. Audit snapshot (global & scoped via prefix) and follow stream
        let cli_global = Cli::try_parse_from([
            "blackwall",
            "--socket",
            sock_path.to_str().unwrap(),
            "audit",
            "--limit",
            "25",
        ])
        .unwrap();
        assert_eq!(run_cli(cli_global).await.unwrap(), 0);

        let cli_scoped = Cli::try_parse_from([
            "blackwall",
            "--socket",
            sock_path.to_str().unwrap(),
            "--json",
            "audit",
            "2ca91",
            "--limit",
            "10",
            "-f",
        ])
        .unwrap();
        assert_eq!(run_cli(cli_scoped).await.unwrap(), 0);

        let recorded_paths = audit_paths.lock().unwrap().clone();
        assert_eq!(
            recorded_paths,
            vec![
                "/v1/audit?limit=25&follow=false",
                "/v1/sandboxes/bw-2ca91111/audit?limit=10&follow=true",
            ]
        );

        server.abort();
    }

    #[test]
    fn bridge_cli_and_create_bridge_flag_parsing() {
        use blackwall_policy::HostServiceSpec;

        // 1. blackwall bridge 1356 5435:127.0.0.1:5435
        let cli = Cli::try_parse_from(["blackwall", "bridge", "1356", "5435:127.0.0.1:5435"])
            .unwrap();
        match cli.command {
            Command::Bridge(a) => {
                assert_eq!(a.id, "1356");
                assert_eq!(a.spec.as_deref(), Some("5435:127.0.0.1:5435"));
                assert!(a.name.is_none());
                assert!(!a.list);
                assert!(a.remove.is_none());
                let parsed = parse_bridge_spec(a.spec.as_deref().unwrap(), a.name.as_deref())
                    .unwrap();
                assert_eq!(
                    parsed,
                    HostServiceSpec {
                        name: "bridge-5435".into(),
                        guest_port: 5435,
                        target: "127.0.0.1:5435".into(),
                    }
                );
            }
            other => panic!("expected Bridge, got {other:?}"),
        }

        // 2. blackwall bridge 1356 5432:unix:///run/pg.sock --name pg
        let cli = Cli::try_parse_from([
            "blackwall",
            "bridge",
            "1356",
            "5432:unix:///run/pg.sock",
            "--name",
            "pg",
        ])
        .unwrap();
        match cli.command {
            Command::Bridge(a) => {
                assert_eq!(a.id, "1356");
                assert_eq!(a.spec.as_deref(), Some("5432:unix:///run/pg.sock"));
                assert_eq!(a.name.as_deref(), Some("pg"));
                let parsed = parse_bridge_spec(a.spec.as_deref().unwrap(), a.name.as_deref())
                    .unwrap();
                assert_eq!(
                    parsed,
                    HostServiceSpec {
                        name: "pg".into(),
                        guest_port: 5432,
                        target: "unix:///run/pg.sock".into(),
                    }
                );
            }
            other => panic!("expected Bridge, got {other:?}"),
        }

        // 3. blackwall bridge 1356 --remove 5435 (and -r / --detach)
        for flag in ["--remove", "-r", "--detach"] {
            let cli = Cli::try_parse_from(["blackwall", "bridge", "1356", flag, "5435"]).unwrap();
            match cli.command {
                Command::Bridge(a) => {
                    assert_eq!(a.id, "1356");
                    assert!(a.spec.is_none());
                    assert!(!a.list);
                    assert_eq!(a.remove, Some(5435));
                }
                other => panic!("expected Bridge for {flag}, got {other:?}"),
            }
        }

        // 4. blackwall bridge 1356 --list (and -l and bare)
        for args in [
            vec!["blackwall", "bridge", "1356", "--list"],
            vec!["blackwall", "bridge", "1356", "-l"],
            vec!["blackwall", "bridge", "1356"],
        ] {
            let cli = Cli::try_parse_from(args).unwrap();
            match cli.command {
                Command::Bridge(a) => {
                    assert_eq!(a.id, "1356");
                    assert!(a.spec.is_none());
                    assert!(a.remove.is_none());
                }
                other => panic!("expected Bridge list, got {other:?}"),
            }
        }

        // 5. blackwall create --bridge 5435:127.0.0.1:5435 (repeatable + named + ipv6 + unix)
        let cli = Cli::try_parse_from([
            "blackwall",
            "create",
            "--bridge",
            "5435:127.0.0.1:5435",
            "--bridge",
            "pg=5432:unix:///run/pg.sock",
            "--bridge",
            "v6=9000:[::1]:9000",
        ])
        .unwrap();
        let Command::Create(create_args) = cli.command else {
            unreachable!()
        };
        let draft = build_create_draft(&create_args).unwrap();
        assert_eq!(
            draft.host_services,
            Some(vec![
                HostServiceSpec {
                    name: "bridge-5435".into(),
                    guest_port: 5435,
                    target: "127.0.0.1:5435".into(),
                },
                HostServiceSpec {
                    name: "pg".into(),
                    guest_port: 5432,
                    target: "unix:///run/pg.sock".into(),
                },
                HostServiceSpec {
                    name: "v6".into(),
                    guest_port: 9000,
                    target: "[::1]:9000".into(),
                },
            ])
        );

        // 6. Invalid specs fail cleanly
        assert!(parse_bridge_spec("no-colon", None).is_err());
        assert!(parse_bridge_spec("0:127.0.0.1:5435", None).is_err());
        assert!(parse_bridge_spec("5435:192.168.1.10:5435", None).is_err());
        assert!(parse_bridge_spec("5432:unix://relative/pg.sock", None).is_err());
        assert!(parse_bridge_spec("=5435:127.0.0.1:5435", None).is_err());
        // Unix path containing '=' after ':' must not be misparsed as a name prefix
        let eq_in_path = parse_bridge_spec("5432:unix:///run/a=b.sock", None).unwrap();
        assert_eq!(eq_in_path.name, "bridge-5432");
        assert_eq!(eq_in_path.target, "unix:///run/a=b.sock");
    }

    #[tokio::test]
    async fn bridge_uds_client_and_cli_round_trip() {
        use blackwall_policy::HostServiceSpec;

        let tmp = tempfile::tempdir().unwrap();
        let sock_path = tmp.path().join("bridge-test.sock");
        let listener = UnixListener::bind(&sock_path).unwrap();
        let bridges = Arc::new(Mutex::new(Vec::<HostServiceSpec>::new()));

        let br = Arc::clone(&bridges);
        let server = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let br = Arc::clone(&br);
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let svc = service_fn(move |req: Request<Incoming>| {
                        let br = Arc::clone(&br);
                        async move {
                            let method = req.method().clone();
                            let path = req.uri().path().to_string();
                            let body = req
                                .into_body()
                                .collect()
                                .await
                                .map(|c| c.to_bytes())
                                .unwrap_or_default();

                            let resp = match (method, path.as_str()) {
                                (Method::GET, "/v1/sandboxes") => {
                                    let sb: SandboxSummary =
                                        serde_json::from_value(serde_json::json!({
                                            "id": "bw-1356abcd",
                                            "profile": "base",
                                            "state": SandboxState::Running,
                                            "image_roothash": "deadbeef",
                                            "network_mode": NetworkMode::Loopback,
                                            "created_at": 1000,
                                            "expires_at": 4600,
                                            "idle_deadline_at": 1600,
                                        }))
                                        .unwrap();
                                    json_response(StatusCode::OK, &vec![sb])
                                }
                                (Method::GET, "/v1/sandboxes/bw-1356abcd/bridges") => {
                                    let list = br.lock().unwrap().clone();
                                    json_response(StatusCode::OK, &list)
                                }
                                (Method::POST, "/v1/sandboxes/bw-1356abcd/bridges") => {
                                    let spec: HostServiceSpec =
                                        serde_json::from_slice(&body).unwrap();
                                    br.lock().unwrap().push(spec.clone());
                                    json_response(StatusCode::CREATED, &spec)
                                }
                                (Method::DELETE, "/v1/sandboxes/bw-1356abcd/bridges/5435") => {
                                    br.lock().unwrap().retain(|b| b.guest_port != 5435);
                                    Response::builder()
                                        .status(StatusCode::NO_CONTENT)
                                        .body(Full::new(Bytes::new()))
                                        .unwrap()
                                }
                                _ => Response::builder()
                                    .status(StatusCode::NOT_FOUND)
                                    .body(Full::new(Bytes::from_static(
                                        br#"{"error":"not found"}"#,
                                    )))
                                    .unwrap(),
                            };
                            Ok::<_, std::convert::Infallible>(resp)
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, svc)
                        .await;
                });
            }
        });

        // Attach via short prefix `1356` using `run_cli`
        let cli_attach = Cli::try_parse_from([
            "blackwall",
            "--socket",
            sock_path.to_str().unwrap(),
            "bridge",
            "1356",
            "5435:127.0.0.1:5435",
        ])
        .unwrap();
        assert_eq!(run_cli(cli_attach).await.unwrap(), 0);

        let cli_attach_named = Cli::try_parse_from([
            "blackwall",
            "--socket",
            sock_path.to_str().unwrap(),
            "--json",
            "bridge",
            "1356",
            "5432:unix:///run/pg.sock",
            "--name",
            "pg",
        ])
        .unwrap();
        assert_eq!(run_cli(cli_attach_named).await.unwrap(), 0);

        // List via client & verify both attached
        let client = UdsClient::new(&sock_path);
        let active = client.list_bridges("bw-1356abcd").await.unwrap();
        assert_eq!(active.len(), 2);
        assert_eq!(active[0].name, "bridge-5435");
        assert_eq!(active[1].name, "pg");

        // Bare `blackwall bridge 1356` lists active bridges cleanly
        let cli_list = Cli::try_parse_from([
            "blackwall",
            "--socket",
            sock_path.to_str().unwrap(),
            "bridge",
            "1356",
        ])
        .unwrap();
        assert_eq!(run_cli(cli_list).await.unwrap(), 0);

        // Detach port 5435 via `--remove`
        let cli_remove = Cli::try_parse_from([
            "blackwall",
            "--socket",
            sock_path.to_str().unwrap(),
            "bridge",
            "1356",
            "--remove",
            "5435",
        ])
        .unwrap();
        assert_eq!(run_cli(cli_remove).await.unwrap(), 0);

        let remaining = client.list_bridges("bw-1356abcd").await.unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].guest_port, 5432);

        server.abort();
    }

    #[test]
    fn ingress_cli_parsing() {
        // 1. Positional port: blackwall ingress bw-123 3000
        let cli = Cli::try_parse_from(["blackwall", "ingress", "bw-123", "3000"]).unwrap();
        match cli.command {
            Command::Ingress(a) => {
                assert_eq!(a.id, "bw-123");
                assert_eq!(a.port, Some(3000));
                assert!(a.allow.is_none());
                assert!(a.close.is_none());
                assert!(!a.list);
            }
            other => panic!("expected Ingress, got {other:?}"),
        }

        // 2. --allow / -a: blackwall ingress bw-123 --allow 5173
        for flag in ["--allow", "-a"] {
            let cli = Cli::try_parse_from(["blackwall", "ingress", "bw-123", flag, "5173"]).unwrap();
            match cli.command {
                Command::Ingress(a) => {
                    assert_eq!(a.id, "bw-123");
                    assert!(a.port.is_none());
                    assert_eq!(a.allow, Some(5173));
                    assert!(a.close.is_none());
                    assert!(!a.list);
                }
                other => panic!("expected Ingress for {flag}, got {other:?}"),
            }
        }

        // 3. --close / -c / --remove: blackwall ingress bw-123 --close 3000
        for flag in ["--close", "-c", "--remove"] {
            let cli = Cli::try_parse_from(["blackwall", "ingress", "bw-123", flag, "3000"]).unwrap();
            match cli.command {
                Command::Ingress(a) => {
                    assert_eq!(a.id, "bw-123");
                    assert!(a.port.is_none());
                    assert!(a.allow.is_none());
                    assert_eq!(a.close, Some(3000));
                    assert!(!a.list);
                }
                other => panic!("expected Ingress for {flag}, got {other:?}"),
            }
        }

        // 4. --list / -l
        for flag in ["--list", "-l"] {
            let cli = Cli::try_parse_from(["blackwall", "ingress", "bw-123", flag]).unwrap();
            match cli.command {
                Command::Ingress(a) => {
                    assert_eq!(a.id, "bw-123");
                    assert!(a.port.is_none());
                    assert!(a.allow.is_none());
                    assert!(a.close.is_none());
                    assert!(a.list);
                }
                other => panic!("expected Ingress for {flag}, got {other:?}"),
            }
        }

        // 5. Bare: blackwall ingress bw-123
        let cli = Cli::try_parse_from(["blackwall", "ingress", "bw-123"]).unwrap();
        match cli.command {
            Command::Ingress(a) => {
                assert_eq!(a.id, "bw-123");
                assert!(a.port.is_none());
                assert!(a.allow.is_none());
                assert!(a.close.is_none());
                assert!(!a.list);
            }
            other => panic!("expected Ingress bare, got {other:?}"),
        }

        // 6. Conflicting flags fail cleanly
        assert!(
            Cli::try_parse_from(["blackwall", "ingress", "bw-123", "3000", "--allow", "5173"])
                .is_err()
        );
        assert!(
            Cli::try_parse_from(["blackwall", "ingress", "bw-123", "--allow", "3000", "--close", "3000"])
                .is_err()
        );
        assert!(
            Cli::try_parse_from(["blackwall", "ingress", "bw-123", "--allow", "3000", "--list"])
                .is_err()
        );
        assert!(
            Cli::try_parse_from(["blackwall", "ingress", "bw-123", "--close", "3000", "--list"])
                .is_err()
        );
    }

    #[tokio::test]
    async fn ingress_uds_client_and_cli_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let sock_path = tmp.path().join("ingress-test.sock");
        let listener = UnixListener::bind(&sock_path).unwrap();
        let ports = Arc::new(Mutex::new(Vec::<u16>::new()));

        let ps = Arc::clone(&ports);
        let server = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let ps = Arc::clone(&ps);
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let svc = service_fn(move |req: Request<Incoming>| {
                        let ps = Arc::clone(&ps);
                        async move {
                            let method = req.method().clone();
                            let path = req.uri().path().to_string();
                            let body = req
                                .into_body()
                                .collect()
                                .await
                                .map(|c| c.to_bytes())
                                .unwrap_or_default();

                            let resp = match (method, path.as_str()) {
                                (Method::GET, "/v1/sandboxes") => {
                                    let sb: SandboxSummary =
                                        serde_json::from_value(serde_json::json!({
                                            "id": "bw-3094abcd",
                                            "profile": "base",
                                            "state": SandboxState::Running,
                                            "image_roothash": "deadbeef",
                                            "network_mode": NetworkMode::Loopback,
                                            "created_at": 1000,
                                            "expires_at": 4600,
                                            "idle_deadline_at": 1600,
                                        }))
                                        .unwrap();
                                    json_response(StatusCode::OK, &vec![sb])
                                }
                                (Method::GET, "/v1/sandboxes/bw-3094abcd/ingress") => {
                                    let list = ps.lock().unwrap().clone();
                                    json_response(StatusCode::OK, &list)
                                }
                                (Method::POST, "/v1/sandboxes/bw-3094abcd/ingress") => {
                                    let v: serde_json::Value =
                                        serde_json::from_slice(&body).unwrap();
                                    let port = v["port"].as_u64().unwrap() as u16;
                                    let mut guard = ps.lock().unwrap();
                                    if !guard.contains(&port) {
                                        guard.push(port);
                                        guard.sort_unstable();
                                    }
                                    json_response(StatusCode::CREATED, &*guard)
                                }
                                (Method::DELETE, p)
                                    if p.starts_with("/v1/sandboxes/bw-3094abcd/ingress/") =>
                                {
                                    let port_str =
                                        p.trim_start_matches("/v1/sandboxes/bw-3094abcd/ingress/");
                                    let port: u16 = port_str.parse().unwrap();
                                    ps.lock().unwrap().retain(|&existing| existing != port);
                                    Response::builder()
                                        .status(StatusCode::NO_CONTENT)
                                        .body(Full::new(Bytes::new()))
                                        .unwrap()
                                }
                                _ => Response::builder()
                                    .status(StatusCode::NOT_FOUND)
                                    .body(Full::new(Bytes::from_static(
                                        br#"{"error":"not found"}"#,
                                    )))
                                    .unwrap(),
                            };
                            Ok::<_, std::convert::Infallible>(resp)
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, svc)
                        .await;
                });
            }
        });

        let client = UdsClient::new(&sock_path);

        // 1. Initial list is empty
        assert!(client.list_ingress_ports("bw-3094abcd").await.unwrap().is_empty());
        let cli_empty_list = Cli::try_parse_from([
            "blackwall",
            "--socket",
            sock_path.to_str().unwrap(),
            "ingress",
            "3094",
        ])
        .unwrap();
        assert_eq!(run_cli(cli_empty_list).await.unwrap(), 0);

        // 2. Allow via positional port using short prefix `3094`
        let cli_allow_pos = Cli::try_parse_from([
            "blackwall",
            "--socket",
            sock_path.to_str().unwrap(),
            "ingress",
            "3094",
            "3000",
        ])
        .unwrap();
        assert_eq!(run_cli(cli_allow_pos).await.unwrap(), 0);
        assert_eq!(client.list_ingress_ports("bw-3094abcd").await.unwrap(), vec![3000]);

        // 3. Allow via --allow and --json
        let cli_allow_flag = Cli::try_parse_from([
            "blackwall",
            "--socket",
            sock_path.to_str().unwrap(),
            "--json",
            "ingress",
            "3094",
            "--allow",
            "5173",
        ])
        .unwrap();
        assert_eq!(run_cli(cli_allow_flag).await.unwrap(), 0);
        assert_eq!(
            client.list_ingress_ports("bw-3094abcd").await.unwrap(),
            vec![3000, 5173]
        );

        // 4. List via --list (plain & json)
        let cli_list = Cli::try_parse_from([
            "blackwall",
            "--socket",
            sock_path.to_str().unwrap(),
            "ingress",
            "3094",
            "--list",
        ])
        .unwrap();
        assert_eq!(run_cli(cli_list).await.unwrap(), 0);

        // 5. Close port 3000 via --close
        let cli_close = Cli::try_parse_from([
            "blackwall",
            "--socket",
            sock_path.to_str().unwrap(),
            "ingress",
            "3094",
            "--close",
            "3000",
        ])
        .unwrap();
        assert_eq!(run_cli(cli_close).await.unwrap(), 0);
        assert_eq!(client.list_ingress_ports("bw-3094abcd").await.unwrap(), vec![5173]);

        // 6. Close port 5173 via --remove and --json
        let cli_remove_json = Cli::try_parse_from([
            "blackwall",
            "--socket",
            sock_path.to_str().unwrap(),
            "--json",
            "ingress",
            "3094",
            "--remove",
            "5173",
        ])
        .unwrap();
        assert_eq!(run_cli(cli_remove_json).await.unwrap(), 0);
        assert!(client.list_ingress_ports("bw-3094abcd").await.unwrap().is_empty());

        // 7. Direct client allow_ingress_port & close_ingress_port
        let allowed = client.allow_ingress_port("bw-3094abcd", 8080).await.unwrap();
        assert_eq!(allowed, vec![8080]);
        client.close_ingress_port("bw-3094abcd", 8080).await.unwrap();
        assert!(client.list_ingress_ports("bw-3094abcd").await.unwrap().is_empty());

        // 8. Port 0 is rejected cleanly
        let cli_zero = Cli::try_parse_from([
            "blackwall",
            "--socket",
            sock_path.to_str().unwrap(),
            "ingress",
            "3094",
            "0",
        ])
        .unwrap();
        assert!(matches!(
            run_cli(cli_zero).await.unwrap_err(),
            CliError::InvalidArgument(_)
        ));

        server.abort();
    }
}
