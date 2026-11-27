//! `blackwall-core` — Embeddable Rust SDK and sandbox runtime orchestrator.
//!
//! Wires together:
//! - `blackwall-policy`: composable `SandboxSpec` profiles and narrow-only lock ceilings
//! - `blackwall-secrets`: HPKE `seal1_` unsealing, `memfd_secret`, and 256-bit random placeholders
//! - `blackwall-oci`: content-addressed `erofs + dm-verity` `vda` image cache
//! - `blackwall-vmm` / `blackwall-vmm-linux`: rootless `cloud-hypervisor` VMM backend
//! - `blackwall-proxy`: per-VM Pingora HTTP/1.1 & H2 MITM + Postgres SCRAM proxy + Port 1000 muxer
//! - `blackwall-unpacker`: mandatory canonical `.tar.gz` / raw download sanitization
//! - `blackwall-audit`: Port 1001 unidirectional audit drain + structured host boundary events

pub mod audit_hub;
pub mod dns;
pub mod error;
pub mod manager;
pub mod mock;
pub mod proxy_runtime;
pub mod secrets_bridge;
pub mod session_client;

pub use audit_hub::{AuditHub, DEFAULT_BROADCAST_CAPACITY, DEFAULT_RING_CAPACITY};
pub use dns::{
    check_ip_allowed, collect_pinned_endpoints, resolve_allowlisted_hosts,
    resolve_allowlisted_hosts_with, DnsResolveOptions, DnsResolver, StaticDnsResolver,
    SystemDnsResolver,
};
pub use error::{CoreError, Result};
pub use manager::{
    validate_bridge_target_against_config, CoreConfig, DownloadMetadata, FsEntry,
    KeepaliveResponse, ListeningPort, LockdownStatus, SandboxDetail, SandboxHandle,
    SandboxManager, SandboxRunStats, SandboxState, SandboxSummary,
};
pub use mock::{CustomCtrlResponder, MockSessionVmmBackend};
pub use proxy_runtime::{
    detect_proxy_tools, DetectedProxyTools, JailedProxyOptions, ProxyLaunchMode, VmProxyHandle,
};
pub use secrets_bridge::VmSecretTableBridge;
pub use session_client::{
    BackgroundProcess, BootReady, ExecRequest, ExecResult, ExecStreamEvent, PtyEvent, PtyHandle,
    PtyOpenParams, PtyWriter, SessionClient, TcpTunnelEvent, TcpTunnelHandle, TcpTunnelStream,
    TcpTunnelWriter, UploadResult,
};

// Re-export key domain types so downstream callers (`blackwall-daemon`, `blackwall-cli`)
// can import common types cleanly from `blackwall_core`.
pub use blackwall_audit::{
    AuditEvent, AuditEventKind, AuditSink, JsonlAuditSink, MemoryAuditSink, NoopAuditSink,
};
pub use blackwall_oci::{BuiltImage, ImageBuilder};
pub use blackwall_policy::{
    validate_host_service, validate_profile_name, ComputePatch, ComputeSpec, ExportPatch,
    ExportSpec, HostServiceSpec, ImagePatch, ImageSpec, IngressPatch, IngressSpec, NetworkMode,
    NetworkPatch, PolicyCeiling, ProfileDraft, ProfileRegistry, SandboxSpec, SecretSpec,
};
pub use blackwall_proto::{
    CtrlErrorCode, DownloadFormat, ProcessInfo, ProcessState, SignalKind, UploadKind,
};
pub use blackwall_secrets::{HostKeyPair, HostPublicKey, SealBinding};
pub use blackwall_unpacker::UnpackSummary;

#[cfg(test)]
mod tests {
    use super::*;
    use blackwall_proto::{
        read_ctrl_request, write_ctrl_response, CtrlRequest, CtrlResponse, GuestAuditFrame,
    };
    use blackwall_vmm_linux::check_linux_vmm_prereqs;
    use flate2::read::GzDecoder;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::{Cursor, Read};
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Duration;

    fn make_targz(entries: &[(&str, tar::EntryType, u32, &[u8], Option<&str>)]) -> Vec<u8> {
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        {
            let mut builder = tar::Builder::new(&mut gz);
            for &(path, kind, mode, data, link_target) in entries {
                let mut hdr = tar::Header::new_gnu();
                hdr.set_entry_type(kind);
                hdr.set_mode(mode);
                hdr.set_uid(1000);
                hdr.set_gid(1000);
                hdr.set_mtime(1_700_000_000);
                if let Some(target) = link_target {
                    hdr.set_size(0);
                    hdr.set_cksum();
                    builder.append_link(&mut hdr, path, target).unwrap();
                } else {
                    hdr.set_size(data.len() as u64);
                    hdr.set_cksum();
                    builder.append_data(&mut hdr, path, data).unwrap();
                }
            }
            builder.finish().unwrap();
        }
        gz.finish().unwrap()
    }

    #[tokio::test]
    async fn full_sandbox_lifecycle_with_composed_profile_exec_bg_pty_unpacker_and_destroy() {
        let tmp = tempfile::tempdir().unwrap();
        let sink = Arc::new(MemoryAuditSink::new());

        // Write a composed profile to profile_dir on disk (testing ProfileRegistry::load_dir).
        let profiles_dir = tmp.path().join("profiles");
        std::fs::create_dir_all(&profiles_dir).unwrap();
        std::fs::write(
            profiles_dir.join("dev-base.toml"),
            r#"
version = 1
name = "dev-base"
extends = ["base"]

[compute]
vcpus = 2
memory_mib = 1024
workspace_mib = 256
idle_timeout_sec = 60
max_wall_time_sec = 300

[env]
DEV_ENV = "composed-ok"
"#,
        )
        .unwrap();

        let cfg = CoreConfig::for_testing(tmp.path(), sink.clone());
        let mock_backend = MockSessionVmmBackend::new();
        let manager = SandboxManager::with_backend(
            cfg,
            Box::new(mock_backend.clone()),
            Arc::new(StaticDnsResolver::new()),
        )
        .unwrap();

        // Profile inspection & secret sealing work.
        let profiles = manager.list_profiles();
        assert!(profiles.contains(&"base".to_string()));
        assert!(profiles.contains(&"dev-base".to_string()));
        let inspected = manager.get_profile("dev-base").unwrap();
        assert_eq!(inspected.env.get("DEV_ENV").map(String::as_str), Some("composed-ok"));

        let binding = SealBinding {
            allow_hosts: vec!["api.github.com".into()],
            allow_path_templates: vec!["/repos/org/repo/".into()],
            policy_tag: "dev".into(),
            exp_unix_sec: None,
        };
        let sealed = manager.seal_secret(b"ghp_REAL_TOKEN", &binding).unwrap();
        assert!(sealed.starts_with("seal1_"));

        // 1. Create sandbox extending `dev-base` with an ephemeral secret.
        let mut draft = ProfileDraft {
            extends: vec!["dev-base".into()],
            ..ProfileDraft::default()
        };
        draft.secrets.insert(
            "API_KEY".into(),
            SecretSpec {
                placeholder_prefix: "sk_bw00_".into(),
                sealed: None,
                ephemeral: Some("sk_REAL_SECRET_NEVER_IN_GUEST".into()),
            },
        );
        let summary = manager.create_sandbox(draft).await.unwrap();
        assert!(summary.id.starts_with("bw-"));
        assert_eq!(summary.state, SandboxState::Running);
        assert_eq!(manager.list_sandboxes().len(), 1);

        // Emit an extra Port 1001 guest audit frame and confirm drain thread ingests it.
        assert!(mock_backend.emit_guest_audit_frame(
            &summary.id,
            &GuestAuditFrame {
                timestamp_ns: 999,
                source: "blackwall-init".into(),
                kind: "custom_telemetry".into(),
                payload: serde_json::json!({"ok": true}),
            }
        ));

        // 2. Upload a file into /workspace.
        let upload_res = manager
            .upload_files(
                &summary.id,
                "/workspace/hello.txt",
                UploadKind::Raw,
                b"hello from blackwall-core\n",
            )
            .await
            .unwrap();
        assert_eq!(upload_res.bytes_written, 26);
        assert_eq!(upload_res.files_written, 1);

        // 3. Sync exec: verify composed env, secret placeholder (NOT real secret!), and uploaded file.
        let exec_res = manager
            .exec(
                &summary.id,
                ExecRequest::new([
                    "/bin/sh",
                    "-c",
                    "echo \"$DEV_ENV|$API_KEY\"; cat hello.txt; echo errline >&2",
                ])
                .with_cwd("/workspace"),
            )
            .await
            .unwrap();
        assert_eq!(exec_res.exit_code, 0);
        assert!(!exec_res.timed_out);
        assert!(exec_res.stdout.contains("composed-ok|sk_bw00_"));
        assert!(!exec_res.stdout.contains("sk_REAL_SECRET_NEVER_IN_GUEST"));
        assert!(exec_res.stdout.contains("hello from blackwall-core"));
        assert!(exec_res.stderr.contains("errline"));

        // 4. Streaming exec.
        let mut stream_rx = manager
            .exec_stream(
                &summary.id,
                ExecRequest::new(["/bin/sh", "-c", "echo chunk1; echo chunk2"]),
            )
            .await
            .unwrap();
        let mut streamed = String::new();
        let mut saw_exit = false;
        while let Some(ev) = stream_rx.recv().await {
            match ev {
                ExecStreamEvent::Stdout(b) => streamed.push_str(&String::from_utf8_lossy(&b)),
                ExecStreamEvent::Exit { exit_code, .. } => {
                    assert_eq!(exit_code, 0);
                    saw_exit = true;
                }
                _ => {}
            }
        }
        assert!(saw_exit);
        assert!(streamed.contains("chunk1"));
        assert!(streamed.contains("chunk2"));

        // 5. Background process + list + logs + signal + delete.
        let bg = manager
            .exec_background(
                &summary.id,
                ExecRequest::new([
                    "/bin/sh",
                    "-c",
                    "echo bg-started; sleep 30",
                ]),
            )
            .await
            .unwrap();
        assert!(!bg.proc_id.is_empty());

        // Give the background process a moment to emit its first line.
        tokio::time::sleep(Duration::from_millis(80)).await;
        let procs = manager.list_processes(&summary.id).await.unwrap();
        assert_eq!(procs.len(), 1);
        assert_eq!(procs[0].proc_id, bg.proc_id);

        let mut logs_rx = manager
            .process_logs(&summary.id, &bg.proc_id, Some(10), false)
            .await
            .unwrap();
        let mut log_text = String::new();
        while let Some(ev) = logs_rx.recv().await {
            if let ExecStreamEvent::Stdout(b) = ev {
                log_text.push_str(&String::from_utf8_lossy(&b));
            }
        }
        assert!(log_text.contains("bg-started"));

        manager
            .signal_process(&summary.id, &bg.proc_id, SignalKind::Sigterm)
            .await
            .unwrap();
        manager
            .delete_process(&summary.id, &bg.proc_id)
            .await
            .unwrap();
        assert!(manager.list_processes(&summary.id).await.unwrap().is_empty());

        // 6. Interactive PTY: send input, resize, read output, exit cleanly.
        let mut pty = manager
            .open_pty(
                &summary.id,
                PtyOpenParams {
                    cmd: Some(vec!["/bin/sh".into()]),
                    cwd: Some("/workspace".into()),
                    cols: 80,
                    rows: 24,
                    ..PtyOpenParams::default()
                },
            )
            .await
            .unwrap();
        pty.resize(100, 30).unwrap();
        pty.write_input(b"echo PTY_OK_TOKEN\nexit 0\n").unwrap();
        let mut pty_out = Vec::new();
        let mut pty_exit = None;
        while let Some(ev) = tokio::time::timeout(Duration::from_secs(5), pty.recv())
            .await
            .expect("PTY should complete within timeout")
        {
            match ev {
                PtyEvent::Output(data) => pty_out.extend_from_slice(&data),
                PtyEvent::Exited(code) => {
                    pty_exit = Some(code);
                    break;
                }
            }
        }
        assert!(String::from_utf8_lossy(&pty_out).contains("PTY_OK_TOKEN"));
        assert_eq!(pty_exit, Some(0));

        // 7. Download /workspace as tar.gz and verify canonical blackwall-unpacker re-pack
        //    (uid=0, gid=0, mtime=0, clean permissions).
        let targz = manager
            .download_files(&summary.id, "/workspace", DownloadFormat::TarGz)
            .await
            .unwrap();
        let mut archive = tar::Archive::new(GzDecoder::new(Cursor::new(&targz)));
        let mut found_hello = false;
        for entry in archive.entries().unwrap() {
            let mut entry = entry.unwrap();
            let hdr = entry.header();
            assert_eq!(hdr.uid().unwrap(), 0, "unpacker must normalize uid=0");
            assert_eq!(hdr.gid().unwrap(), 0, "unpacker must normalize gid=0");
            assert_eq!(hdr.mtime().unwrap(), 0, "unpacker must normalize mtime=0");
            assert_eq!(hdr.mode().unwrap() & !0o777, 0, "setuid/setgid must be stripped");
            if entry.path().unwrap().to_string_lossy() == "hello.txt" {
                let mut content = String::new();
                entry.read_to_string(&mut content).unwrap();
                assert_eq!(content, "hello from blackwall-core\n");
                found_hello = true;
            }
        }
        assert!(found_hello, "downloaded tar.gz must contain hello.txt");

        // 8. Sandbox detail view reflects active state and caps.
        let detail = manager.get_sandbox(&summary.id).await.unwrap();
        assert_eq!(detail.id, summary.id);
        assert_eq!(detail.compute.memory_mib, 1024);

        // 9. Explicit destroy cleans up sandbox and emits lifecycle audit events.
        manager.destroy_sandbox(&summary.id).await.unwrap();
        assert!(manager.list_sandboxes().is_empty());
        assert!(matches!(
            manager.get_sandbox(&summary.id).await,
            Err(CoreError::SandboxNotFound(_))
        ));

        let events = sink.snapshot();
        assert!(events.iter().any(|e| matches!(
            &e.kind,
            AuditEventKind::SandboxLifecycle { phase, .. } if phase == "running"
        )));
        assert!(events.iter().any(|e| matches!(
            &e.kind,
            AuditEventKind::SandboxLifecycle { phase, .. } if phase == "destroyed"
        )));
        assert!(events.iter().any(|e| matches!(
            &e.kind,
            AuditEventKind::GuestPort1001 { frame } if frame.kind == "custom_telemetry"
        )));
        assert!(events
            .iter()
            .any(|e| matches!(&e.kind, AuditEventKind::ExecCommand { .. })));
        assert!(events
            .iter()
            .any(|e| matches!(&e.kind, AuditEventKind::FileTransfer { .. })));
    }

    #[tokio::test]
    async fn download_pipes_through_unpacker_and_rejects_malicious_guest_tar() {
        let tmp = tempfile::tempdir().unwrap();
        let sink = Arc::new(MemoryAuditSink::new());

        // Build a weaponized tar.gz containing a symlink escape and a good tar.gz with setuid bits.
        let bad_symlink_targz = make_targz(&[(
            "escape_link",
            tar::EntryType::Symlink,
            0o777,
            b"",
            Some("/etc/passwd"),
        )]);
        let good_dirty_targz = make_targz(&[(
            "clean.txt",
            tar::EntryType::Regular,
            0o4755, // setuid bit must be stripped by canonical re-pack!
            b"safe-data",
            None,
        )]);

        let responder: CustomCtrlResponder = Arc::new(move |_sid, mut stream, _ws| {
            let bad = bad_symlink_targz.clone();
            let good = good_dirty_targz.clone();
            while let Ok(req) = read_ctrl_request(&mut stream) {
                match req {
                    CtrlRequest::BootConfigure { req_id, .. } => {
                        let _ = write_ctrl_response(
                            &mut stream,
                            &CtrlResponse::BootReady {
                                req_id,
                                version: "evil-mock".into(),
                                workspace_mounted: true,
                                netbridge_ready: false,
                            },
                        );
                    }
                    CtrlRequest::DownloadBegin { req_id, path, .. } => {
                        let payload = if path.contains("evil") { &bad } else { &good };
                        let _ = write_ctrl_response(
                            &mut stream,
                            &CtrlResponse::FileChunk {
                                req_id,
                                data: payload.clone(),
                                eof: true,
                            },
                        );
                    }
                    CtrlRequest::Shutdown { req_id } => {
                        let _ = write_ctrl_response(&mut stream, &CtrlResponse::Ack { req_id });
                        break;
                    }
                    _ => {}
                }
            }
        });

        let cfg = CoreConfig::for_testing(tmp.path(), sink.clone());
        let backend = MockSessionVmmBackend::with_custom_ctrl_responder(responder);
        let manager =
            SandboxManager::with_backend(cfg, Box::new(backend), Arc::new(StaticDnsResolver::new()))
                .unwrap();

        let summary = manager.create_sandbox(ProfileDraft::default()).await.unwrap();

        // Malicious symlink tar from compromised guest MUST be rejected by blackwall-unpacker!
        let err = manager
            .download_files(&summary.id, "/workspace/evil", DownloadFormat::TarGz)
            .await
            .unwrap_err();
        assert!(
            matches!(err, CoreError::Unpacker(_)),
            "expected Unpacker rejection, got {err:?}"
        );
        assert!(sink
            .snapshot()
            .iter()
            .any(|e| matches!(&e.kind, AuditEventKind::UnpackerRejection { .. })));

        // Good tar with dirty uid/gid/mtime/setuid MUST be canonically re-packed!
        let repacked = manager
            .download_files(&summary.id, "/workspace/good", DownloadFormat::TarGz)
            .await
            .unwrap();
        let mut archive = tar::Archive::new(GzDecoder::new(Cursor::new(repacked)));
        let mut entries = archive.entries().unwrap();
        let mut entry = entries.next().unwrap().unwrap();
        assert_eq!(entry.path().unwrap().to_string_lossy(), "clean.txt");
        assert_eq!(entry.header().mode().unwrap(), 0o755);
        assert_eq!(entry.header().uid().unwrap(), 0);
        assert_eq!(entry.header().gid().unwrap(), 0);
        assert_eq!(entry.header().mtime().unwrap(), 0);
        let mut buf = String::new();
        entry.read_to_string(&mut buf).unwrap();
        assert_eq!(buf, "safe-data");

        manager.destroy_sandbox(&summary.id).await.unwrap();
    }

    #[tokio::test]
    async fn reaper_enforces_idle_timeout_and_max_wall_time() {
        let tmp = tempfile::tempdir().unwrap();
        let sink = Arc::new(MemoryAuditSink::new());
        let cfg = CoreConfig::for_testing(tmp.path(), sink.clone());
        let manager = SandboxManager::with_backend(
            cfg,
            Box::new(MockSessionVmmBackend::new()),
            Arc::new(StaticDnsResolver::new()),
        )
        .unwrap();

        // 1. Sandbox with idle_timeout_sec = 1, max_wall_time_sec = 10 -> reaped by idle timeout.
        let idle_draft = ProfileDraft {
            compute: Some(ComputePatch {
                idle_timeout_sec: Some(1),
                max_wall_time_sec: Some(10),
                ..ComputePatch::default()
            }),
            ..ProfileDraft::default()
        };
        let idle_sb = manager.create_sandbox(idle_draft).await.unwrap();

        // 2. Sandbox with idle_timeout_sec = 1, max_wall_time_sec = 2 -> keep touching idle
        //    every 400ms so idle never fires, proving max_wall_time_sec still reaps it!
        let wall_draft = ProfileDraft {
            compute: Some(ComputePatch {
                idle_timeout_sec: Some(1),
                max_wall_time_sec: Some(2),
                ..ComputePatch::default()
            }),
            ..ProfileDraft::default()
        };
        let wall_sb = manager.create_sandbox(wall_draft).await.unwrap();

        // Wait ~1.25s while touching wall_sb so idle_sb gets reaped for idle timeout.
        for _ in 0..4 {
            tokio::time::sleep(Duration::from_millis(350)).await;
            let _ = manager.list_processes(&wall_sb.id).await;
        }
        assert!(
            matches!(
                manager.get_sandbox(&idle_sb.id).await,
                Err(CoreError::SandboxNotFound(_))
            ),
            "idle_sb should have been reaped after idle_timeout_sec"
        );

        // Keep touching wall_sb past max_wall_time_sec = 2s.
        for _ in 0..4 {
            tokio::time::sleep(Duration::from_millis(300)).await;
            let _ = manager.list_processes(&wall_sb.id).await;
        }
        assert!(
            matches!(
                manager.get_sandbox(&wall_sb.id).await,
                Err(CoreError::SandboxNotFound(_))
            ),
            "wall_sb should have been reaped after max_wall_time_sec"
        );

        let events = sink.snapshot();
        assert!(events.iter().any(|e| {
            e.sandbox_id == idle_sb.id
                && matches!(
                    &e.kind,
                    AuditEventKind::SandboxLifecycle { phase, details: Some(d), .. }
                    if phase == "reaped" && d.contains("idle_timeout_sec")
                )
        }));
        assert!(events.iter().any(|e| {
            e.sandbox_id == wall_sb.id
                && matches!(
                    &e.kind,
                    AuditEventKind::SandboxLifecycle { phase, details: Some(d), .. }
                    if phase == "reaped" && d.contains("max_wall_time_sec")
                )
        }));
    }

    #[tokio::test]
    async fn egress_sandbox_starts_proxy_and_resolves_pinned_dns() {
        let tmp = tempfile::tempdir().unwrap();
        let sink = Arc::new(MemoryAuditSink::new());
        let cfg = CoreConfig::for_testing(tmp.path(), sink);

        let mut dns = StaticDnsResolver::new();
        dns.insert_ips("api.github.com", vec![IpAddr::V4(Ipv4Addr::new(140, 82, 121, 6))]);

        let mock = MockSessionVmmBackend::new();
        let manager = SandboxManager::with_backend(cfg, Box::new(mock.clone()), Arc::new(dns))
            .unwrap();

        let mut draft = ProfileDraft {
            network: Some(NetworkPatch {
                mode: Some(NetworkMode::Egress),
                http: vec![blackwall_policy::HttpRule {
                    host: "api.github.com".into(),
                    port: 443,
                    methods: vec!["GET".into()],
                    path_prefixes: vec!["/repos/".into()],
                    max_request_bytes: None,
                    auth: Some(blackwall_policy::AuthSpec::Bearer {
                        secret: "GITHUB_TOKEN".into(),
                    }),
                }],
                postgres: vec![],
                restrict_hosts: None,
            }),
            ..ProfileDraft::default()
        };
        draft.secrets.insert(
            "GITHUB_TOKEN".into(),
            SecretSpec {
                placeholder_prefix: "ghp_bw00_".into(),
                sealed: None,
                ephemeral: Some("ghp_REAL_TOKEN".into()),
            },
        );

        let sb = manager.create_sandbox(draft).await.unwrap();
        assert_eq!(sb.network_mode, NetworkMode::Egress);
        let detail = manager.get_sandbox(&sb.id).await.unwrap();
        assert_eq!(detail.allowed_hosts, vec!["api.github.com".to_string()]);

        // Exercise Port 1000 DNS queries through the in-process proxy muxer and verify
        // AuditHub receives both allowlisted and blocked DnsQuery audit events!
        let guest_std = mock.take_guest_net_stream(&sb.id).unwrap();
        guest_std.set_nonblocking(true).unwrap();
        let mut guest = tokio::net::UnixStream::from_std(guest_std).unwrap();

        use blackwall_proto::{
            mux_flags, DnsQueryPayload, DnsRecordType, DnsResponsePayload, MuxFrame, MuxHeader,
            StreamType, MUX_HEADER_LEN,
        };
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        for (sid, fqdn, expect_allowed) in [(1u32, "api.github.com", true), (2u32, "google.com", false)] {
            let q = DnsQueryPayload {
                query_id: sid as u16,
                fqdn: fqdn.into(),
                record_type: DnsRecordType::A,
            };
            let frame = MuxFrame::new(
                sid,
                mux_flags::DATA | mux_flags::FIN,
                StreamType::DnsQuery,
                serde_json::to_vec(&q).unwrap(),
            )
            .unwrap();
            let mut wire = Vec::with_capacity(MUX_HEADER_LEN + frame.payload.len());
            wire.extend_from_slice(&frame.header.encode().unwrap());
            wire.extend_from_slice(&frame.payload);
            guest.write_all(&wire).await.unwrap();

            let mut hdr_buf = [0u8; MUX_HEADER_LEN];
            guest.read_exact(&mut hdr_buf).await.unwrap();
            let hdr = MuxHeader::decode(&hdr_buf).unwrap();
            assert_eq!(hdr.stream_type, StreamType::DnsResponse);
            let mut payload = vec![0u8; hdr.payload_len as usize];
            guest.read_exact(&mut payload).await.unwrap();
            let resp: DnsResponsePayload = serde_json::from_slice(&payload).unwrap();
            assert_eq!(resp.allowed, expect_allowed);
        }

        let hub_events = manager.recent_audit_events(Some(&sb.id), 100);
        assert!(hub_events.iter().any(|e| matches!(
            &e.kind,
            AuditEventKind::DnsQuery { fqdn, allowed: true, synthetic_ip: Some(ip) }
            if fqdn == "api.github.com" && ip.starts_with("198.18.")
        )));
        assert!(hub_events.iter().any(|e| matches!(
            &e.kind,
            AuditEventKind::DnsQuery { fqdn, allowed: false, synthetic_ip: None }
            if fqdn == "google.com"
        )));

        manager.destroy_sandbox(&sb.id).await.unwrap();
    }

    /// Gated live Linux KVM end-to-end test checking `cloud-hypervisor`, `/dev/kvm`,
    /// `pasta`, `mkfs.erofs`, `veritysetup`, and built guest kernels/initramfs.
    /// Skips cleanly with an explicit diagnostic listing missing host tools/artifacts.
    #[tokio::test]
    async fn gated_live_linux_kvm_e2e_test() {
        let vmm_prereqs = check_linux_vmm_prereqs();
        let oci_tools = ImageBuilder::detect_tools();

        let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap_or_else(|_| PathBuf::from("."));

        let kernel_lo = std::env::var_os("BLACKWALL_KERNEL_LO_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|| workspace_root.join("kernel/out/vmlinux-lo"));
        let kernel_noinet = std::env::var_os("BLACKWALL_KERNEL_NOINET_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|| workspace_root.join("kernel/out/vmlinux-noinet"));
        let initramfs = std::env::var_os("BLACKWALL_INITRAMFS_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|| workspace_root.join("kernel/out/initramfs.cpio.gz"));

        let mut missing = vmm_prereqs.missing_requirements();
        if find_in_path("pasta").is_none() {
            missing.push("pasta binary not found in PATH".into());
        }
        if oci_tools.mkfs_erofs.is_none() {
            missing.push("mkfs.erofs binary not found in PATH".into());
        }
        if oci_tools.veritysetup.is_none() {
            missing.push("veritysetup binary not found in PATH".into());
        }
        if !kernel_lo.is_file() {
            missing.push(format!(
                "built vmlinux-lo kernel missing at {}",
                kernel_lo.display()
            ));
        }
        if !kernel_noinet.is_file() {
            missing.push(format!(
                "built vmlinux-noinet kernel missing at {}",
                kernel_noinet.display()
            ));
        }
        if !initramfs.is_file() {
            missing.push(format!(
                "built initramfs missing at {}",
                initramfs.display()
            ));
        }

        if !missing.is_empty() {
            eprintln!(
                "[gated_live_linux_kvm_e2e_test] SKIPPING live Linux KVM E2E — missing tools/artifacts:\n  - {}",
                missing.join("\n  - ")
            );
            return;
        }

        let tmp = tempfile::tempdir().unwrap();
        let sink = Arc::new(MemoryAuditSink::new());
        let cfg = CoreConfig {
            profile_dir: tmp.path().join("profiles"),
            image_cache_dir: tmp.path().join("images"),
            host_key_path: tmp.path().join("host.key"),
            kernel_lo_path: kernel_lo,
            kernel_noinet_path: kernel_noinet,
            initramfs_path: initramfs,
            runtime_dir: tmp.path().join("run"),
            audit_sink: sink,
            reaper_interval: Duration::from_secs(1),
            dns_options: DnsResolveOptions::strict(),
            allow_unbuilt_images_for_mock: false,
            proxy_launch_mode: ProxyLaunchMode::Auto,
            forbidden_bridge_ports: Vec::new(),
            forbidden_bridge_unix_paths: Vec::new(),
            readonly_profiles: false,
            require_locked_profiles: false,
            policy_ceiling: None,
        };

        let manager = SandboxManager::new(cfg).expect("SandboxManager::new should succeed");
        let sb = manager
            .create_sandbox(ProfileDraft::default())
            .await
            .expect("live KVM sandbox creation should succeed");
        let out = manager
            .exec(&sb.id, ExecRequest::new(["/bin/sh", "-c", "echo live-kvm-ok"]))
            .await
            .expect("live KVM exec should succeed");
        assert_eq!(out.exit_code, 0);
        assert!(out.stdout.contains("live-kvm-ok"));
        manager
            .destroy_sandbox(&sb.id)
            .await
            .expect("live KVM destroy should succeed");
    }

    fn pick_free_loopback_port() -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    }

    #[tokio::test]
    async fn host_service_bridge_tcp_and_unix_e2e_with_audit_and_self_protection() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let tmp = tempfile::tempdir().unwrap();
        let sink = Arc::new(MemoryAuditSink::new());

        // Start a real host loopback TCP echo server.
        let tcp_server = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_host_addr = tcp_server.local_addr().unwrap();
        let tcp_server_task = tokio::spawn(async move {
            while let Ok((mut sock, _)) = tcp_server.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    if let Ok(n) = sock.read(&mut buf).await {
                        let _ = sock.write_all(&buf[..n]).await;
                    }
                    let _ = sock.shutdown().await;
                });
            }
        });

        // Start a real host Unix domain socket echo server.
        let uds_svc_path = tmp.path().join("host-echo.sock");
        let uds_server = tokio::net::UnixListener::bind(&uds_svc_path).unwrap();
        let uds_server_task = tokio::spawn(async move {
            while let Ok((mut sock, _)) = uds_server.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    if let Ok(n) = sock.read(&mut buf).await {
                        let _ = sock.write_all(&buf[..n]).await;
                    }
                    let _ = sock.shutdown().await;
                });
            }
        });

        // Create a dummy daemon socket file + symlink to test canonical path self-protection.
        let daemon_sock = tmp.path().join("daemon.sock");
        std::fs::write(&daemon_sock, b"").unwrap();
        let daemon_sock_symlink = tmp.path().join("evil-link.sock");
        std::os::unix::fs::symlink(&daemon_sock, &daemon_sock_symlink).unwrap();

        let mut cfg = CoreConfig::for_testing(tmp.path(), sink.clone());
        cfg.forbidden_bridge_ports = vec![7700, 7701];
        cfg.forbidden_bridge_unix_paths = vec![daemon_sock.clone()];

        // Direct config validation rejects daemon HTTP port, preview port, UDS path, and symlink.
        for bad_target in [
            "127.0.0.1:7700".to_string(),
            "[::1]:7701".to_string(),
            format!("unix://{}", daemon_sock.display()),
            format!("unix://{}", daemon_sock_symlink.display()),
        ] {
            let err = validate_bridge_target_against_config(
                &HostServiceSpec {
                    name: "self-target".into(),
                    guest_port: 19000,
                    target: bad_target.clone(),
                },
                &cfg,
            )
            .unwrap_err();
            assert!(
                matches!(err, CoreError::PolicyViolation(_)),
                "expected PolicyViolation for {bad_target}, got {err:?}"
            );
        }

        let manager = SandboxManager::with_backend(
            cfg,
            Box::new(MockSessionVmmBackend::new()),
            Arc::new(StaticDnsResolver::new()),
        )
        .unwrap();

        // create_sandbox must reject forbidden host_services BEFORE launching VMM.
        let bad_draft = ProfileDraft {
            host_services: Some(vec![HostServiceSpec {
                name: "bad-http".into(),
                guest_port: 19001,
                target: "127.0.0.1:7700".into(),
            }]),
            ..ProfileDraft::default()
        };
        assert!(matches!(
            manager.create_sandbox(bad_draft).await,
            Err(CoreError::PolicyViolation(_))
        ));
        assert!(manager.list_sandboxes().is_empty());

        // Create a loopback sandbox with a static TCP host service bridge.
        let tcp_guest_port = pick_free_loopback_port();
        let draft = ProfileDraft {
            host_services: Some(vec![HostServiceSpec {
                name: "echo-tcp".into(),
                guest_port: tcp_guest_port,
                target: tcp_host_addr.to_string(),
            }]),
            ..ProfileDraft::default()
        };
        let summary = manager.create_sandbox(draft).await.unwrap();
        assert_eq!(summary.host_services.len(), 1);
        assert_eq!(summary.host_services[0].name, "echo-tcp");
        assert_eq!(summary.host_services[0].guest_port, tcp_guest_port);

        let detail = manager.get_sandbox(&summary.id).await.unwrap();
        assert_eq!(detail.host_services, summary.host_services);

        // Round-trip data across the TCP host bridge (guest loopback -> Port 1002 -> host TCP).
        {
            let mut client = tokio::net::TcpStream::connect(("127.0.0.1", tcp_guest_port))
                .await
                .unwrap();
            client.write_all(b"ping-tcp-bridge").await.unwrap();
            let mut reply = Vec::new();
            client.read_to_end(&mut reply).await.unwrap();
            assert_eq!(reply, b"ping-tcp-bridge");
        }

        // Dynamically attach a Unix socket host service bridge.
        let uds_guest_port = pick_free_loopback_port();
        let uds_spec = HostServiceSpec {
            name: "echo-uds".into(),
            guest_port: uds_guest_port,
            target: format!("unix://{}", uds_svc_path.display()),
        };
        let attached = manager
            .attach_host_bridge(&summary.id, uds_spec.clone())
            .await
            .unwrap();
        assert_eq!(attached, uds_spec);
        assert_eq!(manager.list_host_bridges(&summary.id).unwrap().len(), 2);

        // Round-trip data across the UDS host bridge (guest loopback -> Port 1002 -> host UDS).
        {
            let mut client = tokio::net::TcpStream::connect(("127.0.0.1", uds_guest_port))
                .await
                .unwrap();
            client.write_all(b"ping-uds-bridge").await.unwrap();
            let mut reply = Vec::new();
            client.read_to_end(&mut reply).await.unwrap();
            assert_eq!(reply, b"ping-uds-bridge");
        }

        // Wait briefly for the bridge copy tasks to flush completion audit events.
        tokio::time::sleep(Duration::from_millis(80)).await;
        let events = sink.snapshot();
        assert!(
            events.iter().any(|e| {
                e.origin == blackwall_audit::AuditOrigin::Daemon
                    && matches!(
                        &e.kind,
                        AuditEventKind::HostServiceBridge {
                            name,
                            guest_port,
                            allowed: true,
                            bytes_in,
                            bytes_out,
                            ..
                        } if name == "echo-tcp"
                            && *guest_port == tcp_guest_port
                            && *bytes_in >= 15
                            && *bytes_out >= 15
                    )
            }),
            "expected daemon-originated TCP HostServiceBridge audit event, got {events:?}"
        );
        assert!(
            events.iter().any(|e| {
                e.origin == blackwall_audit::AuditOrigin::Daemon
                    && matches!(
                        &e.kind,
                        AuditEventKind::HostServiceBridge {
                            name,
                            guest_port,
                            allowed: true,
                            bytes_in,
                            bytes_out,
                            ..
                        } if name == "echo-uds"
                            && *guest_port == uds_guest_port
                            && *bytes_in >= 15
                            && *bytes_out >= 15
                    )
            }),
            "expected daemon-originated UDS HostServiceBridge audit event, got {events:?}"
        );

        // Ensure proxy confused-deputy filter NEVER allows HostServiceBridge from a jailed proxy.
        let spoofed = AuditEvent::now(
            &summary.id,
            AuditEventKind::HostServiceBridge {
                name: "spoof".into(),
                guest_port: 1234,
                target: "127.0.0.1:1234".into(),
                bytes_in: 1,
                bytes_out: 1,
                allowed: true,
            },
        );
        assert!(
            proxy_runtime::sanitize_proxy_event(spoofed, &summary.id).is_none(),
            "HostServiceBridge must remain daemon-only and be dropped from proxy audit pipes"
        );

        // Detach UDS bridge and verify NotFound on duplicate detach.
        manager
            .detach_host_bridge(&summary.id, uds_guest_port)
            .await
            .unwrap();
        assert_eq!(manager.list_host_bridges(&summary.id).unwrap().len(), 1);
        assert!(matches!(
            manager.detach_host_bridge(&summary.id, uds_guest_port).await,
            Err(CoreError::NotFound(_))
        ));

        manager.destroy_sandbox(&summary.id).await.unwrap();
        tcp_server_task.abort();
        uds_server_task.abort();
    }

    fn find_in_path(name: &str) -> Option<PathBuf> {
        let path_var = std::env::var_os("PATH")?;
        for dir in std::env::split_paths(&path_var) {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
        None
    }
}
