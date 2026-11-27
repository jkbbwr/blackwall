//! Host-initiated hybrid `vsock` handshake protocol for Cloud Hypervisor / Firecracker.
//!
//! Because Blackwall's VMM jail denies `connect()` via `seccomp-bpf`, the guest
//! (`blackwall-init`) calls `listen()` on `AF_VSOCK` ports 1002, 1001, and 1000
//! during early boot, and the host connects to the VMM's Unix domain socket
//! (`vsock.sock`) sending `CONNECT <port>\n` and expecting `OK <local_port>\n`.
//!
//! Immediately after all required channels are connected:
//! 1. Port `1001` (`AUDIT_UNI`) is half-closed via `shutdown(Shutdown::Write)`
//!    so the kernel enforces unidirectional guest -> host flow.
//! 2. `vsock.sock` is immediately `unlink()`ed from the host filesystem.

use crate::{Result, VmmError, VsockChannels};
use blackwall_proto::{
    format_connect_handshake, parse_ok_handshake, PORT_AUDIT_UNI, PORT_CTRL_SESSION, PORT_NET_MUX,
};
use std::io::{ErrorKind, Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

const MAX_HANDSHAKE_LINE_LEN: usize = 128;

/// Timing and backoff parameters for the early-boot host-initiated `vsock` handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeConfig {
    /// Total deadline for establishing each vsock port connection.
    pub timeout: Duration,
    /// Initial retry sleep when the VMM socket or guest listener is not yet ready.
    pub initial_backoff: Duration,
    /// Upper cap for exponential retry backoff.
    pub max_backoff: Duration,
    /// Per-attempt socket read/write timeout during the `CONNECT`/`OK` exchange.
    pub io_timeout: Duration,
}

impl Default for HandshakeConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(10),
            initial_backoff: Duration::from_millis(10),
            max_backoff: Duration::from_millis(200),
            io_timeout: Duration::from_secs(2),
        }
    }
}

/// Connect to a single guest `AF_VSOCK` port through the VMM's hybrid Unix socket.
///
/// Retries with exponential backoff up to `cfg.timeout` while the VMM is creating
/// `vsock.sock` and the guest kernel/initramfs is bringing up its `AF_VSOCK` listeners.
///
/// Reads the `OK <local_port>\n` line byte-by-byte to guarantee zero over-read
/// into any binary payload that the guest may send immediately after the handshake.
pub fn connect_vsock_port(
    vsock_sock_path: &Path,
    port: u32,
    cfg: &HandshakeConfig,
) -> Result<(UnixStream, u32)> {
    let deadline = Instant::now() + cfg.timeout;
    let mut backoff = cfg.initial_backoff.max(Duration::from_millis(1));
    let mut last_error = String::from("no attempt made");

    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err(VmmError::HandshakeTimeout {
                port,
                timeout: cfg.timeout,
                last_error,
            });
        }
        let remaining = deadline.saturating_duration_since(now);
        let attempt_timeout = remaining.min(cfg.io_timeout).max(Duration::from_millis(1));

        match try_connect_once(vsock_sock_path, port, attempt_timeout) {
            Ok((stream, local_port)) => {
                // Restore blocking mode with no read/write timeouts for long-lived session streams.
                stream.set_read_timeout(None)?;
                stream.set_write_timeout(None)?;
                tracing::debug!(
                    port,
                    local_port,
                    socket = %vsock_sock_path.display(),
                    "established host-initiated vsock channel"
                );
                return Ok((stream, local_port));
            }
            Err(AttemptError::Retryable(msg)) => {
                last_error = msg;
            }
            Err(AttemptError::Fatal(err)) => {
                return Err(err);
            }
        }

        let now_after = Instant::now();
        if now_after >= deadline {
            return Err(VmmError::HandshakeTimeout {
                port,
                timeout: cfg.timeout,
                last_error,
            });
        }
        let sleep_dur = backoff.min(deadline.saturating_duration_since(now_after));
        thread::sleep(sleep_dur);
        backoff = (backoff.saturating_mul(2)).min(cfg.max_backoff.max(backoff));
    }
}

enum AttemptError {
    Retryable(String),
    Fatal(VmmError),
}

fn try_connect_once(
    vsock_sock_path: &Path,
    port: u32,
    io_timeout: Duration,
) -> std::result::Result<(UnixStream, u32), AttemptError> {
    let mut stream = UnixStream::connect(vsock_sock_path).map_err(|err| {
        if is_retryable_io_error(&err) {
            AttemptError::Retryable(format!("connect({}): {err}", vsock_sock_path.display()))
        } else {
            AttemptError::Fatal(VmmError::Io(err))
        }
    })?;

    stream
        .set_read_timeout(Some(io_timeout))
        .map_err(|e| AttemptError::Fatal(VmmError::Io(e)))?;
    stream
        .set_write_timeout(Some(io_timeout))
        .map_err(|e| AttemptError::Fatal(VmmError::Io(e)))?;

    let req = format_connect_handshake(port);
    if let Err(err) = stream.write_all(req.as_bytes()).and_then(|_| stream.flush()) {
        return Err(if is_retryable_io_error(&err) {
            AttemptError::Retryable(format!("write CONNECT {port}: {err}"))
        } else {
            AttemptError::Fatal(VmmError::Io(err))
        });
    }

    let line = read_line_exact(&mut stream, port)?;
    match parse_ok_handshake(&line) {
        Ok(local_port) => Ok((stream, local_port)),
        Err(proto_err) => {
            // During early boot, before the guest calls listen() on this port,
            // Cloud Hypervisor / Firecracker closes the socket or returns an error line.
            Err(AttemptError::Retryable(format!(
                "guest port {port} not ready: {proto_err}"
            )))
        }
    }
}

/// Read a single `\n`-terminated handshake response byte-by-byte so we never
/// buffer or consume bytes belonging to the subsequent framed stream.
fn read_line_exact(
    stream: &mut UnixStream,
    port: u32,
) -> std::result::Result<String, AttemptError> {
    let mut buf = Vec::with_capacity(32);
    let mut byte = [0u8; 1];

    loop {
        match stream.read(&mut byte) {
            Ok(0) => {
                if buf.is_empty() {
                    return Err(AttemptError::Retryable(format!(
                        "peer closed socket before handshake response on port {port}"
                    )));
                }
                break;
            }
            Ok(_) => {
                buf.push(byte[0]);
                if byte[0] == b'\n' {
                    break;
                }
                if buf.len() >= MAX_HANDSHAKE_LINE_LEN {
                    return Err(AttemptError::Fatal(VmmError::HandshakeProtocol {
                        port,
                        detail: format!(
                            "handshake response exceeded {MAX_HANDSHAKE_LINE_LEN} bytes without newline"
                        ),
                    }));
                }
            }
            Err(err) if err.kind() == ErrorKind::Interrupted => continue,
            Err(err) => {
                return Err(if is_retryable_io_error(&err) {
                    AttemptError::Retryable(format!("read handshake response: {err}"))
                } else {
                    AttemptError::Fatal(VmmError::Io(err))
                });
            }
        }
    }

    String::from_utf8(buf).map_err(|_| {
        AttemptError::Fatal(VmmError::HandshakeProtocol {
            port,
            detail: "handshake response was not valid UTF-8".into(),
        })
    })
}

fn is_retryable_io_error(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        ErrorKind::NotFound
            | ErrorKind::ConnectionRefused
            | ErrorKind::ConnectionReset
            | ErrorKind::ConnectionAborted
            | ErrorKind::BrokenPipe
            | ErrorKind::WouldBlock
            | ErrorKind::TimedOut
            | ErrorKind::UnexpectedEof
            | ErrorKind::Interrupted
    )
}

/// Establish all required Blackwall host-initiated `vsock` channels, enforce
/// kernel-level half-close (`SHUT_WR`) on Port `1001`, and immediately `unlink()`
/// `vsock_sock_path`.
///
/// Connection order:
/// 1. Port `1002` (`PORT_CTRL_SESSION`)
/// 2. Port `1001` (`PORT_AUDIT_UNI`) — immediately half-closed via `shutdown(Shutdown::Write)`
/// 3. Port `1000` (`PORT_NET_MUX`) — only if `enable_net_mux == true`
pub fn perform_host_handshake(
    vsock_sock_path: &Path,
    enable_net_mux: bool,
    cfg: &HandshakeConfig,
) -> Result<VsockChannels> {
    let (ctrl_session, _) = connect_vsock_port(vsock_sock_path, PORT_CTRL_SESSION, cfg)?;
    let (audit_uni, _) = connect_vsock_port(vsock_sock_path, PORT_AUDIT_UNI, cfg)?;

    // Enforce kernel-level unidirectional guest -> host flow on Port 1001 immediately.
    audit_uni.shutdown(Shutdown::Write)?;

    let net_mux = if enable_net_mux {
        let (stream, _) = connect_vsock_port(vsock_sock_path, PORT_NET_MUX, cfg)?;
        Some(stream)
    } else {
        None
    };

    // Immediately unlink vsock.sock so no further host-side connections can reach the VMM.
    match std::fs::remove_file(vsock_sock_path) {
        Ok(()) => {
            tracing::debug!(
                socket = %vsock_sock_path.display(),
                "unlinked vsock.sock after host-initiated handshake"
            );
        }
        Err(err) if err.kind() == ErrorKind::NotFound => {}
        Err(err) => return Err(VmmError::Io(err)),
    }

    Ok(VsockChannels {
        net_mux,
        audit_uni,
        ctrl_session,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use blackwall_proto::{
        read_audit_frame, write_audit_frame, GuestAuditFrame, MuxFrame, StreamType, mux_flags,
    };
    use std::io::{BufRead, BufReader};
    use std::os::unix::net::UnixListener;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use tempfile::TempDir;

    /// Spawns a mock Cloud Hypervisor hybrid vsock listener that:
    /// - Optionally rejects the first `fail_attempts` connections to simulate early guest boot
    /// - Speaks `CONNECT <port>\n` -> `OK <local_port>\n`
    /// - Hands accepted sockets for ports 1002, 1001, 1000 back through a channel/thread
    fn spawn_mock_ch_vsock(
        sock_path: std::path::PathBuf,
        expected_ports: Vec<u32>,
        fail_attempts: usize,
        bind_delay: Duration,
    ) -> thread::JoinHandle<Vec<(u32, UnixStream)>> {
        thread::spawn(move || {
            if !bind_delay.is_zero() {
                thread::sleep(bind_delay);
            }
            let listener = UnixListener::bind(&sock_path).expect("bind mock vsock.sock");
            let mut remaining_failures = fail_attempts;
            let mut accepted = Vec::with_capacity(expected_ports.len());
            let next_local_port = Arc::new(AtomicUsize::new(1_073_741_824));

            while accepted.len() < expected_ports.len() {
                let (stream, _) = listener.accept().expect("accept client");
                let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));
                let mut line = String::new();
                let n = reader.read_line(&mut line).expect("read CONNECT line");
                assert!(n > 0, "empty CONNECT line");

                if remaining_failures > 0 {
                    remaining_failures -= 1;
                    // Simulate guest not yet listening by closing connection immediately.
                    drop(stream);
                    continue;
                }

                let trimmed = line.trim_end_matches(['\r', '\n']);
                let port: u32 = trimmed
                    .strip_prefix("CONNECT ")
                    .expect("expected CONNECT prefix")
                    .parse()
                    .expect("valid port");
                let local_port = next_local_port.fetch_add(1, Ordering::Relaxed) as u32;
                let mut writer = stream.try_clone().expect("clone stream");
                writer
                    .write_all(format!("OK {local_port}\n").as_bytes())
                    .expect("write OK response");
                writer.flush().expect("flush OK response");

                // For Port 1001, immediately send a GuestAuditFrame right after `OK ...\n`
                // to verify the host handshake performs zero over-read into the binary stream.
                if port == PORT_AUDIT_UNI {
                    let frame = GuestAuditFrame {
                        timestamp_ns: 999_001,
                        source: "blackwall-init".into(),
                        kind: "boot".into(),
                        payload: serde_json::json!({"ready": true}),
                    };
                    write_audit_frame(&mut writer, &frame).expect("write audit frame");
                    writer.flush().expect("flush audit frame");
                }

                accepted.push((port, stream));
            }
            accepted
        })
    }

    #[test]
    fn host_handshake_connects_all_ports_unlinks_sock_and_half_closes_port1001() {
        let dir = TempDir::new().unwrap();
        let sock_path = dir.path().join("vsock.sock");

        let server = spawn_mock_ch_vsock(
            sock_path.clone(),
            vec![PORT_CTRL_SESSION, PORT_AUDIT_UNI, PORT_NET_MUX],
            2, // fail first 2 attempts to exercise retry/backoff
            Duration::from_millis(30),
        );

        let cfg = HandshakeConfig {
            timeout: Duration::from_secs(5),
            initial_backoff: Duration::from_millis(10),
            max_backoff: Duration::from_millis(50),
            io_timeout: Duration::from_secs(1),
        };

        let mut channels = perform_host_handshake(&sock_path, true, &cfg).unwrap();

        // 1. vsock.sock MUST be unlinked immediately after handshake.
        assert!(
            !sock_path.exists(),
            "vsock.sock must be unlinked immediately after handshake"
        );

        // 2. Verify exact connection order on mock VMM server.
        let mut peers = server.join().unwrap();
        let ports: Vec<u32> = peers.iter().map(|(p, _)| *p).collect();
        assert_eq!(ports, vec![PORT_CTRL_SESSION, PORT_AUDIT_UNI, PORT_NET_MUX]);

        // 3. Verify Port 1001 (`audit_uni`) is half-closed for writing (SHUT_WR):
        //    - Host cannot write to `audit_uni` (EPIPE)
        //    - Guest peer reads immediate EOF from host
        //    - Host CAN still read the GuestAuditFrame sent immediately after `OK ...\n` (zero over-read!)
        let (_, ref mut audit_peer) = peers[1];
        let mut eof_probe = [0u8; 8];
        let n = audit_peer.read(&mut eof_probe).unwrap();
        assert_eq!(
            n, 0,
            "guest peer on Port 1001 must observe immediate EOF due to host SHUT_WR"
        );

        let write_err = channels
            .audit_uni
            .write_all(b"forbidden host->guest write")
            .unwrap_err();
        assert_eq!(
            write_err.kind(),
            ErrorKind::BrokenPipe,
            "writing to half-closed Port 1001 must fail with EPIPE"
        );

        let audit_frame = read_audit_frame(&mut channels.audit_uni).unwrap();
        assert_eq!(audit_frame.source, "blackwall-init");
        assert_eq!(audit_frame.kind, "boot");
        assert_eq!(audit_frame.timestamp_ns, 999_001);

        // 4. Verify Port 1000 (`net_mux`) is bidirectional and carries MuxFrame cleanly.
        let net_mux = channels.net_mux.as_mut().expect("net_mux must be Some");
        let (_, ref mut net_peer) = peers[2];
        let frame = MuxFrame::new(1, mux_flags::SYN, StreamType::Tcp, b"ping".to_vec()).unwrap();
        frame.write_to(net_mux).unwrap();
        let recv = MuxFrame::read_from(net_peer).unwrap();
        assert_eq!(recv, frame);

        // 5. Verify Port 1002 (`ctrl_session`) is bidirectional.
        let (_, ref mut ctrl_peer) = peers[0];
        channels.ctrl_session.write_all(b"hello-ctrl").unwrap();
        let mut buf = [0u8; 10];
        ctrl_peer.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"hello-ctrl");
    }

    #[test]
    fn host_handshake_without_net_mux_skips_port1000() {
        let dir = TempDir::new().unwrap();
        let sock_path = dir.path().join("vsock.sock");

        let server = spawn_mock_ch_vsock(
            sock_path.clone(),
            vec![PORT_CTRL_SESSION, PORT_AUDIT_UNI],
            0,
            Duration::ZERO,
        );

        let cfg = HandshakeConfig {
            timeout: Duration::from_secs(3),
            initial_backoff: Duration::from_millis(5),
            max_backoff: Duration::from_millis(25),
            io_timeout: Duration::from_secs(1),
        };

        let channels = perform_host_handshake(&sock_path, false, &cfg).unwrap();
        assert!(channels.net_mux.is_none());
        assert!(!sock_path.exists());

        let peers = server.join().unwrap();
        let ports: Vec<u32> = peers.iter().map(|(p, _)| *p).collect();
        assert_eq!(ports, vec![PORT_CTRL_SESSION, PORT_AUDIT_UNI]);
    }

    #[test]
    fn connect_vsock_port_times_out_when_socket_missing() {
        let dir = TempDir::new().unwrap();
        let missing = dir.path().join("does-not-exist.sock");
        let cfg = HandshakeConfig {
            timeout: Duration::from_millis(80),
            initial_backoff: Duration::from_millis(10),
            max_backoff: Duration::from_millis(20),
            io_timeout: Duration::from_millis(50),
        };

        let err = connect_vsock_port(&missing, PORT_CTRL_SESSION, &cfg).unwrap_err();
        assert!(matches!(
            err,
            VmmError::HandshakeTimeout {
                port: PORT_CTRL_SESSION,
                ..
            }
        ));
    }
}
