//! `blackwall-netbridge` binary entrypoint.
//!
//! Usage:
//!   blackwall-netbridge --vsock-fd <fd> [--tun-name tun0] [--no-configure-tun]
//!   blackwall-netbridge --unix-sock <path> [--tun-name tun0] [--no-configure-tun]

use blackwall_netbridge::bridge::NetBridge;
use blackwall_netbridge::tun::{
    configure_interface, write_guest_resolv_conf, TunDevice, DEFAULT_TUN_NAME, TUN_DNS_IP,
    TUN_LOCAL_IP, TUN_MTU, TUN_NETMASK,
};
use blackwall_proto::{MuxFrame, MuxHeader, MUX_HEADER_LEN};
use smoltcp::time::Instant as SmolInstant;
use std::collections::VecDeque;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

enum MuxTarget {
    VsockFd(RawFd),
    UnixSock(PathBuf),
}

struct CliArgs {
    mux: MuxTarget,
    tun_name: String,
    configure_tun: bool,
}

fn main() -> ExitCode {
    let args = match parse_args(&std::env::args().collect::<Vec<_>>()) {
        Ok(a) => a,
        Err(msg) => {
            eprintln!("error: {msg}");
            eprintln!(
                "usage: blackwall-netbridge (--vsock-fd <fd> | --unix-sock <path>) [--tun-name tun0] [--no-configure-tun]"
            );
            return ExitCode::FAILURE;
        }
    };

    if let Err(e) = run(args) {
        eprintln!("blackwall-netbridge fatal error: {e}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

fn parse_args(args: &[String]) -> Result<CliArgs, String> {
    let mut vsock_fd: Option<RawFd> = None;
    let mut unix_sock: Option<PathBuf> = None;
    let mut tun_name = DEFAULT_TUN_NAME.to_string();
    let mut configure_tun = true;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--vsock-fd" if i + 1 < args.len() => {
                vsock_fd = Some(
                    args[i + 1]
                        .parse::<RawFd>()
                        .map_err(|_| format!("invalid --vsock-fd: {}", args[i + 1]))?,
                );
                i += 2;
            }
            "--unix-sock" if i + 1 < args.len() => {
                unix_sock = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--tun-name" if i + 1 < args.len() => {
                tun_name = args[i + 1].clone();
                i += 2;
            }
            "--no-configure-tun" => {
                configure_tun = false;
                i += 1;
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }

    let mux = match (vsock_fd, unix_sock) {
        (Some(fd), None) => MuxTarget::VsockFd(fd),
        (None, Some(path)) => MuxTarget::UnixSock(path),
        (Some(_), Some(_)) => {
            return Err("specify exactly one of --vsock-fd or --unix-sock".into())
        }
        (None, None) => return Err("missing --vsock-fd or --unix-sock".into()),
    };

    Ok(CliArgs {
        mux,
        tun_name,
        configure_tun,
    })
}

fn run(args: CliArgs) -> io::Result<()> {
    let tun = TunDevice::open(&args.tun_name)?;
    if args.configure_tun {
        configure_interface(tun.name(), TUN_LOCAL_IP, TUN_NETMASK, TUN_MTU)?;
        let _ = write_guest_resolv_conf(TUN_DNS_IP);
    }

    let mux_fd: OwnedFd = match args.mux {
        MuxTarget::VsockFd(fd) => unsafe { OwnedFd::from_raw_fd(fd) },
        MuxTarget::UnixSock(path) => {
            let s = UnixStream::connect(path)?;
            OwnedFd::from(s)
        }
    };
    set_nonblocking(mux_fd.as_raw_fd())?;

    let start = Instant::now();
    let seed = start.elapsed().as_nanos() as u64 ^ (std::process::id() as u64);
    let mut bridge = NetBridge::new(SmolInstant::from_millis(0), seed);

    let mut mux_rx_buf: Vec<u8> = Vec::with_capacity(64 * 1024);
    let mut mux_tx_queue: VecDeque<Vec<u8>> = VecDeque::new();
    let mut tun_pkt_buf = vec![0u8; 65_536];
    let mut mux_tmp_buf = vec![0u8; 65_536];

    loop {
        let now = SmolInstant::from_millis(start.elapsed().as_millis() as i64);
        bridge.poll(now);

        // Drain outbound guest IP packets -> tun0.
        for pkt in bridge.drain_guest_packets() {
            let _ = tun.write_packet(&pkt);
        }

        // Drain outbound Port 1000 MuxFrames -> mux_tx_queue.
        for frame in bridge.drain_mux_frames() {
            let mut encoded = Vec::with_capacity(MUX_HEADER_LEN + frame.payload.len());
            if frame.write_to(&mut encoded).is_ok() {
                mux_tx_queue.push_back(encoded);
            }
        }

        // Flush as much of mux_tx_queue as possible without blocking.
        flush_mux_tx(mux_fd.as_raw_fd(), &mut mux_tx_queue)?;

        let timeout_ms: libc::c_int = bridge
            .poll_delay(now)
            .map(|d| d.total_millis().min(250) as libc::c_int)
            .unwrap_or(100);

        let mux_events = if mux_tx_queue.is_empty() {
            libc::POLLIN
        } else {
            libc::POLLIN | libc::POLLOUT
        };
        let mut fds = [
            libc::pollfd {
                fd: tun.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: mux_fd.as_raw_fd(),
                events: mux_events,
                revents: 0,
            },
        ];

        let rc = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout_ms) };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(err);
        }

        // Read all available IP packets from tun0.
        if (fds[0].revents & libc::POLLIN) != 0 {
            loop {
                match tun.read_packet(&mut tun_pkt_buf) {
                    Ok(0) => break,
                    Ok(n) => bridge.ingest_guest_packet(&tun_pkt_buf[..n]),
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => return Err(e),
                }
            }
        }

        // Flush pending outbound MuxFrames if mux socket is writable.
        if (fds[1].revents & libc::POLLOUT) != 0 {
            flush_mux_tx(mux_fd.as_raw_fd(), &mut mux_tx_queue)?;
        }

        // Read incoming MuxFrames from Port 1000.
        if (fds[1].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR)) != 0 {
            match read_nonblocking(mux_fd.as_raw_fd(), &mut mux_tmp_buf) {
                Ok(0) => {
                    // Host closed Port 1000 cleanly -> exit.
                    break;
                }
                Ok(n) => {
                    mux_rx_buf.extend_from_slice(&mux_tmp_buf[..n]);
                    while let Some(frame) = try_decode_mux_frame(&mut mux_rx_buf)? {
                        bridge.ingest_mux_frame(frame);
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e),
            }
        }
    }

    Ok(())
}

fn try_decode_mux_frame(buf: &mut Vec<u8>) -> io::Result<Option<MuxFrame>> {
    if buf.len() < MUX_HEADER_LEN {
        return Ok(None);
    }
    let header = MuxHeader::decode(&buf[..MUX_HEADER_LEN])
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    let total = MUX_HEADER_LEN + header.payload_len as usize;
    if buf.len() < total {
        return Ok(None);
    }
    let payload = buf[MUX_HEADER_LEN..total].to_vec();
    buf.drain(..total);
    Ok(Some(MuxFrame { header, payload }))
}

fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn read_nonblocking(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
    loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(err);
        }
        return Ok(n as usize);
    }
}

fn flush_mux_tx(fd: RawFd, queue: &mut VecDeque<Vec<u8>>) -> io::Result<()> {
    while let Some(front) = queue.front_mut() {
        let n = unsafe { libc::write(fd, front.as_ptr() as *const libc::c_void, front.len()) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            if err.kind() == io::ErrorKind::WouldBlock {
                break;
            }
            return Err(err);
        }
        let written = n as usize;
        if written >= front.len() {
            queue.pop_front();
        } else {
            front.drain(..written);
            break;
        }
    }
    Ok(())
}
