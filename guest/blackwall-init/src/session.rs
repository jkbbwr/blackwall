//! Full Port 1002 (`CtrlRequest` / `CtrlResponse`) interactive session server
//! generic over any `Read + Write` transport (AF_VSOCK in guest PID 1, Unix
//! `socketpair` in host unit/integration tests).

use crate::files::{resolve_confined_path, stream_download, UploadSession};
use crate::pty::{apply_privilege_drop_raw, wait_pid_exit_code, PrivilegeDrop, PtySession};
use blackwall_proto::{
    read_ctrl_request, write_ctrl_response, BootConfig, CtrlErrorCode, CtrlRequest, CtrlResponse,
    OutputStream, ProcessInfo, ProcessState, ProtoError, SignalKind,
};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const MAX_LOG_RING_BYTES: usize = 2 * 1024 * 1024; // 2 MiB per background process
const EXEC_READ_BUF_SIZE: usize = 32 * 1024;
const TCP_TUNNEL_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const TCP_TUNNEL_READ_BUF_SIZE: usize = 64 * 1024;
const BRIDGE_ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(50);
const BRIDGE_ACCEPT_TIMEOUT: Duration = Duration::from_secs(10);

pub struct BootApplyOutcome {
    pub workspace_mounted: bool,
    pub netbridge_ready: bool,
}

pub type BootHook = Box<dyn FnMut(&BootConfig) -> Result<BootApplyOutcome, String> + Send>;

pub struct SessionOptions {
    pub workspace_root: PathBuf,
    pub virtual_workspace_mount: String,
    pub drop_privs: Option<PrivilegeDrop>,
    pub on_boot_configure: Option<BootHook>,
}

impl SessionOptions {
    pub fn for_testing(workspace_root: PathBuf) -> Self {
        Self {
            workspace_root,
            virtual_workspace_mount: "/workspace".to_string(),
            drop_privs: None,
            on_boot_configure: None,
        }
    }
}

struct LogEntry {
    seq: u64,
    stream: OutputStream,
    data: Vec<u8>,
}

struct ProcessLogInner {
    entries: VecDeque<LogEntry>,
    total_bytes: usize,
    next_seq: u64,
    state: ProcessState,
    exit_code: Option<i32>,
    deleted: bool,
}

struct TrackedProcess {
    proc_id: String,
    pid: u32,
    cmd: Vec<String>,
    logs: Arc<(Mutex<ProcessLogInner>, Condvar)>,
}

impl TrackedProcess {
    fn info(&self) -> ProcessInfo {
        let guard = self.logs.0.lock().unwrap();
        ProcessInfo {
            proc_id: self.proc_id.clone(),
            pid: self.pid,
            cmd: self.cmd.clone(),
            state: guard.state,
            exit_code: guard.exit_code,
        }
    }

    fn push_log_bytes(logs: &(Mutex<ProcessLogInner>, Condvar), stream: OutputStream, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        let mut guard = logs.0.lock().unwrap();
        // Split on newlines so `tail: Some(n)` operates on natural line boundaries.
        for slice in data.split_inclusive(|&b| b == b'\n') {
            let seq = guard.next_seq;
            guard.next_seq += 1;
            let len = slice.len();
            guard.entries.push_back(LogEntry {
                seq,
                stream,
                data: slice.to_vec(),
            });
            guard.total_bytes += len;
            while guard.total_bytes > MAX_LOG_RING_BYTES && guard.entries.len() > 1 {
                if let Some(old) = guard.entries.pop_front() {
                    guard.total_bytes = guard.total_bytes.saturating_sub(old.data.len());
                }
            }
        }
        logs.1.notify_all();
    }
}

struct ActivePty {
    session: PtySession,
}

struct ActiveTcpTunnel {
    stream: Mutex<TcpStream>,
}

struct BridgeListenerHandle {
    stop: Arc<AtomicBool>,
    wake: Arc<(Mutex<bool>, Condvar)>,
    join: Mutex<Option<thread::JoinHandle<()>>>,
}

impl BridgeListenerHandle {
    fn stop_and_join(&self) {
        self.stop.store(true, Ordering::Release);
        {
            let mut stopped = self.wake.0.lock().unwrap();
            *stopped = true;
            self.wake.1.notify_all();
        }
        if let Some(handle) = self.join.lock().unwrap().take() {
            let _ = handle.join();
        }
    }
}

struct PendingBridgeAccept {
    tx: mpsc::Sender<(bool, Option<String>)>,
    tunnel: Arc<ActiveTcpTunnel>,
}

struct SharedState {
    base_env: Mutex<BTreeMap<String, String>>,
    workspace_root: Mutex<PathBuf>,
    virtual_workspace_mount: Mutex<String>,
    drop_privs: Option<PrivilegeDrop>,
    processes: Mutex<HashMap<String, Arc<TrackedProcess>>>,
    ptys: Mutex<HashMap<String, Arc<ActivePty>>>,
    tcp_tunnels: Mutex<HashMap<String, Arc<ActiveTcpTunnel>>>,
    bridge_listeners: Mutex<HashMap<u16, BridgeListenerHandle>>,
    pending_bridge_accepts: Mutex<HashMap<String, PendingBridgeAccept>>,
    shutting_down: AtomicBool,
    next_proc_seq: AtomicU64,
    next_bridge_stream_id: AtomicU64,
}

impl SharedState {
    fn merged_env(&self, req_env: &BTreeMap<String, String>) -> BTreeMap<String, String> {
        let mut merged = self.base_env.lock().unwrap().clone();
        for (k, v) in req_env {
            merged.insert(k.clone(), v.clone());
        }
        if !merged.contains_key("PATH") {
            merged.insert(
                "PATH".into(),
                std::env::var("PATH").unwrap_or_else(|_| {
                    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into()
                }),
            );
        }
        merged
    }

    fn resolve_cwd(&self, cwd: Option<&str>) -> PathBuf {
        let ws = self.workspace_root.lock().unwrap().clone();
        let vmount = self.virtual_workspace_mount.lock().unwrap().clone();
        match cwd {
            None => ws,
            Some(c) => {
                if let Ok(mapped) = resolve_confined_path(&ws, &vmount, c) {
                    if mapped.is_dir() {
                        return mapped;
                    }
                }
                let p = Path::new(c);
                if p.is_dir() {
                    p.to_path_buf()
                } else {
                    ws
                }
            }
        }
    }
}

fn send_resp<W: Write>(writer: &Arc<Mutex<W>>, resp: &CtrlResponse) -> io::Result<()> {
    let mut guard = writer.lock().unwrap();
    write_ctrl_response(&mut *guard, resp).map_err(|e| match e {
        ProtoError::Io(ioe) => ioe,
        other => io::Error::other(other.to_string()),
    })?;
    guard.flush()
}

fn send_err<W: Write>(
    writer: &Arc<Mutex<W>>,
    req_id: u64,
    code: CtrlErrorCode,
    message: impl Into<String>,
) -> io::Result<()> {
    send_resp(
        writer,
        &CtrlResponse::Error {
            req_id,
            code,
            message: message.into(),
        },
    )
}

/// Serve Port 1002 `CtrlRequest` / `CtrlResponse` RPCs until `Shutdown` or EOF.
pub fn serve_session<R, W>(
    mut reader: R,
    writer: W,
    mut opts: SessionOptions,
) -> io::Result<()>
where
    R: Read,
    W: Write + Send + 'static,
{
    let writer = Arc::new(Mutex::new(writer));
    let state = Arc::new(SharedState {
        base_env: Mutex::new(BTreeMap::new()),
        workspace_root: Mutex::new(opts.workspace_root),
        virtual_workspace_mount: Mutex::new(opts.virtual_workspace_mount),
        drop_privs: opts.drop_privs,
        processes: Mutex::new(HashMap::new()),
        ptys: Mutex::new(HashMap::new()),
        tcp_tunnels: Mutex::new(HashMap::new()),
        bridge_listeners: Mutex::new(HashMap::new()),
        pending_bridge_accepts: Mutex::new(HashMap::new()),
        shutting_down: AtomicBool::new(false),
        next_proc_seq: AtomicU64::new(1),
        next_bridge_stream_id: AtomicU64::new(1),
    });

    let mut uploads: HashMap<u64, UploadSession> = HashMap::new();

    loop {
        let req = match read_ctrl_request(&mut reader) {
            Ok(req) => req,
            Err(ProtoError::Io(ref e))
                if matches!(
                    e.kind(),
                    io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset
                ) =>
            {
                break;
            }
            Err(e) => {
                let _ = send_err(
                    &writer,
                    0,
                    CtrlErrorCode::InvalidRequest,
                    format!("protocol decode error: {e}"),
                );
                break;
            }
        };

        match req {
            CtrlRequest::BootConfigure { req_id, config } => {
                // Store session environment & secret placeholders.
                {
                    let mut env_guard = state.base_env.lock().unwrap();
                    env_guard.clear();
                    for (k, v) in &config.env {
                        env_guard.insert(k.clone(), v.clone());
                    }
                    for (k, v) in &config.secret_placeholders {
                        env_guard.insert(k.clone(), v.clone());
                    }
                }
                if !config.workspace_mount.is_empty() {
                    *state.virtual_workspace_mount.lock().unwrap() = config.workspace_mount.clone();
                }

                let outcome = match opts.on_boot_configure.as_mut() {
                    Some(hook) => match hook(&config) {
                        Ok(o) => o,
                        Err(msg) => {
                            let _ = send_err(&writer, req_id, CtrlErrorCode::Internal, msg);
                            continue;
                        }
                    },
                    None => BootApplyOutcome {
                        workspace_mounted: true,
                        netbridge_ready: false,
                    },
                };

                send_resp(
                    &writer,
                    &CtrlResponse::BootReady {
                        req_id,
                        version: env!("CARGO_PKG_VERSION").to_string(),
                        workspace_mounted: outcome.workspace_mounted,
                        netbridge_ready: outcome.netbridge_ready,
                    },
                )?;
            }

            CtrlRequest::ExecStart {
                req_id,
                cmd,
                cwd,
                env,
                stdin,
                timeout_sec,
                background,
            } => {
                if cmd.is_empty() {
                    send_err(
                        &writer,
                        req_id,
                        CtrlErrorCode::InvalidRequest,
                        "exec cmd must not be empty",
                    )?;
                    continue;
                }
                if background {
                    handle_background_exec(
                        req_id,
                        cmd,
                        cwd,
                        env,
                        stdin,
                        &state,
                        &writer,
                    )?;
                } else {
                    let st = Arc::clone(&state);
                    let wr = Arc::clone(&writer);
                    thread::spawn(move || {
                        handle_sync_exec(req_id, cmd, cwd, env, stdin, timeout_sec, st, wr);
                    });
                }
            }

            CtrlRequest::ProcessList { req_id } => {
                let mut processes: Vec<ProcessInfo> = state
                    .processes
                    .lock()
                    .unwrap()
                    .values()
                    .map(|p| p.info())
                    .collect();
                processes.sort_by(|a, b| a.proc_id.cmp(&b.proc_id));
                send_resp(&writer, &CtrlResponse::ProcessListResult { req_id, processes })?;
            }

            CtrlRequest::ProcessLogs {
                req_id,
                proc_id,
                tail,
                follow,
            } => {
                let proc_opt = state.processes.lock().unwrap().get(&proc_id).cloned();
                let Some(proc_ref) = proc_opt else {
                    send_err(
                        &writer,
                        req_id,
                        CtrlErrorCode::NotFound,
                        format!("unknown proc_id: {proc_id}"),
                    )?;
                    continue;
                };
                if follow {
                    let wr = Arc::clone(&writer);
                    thread::spawn(move || {
                        stream_process_logs(req_id, proc_ref, tail, true, wr);
                    });
                } else {
                    stream_process_logs(req_id, proc_ref, tail, false, Arc::clone(&writer));
                }
            }

            CtrlRequest::ProcessSignal {
                req_id,
                proc_id,
                signal,
            } => {
                let proc_opt = state.processes.lock().unwrap().get(&proc_id).cloned();
                let Some(proc_ref) = proc_opt else {
                    send_err(
                        &writer,
                        req_id,
                        CtrlErrorCode::NotFound,
                        format!("unknown proc_id: {proc_id}"),
                    )?;
                    continue;
                };
                let sig = match signal {
                    SignalKind::Sigterm => libc::SIGTERM,
                    SignalKind::Sigkill => libc::SIGKILL,
                    SignalKind::Sigint => libc::SIGINT,
                };
                kill_process_group(proc_ref.pid as libc::pid_t, sig);
                send_resp(&writer, &CtrlResponse::Ack { req_id })?;
            }

            CtrlRequest::ProcessDelete { req_id, proc_id } => {
                let removed = state.processes.lock().unwrap().remove(&proc_id);
                let Some(proc_ref) = removed else {
                    send_err(
                        &writer,
                        req_id,
                        CtrlErrorCode::NotFound,
                        format!("unknown proc_id: {proc_id}"),
                    )?;
                    continue;
                };
                kill_process_group(proc_ref.pid as libc::pid_t, libc::SIGKILL);
                {
                    let mut guard = proc_ref.logs.0.lock().unwrap();
                    guard.deleted = true;
                    proc_ref.logs.1.notify_all();
                }
                send_resp(&writer, &CtrlResponse::Ack { req_id })?;
            }

            CtrlRequest::PtyOpen {
                req_id,
                session_id,
                cmd,
                cwd,
                env,
                cols,
                rows,
            } => {
                if state.ptys.lock().unwrap().contains_key(&session_id) {
                    send_err(
                        &writer,
                        req_id,
                        CtrlErrorCode::InvalidRequest,
                        format!("pty session already exists: {session_id}"),
                    )?;
                    continue;
                }
                let pty_cmd = cmd.unwrap_or_else(default_shell_cmd);
                let merged_env = state.merged_env(&env);
                let work_dir = state.resolve_cwd(cwd.as_deref());

                match PtySession::spawn(
                    &pty_cmd,
                    Some(&work_dir),
                    &merged_env,
                    cols,
                    rows,
                    state.drop_privs,
                ) {
                    Ok(pty_sess) => {
                        let reader_file = match pty_sess.try_clone_reader() {
                            Ok(f) => f,
                            Err(e) => {
                                pty_sess.kill(libc::SIGKILL);
                                send_err(
                                    &writer,
                                    req_id,
                                    CtrlErrorCode::Internal,
                                    format!("failed to clone pty reader: {e}"),
                                )?;
                                continue;
                            }
                        };
                        let child_pid = pty_sess.child_pid();
                        state
                            .ptys
                            .lock()
                            .unwrap()
                            .insert(session_id.clone(), Arc::new(ActivePty { session: pty_sess }));

                        send_resp(
                            &writer,
                            &CtrlResponse::PtyOpened {
                                req_id,
                                session_id: session_id.clone(),
                            },
                        )?;

                        let wr = Arc::clone(&writer);
                        let st = Arc::clone(&state);
                        thread::spawn(move || {
                            pump_pty_output(session_id, child_pid, reader_file, st, wr);
                        });
                    }
                    Err(e) => {
                        send_err(
                            &writer,
                            req_id,
                            CtrlErrorCode::Internal,
                            format!("failed to spawn pty: {e}"),
                        )?;
                    }
                }
            }

            CtrlRequest::PtyInput { session_id, data } => {
                let pty_opt = state.ptys.lock().unwrap().get(&session_id).cloned();
                if let Some(pty) = pty_opt {
                    let _ = pty.session.write_input(&data);
                }
            }

            CtrlRequest::PtyResize {
                session_id,
                cols,
                rows,
            } => {
                let pty_opt = state.ptys.lock().unwrap().get(&session_id).cloned();
                if let Some(pty) = pty_opt {
                    let _ = pty.session.resize(cols, rows);
                }
            }

            CtrlRequest::PtyClose { session_id } => {
                let pty_opt = state.ptys.lock().unwrap().remove(&session_id);
                if let Some(pty) = pty_opt {
                    pty.session.kill(libc::SIGHUP);
                    pty.session.kill(libc::SIGKILL);
                }
            }

            CtrlRequest::UploadBegin { req_id, path, kind } => {
                let ws = state.workspace_root.lock().unwrap().clone();
                let vmount = state.virtual_workspace_mount.lock().unwrap().clone();
                match UploadSession::begin(&ws, &vmount, &path, kind) {
                    Ok(session) => {
                        uploads.insert(req_id, session);
                    }
                    Err(e) => {
                        send_err(&writer, req_id, e.error_code(), e.to_string())?;
                    }
                }
            }

            CtrlRequest::FileChunk { req_id, data, eof } => {
                let Some(upload) = uploads.get_mut(&req_id) else {
                    send_err(
                        &writer,
                        req_id,
                        CtrlErrorCode::NotFound,
                        format!("no active upload for req_id {req_id}"),
                    )?;
                    continue;
                };
                if let Err(e) = upload.write_chunk(data) {
                    uploads.remove(&req_id);
                    send_err(&writer, req_id, e.error_code(), e.to_string())?;
                    continue;
                }
                if eof {
                    let upload = uploads.remove(&req_id).unwrap();
                    match upload.finish() {
                        Ok((bytes_written, files_written)) => {
                            send_resp(
                                &writer,
                                &CtrlResponse::UploadComplete {
                                    req_id,
                                    bytes_written,
                                    files_written,
                                },
                            )?;
                        }
                        Err(e) => {
                            send_err(&writer, req_id, e.error_code(), e.to_string())?;
                        }
                    }
                }
            }

            CtrlRequest::DownloadBegin {
                req_id,
                path,
                format,
            } => {
                let ws = state.workspace_root.lock().unwrap().clone();
                let vmount = state.virtual_workspace_mount.lock().unwrap().clone();
                let wr = Arc::clone(&writer);
                let res = stream_download(req_id, &ws, &vmount, &path, format, |resp| {
                    send_resp(&wr, &resp)
                });
                if let Err(e) = res {
                    send_err(&writer, req_id, e.error_code(), e.to_string())?;
                }
            }

            CtrlRequest::TcpConnect {
                req_id,
                stream_id,
                guest_port,
            } => {
                if guest_port == 0 || stream_id.trim().is_empty() {
                    send_err(
                        &writer,
                        req_id,
                        CtrlErrorCode::InvalidRequest,
                        "tcp_connect requires non-empty stream_id and guest_port > 0",
                    )?;
                    continue;
                }
                if state.tcp_tunnels.lock().unwrap().contains_key(&stream_id) {
                    send_err(
                        &writer,
                        req_id,
                        CtrlErrorCode::InvalidRequest,
                        format!("tcp tunnel already exists: {stream_id}"),
                    )?;
                    continue;
                }
                let st = Arc::clone(&state);
                let wr = Arc::clone(&writer);
                thread::spawn(move || {
                    handle_tcp_connect(req_id, stream_id, guest_port, st, wr);
                });
            }

            CtrlRequest::TcpData { stream_id, data } => {
                let tunnel_opt = state.tcp_tunnels.lock().unwrap().get(&stream_id).cloned();
                if let Some(tunnel) = tunnel_opt {
                    let write_res = tunnel.stream.lock().unwrap().write_all(&data);
                    if write_res.is_err() {
                        if let Some(removed) = state.tcp_tunnels.lock().unwrap().remove(&stream_id)
                        {
                            let _ = removed.stream.lock().unwrap().shutdown(Shutdown::Both);
                        }
                    }
                }
            }

            CtrlRequest::TcpClose { stream_id } => {
                if let Some(tunnel) = state.tcp_tunnels.lock().unwrap().remove(&stream_id) {
                    let _ = tunnel.stream.lock().unwrap().shutdown(Shutdown::Both);
                }
            }

            CtrlRequest::HostBridgeBind { req_id, guest_port } => {
                if guest_port == 0 {
                    send_err(
                        &writer,
                        req_id,
                        CtrlErrorCode::InvalidRequest,
                        "host_bridge_bind requires guest_port > 0",
                    )?;
                    continue;
                }
                if state
                    .bridge_listeners
                    .lock()
                    .unwrap()
                    .contains_key(&guest_port)
                {
                    send_err(
                        &writer,
                        req_id,
                        CtrlErrorCode::InvalidRequest,
                        format!("host bridge already bound on port {guest_port}"),
                    )?;
                    continue;
                }
                let listener = match TcpListener::bind((Ipv4Addr::LOCALHOST, guest_port)) {
                    Ok(l) => l,
                    Err(e) => {
                        let code = if e.kind() == io::ErrorKind::PermissionDenied {
                            CtrlErrorCode::PermissionDenied
                        } else {
                            CtrlErrorCode::Internal
                        };
                        send_err(
                            &writer,
                            req_id,
                            code,
                            format!("failed to bind host bridge on 127.0.0.1:{guest_port}: {e}"),
                        )?;
                        continue;
                    }
                };
                if let Err(e) = listener.set_nonblocking(true) {
                    send_err(
                        &writer,
                        req_id,
                        CtrlErrorCode::Internal,
                        format!(
                            "failed to set nonblocking on host bridge 127.0.0.1:{guest_port}: {e}"
                        ),
                    )?;
                    continue;
                }

                let stop = Arc::new(AtomicBool::new(false));
                let wake = Arc::new((Mutex::new(false), Condvar::new()));
                let stop_clone = Arc::clone(&stop);
                let wake_clone = Arc::clone(&wake);
                let st = Arc::clone(&state);
                let wr = Arc::clone(&writer);
                let join = thread::spawn(move || {
                    run_bridge_listener(guest_port, listener, stop_clone, wake_clone, st, wr);
                });

                state.bridge_listeners.lock().unwrap().insert(
                    guest_port,
                    BridgeListenerHandle {
                        stop,
                        wake,
                        join: Mutex::new(Some(join)),
                    },
                );
                send_resp(&writer, &CtrlResponse::Ack { req_id })?;
            }

            CtrlRequest::HostBridgeUnbind { req_id, guest_port } => {
                let removed = state.bridge_listeners.lock().unwrap().remove(&guest_port);
                let Some(handle) = removed else {
                    send_err(
                        &writer,
                        req_id,
                        CtrlErrorCode::NotFound,
                        format!("no host bridge bound on port {guest_port}"),
                    )?;
                    continue;
                };
                handle.stop_and_join();
                send_resp(&writer, &CtrlResponse::Ack { req_id })?;
            }

            CtrlRequest::HostBridgeAccepted { stream_id } => {
                let pending = state
                    .pending_bridge_accepts
                    .lock()
                    .unwrap()
                    .remove(&stream_id);
                if let Some(pending) = pending {
                    let allowed = !state.shutting_down.load(Ordering::Acquire);
                    if allowed {
                        state
                            .tcp_tunnels
                            .lock()
                            .unwrap()
                            .insert(stream_id, pending.tunnel);
                    }
                    let _ = pending.tx.send((allowed, None));
                }
            }

            CtrlRequest::HostBridgeRejected { stream_id, reason } => {
                let pending = state
                    .pending_bridge_accepts
                    .lock()
                    .unwrap()
                    .remove(&stream_id);
                if let Some(pending) = pending {
                    let _ = pending.tx.send((false, Some(reason)));
                }
            }

            CtrlRequest::Shutdown { req_id } => {
                cleanup_all(&state);
                send_resp(&writer, &CtrlResponse::Ack { req_id })?;
                break;
            }
        }
    }

    cleanup_all(&state);
    Ok(())
}

fn cleanup_all(state: &SharedState) {
    state.shutting_down.store(true, Ordering::Release);
    let bridges: Vec<_> = state.bridge_listeners.lock().unwrap().drain().collect();
    for (_, handle) in bridges {
        handle.stop_and_join();
    }
    state.pending_bridge_accepts.lock().unwrap().clear();
    let procs: Vec<_> = state.processes.lock().unwrap().drain().collect();
    for (_, proc_ref) in procs {
        kill_process_group(proc_ref.pid as libc::pid_t, libc::SIGKILL);
        let mut guard = proc_ref.logs.0.lock().unwrap();
        guard.deleted = true;
        proc_ref.logs.1.notify_all();
    }
    let ptys: Vec<_> = state.ptys.lock().unwrap().drain().collect();
    for (_, pty) in ptys {
        pty.session.kill(libc::SIGKILL);
    }
    let tunnels: Vec<_> = state.tcp_tunnels.lock().unwrap().drain().collect();
    for (_, tunnel) in tunnels {
        if let Ok(stream) = tunnel.stream.lock() {
            let _ = stream.shutdown(Shutdown::Both);
        }
    }
}

fn run_bridge_listener<W: Write + Send + 'static>(
    guest_port: u16,
    listener: TcpListener,
    stop: Arc<AtomicBool>,
    wake: Arc<(Mutex<bool>, Condvar)>,
    state: Arc<SharedState>,
    writer: Arc<Mutex<W>>,
) {
    loop {
        if stop.load(Ordering::Acquire) || state.shutting_down.load(Ordering::Acquire) {
            break;
        }
        match listener.accept() {
            Ok((stream, _peer)) => {
                if stop.load(Ordering::Acquire) || state.shutting_down.load(Ordering::Acquire) {
                    let _ = stream.shutdown(Shutdown::Both);
                    break;
                }
                let st = Arc::clone(&state);
                let wr = Arc::clone(&writer);
                thread::spawn(move || {
                    handle_bridge_connection(guest_port, stream, st, wr);
                });
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                let guard = wake.0.lock().unwrap();
                if *guard
                    || stop.load(Ordering::Acquire)
                    || state.shutting_down.load(Ordering::Acquire)
                {
                    break;
                }
                let _ = wake.1.wait_timeout(guard, BRIDGE_ACCEPT_POLL_INTERVAL);
            }
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => {
                if stop.load(Ordering::Acquire) || state.shutting_down.load(Ordering::Acquire) {
                    break;
                }
                let guard = wake.0.lock().unwrap();
                if *guard {
                    break;
                }
                let _ = wake.1.wait_timeout(guard, BRIDGE_ACCEPT_POLL_INTERVAL);
            }
        }
    }
}

fn handle_bridge_connection<W: Write>(
    guest_port: u16,
    stream: TcpStream,
    state: Arc<SharedState>,
    writer: Arc<Mutex<W>>,
) {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_nodelay(true);

    let read_stream = match stream.try_clone() {
        Ok(s) => s,
        Err(_) => {
            let _ = stream.shutdown(Shutdown::Both);
            return;
        }
    };

    let stream_id = format!(
        "bridge-{}",
        state.next_bridge_stream_id.fetch_add(1, Ordering::Relaxed)
    );
    let tunnel = Arc::new(ActiveTcpTunnel {
        stream: Mutex::new(stream),
    });
    let (tx, rx) = mpsc::channel::<(bool, Option<String>)>();

    {
        let mut pending = state.pending_bridge_accepts.lock().unwrap();
        if state.shutting_down.load(Ordering::Acquire) {
            let _ = read_stream.shutdown(Shutdown::Both);
            return;
        }
        pending.insert(stream_id.clone(), PendingBridgeAccept { tx, tunnel });
    }

    if send_resp(
        &writer,
        &CtrlResponse::HostBridgeOpen {
            stream_id: stream_id.clone(),
            guest_port,
        },
    )
    .is_err()
    {
        state
            .pending_bridge_accepts
            .lock()
            .unwrap()
            .remove(&stream_id);
        let _ = read_stream.shutdown(Shutdown::Both);
        return;
    }

    let accepted = match rx.recv_timeout(BRIDGE_ACCEPT_TIMEOUT) {
        Ok((ok, _reason)) => ok,
        Err(mpsc::RecvTimeoutError::Timeout) => {
            let removed = state
                .pending_bridge_accepts
                .lock()
                .unwrap()
                .remove(&stream_id);
            if removed.is_some() {
                false
            } else {
                // `HostBridgeAccepted` or `cleanup_all` already removed the entry;
                // receive the authoritative decision from the sender.
                matches!(rx.recv(), Ok((true, _)))
            }
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => false,
    };

    if !accepted || state.shutting_down.load(Ordering::Acquire) {
        if let Some(removed) = state.tcp_tunnels.lock().unwrap().remove(&stream_id) {
            let _ = removed.stream.lock().unwrap().shutdown(Shutdown::Both);
        }
        let _ = read_stream.shutdown(Shutdown::Both);
        return;
    }

    pump_tcp_stream_reads(stream_id, read_stream, state, writer);
}

fn handle_tcp_connect<W: Write>(
    req_id: u64,
    stream_id: String,
    guest_port: u16,
    state: Arc<SharedState>,
    writer: Arc<Mutex<W>>,
) {
    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, guest_port));
    let stream = match TcpStream::connect_timeout(&addr, TCP_TUNNEL_CONNECT_TIMEOUT) {
        Ok(s) => s,
        Err(e) => {
            let _ = send_err(
                &writer,
                req_id,
                CtrlErrorCode::NotFound,
                format!("failed to connect to 127.0.0.1:{guest_port}: {e}"),
            );
            return;
        }
    };
    let _ = stream.set_nodelay(true);

    let read_stream = match stream.try_clone() {
        Ok(s) => s,
        Err(e) => {
            let _ = stream.shutdown(Shutdown::Both);
            let _ = send_err(
                &writer,
                req_id,
                CtrlErrorCode::Internal,
                format!("failed to clone tcp tunnel stream: {e}"),
            );
            return;
        }
    };

    {
        let mut tunnels = state.tcp_tunnels.lock().unwrap();
        if state.shutting_down.load(Ordering::Acquire) {
            let _ = stream.shutdown(Shutdown::Both);
            return;
        }
        if tunnels.contains_key(&stream_id) {
            let _ = stream.shutdown(Shutdown::Both);
            let _ = send_err(
                &writer,
                req_id,
                CtrlErrorCode::InvalidRequest,
                format!("tcp tunnel already exists: {stream_id}"),
            );
            return;
        }
        tunnels.insert(
            stream_id.clone(),
            Arc::new(ActiveTcpTunnel {
                stream: Mutex::new(stream),
            }),
        );
    }

    if send_resp(
        &writer,
        &CtrlResponse::TcpConnected {
            req_id,
            stream_id: stream_id.clone(),
        },
    )
    .is_err()
    {
        if let Some(removed) = state.tcp_tunnels.lock().unwrap().remove(&stream_id) {
            let _ = removed.stream.lock().unwrap().shutdown(Shutdown::Both);
        }
        return;
    }

    pump_tcp_stream_reads(stream_id, read_stream, state, writer);
}

fn pump_tcp_stream_reads<W: Write>(
    stream_id: String,
    mut read_stream: TcpStream,
    state: Arc<SharedState>,
    writer: Arc<Mutex<W>>,
) {
    let mut buf = vec![0u8; TCP_TUNNEL_READ_BUF_SIZE];
    let reason = loop {
        match read_stream.read(&mut buf) {
            Ok(0) => break None,
            Ok(n) => {
                if send_resp(
                    &writer,
                    &CtrlResponse::TcpData {
                        stream_id: stream_id.clone(),
                        data: buf[..n].to_vec(),
                    },
                )
                .is_err()
                {
                    break Some("control session closed".to_string());
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => break Some(e.to_string()),
        }
    };

    if let Some(removed) = state.tcp_tunnels.lock().unwrap().remove(&stream_id) {
        let _ = removed.stream.lock().unwrap().shutdown(Shutdown::Both);
    }
    let _ = send_resp(&writer, &CtrlResponse::TcpClosed { stream_id, reason });
}

fn build_command(
    cmd: &[String],
    cwd: &Path,
    env: &BTreeMap<String, String>,
    has_stdin: bool,
    drop_privs: Option<PrivilegeDrop>,
) -> Command {
    let mut command = Command::new(&cmd[0]);
    if cmd.len() > 1 {
        command.args(&cmd[1..]);
    }
    command.current_dir(cwd);
    command.env_clear();
    command.envs(env);
    command.stdin(if has_stdin {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());

    unsafe {
        command.pre_exec(move || {
            // Isolate into its own process group so timeouts/signals kill grandchildren too.
            libc::setpgid(0, 0);
            if let Some(privs) = drop_privs {
                if apply_privilege_drop_raw(privs) != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    command
}

#[allow(clippy::too_many_arguments)]
fn handle_sync_exec<W: Write + Send + 'static>(
    req_id: u64,
    cmd: Vec<String>,
    cwd: Option<String>,
    env: BTreeMap<String, String>,
    stdin: Option<Vec<u8>>,
    timeout_sec: Option<u64>,
    state: Arc<SharedState>,
    writer: Arc<Mutex<W>>,
) {
    let start = Instant::now();
    let merged_env = state.merged_env(&env);
    let work_dir = state.resolve_cwd(cwd.as_deref());
    let mut command = build_command(&cmd, &work_dir, &merged_env, stdin.is_some(), state.drop_privs);

    let mut child = match command.spawn() {
        Ok(c) => c,
        Err(e) => {
            let _ = send_err(
                &writer,
                req_id,
                CtrlErrorCode::Internal,
                format!("failed to spawn {:?}: {e}", cmd[0]),
            );
            return;
        }
    };

    let pid = child.id() as libc::pid_t;

    if let (Some(bytes), Some(mut child_stdin)) = (stdin, child.stdin.take()) {
        thread::spawn(move || {
            let _ = child_stdin.write_all(&bytes);
        });
    }

    let stdout_handle = child.stdout.take().map(|mut out| {
        let wr = Arc::clone(&writer);
        thread::spawn(move || {
            let mut buf = vec![0u8; EXEC_READ_BUF_SIZE];
            while let Ok(n) = out.read(&mut buf) {
                if n == 0 {
                    break;
                }
                let _ = send_resp(
                    &wr,
                    &CtrlResponse::ExecOutput {
                        req_id,
                        stream: OutputStream::Stdout,
                        data: buf[..n].to_vec(),
                    },
                );
            }
        })
    });

    let stderr_handle = child.stderr.take().map(|mut err| {
        let wr = Arc::clone(&writer);
        thread::spawn(move || {
            let mut buf = vec![0u8; EXEC_READ_BUF_SIZE];
            while let Ok(n) = err.read(&mut buf) {
                if n == 0 {
                    break;
                }
                let _ = send_resp(
                    &wr,
                    &CtrlResponse::ExecOutput {
                        req_id,
                        stream: OutputStream::Stderr,
                        data: buf[..n].to_vec(),
                    },
                );
            }
        })
    });

    let mut timed_out = false;
    let status = if let Some(secs) = timeout_sec {
        let deadline = start + Duration::from_secs(secs);
        loop {
            match child.try_wait() {
                Ok(Some(st)) => break Ok(st),
                Ok(None) => {
                    if Instant::now() >= deadline {
                        timed_out = true;
                        kill_process_group(pid, libc::SIGKILL);
                        break child.wait();
                    }
                    thread::sleep(Duration::from_millis(5));
                }
                Err(e) => break Err(e),
            }
        }
    } else {
        child.wait()
    };

    if let Some(h) = stdout_handle {
        let _ = h.join();
    }
    if let Some(h) = stderr_handle {
        let _ = h.join();
    }

    let exit_code = match status {
        Ok(st) => st
            .code()
            .unwrap_or_else(|| st.signal().map(|s| 128 + s).unwrap_or(-1)),
        Err(_) => -1,
    };

    let _ = send_resp(
        &writer,
        &CtrlResponse::ExecExit {
            req_id,
            exit_code,
            timed_out,
            duration_ms: start.elapsed().as_millis() as u64,
        },
    );
}

fn handle_background_exec<W: Write>(
    req_id: u64,
    cmd: Vec<String>,
    cwd: Option<String>,
    env: BTreeMap<String, String>,
    stdin: Option<Vec<u8>>,
    state: &Arc<SharedState>,
    writer: &Arc<Mutex<W>>,
) -> io::Result<()> {
    let merged_env = state.merged_env(&env);
    let work_dir = state.resolve_cwd(cwd.as_deref());
    let mut command = build_command(&cmd, &work_dir, &merged_env, stdin.is_some(), state.drop_privs);

    let mut child = match command.spawn() {
        Ok(c) => c,
        Err(e) => {
            send_err(
                writer,
                req_id,
                CtrlErrorCode::Internal,
                format!("failed to spawn {:?}: {e}", cmd[0]),
            )?;
            return Ok(());
        }
    };

    let pid = child.id();
    let seq = state.next_proc_seq.fetch_add(1, Ordering::Relaxed);
    let proc_id = format!("proc-{seq}");

    if let (Some(bytes), Some(mut child_stdin)) = (stdin, child.stdin.take()) {
        thread::spawn(move || {
            let _ = child_stdin.write_all(&bytes);
        });
    }

    let logs = Arc::new((
        Mutex::new(ProcessLogInner {
            entries: VecDeque::new(),
            total_bytes: 0,
            next_seq: 0,
            state: ProcessState::Running,
            exit_code: None,
            deleted: false,
        }),
        Condvar::new(),
    ));

    let tracked = Arc::new(TrackedProcess {
        proc_id: proc_id.clone(),
        pid,
        cmd,
        logs: Arc::clone(&logs),
    });

    state
        .processes
        .lock()
        .unwrap()
        .insert(proc_id.clone(), tracked);

    let out_logs = Arc::clone(&logs);
    let stdout_handle = child.stdout.take().map(|mut out| {
        thread::spawn(move || {
            let mut buf = vec![0u8; EXEC_READ_BUF_SIZE];
            while let Ok(n) = out.read(&mut buf) {
                if n == 0 {
                    break;
                }
                TrackedProcess::push_log_bytes(&out_logs, OutputStream::Stdout, &buf[..n]);
            }
        })
    });

    let err_logs = Arc::clone(&logs);
    let stderr_handle = child.stderr.take().map(|mut err| {
        thread::spawn(move || {
            let mut buf = vec![0u8; EXEC_READ_BUF_SIZE];
            while let Ok(n) = err.read(&mut buf) {
                if n == 0 {
                    break;
                }
                TrackedProcess::push_log_bytes(&err_logs, OutputStream::Stderr, &buf[..n]);
            }
        })
    });

    // Reaper thread updates process state once child & output pipes finish.
    let wait_logs = Arc::clone(&logs);
    thread::spawn(move || {
        let status = child.wait();
        if let Some(h) = stdout_handle {
            let _ = h.join();
        }
        if let Some(h) = stderr_handle {
            let _ = h.join();
        }
        let exit_code = match status {
            Ok(st) => st
                .code()
                .unwrap_or_else(|| st.signal().map(|s| 128 + s).unwrap_or(-1)),
            Err(_) => -1,
        };
        let mut guard = wait_logs.0.lock().unwrap();
        guard.state = ProcessState::Exited;
        guard.exit_code = Some(exit_code);
        wait_logs.1.notify_all();
    });

    send_resp(
        writer,
        &CtrlResponse::ProcessSpawned {
            req_id,
            proc_id,
            pid,
        },
    )
}

fn stream_process_logs<W: Write>(
    req_id: u64,
    proc_ref: Arc<TrackedProcess>,
    tail: Option<usize>,
    follow: bool,
    writer: Arc<Mutex<W>>,
) {
    let mut cursor: u64;
    let initial: Vec<(OutputStream, Vec<u8>)>;
    let done_immediately: bool;

    {
        let guard = proc_ref.logs.0.lock().unwrap();
        let total = guard.entries.len();
        let start_idx = match tail {
            Some(n) if n < total => total - n,
            _ => 0,
        };
        initial = guard
            .entries
            .iter()
            .skip(start_idx)
            .map(|e| (e.stream, e.data.clone()))
            .collect();
        cursor = guard.next_seq;
        done_immediately = !follow || guard.state == ProcessState::Exited || guard.deleted;
    }

    for (stream, data) in initial {
        if send_resp(
            &writer,
            &CtrlResponse::ExecOutput {
                req_id,
                stream,
                data,
            },
        )
        .is_err()
        {
            return;
        }
    }

    if done_immediately {
        let _ = send_resp(&writer, &CtrlResponse::ProcessLogsEnd { req_id });
        return;
    }

    loop {
        let batch: Vec<(OutputStream, Vec<u8>)>;
        let exited: bool;
        {
            let mut guard = proc_ref.logs.0.lock().unwrap();
            while guard.next_seq == cursor
                && guard.state == ProcessState::Running
                && !guard.deleted
            {
                guard = proc_ref.logs.1.wait(guard).unwrap();
            }
            batch = guard
                .entries
                .iter()
                .filter(|e| e.seq >= cursor)
                .map(|e| (e.stream, e.data.clone()))
                .collect();
            cursor = guard.next_seq;
            exited = guard.state == ProcessState::Exited || guard.deleted;
        }

        for (stream, data) in batch {
            if send_resp(
                &writer,
                &CtrlResponse::ExecOutput {
                    req_id,
                    stream,
                    data,
                },
            )
            .is_err()
            {
                return;
            }
        }

        if exited {
            let _ = send_resp(&writer, &CtrlResponse::ProcessLogsEnd { req_id });
            break;
        }
    }
}

fn pump_pty_output<W: Write>(
    session_id: String,
    child_pid: libc::pid_t,
    mut reader_file: std::fs::File,
    state: Arc<SharedState>,
    writer: Arc<Mutex<W>>,
) {
    let mut buf = vec![0u8; 8192];
    loop {
        match reader_file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if send_resp(
                    &writer,
                    &CtrlResponse::PtyOutput {
                        session_id: session_id.clone(),
                        data: buf[..n].to_vec(),
                    },
                )
                .is_err()
                {
                    break;
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            // Linux returns EIO on PTY master when the slave side closes on child exit.
            Err(ref e) if e.raw_os_error() == Some(libc::EIO) => break,
            Err(_) => break,
        }
    }

    let exit_code = wait_pid_exit_code(child_pid);
    state.ptys.lock().unwrap().remove(&session_id);
    let _ = send_resp(
        &writer,
        &CtrlResponse::PtyExited {
            session_id,
            exit_code,
        },
    );
}

fn kill_process_group(pid: libc::pid_t, sig: libc::c_int) {
    unsafe {
        if libc::kill(-pid, sig) != 0 {
            libc::kill(pid, sig);
        }
    }
}

fn default_shell_cmd() -> Vec<String> {
    if Path::new("/bin/bash").is_file() {
        vec!["/bin/bash".into()]
    } else {
        vec!["/bin/sh".into()]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blackwall_proto::{
        read_ctrl_response, write_ctrl_request, DownloadFormat, GuestNetMode, UploadKind,
    };
    use flate2::read::GzDecoder;
    use std::io::Cursor;
    use std::os::unix::net::UnixStream;

    fn spawn_test_session() -> (UnixStream, tempfile::TempDir, thread::JoinHandle<()>) {
        let tmp = tempfile::tempdir().unwrap();
        let ws = tmp.path().to_path_buf();
        let (client, server) = UnixStream::pair().unwrap();
        let server_rx = server.try_clone().unwrap();
        let handle = thread::spawn(move || {
            serve_session(server_rx, server, SessionOptions::for_testing(ws)).unwrap();
        });
        (client, tmp, handle)
    }

    #[test]
    fn session_boot_and_sync_exec_stdout_stderr_exit_timeout() {
        let (mut client, _tmp, handle) = spawn_test_session();

        // 1. BootConfigure -> BootReady
        write_ctrl_request(
            &mut client,
            &CtrlRequest::BootConfigure {
                req_id: 1,
                config: BootConfig {
                    vda_verity: None,
                    network_mode: GuestNetMode::Loopback,
                    mitm_ca_pem: None,
                    env: BTreeMap::from([("TEST_VAR".into(), "blackwall".into())]),
                    secret_placeholders: BTreeMap::from([("API_KEY".into(), "bw_placeholder".into())]),
                    workspace_mount: "/workspace".into(),
                },
            },
        )
        .unwrap();
        match read_ctrl_response(&mut client).unwrap() {
            CtrlResponse::BootReady {
                req_id,
                workspace_mounted,
                ..
            } => {
                assert_eq!(req_id, 1);
                assert!(workspace_mounted);
            }
            other => panic!("unexpected boot response: {other:?}"),
        }

        // 2. Sync ExecStart: echo stdout, stderr, env, non-zero exit code
        write_ctrl_request(
            &mut client,
            &CtrlRequest::ExecStart {
                req_id: 2,
                cmd: vec![
                    "/bin/sh".into(),
                    "-c".into(),
                    "echo \"hello $TEST_VAR $API_KEY\"; echo oops >&2; exit 7".into(),
                ],
                cwd: Some("/workspace".into()),
                env: BTreeMap::new(),
                stdin: None,
                timeout_sec: Some(5),
                background: false,
            },
        )
        .unwrap();

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        loop {
            match read_ctrl_response(&mut client).unwrap() {
                CtrlResponse::ExecOutput {
                    req_id: 2,
                    stream: OutputStream::Stdout,
                    data,
                } => stdout.extend_from_slice(&data),
                CtrlResponse::ExecOutput {
                    req_id: 2,
                    stream: OutputStream::Stderr,
                    data,
                } => stderr.extend_from_slice(&data),
                CtrlResponse::ExecExit {
                    req_id: 2,
                    exit_code,
                    timed_out,
                    ..
                } => {
                    assert_eq!(exit_code, 7);
                    assert!(!timed_out);
                    break;
                }
                other => panic!("unexpected exec response: {other:?}"),
            }
        }
        assert_eq!(String::from_utf8_lossy(&stdout).trim(), "hello blackwall bw_placeholder");
        assert_eq!(String::from_utf8_lossy(&stderr).trim(), "oops");

        // 2b. Sync ExecStart with stdin piping
        write_ctrl_request(
            &mut client,
            &CtrlRequest::ExecStart {
                req_id: 22,
                cmd: vec!["/bin/cat".into()],
                cwd: None,
                env: BTreeMap::new(),
                stdin: Some(b"piped-stdin-ok".to_vec()),
                timeout_sec: Some(5),
                background: false,
            },
        )
        .unwrap();
        let mut cat_out = Vec::new();
        loop {
            match read_ctrl_response(&mut client).unwrap() {
                CtrlResponse::ExecOutput {
                    req_id: 22,
                    stream: OutputStream::Stdout,
                    data,
                } => cat_out.extend_from_slice(&data),
                CtrlResponse::ExecExit {
                    req_id: 22,
                    exit_code,
                    timed_out,
                    ..
                } => {
                    assert_eq!(exit_code, 0);
                    assert!(!timed_out);
                    break;
                }
                other => panic!("unexpected cat response: {other:?}"),
            }
        }
        assert_eq!(cat_out, b"piped-stdin-ok");

        // 3. Sync ExecStart timeout
        write_ctrl_request(
            &mut client,
            &CtrlRequest::ExecStart {
                req_id: 3,
                cmd: vec!["/bin/sh".into(), "-c".into(), "sleep 30".into()],
                cwd: None,
                env: BTreeMap::new(),
                stdin: None,
                timeout_sec: Some(1),
                background: false,
            },
        )
        .unwrap();
        match read_ctrl_response(&mut client).unwrap() {
            CtrlResponse::ExecExit {
                req_id: 3,
                timed_out,
                ..
            } => assert!(timed_out),
            other => panic!("expected timeout ExecExit, got {other:?}"),
        }

        // Shutdown
        write_ctrl_request(&mut client, &CtrlRequest::Shutdown { req_id: 99 }).unwrap();
        assert_eq!(
            read_ctrl_response(&mut client).unwrap(),
            CtrlResponse::Ack { req_id: 99 }
        );
        handle.join().unwrap();
    }

    #[test]
    fn session_background_process_lifecycle() {
        let (mut client, _tmp, handle) = spawn_test_session();

        write_ctrl_request(
            &mut client,
            &CtrlRequest::ExecStart {
                req_id: 10,
                cmd: vec![
                    "/bin/sh".into(),
                    "-c".into(),
                    "echo line1; echo line2; sleep 30".into(),
                ],
                cwd: None,
                env: BTreeMap::new(),
                stdin: None,
                timeout_sec: None,
                background: true,
            },
        )
        .unwrap();

        let proc_id = match read_ctrl_response(&mut client).unwrap() {
            CtrlResponse::ProcessSpawned {
                req_id: 10,
                proc_id,
                pid,
            } => {
                assert!(pid > 0);
                proc_id
            }
            other => panic!("expected ProcessSpawned, got {other:?}"),
        };

        // Wait briefly for the two echo lines to reach the ring buffer.
        thread::sleep(Duration::from_millis(120));

        // ProcessList
        write_ctrl_request(&mut client, &CtrlRequest::ProcessList { req_id: 11 }).unwrap();
        match read_ctrl_response(&mut client).unwrap() {
            CtrlResponse::ProcessListResult {
                req_id: 11,
                processes,
            } => {
                assert_eq!(processes.len(), 1);
                assert_eq!(processes[0].proc_id, proc_id);
                assert_eq!(processes[0].state, ProcessState::Running);
            }
            other => panic!("expected ProcessListResult, got {other:?}"),
        }

        // ProcessLogs (tail=1, follow=false)
        write_ctrl_request(
            &mut client,
            &CtrlRequest::ProcessLogs {
                req_id: 12,
                proc_id: proc_id.clone(),
                tail: Some(1),
                follow: false,
            },
        )
        .unwrap();
        let mut logged = Vec::new();
        loop {
            match read_ctrl_response(&mut client).unwrap() {
                CtrlResponse::ExecOutput {
                    req_id: 12, data, ..
                } => logged.extend_from_slice(&data),
                CtrlResponse::ProcessLogsEnd { req_id: 12 } => break,
                other => panic!("unexpected logs response: {other:?}"),
            }
        }
        assert_eq!(String::from_utf8_lossy(&logged), "line2\n");

        // ProcessSignal(SIGTERM)
        write_ctrl_request(
            &mut client,
            &CtrlRequest::ProcessSignal {
                req_id: 13,
                proc_id: proc_id.clone(),
                signal: SignalKind::Sigterm,
            },
        )
        .unwrap();
        assert_eq!(
            read_ctrl_response(&mut client).unwrap(),
            CtrlResponse::Ack { req_id: 13 }
        );

        // ProcessDelete
        write_ctrl_request(
            &mut client,
            &CtrlRequest::ProcessDelete {
                req_id: 14,
                proc_id: proc_id.clone(),
            },
        )
        .unwrap();
        assert_eq!(
            read_ctrl_response(&mut client).unwrap(),
            CtrlResponse::Ack { req_id: 14 }
        );

        // List should now be empty.
        write_ctrl_request(&mut client, &CtrlRequest::ProcessList { req_id: 15 }).unwrap();
        match read_ctrl_response(&mut client).unwrap() {
            CtrlResponse::ProcessListResult {
                req_id: 15,
                processes,
            } => assert!(processes.is_empty()),
            other => panic!("unexpected list response: {other:?}"),
        }

        write_ctrl_request(&mut client, &CtrlRequest::Shutdown { req_id: 99 }).unwrap();
        assert_eq!(
            read_ctrl_response(&mut client).unwrap(),
            CtrlResponse::Ack { req_id: 99 }
        );
        handle.join().unwrap();
    }

    #[test]
    fn session_interactive_pty_io_resize_and_exit() {
        let (mut client, _tmp, handle) = spawn_test_session();

        write_ctrl_request(
            &mut client,
            &CtrlRequest::PtyOpen {
                req_id: 20,
                session_id: "pty-1".into(),
                cmd: Some(vec!["/bin/sh".into()]),
                cwd: Some("/workspace".into()),
                env: BTreeMap::new(),
                cols: 80,
                rows: 24,
            },
        )
        .unwrap();
        assert_eq!(
            read_ctrl_response(&mut client).unwrap(),
            CtrlResponse::PtyOpened {
                req_id: 20,
                session_id: "pty-1".into(),
            }
        );

        // Resize + send interactive commands + exit 0
        write_ctrl_request(
            &mut client,
            &CtrlRequest::PtyResize {
                session_id: "pty-1".into(),
                cols: 120,
                rows: 40,
            },
        )
        .unwrap();
        write_ctrl_request(
            &mut client,
            &CtrlRequest::PtyInput {
                session_id: "pty-1".into(),
                data: b"echo PTY_MAGIC_42\nexit 0\n".to_vec(),
            },
        )
        .unwrap();

        let mut output = Vec::new();
        let exit_code = loop {
            match read_ctrl_response(&mut client).unwrap() {
                CtrlResponse::PtyOutput { session_id, data } => {
                    assert_eq!(session_id, "pty-1");
                    output.extend_from_slice(&data);
                }
                CtrlResponse::PtyExited {
                    session_id,
                    exit_code,
                } => {
                    assert_eq!(session_id, "pty-1");
                    break exit_code;
                }
                other => panic!("unexpected pty response: {other:?}"),
            }
        };
        assert_eq!(exit_code, 0);
        let text = String::from_utf8_lossy(&output);
        assert!(
            text.contains("PTY_MAGIC_42"),
            "expected PTY_MAGIC_42 in output: {text:?}"
        );

        write_ctrl_request(&mut client, &CtrlRequest::Shutdown { req_id: 99 }).unwrap();
        assert_eq!(
            read_ctrl_response(&mut client).unwrap(),
            CtrlResponse::Ack { req_id: 99 }
        );
        handle.join().unwrap();
    }

    #[test]
    fn session_upload_download_raw_tar_targz_and_path_rejection() {
        let (mut client, _tmp, handle) = spawn_test_session();

        // 1. Raw upload -> raw download round-trip
        write_ctrl_request(
            &mut client,
            &CtrlRequest::UploadBegin {
                req_id: 30,
                path: "/workspace/hello.txt".into(),
                kind: UploadKind::Raw,
            },
        )
        .unwrap();
        write_ctrl_request(
            &mut client,
            &CtrlRequest::FileChunk {
                req_id: 30,
                data: b"hello ".to_vec(),
                eof: false,
            },
        )
        .unwrap();
        write_ctrl_request(
            &mut client,
            &CtrlRequest::FileChunk {
                req_id: 30,
                data: b"blackwall!".to_vec(),
                eof: true,
            },
        )
        .unwrap();
        assert_eq!(
            read_ctrl_response(&mut client).unwrap(),
            CtrlResponse::UploadComplete {
                req_id: 30,
                bytes_written: 16,
                files_written: 1,
            }
        );

        write_ctrl_request(
            &mut client,
            &CtrlRequest::DownloadBegin {
                req_id: 31,
                path: "/workspace/hello.txt".into(),
                format: DownloadFormat::Raw,
            },
        )
        .unwrap();
        let mut downloaded = Vec::new();
        loop {
            match read_ctrl_response(&mut client).unwrap() {
                CtrlResponse::FileChunk {
                    req_id: 31,
                    data,
                    eof,
                } => {
                    downloaded.extend_from_slice(&data);
                    if eof {
                        break;
                    }
                }
                other => panic!("unexpected raw download response: {other:?}"),
            }
        }
        assert_eq!(downloaded, b"hello blackwall!");

        // 2. Tar upload -> TarGz download round-trip
        let mut tar_bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_bytes);
            let data = b"fn main() {}\n";
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, "src/main.rs", &data[..])
                .unwrap();
            builder.finish().unwrap();
        }
        write_ctrl_request(
            &mut client,
            &CtrlRequest::UploadBegin {
                req_id: 32,
                path: "/workspace/proj".into(),
                kind: UploadKind::Tar,
            },
        )
        .unwrap();
        write_ctrl_request(
            &mut client,
            &CtrlRequest::FileChunk {
                req_id: 32,
                data: tar_bytes,
                eof: true,
            },
        )
        .unwrap();
        assert_eq!(
            read_ctrl_response(&mut client).unwrap(),
            CtrlResponse::UploadComplete {
                req_id: 32,
                bytes_written: 13,
                files_written: 1,
            }
        );

        write_ctrl_request(
            &mut client,
            &CtrlRequest::DownloadBegin {
                req_id: 33,
                path: "/workspace/proj".into(),
                format: DownloadFormat::TarGz,
            },
        )
        .unwrap();
        let mut targz_bytes = Vec::new();
        loop {
            match read_ctrl_response(&mut client).unwrap() {
                CtrlResponse::FileChunk {
                    req_id: 33,
                    data,
                    eof,
                } => {
                    targz_bytes.extend_from_slice(&data);
                    if eof {
                        break;
                    }
                }
                other => panic!("unexpected targz download response: {other:?}"),
            }
        }
        let gz = GzDecoder::new(Cursor::new(targz_bytes));
        let mut archive = tar::Archive::new(gz);
        let mut found_main = false;
        for entry in archive.entries().unwrap() {
            let mut e = entry.unwrap();
            if e.path().unwrap() == Path::new("src/main.rs") {
                let mut content = String::new();
                e.read_to_string(&mut content).unwrap();
                assert_eq!(content, "fn main() {}\n");
                found_main = true;
            }
        }
        assert!(found_main, "expected src/main.rs in downloaded tar.gz");

        // 3. Reject path traversal outside workspace
        write_ctrl_request(
            &mut client,
            &CtrlRequest::UploadBegin {
                req_id: 34,
                path: "/workspace/../etc/passwd".into(),
                kind: UploadKind::Raw,
            },
        )
        .unwrap();
        match read_ctrl_response(&mut client).unwrap() {
            CtrlResponse::Error { req_id: 34, code, .. } => {
                assert_eq!(code, CtrlErrorCode::PathViolation);
            }
            other => panic!("expected PathViolation error, got {other:?}"),
        }

        write_ctrl_request(
            &mut client,
            &CtrlRequest::DownloadBegin {
                req_id: 35,
                path: "../etc/passwd".into(),
                format: DownloadFormat::Raw,
            },
        )
        .unwrap();
        match read_ctrl_response(&mut client).unwrap() {
            CtrlResponse::Error { req_id: 35, code, .. } => {
                assert_eq!(code, CtrlErrorCode::PathViolation);
            }
            other => panic!("expected PathViolation error, got {other:?}"),
        }

        write_ctrl_request(&mut client, &CtrlRequest::Shutdown { req_id: 99 }).unwrap();
        assert_eq!(
            read_ctrl_response(&mut client).unwrap(),
            CtrlResponse::Ack { req_id: 99 }
        );
        handle.join().unwrap();
    }

    #[test]
    fn session_tcp_ingress_tunnel_echo_and_connrefused() {
        let (mut client, _tmp, handle) = spawn_test_session();

        // Start a local loopback TCP echo server on an ephemeral port.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server_thread = thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut buf = [0u8; 4096];
            loop {
                match conn.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        conn.write_all(&buf[..n]).unwrap();
                        if &buf[..n] == b"bye" {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        // 1. Connect to the listening port via Port 1002 TcpConnect.
        write_ctrl_request(
            &mut client,
            &CtrlRequest::TcpConnect {
                req_id: 50,
                stream_id: "tcp-test-1".into(),
                guest_port: port,
            },
        )
        .unwrap();
        assert_eq!(
            read_ctrl_response(&mut client).unwrap(),
            CtrlResponse::TcpConnected {
                req_id: 50,
                stream_id: "tcp-test-1".into(),
            }
        );

        // 2. Exchange data bidirectionally.
        write_ctrl_request(
            &mut client,
            &CtrlRequest::TcpData {
                stream_id: "tcp-test-1".into(),
                data: b"hello ingress tunnel".to_vec(),
            },
        )
        .unwrap();
        match read_ctrl_response(&mut client).unwrap() {
            CtrlResponse::TcpData { stream_id, data } => {
                assert_eq!(stream_id, "tcp-test-1");
                assert_eq!(data, b"hello ingress tunnel");
            }
            other => panic!("expected TcpData, got {other:?}"),
        }

        // 3. Trigger clean server-side close and verify TcpClosed arrives.
        write_ctrl_request(
            &mut client,
            &CtrlRequest::TcpData {
                stream_id: "tcp-test-1".into(),
                data: b"bye".to_vec(),
            },
        )
        .unwrap();
        let mut echoed = Vec::new();
        loop {
            match read_ctrl_response(&mut client).unwrap() {
                CtrlResponse::TcpData { stream_id, data } => {
                    assert_eq!(stream_id, "tcp-test-1");
                    echoed.extend_from_slice(&data);
                }
                CtrlResponse::TcpClosed { stream_id, .. } => {
                    assert_eq!(stream_id, "tcp-test-1");
                    break;
                }
                other => panic!("unexpected tcp tunnel response: {other:?}"),
            }
        }
        assert_eq!(echoed, b"bye");
        server_thread.join().unwrap();

        // 4. Connecting to a closed port returns CtrlErrorCode::NotFound.
        let closed_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let closed_port = closed_listener.local_addr().unwrap().port();
        drop(closed_listener);

        write_ctrl_request(
            &mut client,
            &CtrlRequest::TcpConnect {
                req_id: 51,
                stream_id: "tcp-test-closed".into(),
                guest_port: closed_port,
            },
        )
        .unwrap();
        match read_ctrl_response(&mut client).unwrap() {
            CtrlResponse::Error {
                req_id: 51, code, ..
            } => {
                assert_eq!(code, CtrlErrorCode::NotFound);
            }
            other => panic!("expected NotFound error for closed port, got {other:?}"),
        }

        write_ctrl_request(&mut client, &CtrlRequest::Shutdown { req_id: 99 }).unwrap();
        assert_eq!(
            read_ctrl_response(&mut client).unwrap(),
            CtrlResponse::Ack { req_id: 99 }
        );
        handle.join().unwrap();
    }

    fn pick_free_loopback_port() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    }

    #[test]
    fn session_host_bridge_bind_echo_reject_unbind_and_shutdown() {
        let (mut client, _tmp, handle) = spawn_test_session();

        // 1. Reject guest_port == 0 with InvalidRequest.
        write_ctrl_request(
            &mut client,
            &CtrlRequest::HostBridgeBind {
                req_id: 60,
                guest_port: 0,
            },
        )
        .unwrap();
        match read_ctrl_response(&mut client).unwrap() {
            CtrlResponse::Error {
                req_id: 60, code, ..
            } => assert_eq!(code, CtrlErrorCode::InvalidRequest),
            other => panic!("expected InvalidRequest for port 0, got {other:?}"),
        }

        // 2. Bind a free loopback port (retrying if a concurrent workspace test grabbed the
        //    ephemeral port between pick_free_loopback_port and HostBridgeBind) and reject duplicate bind.
        let mut port = 0u16;
        for attempt in 0..8 {
            let candidate = pick_free_loopback_port();
            let req_id = 610 + attempt;
            write_ctrl_request(
                &mut client,
                &CtrlRequest::HostBridgeBind {
                    req_id,
                    guest_port: candidate,
                },
            )
            .unwrap();
            match read_ctrl_response(&mut client).unwrap() {
                CtrlResponse::Ack { req_id: rid } if rid == req_id => {
                    port = candidate;
                    break;
                }
                CtrlResponse::Error { message, .. } if message.contains("Address already in use") => {
                    continue;
                }
                other => panic!("unexpected response binding host bridge: {other:?}"),
            }
        }
        assert_ne!(port, 0, "failed to bind a free loopback port after retries");

        write_ctrl_request(
            &mut client,
            &CtrlRequest::HostBridgeBind {
                req_id: 62,
                guest_port: port,
            },
        )
        .unwrap();
        match read_ctrl_response(&mut client).unwrap() {
            CtrlResponse::Error {
                req_id: 62, code, ..
            } => assert_eq!(code, CtrlErrorCode::InvalidRequest),
            other => panic!("expected InvalidRequest for duplicate bind, got {other:?}"),
        }

        // 3. Guest TCP client connects -> HostBridgeOpen -> HostBridgeAccepted(ok=true)
        //    -> bidirectional TcpData echo -> TcpClose.
        let guest_thread = thread::spawn(move || {
            let mut conn = TcpStream::connect(("127.0.0.1", port)).unwrap();
            conn.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            conn.write_all(b"hello host service").unwrap();
            let mut reply = [0u8; 64];
            let n = conn.read(&mut reply).unwrap();
            assert_eq!(&reply[..n], b"echo: hello host service");
            // Wait for host-initiated TcpClose -> EOF.
            let n2 = conn.read(&mut reply).unwrap();
            assert_eq!(n2, 0);
        });

        let stream_id = match read_ctrl_response(&mut client).unwrap() {
            CtrlResponse::HostBridgeOpen {
                stream_id,
                guest_port,
            } => {
                assert!(stream_id.starts_with("bridge-"), "unexpected id: {stream_id}");
                assert_eq!(guest_port, port);
                stream_id
            }
            other => panic!("expected HostBridgeOpen, got {other:?}"),
        };

        write_ctrl_request(
            &mut client,
            &CtrlRequest::HostBridgeAccepted {
                stream_id: stream_id.clone(),
            },
        )
        .unwrap();

        match read_ctrl_response(&mut client).unwrap() {
            CtrlResponse::TcpData {
                stream_id: sid,
                data,
            } => {
                assert_eq!(sid, stream_id);
                assert_eq!(data, b"hello host service");
            }
            other => panic!("expected TcpData from guest, got {other:?}"),
        }

        write_ctrl_request(
            &mut client,
            &CtrlRequest::TcpData {
                stream_id: stream_id.clone(),
                data: b"echo: hello host service".to_vec(),
            },
        )
        .unwrap();

        write_ctrl_request(
            &mut client,
            &CtrlRequest::TcpClose {
                stream_id: stream_id.clone(),
            },
        )
        .unwrap();

        match read_ctrl_response(&mut client).unwrap() {
            CtrlResponse::TcpClosed { stream_id: sid, .. } => {
                assert_eq!(sid, stream_id);
            }
            other => panic!("expected TcpClosed after TcpClose, got {other:?}"),
        }
        guest_thread.join().unwrap();

        // 4. Guest TCP client rejected via HostBridgeRejected closes cleanly.
        let rejected_guest = thread::spawn(move || {
            let mut conn = TcpStream::connect(("127.0.0.1", port)).unwrap();
            conn.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut buf = [0u8; 16];
            match conn.read(&mut buf) {
                Ok(0) => {}
                Err(e) if e.kind() == io::ErrorKind::ConnectionReset => {}
                other => panic!("expected EOF or reset on rejected bridge conn, got {other:?}"),
            }
        });

        let rejected_stream_id = match read_ctrl_response(&mut client).unwrap() {
            CtrlResponse::HostBridgeOpen {
                stream_id,
                guest_port,
            } => {
                assert_eq!(guest_port, port);
                stream_id
            }
            other => panic!("expected HostBridgeOpen for second client, got {other:?}"),
        };

        write_ctrl_request(
            &mut client,
            &CtrlRequest::HostBridgeRejected {
                stream_id: rejected_stream_id,
                reason: "host refused".into(),
            },
        )
        .unwrap();
        rejected_guest.join().unwrap();

        // 5. Unbind stops listener; duplicate unbind returns NotFound; post-unbind connect fails.
        write_ctrl_request(
            &mut client,
            &CtrlRequest::HostBridgeUnbind {
                req_id: 63,
                guest_port: port,
            },
        )
        .unwrap();
        assert_eq!(
            read_ctrl_response(&mut client).unwrap(),
            CtrlResponse::Ack { req_id: 63 }
        );

        assert!(
            TcpStream::connect(("127.0.0.1", port)).is_err(),
            "expected connection refused after HostBridgeUnbind"
        );

        write_ctrl_request(
            &mut client,
            &CtrlRequest::HostBridgeUnbind {
                req_id: 64,
                guest_port: port,
            },
        )
        .unwrap();
        match read_ctrl_response(&mut client).unwrap() {
            CtrlResponse::Error {
                req_id: 64, code, ..
            } => assert_eq!(code, CtrlErrorCode::NotFound),
            other => panic!("expected NotFound for unbound port, got {other:?}"),
        }

        // 6. Bind another port and verify Shutdown cleans up bound bridge listeners.
        let shutdown_port = pick_free_loopback_port();
        write_ctrl_request(
            &mut client,
            &CtrlRequest::HostBridgeBind {
                req_id: 65,
                guest_port: shutdown_port,
            },
        )
        .unwrap();
        assert_eq!(
            read_ctrl_response(&mut client).unwrap(),
            CtrlResponse::Ack { req_id: 65 }
        );

        write_ctrl_request(&mut client, &CtrlRequest::Shutdown { req_id: 99 }).unwrap();
        assert_eq!(
            read_ctrl_response(&mut client).unwrap(),
            CtrlResponse::Ack { req_id: 99 }
        );
        handle.join().unwrap();

        assert!(
            TcpStream::connect(("127.0.0.1", shutdown_port)).is_err(),
            "expected bridge listener to be closed after Shutdown"
        );
    }
}
