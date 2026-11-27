//! Interactive PTY terminal handling (`blackwall shell`).
//!
//! Sets raw terminal mode via `termios` when stdin is a TTY, unconditionally restores
//! the saved `termios` on `Drop`, forwards stdin/stdout binary WebSocket frames, and
//! relays `SIGWINCH` terminal resize events as JSON text frames.

use crate::cli::ShellArgs;
use crate::client::UdsClient;
use crate::error::Result;
use futures_util::{SinkExt, StreamExt};
use std::io::{self, Read, Write};
use std::os::unix::io::RawFd;
use tokio::signal::unix::{signal, SignalKind as UnixSignalKind};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

const DEFAULT_COLS: u16 = 120;
const DEFAULT_ROWS: u16 = 40;

/// RAII guard that puts a TTY file descriptor into raw mode and restores the
/// original `termios` attributes cleanly on `Drop`.
pub struct RawTerminalGuard {
    fd: RawFd,
    orig: libc::termios,
}

impl RawTerminalGuard {
    /// Enter raw terminal mode if `fd` refers to a TTY; returns `Ok(None)` if not a TTY.
    pub fn enter(fd: RawFd) -> io::Result<Option<Self>> {
        let is_tty = unsafe { libc::isatty(fd) };
        if is_tty != 1 {
            return Ok(None);
        }

        let mut orig = std::mem::MaybeUninit::<libc::termios>::zeroed();
        if unsafe { libc::tcgetattr(fd, orig.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let orig = unsafe { orig.assume_init() };

        let mut raw = orig;
        unsafe { libc::cfmakeraw(&mut raw) };
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &raw) } != 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(Some(Self { fd, orig }))
    }
}

impl Drop for RawTerminalGuard {
    fn drop(&mut self) {
        let _ = unsafe { libc::tcsetattr(self.fd, libc::TCSANOW, &self.orig) };
    }
}

/// Query `(cols, rows)` from the given TTY file descriptor via `TIOCGWINSZ`.
pub fn query_terminal_size(fd: RawFd) -> Option<(u16, u16)> {
    let mut ws = libc::winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    if unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws) } == 0 && ws.ws_col > 0 && ws.ws_row > 0
    {
        Some((ws.ws_col, ws.ws_row))
    } else {
        None
    }
}

/// Format a WebSocket PTY resize control JSON frame.
pub fn format_resize_frame(cols: u16, rows: u16) -> String {
    serde_json::json!({
        "type": "resize",
        "cols": cols,
        "rows": rows,
    })
    .to_string()
}

/// Attach an interactive PTY session over the daemon UDS WebSocket endpoint.
pub async fn run_pty_shell(client: &UdsClient, args: &ShellArgs) -> Result<i32> {
    let id = crate::commands::resolve_sandbox_id(client, &args.id).await?;
    let detected = query_terminal_size(libc::STDOUT_FILENO)
        .or_else(|| query_terminal_size(libc::STDIN_FILENO));
    let cols = args
        .cols
        .or_else(|| detected.map(|(c, _)| c))
        .unwrap_or(DEFAULT_COLS);
    let rows = args
        .rows
        .or_else(|| detected.map(|(_, r)| r))
        .unwrap_or(DEFAULT_ROWS);

    let ws_stream = client
        .connect_pty_ws(&id, cols, rows, args.cwd.as_deref(), &args.cmd)
        .await?;

    // Enter raw mode only after the WebSocket handshake succeeds; restored automatically on drop.
    let _raw_guard = RawTerminalGuard::enter(libc::STDIN_FILENO)?;

    let (mut ws_write, mut ws_read) = ws_stream.split();

    // Dedicated blocking thread for stdin so we never block the Tokio executor.
    let (stdin_tx, mut stdin_rx) = mpsc::channel::<Vec<u8>>(32);
    std::thread::Builder::new()
        .name("bw-pty-stdin".to_string())
        .spawn(move || {
            let mut stdin = io::stdin().lock();
            let mut buf = [0u8; 4096];
            loop {
                match stdin.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if stdin_tx.blocking_send(buf[..n].to_vec()).is_err() {
                            break;
                        }
                    }
                    Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                    Err(_) => break,
                }
            }
        })?;

    let mut sigwinch = signal(UnixSignalKind::window_change())?;
    let mut exit_code: i32 = 0;

    loop {
        tokio::select! {
            maybe_input = stdin_rx.recv() => {
                match maybe_input {
                    Some(bytes) => {
                        if ws_write.send(Message::Binary(bytes)).await.is_err() {
                            break;
                        }
                    }
                    None => {
                        // Local stdin closed; keep reading remote output until guest exits.
                        let _ = ws_write.send(Message::Close(None)).await;
                        break;
                    }
                }
            }
            _ = sigwinch.recv() => {
                if let Some((new_cols, new_rows)) = query_terminal_size(libc::STDOUT_FILENO)
                    .or_else(|| query_terminal_size(libc::STDIN_FILENO))
                {
                    let frame = format_resize_frame(new_cols, new_rows);
                    let _ = ws_write.send(Message::Text(frame)).await;
                }
            }
            ws_msg = ws_read.next() => {
                match ws_msg {
                    Some(Ok(Message::Binary(data))) => {
                        let mut stdout = io::stdout().lock();
                        stdout.write_all(&data)?;
                        stdout.flush()?;
                    }
                    Some(Ok(Message::Text(txt))) => {
                        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&txt) {
                            match val.get("type").and_then(|v| v.as_str()) {
                                Some("exit") => {
                                    exit_code = val
                                        .get("code")
                                        .or_else(|| val.get("exit_code"))
                                        .and_then(|v| v.as_i64())
                                        .unwrap_or(0) as i32;
                                    let _ = ws_write.send(Message::Close(None)).await;
                                    break;
                                }
                                Some("error") => {
                                    if let Some(msg) = val.get("message").and_then(|v| v.as_str()) {
                                        let _ = writeln!(io::stderr(), "pty error: {msg}");
                                    }
                                    exit_code = 1;
                                    break;
                                }
                                _ => {}
                            }
                        }
                    }
                    Some(Ok(Message::Ping(payload))) => {
                        let _ = ws_write.send(Message::Pong(payload)).await;
                    }
                    Some(Ok(Message::Close(_))) | None => {
                        break;
                    }
                    Some(Ok(_)) => {}
                    Some(Err(err)) => {
                        return Err(err.into());
                    }
                }
            }
        }
    }

    Ok(exit_code)
}
