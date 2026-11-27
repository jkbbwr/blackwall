//! Local TCP port forwarding (`blackwall forward <id> <guest_port>`).
//!
//! Binds a local loopback TCP listener (default `127.0.0.1:<guest_port>`) and relays
//! every accepted connection bidirectionally over a daemon WebSocket tunnel
//! (`GET /v1/sandboxes/{id}/tunnel/{guest_port}`) on the `0600` Unix domain socket.

use crate::cli::ForwardArgs;
use crate::client::UdsClient;
use crate::error::{CliError, Result};
use futures_util::{SinkExt, StreamExt};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UnixStream};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

const TCP_READ_BUF_SIZE: usize = 32 * 1024;

/// Parse `--local` bind address (accepts `SocketAddr` like `127.0.0.1:8080` or a bare port like `8080`).
/// Defaults to `127.0.0.1:<guest_port>`.
pub fn parse_local_addr(local: Option<&str>, guest_port: u16) -> Result<SocketAddr> {
    let Some(raw) = local else {
        return Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), guest_port));
    };
    let trimmed = raw.trim();
    if let Ok(port) = trimmed.parse::<u16>() {
        return Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port));
    }
    trimmed.parse::<SocketAddr>().map_err(|e| {
        CliError::InvalidArgument(format!(
            "invalid --local address '{trimmed}': expected IP:PORT (e.g. 127.0.0.1:8080) or PORT: {e}"
        ))
    })
}

/// Relay bytes bidirectionally between a local TCP connection and a daemon tunnel WebSocket.
pub async fn relay_tcp_to_tunnel_ws(
    tcp: TcpStream,
    ws: WebSocketStream<UnixStream>,
) -> io::Result<()> {
    let _ = tcp.set_nodelay(true);
    let (mut tcp_rx, mut tcp_tx) = tcp.into_split();
    let (mut ws_tx, mut ws_rx) = ws.split();

    let mut buf = vec![0u8; TCP_READ_BUF_SIZE];

    loop {
        tokio::select! {
            biased;

            ws_msg = ws_rx.next() => {
                match ws_msg {
                    Some(Ok(Message::Binary(data))) => {
                        if tcp_tx.write_all(&data).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Ping(payload))) => {
                        if ws_tx.send(Message::Pong(payload)).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Pong(_))) | Some(Ok(Message::Text(_))) | Some(Ok(Message::Frame(_))) => {}
                    Some(Ok(Message::Close(_))) | Some(Err(_)) | None => {
                        let _ = tcp_tx.shutdown().await;
                        break;
                    }
                }
            }

            read_res = tcp_rx.read(&mut buf) => {
                match read_res {
                    Ok(0) => {
                        let _ = ws_tx.send(Message::Close(None)).await;
                        break;
                    }
                    Ok(n) => {
                        if ws_tx.send(Message::Binary(buf[..n].to_vec())).await.is_err() {
                            break;
                        }
                    }
                    Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                    Err(_) => {
                        let _ = ws_tx.send(Message::Close(None)).await;
                        break;
                    }
                }
            }
        }
    }

    let _ = ws_tx.close().await;
    Ok(())
}

/// Run `blackwall forward <id> <guest_port> [--local 127.0.0.1:<port>]` until Ctrl-C.
pub async fn run_forward(client: &UdsClient, args: &ForwardArgs, json_out: bool) -> Result<i32> {
    if args.guest_port == 0 {
        return Err(CliError::InvalidArgument(
            "guest_port must be >= 1".into(),
        ));
    }
    let id = crate::commands::resolve_sandbox_id(client, &args.id).await?;
    let bind_addr = parse_local_addr(args.local.as_deref(), args.guest_port)?;
    let listener = TcpListener::bind(bind_addr).await?;
    let local_addr = listener.local_addr()?;
    let browser_url = format!("http://{}.localhost:{}", id, local_addr.port());

    if json_out {
        println!(
            "{}",
            serde_json::to_string(&serde_json::json!({
                "sandbox_id": id,
                "guest_port": args.guest_port,
                "local_addr": local_addr.to_string(),
                "browser_url": browser_url,
            }))?
        );
    } else {
        println!(
            "Forwarding {} -> sandbox {} (127.0.0.1:{})",
            local_addr, id, args.guest_port
        );
        println!("Origin-isolated browser URL: {browser_url}");
        println!("Press Ctrl-C to stop.");
    }

    loop {
        tokio::select! {
            accept_res = listener.accept() => {
                let (tcp_stream, peer) = accept_res?;
                let client = client.clone();
                let sandbox_id = id.clone();
                let guest_port = args.guest_port;
                tokio::spawn(async move {
                    match client.connect_tunnel_ws(&sandbox_id, guest_port).await {
                        Ok(ws) => {
                            let _ = relay_tcp_to_tunnel_ws(tcp_stream, ws).await;
                        }
                        Err(err) => {
                            eprintln!(
                                "blackwall forward ({peer} -> {sandbox_id}:{guest_port}): {err}"
                            );
                        }
                    }
                });
            }
            _ = tokio::signal::ctrl_c() => {
                break;
            }
        }
    }

    Ok(0)
}
