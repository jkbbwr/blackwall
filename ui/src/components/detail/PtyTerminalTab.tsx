import { FitAddon } from "@xterm/addon-fit";
import { Terminal } from "@xterm/xterm";
import "@xterm/xterm/css/xterm.css";
import { createEffect, createSignal, onCleanup, onMount, Show } from "solid-js";
import { buildPtyWsUrl } from "../../api/client";
import type { PtyClientMessage, PtyServerMessage } from "../../api/types";
import { IconPlay, IconRefresh, IconSquare } from "../Icons";

export interface PtyTerminalTabProps {
  sandboxId: string;
  running: boolean;
}

type ConnStatus = "disconnected" | "connecting" | "connected" | "exited" | "error";

export function PtyTerminalTab(props: PtyTerminalTabProps) {
  let mountRef: HTMLDivElement | undefined;
  let terminal: Terminal | undefined;
  let fitAddon: FitAddon | undefined;
  let ws: WebSocket | undefined;
  let resizeObserver: ResizeObserver | undefined;
  const encoder = new TextEncoder();

  const [status, setStatus] = createSignal<ConnStatus>("disconnected");
  const [exitCode, setExitCode] = createSignal<number | null>(null);
  const [errorMsg, setErrorMsg] = createSignal<string | null>(null);
  const [dims, setDims] = createSignal<{ cols: number; rows: number }>({
    cols: 120,
    rows: 40,
  });
  const [customCmd, setCustomCmd] = createSignal("");
  const [customCwd, setCustomCwd] = createSignal("/workspace");

  const closeSocket = () => {
    if (ws) {
      ws.onopen = null;
      ws.onmessage = null;
      ws.onerror = null;
      ws.onclose = null;
      if (
        ws.readyState === WebSocket.OPEN ||
        ws.readyState === WebSocket.CONNECTING
      ) {
        ws.close();
      }
      ws = undefined;
    }
  };

  const sendResize = (cols: number, rows: number) => {
    setDims({ cols, rows });
    if (ws && ws.readyState === WebSocket.OPEN && cols > 0 && rows > 0) {
      const msg: PtyClientMessage = { type: "resize", cols, rows };
      ws.send(JSON.stringify(msg));
    }
  };

  const connect = () => {
    if (!terminal || !fitAddon) return;
    closeSocket();
    setErrorMsg(null);
    setExitCode(null);

    try {
      fitAddon.fit();
    } catch {
      // Container may not be laid out yet
    }

    const cols = Math.max(20, terminal.cols || 120);
    const rows = Math.max(8, terminal.rows || 40);
    setDims({ cols, rows });

    const wsUrl = buildPtyWsUrl(props.sandboxId, {
      cols,
      rows,
      cmd: customCmd().trim() || undefined,
      cwd: customCwd().trim() || undefined,
    });

    setStatus("connecting");
    terminal.reset();
    terminal.writeln(
      `\x1b[38;5;244m[blackwall-pty] connecting to ${props.sandboxId} (${cols}x${rows})…\x1b[0m`,
    );

    const socket = new WebSocket(wsUrl);
    socket.binaryType = "arraybuffer";
    ws = socket;

    socket.onopen = () => {
      if (ws !== socket) return;
      setStatus("connected");
      terminal?.focus();
      sendResize(terminal?.cols ?? cols, terminal?.rows ?? rows);
    };

    socket.onmessage = (event: MessageEvent<ArrayBuffer | Blob | string>) => {
      if (ws !== socket || !terminal) return;
      if (event.data instanceof ArrayBuffer) {
        terminal.write(new Uint8Array(event.data));
      } else if (event.data instanceof Blob) {
        void event.data.arrayBuffer().then((buf) => {
          terminal?.write(new Uint8Array(buf));
        });
      } else if (typeof event.data === "string") {
        try {
          const parsed = JSON.parse(event.data) as Partial<PtyServerMessage>;
          if (parsed.type === "exit" && typeof parsed.code === "number") {
            setExitCode(parsed.code);
            setStatus("exited");
            const color = parsed.code === 0 ? "32" : "31";
            terminal.writeln(
              `\r\n\x1b[${color}m[blackwall-pty] session exited with code ${parsed.code}\x1b[0m`,
            );
          }
        } catch {
          terminal.write(event.data);
        }
      }
    };

    socket.onerror = () => {
      if (ws !== socket) return;
      setErrorMsg("WebSocket connection error — verify sandbox is running and daemon is reachable.");
      setStatus("error");
    };

    socket.onclose = (ev) => {
      if (ws !== socket) return;
      ws = undefined;
      if (status() !== "exited" && status() !== "error") {
        setStatus("disconnected");
        terminal?.writeln(
          `\r\n\x1b[33m[blackwall-pty] disconnected (code ${ev.code})\x1b[0m`,
        );
      }
    };
  };

  const disconnect = () => {
    closeSocket();
    setStatus("disconnected");
    terminal?.writeln("\r\n\x1b[33m[blackwall-pty] closed by operator\x1b[0m");
  };

  onMount(() => {
    if (!mountRef) return;

    const term = new Terminal({
      cursorBlink: true,
      fontFamily:
        '"JetBrains Mono", "Fira Code", ui-monospace, SFMono-Regular, Menlo, monospace',
      fontSize: 13,
      lineHeight: 1.28,
      scrollback: 5000,
      theme: {
        background: "#07090d",
        foreground: "#e6edf3",
        cursor: "#22c55e",
        cursorAccent: "#07090d",
        selectionBackground: "rgba(34, 197, 94, 0.25)",
        black: "#11151c",
        red: "#ef4444",
        green: "#22c55e",
        yellow: "#f59e0b",
        blue: "#3b82f6",
        magenta: "#a855f7",
        cyan: "#38bdf8",
        white: "#e6edf3",
        brightBlack: "#647285",
        brightRed: "#f87171",
        brightGreen: "#4ade80",
        brightYellow: "#fbbf24",
        brightBlue: "#60a5fa",
        brightMagenta: "#c084fc",
        brightCyan: "#7dd3fc",
        brightWhite: "#ffffff",
      },
    });

    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(mountRef);
    fit.fit();

    terminal = term;
    fitAddon = fit;

    const inputDisposable = term.onData((data) => {
      if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(encoder.encode(data));
      }
    });

    const binaryDisposable = term.onBinary((data) => {
      if (ws && ws.readyState === WebSocket.OPEN) {
        const bytes = new Uint8Array(data.length);
        for (let i = 0; i < data.length; i += 1) {
          bytes[i] = data.charCodeAt(i) & 0xff;
        }
        ws.send(bytes);
      }
    });

    const resizeDisposable = term.onResize(({ cols, rows }) => {
      sendResize(cols, rows);
    });

    resizeObserver = new ResizeObserver(() => {
      try {
        fit.fit();
      } catch {
        // Ignore fit during hidden transitions
      }
    });
    resizeObserver.observe(mountRef);

    if (props.running) {
      connect();
    }

    onCleanup(() => {
      closeSocket();
      resizeObserver?.disconnect();
      inputDisposable.dispose();
      binaryDisposable.dispose();
      resizeDisposable.dispose();
      term.dispose();
      terminal = undefined;
      fitAddon = undefined;
    });
  });

  // Reconnect if sandboxId changes while mounted
  let lastSandboxId = props.sandboxId;
  createEffect(() => {
    const id = props.sandboxId;
    if (id !== lastSandboxId) {
      lastSandboxId = id;
      if (props.running && terminal) {
        connect();
      }
    }
  });

  const statusPillClass = () => {
    switch (status()) {
      case "connected":
        return "pill pill-emerald";
      case "connecting":
        return "pill pill-amber";
      case "exited":
        return exitCode() === 0 ? "pill pill-emerald" : "pill pill-crimson";
      case "error":
        return "pill pill-crimson";
      default:
        return "pill";
    }
  };

  return (
    <div class="stack" style={{ gap: "10px" }}>
      <Show when={errorMsg()}>
        {(err) => <div class="banner banner-error mono">{err()}</div>}
      </Show>

      <div class="terminal-shell">
        <div class="terminal-toolbar">
          <div class="row-wrap">
            <span class={statusPillClass()}>
              {status() === "exited"
                ? `exited (code ${exitCode() ?? "?"})`
                : status()}
            </span>
            <span class="pill mono">
              {dims().cols}×{dims().rows}
            </span>
            <input
              type="text"
              class="input mono"
              style={{ width: "160px", padding: "4px 8px", "font-size": "11.5px" }}
              placeholder="cwd (/workspace)"
              value={customCwd()}
              onInput={(e) => setCustomCwd(e.currentTarget.value)}
            />
            <input
              type="text"
              class="input mono"
              style={{ width: "180px", padding: "4px 8px", "font-size": "11.5px" }}
              placeholder="cmd (default shell)"
              value={customCmd()}
              onInput={(e) => setCustomCmd(e.currentTarget.value)}
            />
          </div>
          <div class="row">
            <Show
              when={status() === "connected" || status() === "connecting"}
              fallback={
                <button
                  type="button"
                  class="btn btn-primary btn-sm"
                  onClick={connect}
                  disabled={!props.running}
                >
                  <IconPlay size={12} />
                  <span>Connect PTY</span>
                </button>
              }
            >
              <button
                type="button"
                class="btn btn-sm"
                onClick={connect}
              >
                <IconRefresh size={12} />
                <span>Reconnect</span>
              </button>
              <button
                type="button"
                class="btn btn-danger btn-sm"
                onClick={disconnect}
              >
                <IconSquare size={12} />
                <span>Disconnect</span>
              </button>
            </Show>
          </div>
        </div>

        <div class="terminal-mount" ref={mountRef} />
      </div>
    </div>
  );
}
