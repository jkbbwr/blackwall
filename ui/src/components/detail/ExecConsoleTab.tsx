import { createSignal, For, onCleanup, Show } from "solid-js";
import { execStream, execSync } from "../../api/client";
import type { ExecNdjsonEvent, ExecResult } from "../../api/types";
import {
  formatBytes,
  formatDurationMs,
  parseCommandLine,
} from "../../utils/format";
import { IconPlay, IconSquare, IconTrash } from "../Icons";

interface OutputChunk {
  stream: "stdout" | "stderr" | "system";
  text: string;
}

interface HistoryEntry {
  id: number;
  command: string;
  cwd: string;
  mode: "sync" | "stream";
  exitCode: number | null;
  timedOut: boolean;
  durationMs: number;
  stdoutBytesLen: number;
  stderrBytesLen: number;
  chunks: OutputChunk[];
  timestamp: string;
}

export interface ExecConsoleTabProps {
  sandboxId: string;
  running: boolean;
  onActivity?: () => void;
}

export function ExecConsoleTab(props: ExecConsoleTabProps) {
  let nextHistoryId = 1;
  let activeAbort: AbortController | null = null;
  let outputRef: HTMLDivElement | undefined;

  const [command, setCommand] = createSignal("");
  const [cwd, setCwd] = createSignal("/workspace");
  const [timeoutSec, setTimeoutSec] = createSignal("60");
  const [stdinText, setStdinText] = createSignal("");
  const [useShellWrapper, setUseShellWrapper] = createSignal(true);
  const [mode, setMode] = createSignal<"sync" | "stream">("stream");
  const [showAdvanced, setShowAdvanced] = createSignal(false);

  const [executing, setExecuting] = createSignal(false);
  const [errorMsg, setErrorMsg] = createSignal<string | null>(null);
  const [liveChunks, setLiveChunks] = createSignal<OutputChunk[]>([]);
  const [lastMeta, setLastMeta] = createSignal<{
    exitCode: number | null;
    timedOut: boolean;
    durationMs: number;
    stdoutBytesLen: number;
    stderrBytesLen: number;
  } | null>(null);
  const [history, setHistory] = createSignal<HistoryEntry[]>([]);

  onCleanup(() => {
    activeAbort?.abort();
    activeAbort = null;
  });

  const scrollToBottom = () => {
    if (outputRef) {
      outputRef.scrollTop = outputRef.scrollHeight;
    }
  };

  const stopExecution = () => {
    activeAbort?.abort();
    activeAbort = null;
  };

  const runCommand = async (ev?: SubmitEvent) => {
    ev?.preventDefault();
    const raw = command().trim();
    if (!raw || executing()) return;

    const cmd = useShellWrapper()
      ? ["/bin/sh", "-lc", raw]
      : parseCommandLine(raw);

    if (cmd.length === 0) return;

    const parsedTimeout = Number(timeoutSec().trim());
    const req = {
      cmd,
      cwd: cwd().trim() || undefined,
      stdin: stdinText().length > 0 ? stdinText() : undefined,
      timeout_sec:
        Number.isFinite(parsedTimeout) && parsedTimeout > 0
          ? Math.floor(parsedTimeout)
          : undefined,
    };

    activeAbort?.abort();
    const controller = new AbortController();
    activeAbort = controller;

    setExecuting(true);
    setErrorMsg(null);
    setLiveChunks([]);
    setLastMeta(null);

    const currentMode = mode();
    const currentCwd = cwd().trim() || "/workspace";
    const startedLabel = new Date().toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    });

    try {
      if (currentMode === "sync") {
        const res: ExecResult = await execSync(
          props.sandboxId,
          req,
          controller.signal,
        );
        const chunks: OutputChunk[] = [];
        if (res.stdout) chunks.push({ stream: "stdout", text: res.stdout });
        if (res.stderr) chunks.push({ stream: "stderr", text: res.stderr });

        const stdoutLen =
          res.stdout_bytes_len ?? new TextEncoder().encode(res.stdout).length;
        const stderrLen =
          res.stderr_bytes_len ?? new TextEncoder().encode(res.stderr).length;

        setLiveChunks(chunks);
        setLastMeta({
          exitCode: res.exit_code,
          timedOut: res.timed_out,
          durationMs: res.duration_ms,
          stdoutBytesLen: stdoutLen,
          stderrBytesLen: stderrLen,
        });
        setHistory((prev) => [
          {
            id: nextHistoryId++,
            command: raw,
            cwd: currentCwd,
            mode: "sync",
            exitCode: res.exit_code,
            timedOut: res.timed_out,
            durationMs: res.duration_ms,
            stdoutBytesLen: stdoutLen,
            stderrBytesLen: stderrLen,
            chunks,
            timestamp: startedLabel,
          },
          ...prev.slice(0, 29),
        ]);
      } else {
        const collected: OutputChunk[] = [];
        const encoder = new TextEncoder();
        let stdoutBytes = 0;
        let stderrBytes = 0;
        let exitCode: number | null = null;
        let timedOut = false;
        let durationMs = 0;

        await execStream(
          props.sandboxId,
          req,
          (event: ExecNdjsonEvent) => {
            if (event.type === "stdout") {
              stdoutBytes += encoder.encode(event.data).length;
              collected.push({ stream: "stdout", text: event.data });
              setLiveChunks([...collected]);
              queueMicrotask(scrollToBottom);
            } else if (event.type === "stderr") {
              stderrBytes += encoder.encode(event.data).length;
              collected.push({ stream: "stderr", text: event.data });
              setLiveChunks([...collected]);
              queueMicrotask(scrollToBottom);
            } else if (event.type === "exit") {
              exitCode = event.exit_code;
              timedOut = event.timed_out;
              durationMs = event.duration_ms;
            } else if (event.type === "error") {
              collected.push({
                stream: "system",
                text: `\n[error:${event.code}] ${event.message}\n`,
              });
              setLiveChunks([...collected]);
            }
          },
          controller.signal,
        );

        setLastMeta({
          exitCode,
          timedOut,
          durationMs,
          stdoutBytesLen: stdoutBytes,
          stderrBytesLen: stderrBytes,
        });
        setHistory((prev) => [
          {
            id: nextHistoryId++,
            command: raw,
            cwd: currentCwd,
            mode: "stream",
            exitCode,
            timedOut,
            durationMs,
            stdoutBytesLen: stdoutBytes,
            stderrBytesLen: stderrBytes,
            chunks: collected,
            timestamp: startedLabel,
          },
          ...prev.slice(0, 29),
        ]);
      }
      props.onActivity?.();
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") {
        setLiveChunks((prev) => [
          ...prev,
          { stream: "system", text: "\n[aborted by user]\n" },
        ]);
      } else {
        setErrorMsg(err instanceof Error ? err.message : String(err));
      }
    } finally {
      if (activeAbort === controller) {
        activeAbort = null;
      }
      setExecuting(false);
      queueMicrotask(scrollToBottom);
    }
  };

  const selectHistoryEntry = (entry: HistoryEntry) => {
    setCommand(entry.command);
    setCwd(entry.cwd);
    setLiveChunks(entry.chunks);
    setLastMeta({
      exitCode: entry.exitCode,
      timedOut: entry.timedOut,
      durationMs: entry.durationMs,
      stdoutBytesLen: entry.stdoutBytesLen,
      stderrBytesLen: entry.stderrBytesLen,
    });
  };

  return (
    <div class="stack">
      <form class="panel" onSubmit={runCommand}>
        <div class="panel-header">
          <span class="panel-title">Command Runner</span>
          <div class="row">
            <div class="segmented" role="group" aria-label="Execution mode">
              <button
                type="button"
                class={`segmented-btn mono ${mode() === "stream" ? "active" : ""}`}
                onClick={() => setMode("stream")}
              >
                Stream
              </button>
              <button
                type="button"
                class={`segmented-btn mono ${mode() === "sync" ? "active" : ""}`}
                onClick={() => setMode("sync")}
              >
                Sync
              </button>
            </div>
          </div>
        </div>

        <div class="panel-body stack">
          <div class="row">
            <input
              type="text"
              class="input mono"
              placeholder={
                useShellWrapper()
                  ? "e.g. uname -a && ls -la /workspace"
                  : "e.g. /usr/bin/env"
              }
              value={command()}
              onInput={(e) => setCommand(e.currentTarget.value)}
              disabled={!props.running || executing()}
            />
            <Show
              when={!executing()}
              fallback={
                <button
                  type="button"
                  class="btn btn-danger"
                  onClick={stopExecution}
                >
                  <IconSquare size={13} />
                  <span>Abort</span>
                </button>
              }
            >
              <button
                type="submit"
                class="btn btn-primary"
                disabled={!props.running || command().trim().length === 0}
              >
                <IconPlay size={13} />
                <span>Run</span>
              </button>
            </Show>
          </div>

          <div class="grid-3">
            <div class="field">
              <label class="field-label" for="exec-cwd">Working Dir</label>
              <input
                id="exec-cwd"
                type="text"
                class="input mono"
                value={cwd()}
                onInput={(e) => setCwd(e.currentTarget.value)}
              />
            </div>
            <div class="field">
              <label class="field-label" for="exec-timeout">Timeout (s)</label>
              <input
                id="exec-timeout"
                type="number"
                min="1"
                class="input mono"
                value={timeoutSec()}
                onInput={(e) => setTimeoutSec(e.currentTarget.value)}
              />
            </div>
            <div class="field">
              <span class="field-label">Mode</span>
              <div class="row" style={{ height: "34px" }}>
                <label class="row" style={{ cursor: "pointer", "font-size": "12px" }}>
                  <input
                    type="checkbox"
                    checked={useShellWrapper()}
                    onChange={(e) => setUseShellWrapper(e.currentTarget.checked)}
                  />
                  <span class="mono">/bin/sh -lc</span>
                </label>
                <button
                  type="button"
                  class="btn btn-ghost btn-xs"
                  onClick={() => setShowAdvanced((v) => !v)}
                >
                  {showAdvanced() ? "Hide stdin" : "+ stdin"}
                </button>
              </div>
            </div>
          </div>

          <Show when={showAdvanced()}>
            <div class="field">
              <label class="field-label" for="exec-stdin">Stdin</label>
              <textarea
                id="exec-stdin"
                class="textarea mono"
                placeholder="Optional stdin payload…"
                value={stdinText()}
                onInput={(e) => setStdinText(e.currentTarget.value)}
              />
            </div>
          </Show>
        </div>
      </form>

      <Show when={errorMsg()}>
        {(err) => <div class="banner banner-error mono">{err()}</div>}
      </Show>

      {/* Output & Metadata Bar */}
      <div class="panel">
        <div class="panel-header">
          <div class="row-wrap">
            <span class="panel-title">Output</span>
            <Show when={executing()}>
              <span class="pill pill-amber">streaming…</span>
            </Show>
            <Show when={lastMeta()}>
              {(meta) => (
                <>
                  <span
                    class={
                      meta().exitCode === 0
                        ? "pill pill-emerald"
                        : "pill pill-crimson"
                    }
                  >
                    exit {meta().exitCode ?? "—"}
                  </span>
                  <span class="pill">
                    {formatDurationMs(meta().durationMs)}
                  </span>
                  <span class="pill">
                    stdout {formatBytes(meta().stdoutBytesLen)}
                  </span>
                  <span class="pill">
                    stderr {formatBytes(meta().stderrBytesLen)}
                  </span>
                  <Show when={meta().timedOut}>
                    <span class="pill pill-crimson">TIMED OUT</span>
                  </Show>
                </>
              )}
            </Show>
          </div>
          <button
            type="button"
            class="btn btn-ghost btn-xs"
            onClick={() => {
              setLiveChunks([]);
              setLastMeta(null);
            }}
          >
            <IconTrash size={12} /> Clear
          </button>
        </div>
        <div class="panel-body">
          <div class="console-output" ref={outputRef}>
            <Show
              when={liveChunks().length > 0}
              fallback={
                <span style={{ color: "var(--text-muted)" }}>
                  {executing()
                    ? "Awaiting output frames…"
                    : "Run a command above to see stdout/stderr output."}
                </span>
              }
            >
              <For each={liveChunks()}>
                {(chunk) => (
                  <span
                    class={
                      chunk.stream === "stderr"
                        ? "stream-stderr"
                        : chunk.stream === "system"
                          ? "stream-system"
                          : "stream-stdout"
                    }
                  >
                    {chunk.text}
                  </span>
                )}
              </For>
            </Show>
          </div>
        </div>
      </div>

      {/* Command History */}
      <Show when={history().length > 0}>
        <div class="panel">
          <div class="panel-header">
            <span class="panel-title">
              Command History ({history().length})
            </span>
            <button
              type="button"
              class="btn btn-ghost btn-xs"
              onClick={() => setHistory([])}
            >
              Clear History
            </button>
          </div>
          <table class="data-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Command</th>
                <th>Mode</th>
                <th>Exit</th>
                <th>Duration</th>
                <th>Bytes</th>
              </tr>
            </thead>
            <tbody>
              <For each={history()}>
                {(entry) => (
                  <tr
                    style={{ cursor: "pointer" }}
                    onClick={() => selectHistoryEntry(entry)}
                    title="Click to inspect output and load command"
                  >
                    <td class="mono" style={{ color: "var(--text-muted)" }}>
                      {entry.timestamp}
                    </td>
                    <td class="mono truncate" style={{ "max-width": "380px" }}>
                      {entry.command}
                    </td>
                    <td>
                      <span class="pill">{entry.mode}</span>
                    </td>
                    <td>
                      <span
                        class={
                          entry.exitCode === 0
                            ? "pill pill-emerald"
                            : "pill pill-crimson"
                        }
                      >
                        {entry.exitCode ?? "—"}
                      </span>
                    </td>
                    <td class="mono">{formatDurationMs(entry.durationMs)}</td>
                    <td class="mono" style={{ color: "var(--text-secondary)" }}>
                      {formatBytes(entry.stdoutBytesLen)} / {formatBytes(entry.stderrBytesLen)}
                    </td>
                  </tr>
                )}
              </For>
            </tbody>
          </table>
        </div>
      </Show>
    </div>
  );
}
