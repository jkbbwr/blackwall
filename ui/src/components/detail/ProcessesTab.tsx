import {
  createEffect,
  createSignal,
  For,
  onCleanup,
  Show,
} from "solid-js";
import { createStore, reconcile } from "solid-js/store";
import {
  deleteProcess,
  execBackground,
  listProcesses,
  processLogsStream,
  signalProcess,
} from "../../api/client";
import type {
  ExecNdjsonEvent,
  ProcessInfo,
  SignalKind,
} from "../../api/types";
import { parseCommandLine } from "../../utils/format";
import { IconPlay, IconRefresh, IconSquare, IconTrash } from "../Icons";

interface LogChunk {
  stream: "stdout" | "stderr" | "system";
  text: string;
}

export interface ProcessesTabProps {
  sandboxId: string;
  initialProcesses: ProcessInfo[];
  running: boolean;
  onActivity?: () => void;
}

export function ProcessesTab(props: ProcessesTabProps) {
  let logAbort: AbortController | null = null;
  let logOutputRef: HTMLDivElement | undefined;

  const [procStore, setProcStore] = createStore<{ items: ProcessInfo[] }>({
    items: props.initialProcesses,
  });
  const [loading, setLoading] = createSignal(false);
  const [errorMsg, setErrorMsg] = createSignal<string | null>(null);

  // Spawn form
  const [spawnCmd, setSpawnCmd] = createSignal("");
  const [spawnCwd, setSpawnCwd] = createSignal("/workspace");
  const [useShell, setUseShell] = createSignal(true);
  const [spawning, setSpawning] = createSignal(false);

  // Log viewer state
  const [selectedProcId, setSelectedProcId] = createSignal<string | null>(null);
  const [followLogs, setFollowLogs] = createSignal(true);
  const [tailLines, setTailLines] = createSignal(200);
  const [streamingLogs, setStreamingLogs] = createSignal(false);
  const [logChunks, setLogChunks] = createSignal<LogChunk[]>([]);

  const refreshProcesses = async () => {
    setLoading(true);
    try {
      const list = await listProcesses(props.sandboxId);
      setProcStore("items", reconcile(list, { key: "proc_id" }));
      setErrorMsg(null);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  };

  createEffect(() => {
    setProcStore("items", reconcile(props.initialProcesses, { key: "proc_id" }));
  });

  onCleanup(() => {
    logAbort?.abort();
    logAbort = null;
  });

  const stopLogStream = () => {
    logAbort?.abort();
    logAbort = null;
    setStreamingLogs(false);
  };

  const openLogs = async (procId: string, follow: boolean, tail: number) => {
    stopLogStream();
    setSelectedProcId(procId);
    setLogChunks([]);
    setStreamingLogs(true);
    setErrorMsg(null);

    const controller = new AbortController();
    logAbort = controller;

    try {
      await processLogsStream(
        props.sandboxId,
        procId,
        { tail, follow, signal: controller.signal },
        (ev: ExecNdjsonEvent) => {
          if (ev.type === "stdout") {
            setLogChunks((prev) => [...prev, { stream: "stdout", text: ev.data }]);
          } else if (ev.type === "stderr") {
            setLogChunks((prev) => [...prev, { stream: "stderr", text: ev.data }]);
          } else if (ev.type === "end") {
            setLogChunks((prev) => [
              ...prev,
              { stream: "system", text: "\n[end of log stream]\n" },
            ]);
          } else if (ev.type === "error") {
            setLogChunks((prev) => [
              ...prev,
              {
                stream: "system",
                text: `\n[error:${ev.code}] ${ev.message}\n`,
              },
            ]);
          }
          queueMicrotask(() => {
            if (logOutputRef) {
              logOutputRef.scrollTop = logOutputRef.scrollHeight;
            }
          });
        },
      );
    } catch (err) {
      if (!(err instanceof DOMException && err.name === "AbortError")) {
        setErrorMsg(err instanceof Error ? err.message : String(err));
      }
    } finally {
      if (logAbort === controller) {
        logAbort = null;
        setStreamingLogs(false);
      }
    }
  };

  const handleSpawn = async (ev: SubmitEvent) => {
    ev.preventDefault();
    const raw = spawnCmd().trim();
    if (!raw || spawning()) return;

    const cmd = useShell() ? ["/bin/sh", "-lc", raw] : parseCommandLine(raw);
    if (cmd.length === 0) return;

    setSpawning(true);
    setErrorMsg(null);
    try {
      const spawned = await execBackground(props.sandboxId, {
        cmd,
        cwd: spawnCwd().trim() || undefined,
        background: true,
      });
      setSpawnCmd("");
      await refreshProcesses();
      props.onActivity?.();
      void openLogs(spawned.proc_id, followLogs(), tailLines());
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : String(err));
    } finally {
      setSpawning(false);
    }
  };

  const handleSignal = async (procId: string, sig: SignalKind) => {
    setErrorMsg(null);
    try {
      await signalProcess(props.sandboxId, procId, sig);
      await refreshProcesses();
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : String(err));
    }
  };

  const handleDelete = async (procId: string) => {
    setErrorMsg(null);
    try {
      if (selectedProcId() === procId) {
        stopLogStream();
        setSelectedProcId(null);
      }
      await deleteProcess(props.sandboxId, procId);
      await refreshProcesses();
      props.onActivity?.();
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : String(err));
    }
  };

  return (
    <div class="stack">
      <Show when={errorMsg()}>
        {(err) => <div class="banner banner-error mono">{err()}</div>}
      </Show>

      {/* Start Process */}
      <form class="panel" onSubmit={handleSpawn}>
        <div class="panel-header">
          <span class="panel-title">Start Process</span>
          <label class="row" style={{ cursor: "pointer", "font-size": "11.5px" }}>
            <input
              type="checkbox"
              checked={useShell()}
              onChange={(e) => setUseShell(e.currentTarget.checked)}
            />
            <span class="mono">/bin/sh -lc</span>
          </label>
        </div>
        <div class="panel-body row">
          <input
            type="text"
            class="input mono"
            placeholder="e.g. python3 -m http.server 8080"
            value={spawnCmd()}
            onInput={(e) => setSpawnCmd(e.currentTarget.value)}
            disabled={!props.running || spawning()}
          />
          <input
            type="text"
            class="input mono"
            style={{ width: "180px" }}
            placeholder="/workspace"
            value={spawnCwd()}
            onInput={(e) => setSpawnCwd(e.currentTarget.value)}
            disabled={!props.running || spawning()}
          />
          <button
            type="submit"
            class="btn btn-primary"
            disabled={!props.running || spawning() || spawnCmd().trim().length === 0}
          >
            <IconPlay size={13} />
            <span>{spawning() ? "Starting…" : "Start"}</span>
          </button>
        </div>
      </form>

      {/* Process Table */}
      <div class="panel">
        <div class="panel-header">
          <span class="panel-title">
            Processes ({procStore.items.length})
          </span>
          <button
            type="button"
            class="btn btn-xs"
            onClick={() => void refreshProcesses()}
            disabled={loading()}
          >
            <IconRefresh size={12} /> Refresh
          </button>
        </div>

        <Show
          when={procStore.items.length > 0}
          fallback={
            <div class="panel-body" style={{ color: "var(--text-muted)" }}>
              No background processes running.
            </div>
          }
        >
          <table class="data-table">
            <thead>
              <tr>
                <th>Proc ID</th>
                <th>PID</th>
                <th>Command</th>
                <th>State</th>
                <th>Exit</th>
                <th style={{ "text-align": "right" }}>Controls</th>
              </tr>
            </thead>
            <tbody>
              <For each={procStore.items}>
                {(proc) => (
                  <tr
                    style={{
                      background:
                        selectedProcId() === proc.proc_id
                          ? "rgba(34, 197, 94, 0.06)"
                          : undefined,
                    }}
                  >
                    <td class="mono" style={{ "font-weight": 600 }}>
                      {proc.proc_id}
                    </td>
                    <td class="mono">{proc.pid}</td>
                    <td class="mono truncate" style={{ "max-width": "300px" }} title={proc.cmd.join(" ")}>
                      {proc.cmd.join(" ")}
                    </td>
                    <td>
                      <span
                        class={
                          proc.state === "running"
                            ? "pill pill-emerald"
                            : "pill"
                        }
                      >
                        {proc.state}
                      </span>
                    </td>
                    <td class="mono">
                      {proc.exit_code !== null ? proc.exit_code : "—"}
                    </td>
                    <td style={{ "text-align": "right" }}>
                      <div class="row" style={{ "justify-content": "flex-end" }}>
                        <button
                          type="button"
                          class="btn btn-xs"
                          onClick={() =>
                            void openLogs(proc.proc_id, followLogs(), tailLines())
                          }
                        >
                          Logs
                        </button>
                        <button
                          type="button"
                          class="btn btn-xs mono"
                          disabled={proc.state !== "running"}
                          onClick={() => void handleSignal(proc.proc_id, "SIGINT")}
                          title="Send SIGINT"
                        >
                          INT
                        </button>
                        <button
                          type="button"
                          class="btn btn-amber btn-xs mono"
                          disabled={proc.state !== "running"}
                          onClick={() => void handleSignal(proc.proc_id, "SIGTERM")}
                          title="Send SIGTERM"
                        >
                          TERM
                        </button>
                        <button
                          type="button"
                          class="btn btn-danger btn-xs mono"
                          disabled={proc.state !== "running"}
                          onClick={() => void handleSignal(proc.proc_id, "SIGKILL")}
                          title="Send SIGKILL"
                        >
                          KILL
                        </button>
                        <button
                          type="button"
                          class="btn btn-ghost btn-xs"
                          onClick={() => void handleDelete(proc.proc_id)}
                          title="Kill & reap handle"
                        >
                          <IconTrash size={12} />
                        </button>
                      </div>
                    </td>
                  </tr>
                )}
              </For>
            </tbody>
          </table>
        </Show>
      </div>

      {/* Live NDJSON Log Viewer */}
      <Show when={selectedProcId()}>
        {(pid) => (
          <div class="panel">
            <div class="panel-header">
              <div class="row-wrap">
                <span class="panel-title">
                  Logs — <span class="mono">{pid()}</span>
                </span>
                <Show when={streamingLogs()}>
                  <span class="pill pill-emerald">LIVE</span>
                </Show>
              </div>
              <div class="row">
                <label class="row" style={{ cursor: "pointer", "font-size": "11.5px" }}>
                  <input
                    type="checkbox"
                    checked={followLogs()}
                    onChange={(e) => {
                      const next = e.currentTarget.checked;
                      setFollowLogs(next);
                      void openLogs(pid(), next, tailLines());
                    }}
                  />
                  <span>Follow</span>
                </label>
                <select
                  class="select mono"
                  style={{ width: "92px", padding: "3px 6px", "font-size": "11px" }}
                  value={tailLines()}
                  onChange={(e) => {
                    const next = Number(e.currentTarget.value);
                    setTailLines(next);
                    void openLogs(pid(), followLogs(), next);
                  }}
                >
                  <option value={50}>tail 50</option>
                  <option value={200}>tail 200</option>
                  <option value={1000}>tail 1000</option>
                </select>
                <Show when={streamingLogs()}>
                  <button
                    type="button"
                    class="btn btn-danger btn-xs"
                    onClick={stopLogStream}
                  >
                    <IconSquare size={11} /> Stop
                  </button>
                </Show>
              </div>
            </div>
            <div class="panel-body">
              <div class="console-output" ref={logOutputRef}>
                <Show
                  when={logChunks().length > 0}
                  fallback={
                    <span style={{ color: "var(--text-muted)" }}>
                      {streamingLogs()
                        ? "Subscribed to process log ring buffer…"
                        : "No log output captured."}
                    </span>
                  }
                >
                  <For each={logChunks()}>
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
        )}
      </Show>
    </div>
  );
}
