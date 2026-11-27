import { createMemo, createSignal, For, onCleanup, Show } from "solid-js";
import type { SandboxRunStats, SandboxSummary } from "../api/types";
import {
  formatBytes,
  formatDurationMs,
  formatDurationSec,
  formatMib,
  shortId,
} from "../utils/format";
import {
  IconActivity,
  IconCpu,
  IconCube,
  IconFileText,
  IconFolder,
  IconPlus,
  IconRefresh,
  IconShield,
  IconTerminal,
  IconTrash,
} from "./Icons";
import type { DetailTab } from "./SandboxDetailView";

export interface SandboxOverviewProps {
  sandboxes: SandboxSummary[];
  statsById: Record<string, SandboxRunStats>;
  loading: boolean;
  onInspect: (id: string, tab?: DetailTab) => void;
  onDestroy: (id: string) => Promise<void>;
  onOpenCreate: () => void;
  onRefresh: () => void;
}

export function SandboxOverview(props: SandboxOverviewProps) {
  const [search, setSearch] = createSignal("");
  const [modeFilter, setModeFilter] = createSignal<string>("all");
  const [confirmDestroyId, setConfirmDestroyId] = createSignal<string | null>(
    null,
  );
  const [destroyingId, setDestroyingId] = createSignal<string | null>(null);
  const [nowSec, setNowSec] = createSignal(Math.floor(Date.now() / 1000));

  const ticker = window.setInterval(() => {
    setNowSec(Math.floor(Date.now() / 1000));
  }, 1000);
  onCleanup(() => window.clearInterval(ticker));

  const totals = createMemo(() => {
    let activeVms = 0;
    let totalVcpus = 0;
    let totalRamMib = 0;
    let totalWorkspaceMib = 0;
    let totalExecs = 0;
    let totalExecFailed = 0;
    let totalBytesIn = 0;
    let totalBytesOut = 0;

    for (const sb of props.sandboxes) {
      if (sb.state === "running" || sb.state === "starting") {
        activeVms += 1;
      }
      totalVcpus += sb.compute.vcpus;
      totalRamMib += sb.compute.memory_mib;
      totalWorkspaceMib += sb.compute.workspace_mib;

      const st = props.statsById[sb.id];
      if (st) {
        totalExecs += st.exec_count;
        totalExecFailed += st.exec_failed_count;
        totalBytesIn += st.upload_bytes;
        totalBytesOut += st.download_bytes;
      }
    }

    return {
      activeVms,
      totalVcpus,
      totalRamMib,
      totalWorkspaceMib,
      totalExecs,
      totalExecFailed,
      totalBytesTransferred: totalBytesIn + totalBytesOut,
      totalBytesIn,
      totalBytesOut,
    };
  });

  const filteredSandboxes = createMemo(() => {
    const q = search().trim().toLowerCase();
    const mode = modeFilter();
    return props.sandboxes.filter((sb) => {
      if (mode !== "all" && sb.network_mode !== mode) return false;
      if (!q) return true;
      return (
        sb.id.toLowerCase().includes(q) ||
        sb.profile.toLowerCase().includes(q) ||
        sb.state.toLowerCase().includes(q) ||
        (sb.kernel_profile ?? "").toLowerCase().includes(q)
      );
    });
  });

  const handleDestroy = async (id: string) => {
    setDestroyingId(id);
    try {
      await props.onDestroy(id);
      setConfirmDestroyId(null);
    } finally {
      setDestroyingId(null);
    }
  };

  const computeIdleRemaining = (sb: SandboxSummary): number => {
    if (sb.idle_deadline_at > 0) {
      return Math.max(0, sb.idle_deadline_at - nowSec());
    }
    return sb.idle_remaining_sec ?? 0;
  };

  const computeWallRemaining = (sb: SandboxSummary): number => {
    if (sb.expires_at > 0) {
      return Math.max(0, sb.expires_at - nowSec());
    }
    return sb.wall_remaining_sec ?? 0;
  };

  return (
    <>
      <header class="page-header">
        <div class="page-title-group">
          <h1 class="page-title">Sandboxes</h1>
        </div>
        <div class="toolbar-actions">
          <button
            type="button"
            class="btn"
            onClick={() => props.onRefresh()}
            disabled={props.loading}
          >
            <IconRefresh size={14} />
            <span>Refresh</span>
          </button>
          <button
            type="button"
            class="btn btn-primary"
            onClick={() => props.onOpenCreate()}
          >
            <IconPlus size={14} />
            <span>New Sandbox</span>
          </button>
        </div>
      </header>

      <div class="page-scroll">
        {/* Fleet Summary Metrics */}
        <section class="metrics-grid" aria-label="Fleet Metrics">
          <div class="metric-card">
            <div class="metric-label">
              <span>Active VMs</span>
              <IconCube size={14} />
            </div>
            <div class="metric-value" style={{ color: "var(--emerald)" }}>
              {totals().activeVms}
              <span
                style={{
                  "font-size": "13px",
                  color: "var(--text-muted)",
                  "margin-left": "6px",
                }}
              >
                / {props.sandboxes.length}
              </span>
            </div>
            <div class="metric-sub">running</div>
          </div>

          <div class="metric-card">
            <div class="metric-label">
              <span>Compute</span>
              <IconCpu size={14} />
            </div>
            <div class="metric-value">
              {totals().totalVcpus} <span style={{ "font-size": "13px", color: "var(--text-muted)" }}>vCPU</span>
            </div>
            <div class="metric-sub">
              {formatMib(totals().totalRamMib)} RAM · {formatMib(totals().totalWorkspaceMib)} disk
            </div>
          </div>

          <div class="metric-card">
            <div class="metric-label">
              <span>Executions</span>
              <IconActivity size={14} />
            </div>
            <div class="metric-value">{totals().totalExecs}</div>
            <div class="metric-sub">
              {totals().totalExecFailed > 0
                ? `${totals().totalExecFailed} failed`
                : "0 failed"}
            </div>
          </div>

          <div class="metric-card">
            <div class="metric-label">
              <span>Workspace I/O</span>
              <IconShield size={14} />
            </div>
            <div class="metric-value">
              {formatBytes(totals().totalBytesTransferred)}
            </div>
            <div class="metric-sub">
              ↑ {formatBytes(totals().totalBytesIn)} · ↓ {formatBytes(totals().totalBytesOut)}
            </div>
          </div>
        </section>

        {/* Filter Bar */}
        <div
          class="row-wrap"
          style={{ "margin-bottom": "16px", "justify-content": "space-between" }}
        >
          <div class="row" style={{ flex: "1", "max-width": "420px" }}>
            <input
              type="search"
              class="input mono"
              placeholder="Filter by ID or profile…"
              value={search()}
              onInput={(e) => setSearch(e.currentTarget.value)}
            />
          </div>
          <div class="segmented" role="group" aria-label="Network mode filter">
            <For each={["all", "none", "loopback", "egress"] as const}>
              {(mode) => (
                <button
                  type="button"
                  class={`segmented-btn mono ${modeFilter() === mode ? "active" : ""}`}
                  onClick={() => setModeFilter(mode)}
                >
                  {mode}
                </button>
              )}
            </For>
          </div>
        </div>

        {/* Fleet Grid */}
        <Show
          when={filteredSandboxes().length > 0}
          fallback={
            <div class="empty-state">
              <IconCube size={28} />
              <div class="empty-state-title">
                {props.sandboxes.length === 0
                  ? "No active sandboxes"
                  : "No matching sandboxes"}
              </div>
              <div style={{ "font-size": "12px", "margin-bottom": "14px" }}>
                {props.sandboxes.length === 0
                  ? "Launch a sandbox to run commands, browse files, or attach a PTY."
                  : "Adjust your search query or network filter."}
              </div>
              <Show when={props.sandboxes.length === 0}>
                <button
                  type="button"
                  class="btn btn-primary"
                  onClick={() => props.onOpenCreate()}
                >
                  <IconPlus size={14} />
                  <span>New Sandbox</span>
                </button>
              </Show>
            </div>
          }
        >
          <div class="fleet-grid">
            <For each={filteredSandboxes()}>
              {(sb) => {
                const stats = () => props.statsById[sb.id];
                const netPillClass = () =>
                  sb.network_mode === "egress"
                    ? "pill pill-amber"
                    : sb.network_mode === "none"
                      ? "pill pill-emerald"
                      : "pill pill-cyan";
                const statePillClass = () =>
                  sb.state === "running"
                    ? "pill pill-emerald"
                    : sb.state === "stopped"
                      ? "pill pill-crimson"
                      : "pill pill-amber";
                return (
                  <article class="sandbox-card">
                    <div class="sandbox-card-top">
                      <div class="row" style={{ gap: "7px", "min-width": 0 }}>
                        <span class={`dot dot-${sb.state}`} />
                        <span
                          class="sandbox-card-id truncate"
                          onClick={() => props.onInspect(sb.id, "overview")}
                          title={sb.id}
                        >
                          {shortId(sb.id)}
                        </span>
                        <span class="pill">{sb.profile}</span>
                      </div>
                      <span class={statePillClass()}>{sb.state}</span>
                    </div>

                    <div class="sandbox-card-specs">
                      <div class="spec-cell">
                        <span class="spec-cell-label">Compute</span>
                        <span class="spec-cell-value">
                          {sb.compute.vcpus}c / {formatMib(sb.compute.memory_mib)}
                        </span>
                      </div>
                      <div class="spec-cell">
                        <span class="spec-cell-label">Idle TTL</span>
                        <span class="spec-cell-value">
                          {formatDurationSec(computeIdleRemaining(sb))}
                        </span>
                      </div>
                      <div class="spec-cell">
                        <span class="spec-cell-label">Wall TTL</span>
                        <span class="spec-cell-value">
                          {formatDurationSec(computeWallRemaining(sb))}
                        </span>
                      </div>
                    </div>

                    <div class="sandbox-card-meta">
                      <span class={netPillClass()}>net:{sb.network_mode}</span>
                      <Show when={sb.boot_duration_ms !== undefined && sb.boot_duration_ms > 0}>
                        <span class="pill">
                          boot {formatDurationMs(sb.boot_duration_ms ?? 0)}
                        </span>
                      </Show>
                      <Show when={(sb.ingress_allow_ports?.length ?? 0) > 0}>
                        <span class="pill pill-cyan">
                          ports: {sb.ingress_allow_ports?.join(",")}
                        </span>
                      </Show>
                      <Show when={(stats()?.exec_count ?? 0) > 0}>
                        <span class="pill">
                          execs:{stats()?.exec_count}
                        </span>
                      </Show>
                    </div>

                    <div class="sandbox-card-footer">
                      <div class="row-wrap" style={{ gap: "6px" }}>
                        <button
                          type="button"
                          class="btn btn-sm"
                          onClick={() => props.onInspect(sb.id, "overview")}
                        >
                          Inspect
                        </button>
                        <button
                          type="button"
                          class="btn btn-sm"
                          onClick={() => props.onInspect(sb.id, "files")}
                        >
                          <IconFolder size={13} />
                          <span>Files</span>
                        </button>
                        <button
                          type="button"
                          class="btn btn-sm"
                          onClick={() => props.onInspect(sb.id, "logs")}
                        >
                          <IconFileText size={13} />
                          <span>Logs</span>
                        </button>
                        <button
                          type="button"
                          class="btn btn-sm"
                          onClick={() => props.onInspect(sb.id, "terminal")}
                          disabled={sb.state !== "running"}
                        >
                          <IconTerminal size={13} />
                          <span>PTY</span>
                        </button>
                      </div>

                      <Show
                        when={confirmDestroyId() === sb.id}
                        fallback={
                          <button
                            type="button"
                            class="btn btn-danger btn-sm"
                            onClick={() => setConfirmDestroyId(sb.id)}
                          >
                            <IconTrash size={13} />
                            <span>Destroy</span>
                          </button>
                        }
                      >
                        <div class="row">
                          <button
                            type="button"
                            class="btn btn-ghost btn-xs"
                            onClick={() => setConfirmDestroyId(null)}
                            disabled={destroyingId() === sb.id}
                          >
                            Cancel
                          </button>
                          <button
                            type="button"
                            class="btn btn-danger btn-xs"
                            onClick={() => void handleDestroy(sb.id)}
                            disabled={destroyingId() === sb.id}
                          >
                            {destroyingId() === sb.id ? "Wiping…" : "Confirm Wipe"}
                          </button>
                        </div>
                      </Show>
                    </div>
                  </article>
                );
              }}
            </For>
          </div>
        </Show>
      </div>
    </>
  );
}
