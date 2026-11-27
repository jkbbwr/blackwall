import { createMemo, createSignal, For, onCleanup, Show } from "solid-js";
import { keepaliveSandbox } from "../../api/client";
import type { SandboxDetail } from "../../api/types";
import {
  copyToClipboard,
  formatBytes,
  formatDurationMs,
  formatDurationSec,
  formatMib,
  formatUnixDateTime,
  formatUnixTime,
} from "../../utils/format";
import {
  IconActivity,
  IconCheck,
  IconCopy,
  IconCpu,
  IconGlobe,
  IconLock,
  IconShield,
  IconZap,
} from "../Icons";

export interface OverviewSecurityTabProps {
  detail: SandboxDetail;
  onActivity?: () => void;
}

export function OverviewSecurityTab(props: OverviewSecurityTabProps) {
  const [copiedField, setCopiedField] = createSignal<string | null>(null);
  const [nowSec, setNowSec] = createSignal(Math.floor(Date.now() / 1000));
  const [extending, setExtending] = createSignal(false);
  const [extendedOk, setExtendedOk] = createSignal(false);
  const [keepaliveError, setKeepaliveError] = createSignal<string | null>(null);

  const timer = window.setInterval(() => {
    setNowSec(Math.floor(Date.now() / 1000));
  }, 1000);
  onCleanup(() => window.clearInterval(timer));

  const handleKeepalive = async () => {
    if (extending() || props.detail.state !== "running") return;
    setExtending(true);
    setKeepaliveError(null);
    try {
      await keepaliveSandbox(props.detail.id);
      setExtendedOk(true);
      props.onActivity?.();
      window.setTimeout(() => setExtendedOk(false), 2000);
    } catch (err) {
      setKeepaliveError(err instanceof Error ? err.message : String(err));
    } finally {
      setExtending(false);
    }
  };

  const handleCopy = async (field: string, value: string) => {
    if (await copyToClipboard(value)) {
      setCopiedField(field);
      window.setTimeout(() => {
        setCopiedField((prev) => (prev === field ? null : prev));
      }, 1600);
    }
  };

  const idleRemaining = createMemo(() => {
    const d = props.detail;
    if (d.idle_deadline_at > 0) {
      return Math.max(0, d.idle_deadline_at - nowSec());
    }
    return d.idle_remaining_sec ?? 0;
  });

  const wallRemaining = createMemo(() => {
    const d = props.detail;
    if (d.expires_at > 0) {
      return Math.max(0, d.expires_at - nowSec());
    }
    return d.wall_remaining_sec ?? 0;
  });

  const uptimeSec = createMemo(() => {
    const d = props.detail;
    if (d.created_at > 0) {
      return Math.max(0, nowSec() - d.created_at);
    }
    return d.uptime_sec ?? 0;
  });

  const idlePct = createMemo(() => {
    const max = Math.max(1, props.detail.compute.idle_timeout_sec);
    return Math.min(100, Math.max(0, (idleRemaining() / max) * 100));
  });

  const wallPct = createMemo(() => {
    const max = Math.max(1, props.detail.compute.max_wall_time_sec);
    return Math.min(100, Math.max(0, (wallRemaining() / max) * 100));
  });

  const pinnedDnsEntries = createMemo(() =>
    Object.entries(props.detail.pinned_dns ?? {}),
  );

  const configuredSecrets = createMemo(
    () => props.detail.configured_secrets ?? [],
  );

  const stats = createMemo(() => props.detail.stats);

  return (
    <div class="stack">
      {/* Row 1: Security Isolation & Lifecycle Timers */}
      <div class="grid-2">
        <div class="panel">
          <div class="panel-header">
            <span class="panel-title">
              <IconShield size={13} /> Isolation
            </span>
            <span class="pill pill-emerald">dm-verity</span>
          </div>
          <div class="panel-body stack">
            <div class="kv-grid">
              <div class="kv-item">
                <span class="kv-label">Kernel</span>
                <span class="kv-value">
                  {props.detail.kernel_profile ||
                    (props.detail.network_mode === "none"
                      ? "vmlinux-noinet"
                      : "vmlinux-lo")}
                </span>
              </div>
              <div class="kv-item">
                <span class="kv-label">VMM</span>
                <span class="kv-value">
                  {props.detail.vmm_backend || "vmm"} · PID {props.detail.vmm_pid}
                </span>
              </div>
              <div class="kv-item">
                <span class="kv-label">Proxy</span>
                <span class="kv-value">
                  {props.detail.proxy_pid !== undefined &&
                  props.detail.proxy_pid !== null
                    ? `PID ${props.detail.proxy_pid}`
                    : "—"}
                  {" · "}
                  <span
                    style={{
                      color: props.detail.proxy_isolated
                        ? "var(--emerald)"
                        : "var(--text-secondary)",
                    }}
                  >
                    {props.detail.proxy_isolated
                      ? "jailed"
                      : "in-process"}
                  </span>
                </span>
              </div>
              <div class="kv-item">
                <span class="kv-label">Boot</span>
                <span class="kv-value">
                  {props.detail.boot_duration_ms !== undefined
                    ? formatDurationMs(props.detail.boot_duration_ms)
                    : "—"}
                </span>
              </div>
              <div class="kv-item">
                <span class="kv-label">Guest Init</span>
                <span class="kv-value">
                  {props.detail.guest_init_version || "—"}
                </span>
              </div>
            </div>

            <div class="row-wrap">
              <span
                class={
                  props.detail.workspace_mounted
                    ? "pill pill-emerald"
                    : "pill pill-amber"
                }
              >
                {props.detail.workspace_mounted
                  ? "Workspace rw"
                  : "Workspace unmounted"}
              </span>
              <span
                class={
                  props.detail.netbridge_ready
                    ? "pill pill-emerald"
                    : "pill"
                }
              >
                {props.detail.netbridge_ready ? "Netbridge" : "No netbridge"}
              </span>
              <span
                class={
                  props.detail.network_mode === "egress"
                    ? "pill pill-amber"
                    : props.detail.network_mode === "none"
                      ? "pill pill-emerald"
                      : "pill pill-cyan"
                }
              >
                Network: {props.detail.network_mode}
              </span>
              <span
                class={
                  props.detail.proxy_isolated
                    ? "pill pill-emerald"
                    : "pill"
                }
              >
                {props.detail.proxy_isolated
                  ? "Proxy jailed"
                  : "Proxy in-process"}
              </span>
            </div>

            <div class="kv-item">
              <span class="kv-label">Verity Root Hash</span>
              <div class="row">
                <span
                  class="kv-value"
                  style={{ color: "var(--emerald)", "font-size": "11.5px" }}
                >
                  {props.detail.image_roothash}
                </span>
                <button
                  type="button"
                  class="btn btn-xs"
                  onClick={() =>
                    void handleCopy("roothash", props.detail.image_roothash)
                  }
                  title="Copy verity root hash"
                >
                  <Show
                    when={copiedField() === "roothash"}
                    fallback={<IconCopy size={11} />}
                  >
                    <IconCheck size={11} />
                  </Show>
                </button>
              </div>
            </div>

            <Show when={props.detail.image_content_hash}>
              {(ch) => (
                <div class="kv-item">
                  <span class="kv-label">Content Hash</span>
                  <div class="row">
                    <span class="kv-value" style={{ "font-size": "11.5px" }}>
                      {ch()}
                    </span>
                    <button
                      type="button"
                      class="btn btn-xs"
                      onClick={() => void handleCopy("content_hash", ch())}
                    >
                      <Show
                        when={copiedField() === "content_hash"}
                        fallback={<IconCopy size={11} />}
                      >
                        <IconCheck size={11} />
                      </Show>
                    </button>
                  </div>
                </div>
              )}
            </Show>
          </div>
        </div>

        {/* Lifecycle & Compute */}
        <div class="panel">
          <div class="panel-header">
            <span class="panel-title">
              <IconCpu size={13} /> Lifecycle &amp; Compute
            </span>
            <div class="row" style={{ gap: "8px" }}>
              <span class="mono" style={{ "font-size": "11px", color: "var(--text-muted)" }}>
                up {formatDurationSec(uptimeSec())}
              </span>
              <button
                type="button"
                class={`btn btn-xs ${extendedOk() ? "btn-primary" : ""}`}
                onClick={() => void handleKeepalive()}
                disabled={props.detail.state !== "running" || extending()}
                title="Reset idle timeout deadline"
              >
                <Show
                  when={extendedOk()}
                  fallback={<IconZap size={11} />}
                >
                  <IconCheck size={11} />
                </Show>
                <span>
                  {extending()
                    ? "Extending…"
                    : extendedOk()
                      ? "Extended"
                      : "Keepalive"}
                </span>
              </button>
            </div>
          </div>
          <div class="panel-body stack">
            <Show when={keepaliveError()}>
              {(err) => (
                <div class="banner banner-error mono">{err()}</div>
              )}
            </Show>
            <div class="field">
              <div class="row" style={{ "justify-content": "space-between" }}>
                <span class="kv-label">Idle TTL</span>
                <span class="mono" style={{ "font-size": "12px" }}>
                  {formatDurationSec(idleRemaining())} /{" "}
                  {formatDurationSec(props.detail.compute.idle_timeout_sec)}
                </span>
              </div>
              <div class="progress-track">
                <div
                  class={`progress-fill ${idlePct() < 15 ? "crit" : idlePct() < 35 ? "warn" : ""}`}
                  style={{ width: `${idlePct()}%` }}
                />
              </div>
              <span class="field-hint mono">
                deadline: {formatUnixDateTime(props.detail.idle_deadline_at)}
              </span>
            </div>

            <div class="field">
              <div class="row" style={{ "justify-content": "space-between" }}>
                <span class="kv-label">Wall TTL</span>
                <span class="mono" style={{ "font-size": "12px" }}>
                  {formatDurationSec(wallRemaining())} /{" "}
                  {formatDurationSec(props.detail.compute.max_wall_time_sec)}
                </span>
              </div>
              <div class="progress-track">
                <div
                  class={`progress-fill ${wallPct() < 15 ? "crit" : wallPct() < 35 ? "warn" : ""}`}
                  style={{ width: `${wallPct()}%` }}
                />
              </div>
              <span class="field-hint mono">
                expires: {formatUnixDateTime(props.detail.expires_at)}
              </span>
            </div>

            <div class="kv-grid" style={{ "padding-top": "4px" }}>
              <div class="kv-item">
                <span class="kv-label">vCPUs</span>
                <span class="kv-value">{props.detail.compute.vcpus}</span>
              </div>
              <div class="kv-item">
                <span class="kv-label">Memory</span>
                <span class="kv-value">
                  {formatMib(props.detail.compute.memory_mib)}
                </span>
              </div>
              <div class="kv-item">
                <span class="kv-label">Workspace</span>
                <span class="kv-value">
                  {formatMib(props.detail.compute.workspace_mib)}
                </span>
              </div>
              <div class="kv-item">
                <span class="kv-label">Created</span>
                <span class="kv-value">
                  {formatUnixDateTime(props.detail.created_at)}
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Row 2: Live Runtime Stats */}
      <div class="panel">
        <div class="panel-header">
          <span class="panel-title">
            <IconActivity size={13} /> Session Activity
          </span>
          <Show when={stats()?.last_activity_at}>
            {(ts) => (
              <span class="mono" style={{ "font-size": "11px", color: "var(--text-muted)" }}>
                last activity: {formatUnixTime(ts())}
              </span>
            )}
          </Show>
        </div>
        <div class="panel-body">
          <Show
            when={stats()}
            fallback={
              <span style={{ color: "var(--text-muted)" }}>
                No activity recorded yet.
              </span>
            }
          >
            {(s) => (
              <div class="kv-grid">
                <div class="kv-item">
                  <span class="kv-label">Execs</span>
                  <span class="kv-value">
                    {s().exec_count}{" "}
                    <span
                      style={{
                        color:
                          s().exec_failed_count > 0
                            ? "var(--crimson)"
                            : "var(--text-muted)",
                      }}
                    >
                      ({s().exec_failed_count} failed)
                    </span>
                  </span>
                </div>
                <div class="kv-item">
                  <span class="kv-label">Exec Time</span>
                  <span class="kv-value">
                    {formatDurationMs(s().total_exec_duration_ms)}
                  </span>
                </div>
                <div class="kv-item">
                  <span class="kv-label">Processes / PTY</span>
                  <span class="kv-value">
                    {s().background_spawned_count} procs · {s().pty_sessions_count} PTY
                  </span>
                </div>
                <div class="kv-item">
                  <span class="kv-label">Uploads</span>
                  <span class="kv-value">
                    {s().upload_count} ({formatBytes(s().upload_bytes)})
                  </span>
                </div>
                <div class="kv-item">
                  <span class="kv-label">Downloads</span>
                  <span class="kv-value">
                    {s().download_count} ({formatBytes(s().download_bytes)})
                  </span>
                </div>
                <Show when={s().ingress_connections_count !== undefined}>
                  <div class="kv-item">
                    <span class="kv-label">Ingress</span>
                    <span class="kv-value">
                      {s().ingress_connections_count}
                    </span>
                  </div>
                </Show>
              </div>
            )}
          </Show>
        </div>
      </div>

      {/* Row 3: Pinned DNS & Configured Secrets */}
      <div class="grid-2">
        <div class="panel">
          <div class="panel-header">
            <span class="panel-title">
              <IconGlobe size={13} /> Pinned DNS
            </span>
            <span class="pill">{pinnedDnsEntries().length} hosts</span>
          </div>
          <Show
            when={pinnedDnsEntries().length > 0}
            fallback={
              <div class="panel-body" style={{ color: "var(--text-muted)" }}>
                {props.detail.allowed_hosts.length > 0
                  ? `Allowed hosts: ${props.detail.allowed_hosts.join(", ")} (no pinned IPs yet)`
                  : "No egress hosts permitted (fail-closed DNS)."}
              </div>
            }
          >
            <table class="data-table">
              <thead>
                <tr>
                  <th>FQDN</th>
                  <th>Pinned Public IPs</th>
                </tr>
              </thead>
              <tbody>
                <For each={pinnedDnsEntries()}>
                  {([host, ips]) => (
                    <tr>
                      <td class="mono">{host}</td>
                      <td class="mono" style={{ color: "var(--emerald)" }}>
                        {ips.join(", ")}
                      </td>
                    </tr>
                  )}
                </For>
              </tbody>
            </table>
          </Show>
        </div>

        <div class="panel">
          <div class="panel-header">
            <span class="panel-title">
              <IconLock size={13} /> Secrets
            </span>
            <span class="pill">{configuredSecrets().length} keys</span>
          </div>
          <div class="panel-body">
            <Show
              when={configuredSecrets().length > 0}
              fallback={
                <span style={{ color: "var(--text-muted)" }}>
                  No secrets attached.
                </span>
              }
            >
              <div class="row-wrap">
                <For each={configuredSecrets()}>
                  {(keyName) => (
                    <span class="pill pill-amber">
                      <IconLock size={10} /> {keyName}
                    </span>
                  )}
                </For>
              </div>
            </Show>
          </div>
        </div>
      </div>
    </div>
  );
}
