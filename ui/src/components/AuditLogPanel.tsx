import {
  createEffect,
  createMemo,
  createSignal,
  For,
  onCleanup,
  Show,
} from "solid-js";
import { streamAuditEvents } from "../api/client";
import type { AuditEvent, AuditOrigin } from "../api/types";
import {
  formatBytes,
  formatDurationMs,
  formatTimestampMs,
  shortHash,
  shortId,
} from "../utils/format";
import { IconPause, IconPlay, IconTrash } from "./Icons";

export interface AuditLogPanelProps {
  sandboxId?: string;
  onSelectSandbox?: (id: string) => void;
}

type CategoryFilter =
  | "all"
  | "proxy"
  | "blocked"
  | "ingress"
  | "exec"
  | "files"
  | "lifecycle";

type ConnectionState = "connecting" | "live" | "paused" | "reconnecting";

interface AuditRow {
  id: number;
  event: AuditEvent;
  searchBlob: string;
}

const MAX_EVENTS = 1000;
const INITIAL_LIMIT = 300;

function isBlockedEvent(ev: AuditEvent): boolean {
  switch (ev.event) {
    case "http_request":
      return ev.status === 403 || ev.status === 407;
    case "dns_query":
      return !ev.allowed;
    case "auth_mismatch":
      return true;
    case "ingress_tunnel":
      return !ev.allowed;
    case "host_service_bridge":
      return !ev.allowed;
    case "unpacker_rejection":
      return true;
    case "vmm_fatal_exit":
      return true;
    case "postgres_query":
    case "exec_command":
    case "file_transfer":
    case "sandbox_lifecycle":
    case "guest_port1001":
      return false;
  }
}

function matchesCategory(ev: AuditEvent, category: CategoryFilter): boolean {
  switch (category) {
    case "all":
      return true;
    case "proxy":
      return (
        ev.event === "http_request" ||
        ev.event === "dns_query" ||
        ev.event === "auth_mismatch" ||
        ev.event === "postgres_query"
      );
    case "blocked":
      return isBlockedEvent(ev);
    case "ingress":
      return (
        ev.event === "ingress_tunnel" || ev.event === "host_service_bridge"
      );
    case "exec":
      return ev.event === "exec_command";
    case "files":
      return (
        ev.event === "file_transfer" || ev.event === "unpacker_rejection"
      );
    case "lifecycle":
      return (
        ev.event === "sandbox_lifecycle" ||
        ev.event === "vmm_fatal_exit" ||
        ev.event === "guest_port1001"
      );
  }
}

function formatGuestPayload(payload: unknown): string {
  if (payload === null || payload === undefined) return "";
  if (typeof payload === "string") return payload;
  try {
    const raw = JSON.stringify(payload);
    return raw.length > 160 ? `${raw.slice(0, 160)}…` : raw;
  } catch {
    return String(payload);
  }
}

function buildSearchBlob(ev: AuditEvent): string {
  const parts: string[] = [ev.sandbox_id, ev.event, ev.origin ?? ""];
  switch (ev.event) {
    case "http_request":
      parts.push(ev.method, ev.host, ev.path, String(ev.status));
      if (ev.auth_injected) parts.push("auth injected");
      break;
    case "dns_query":
      parts.push(
        ev.fqdn,
        ev.allowed ? "allow" : "deny nxdomain blocked",
        ev.synthetic_ip ?? "",
      );
      break;
    case "auth_mismatch":
      parts.push(ev.host, ev.path, ev.reason);
      break;
    case "postgres_query":
      parts.push(ev.host, String(ev.port), ev.message_type, ev.statement);
      break;
    case "ingress_tunnel":
      parts.push(
        String(ev.guest_port),
        `port ${ev.guest_port}`,
        ev.allowed ? "allowed" : "blocked",
      );
      break;
    case "host_service_bridge":
      parts.push(
        ev.name,
        String(ev.guest_port),
        `port ${ev.guest_port}`,
        ev.target,
        "bridge",
        ev.allowed ? "allowed" : "blocked",
      );
      break;
    case "exec_command":
      parts.push(
        ev.cmd.join(" "),
        ev.cwd ?? "",
        ev.background ? "background" : "",
        ev.exit_code !== null ? `exit ${ev.exit_code}` : "",
      );
      break;
    case "file_transfer":
      parts.push(ev.direction, ev.path);
      break;
    case "unpacker_rejection":
      parts.push(ev.path, ev.reason);
      break;
    case "sandbox_lifecycle":
      parts.push(ev.phase, ev.details ?? "", ev.image_roothash ?? "");
      break;
    case "vmm_fatal_exit":
      parts.push(ev.reason, ev.exit_detail);
      break;
    case "guest_port1001":
      parts.push(
        ev.frame.source,
        ev.frame.kind,
        formatGuestPayload(ev.frame.payload),
      );
      break;
  }
  return parts.join(" ").toLowerCase();
}

function badgeForEvent(ev: AuditEvent): { label: string; cls: string } {
  switch (ev.event) {
    case "http_request":
      if (ev.status >= 200 && ev.status < 300) {
        return { label: `HTTP ${ev.status}`, cls: "pill pill-emerald" };
      }
      if (ev.status === 403 || ev.status >= 400) {
        return { label: `HTTP ${ev.status}`, cls: "pill pill-crimson" };
      }
      if (ev.status >= 300 && ev.status < 400) {
        return { label: `HTTP ${ev.status}`, cls: "pill pill-cyan" };
      }
      return { label: `HTTP ${ev.status}`, cls: "pill" };
    case "dns_query":
      return ev.allowed
        ? { label: "DNS ALLOW", cls: "pill pill-cyan" }
        : { label: "DNS DENY", cls: "pill pill-crimson" };
    case "auth_mismatch":
      return { label: "AUTH MISMATCH", cls: "pill pill-crimson" };
    case "postgres_query":
      return { label: `PG ${ev.message_type}`, cls: "pill pill-amber" };
    case "ingress_tunnel":
      return ev.allowed
        ? { label: "INGRESS", cls: "pill pill-emerald" }
        : { label: "INGRESS DENY", cls: "pill pill-crimson" };
    case "host_service_bridge":
      return ev.allowed
        ? { label: "BRIDGE", cls: "pill pill-emerald" }
        : { label: "BRIDGE DENY", cls: "pill pill-crimson" };
    case "exec_command":
      return { label: "EXEC", cls: "pill" };
    case "file_transfer":
      return {
        label: ev.direction === "upload" ? "UPLOAD" : "DOWNLOAD",
        cls: "pill pill-cyan",
      };
    case "unpacker_rejection":
      return { label: "UNPACKER DENY", cls: "pill pill-crimson" };
    case "sandbox_lifecycle":
      return { label: "LIFECYCLE", cls: "pill" };
    case "vmm_fatal_exit":
      return { label: "FATAL", cls: "pill pill-crimson" };
    case "guest_port1001":
      return { label: "GUEST", cls: "pill" };
  }
}

function originBadge(
  origin?: AuditOrigin,
): { label: string; cls: string; title: string } | null {
  switch (origin) {
    case "guest_untrusted":
      return {
        label: "guest (untrusted)",
        cls: "pill pill-amber",
        title: "Untrusted telemetry emitted by guest VM",
      };
    case "unpacker":
      return {
        label: "unpacker",
        cls: "audit-origin-tag audit-origin-cyan",
        title: "Host unpacker",
      };
    case "proxy":
      return {
        label: "proxy",
        cls: "audit-origin-tag",
        title: "Host egress/ingress proxy",
      };
    case "daemon":
      return {
        label: "daemon",
        cls: "audit-origin-tag",
        title: "Host control-plane daemon",
      };
    case "vmm":
      return {
        label: "vmm",
        cls: "audit-origin-tag",
        title: "Host VMM supervisor",
      };
    default:
      return null;
  }
}

const CATEGORY_CHIPS: ReadonlyArray<{
  id: CategoryFilter;
  label: string;
  danger?: boolean;
}> = [
  { id: "all", label: "All" },
  { id: "proxy", label: "Proxy" },
  { id: "blocked", label: "Blocked", danger: true },
  { id: "ingress", label: "Ingress" },
  { id: "exec", label: "Exec" },
  { id: "files", label: "Files" },
  { id: "lifecycle", label: "Lifecycle" },
];

export function AuditLogPanel(props: AuditLogPanelProps) {
  let nextRowId = 1;
  let streamWrapRef: HTMLDivElement | undefined;
  const seenKeys = new Set<string>();

  const [rows, setRows] = createSignal<AuditRow[]>([]);
  const [category, setCategory] = createSignal<CategoryFilter>("all");
  const [search, setSearch] = createSignal("");
  const [live, setLive] = createSignal(true);
  const [autoScroll, setAutoScroll] = createSignal(true);
  const [connState, setConnState] = createSignal<ConnectionState>("connecting");
  const [streamError, setStreamError] = createSignal<string | null>(null);
  const [expandedId, setExpandedId] = createSignal<number | null>(null);

  // Memoize sandboxId so parent telemetry polls never re-trigger stream teardown/reset
  // when the underlying sandbox ID string hasn't actually changed.
  const targetSandboxId = createMemo(() => props.sandboxId);

  // Reset buffered rows when switching between global logs and a specific sandbox (or across sandboxes)
  createEffect(() => {
    void targetSandboxId();
    seenKeys.clear();
    setRows([]);
    setExpandedId(null);
    setStreamError(null);
  });

  // Live NDJSON stream with AbortController cleanup and exponential reconnect backoff
  createEffect(() => {
    const sbId = targetSandboxId();
    const isLive = live();

    if (!isLive) {
      setConnState("paused");
      return;
    }

    let cancelled = false;
    let activeController: AbortController | null = null;
    let retryTimer: number | null = null;
    let attempt = 0;

    // Batch bursty NDJSON lines (e.g. initial 300-event backfill) into one DOM update per frame/microtask
    let pendingRows: AuditRow[] = [];
    let flushScheduled = false;

    const flushPending = () => {
      flushScheduled = false;
      if (cancelled || pendingRows.length === 0) {
        pendingRows = [];
        return;
      }
      // pendingRows arrived oldest -> newest; reverse so newest is at index 0
      const batch = pendingRows.reverse();
      pendingRows = [];
      setRows((prev) => {
        const next = [...batch, ...prev];
        return next.length > MAX_EVENTS ? next.slice(0, MAX_EVENTS) : next;
      });
      if (autoScroll() && streamWrapRef && streamWrapRef.scrollTop !== 0) {
        streamWrapRef.scrollTop = 0;
      }
    };

    const connect = async () => {
      while (!cancelled) {
        activeController = new AbortController();
        setConnState(attempt === 0 ? "connecting" : "reconnecting");

        try {
          await streamAuditEvents({
            sandboxId: sbId,
            limit: INITIAL_LIMIT,
            signal: activeController.signal,
            onOpen: () => {
              if (!cancelled) {
                attempt = 0;
                setConnState("live");
                setStreamError(null);
              }
            },
            onEvent: (ev) => {
              if (cancelled) return;
              const dedupKey = JSON.stringify(ev);
              if (seenKeys.has(dedupKey)) return;
              seenKeys.add(dedupKey);
              if (seenKeys.size > MAX_EVENTS * 2) {
                const oldest = seenKeys.values().next().value;
                if (oldest !== undefined) {
                  seenKeys.delete(oldest);
                }
              }

              pendingRows.push({
                id: nextRowId++,
                event: ev,
                searchBlob: buildSearchBlob(ev),
              });

              if (!flushScheduled) {
                flushScheduled = true;
                queueMicrotask(flushPending);
              }
            },
          });

          if (cancelled) break;
          // Stream ended cleanly while still in live mode -> reconnect with backoff
          attempt += 1;
          setConnState("reconnecting");
        } catch (err) {
          if (cancelled) break;
          if (err instanceof DOMException && err.name === "AbortError") {
            break;
          }
          attempt += 1;
          setConnState("reconnecting");
          setStreamError(err instanceof Error ? err.message : String(err));
        }

        if (cancelled) break;
        const delayMs = Math.min(10_000, 1000 * 2 ** Math.min(attempt - 1, 4));
        await new Promise<void>((resolve) => {
          retryTimer = window.setTimeout(() => {
            retryTimer = null;
            resolve();
          }, delayMs);
        });
      }
    };

    void connect();

    onCleanup(() => {
      cancelled = true;
      pendingRows = [];
      activeController?.abort();
      activeController = null;
      if (retryTimer !== null) {
        window.clearTimeout(retryTimer);
        retryTimer = null;
      }
    });
  });

  const summary = createMemo(() => {
    let httpAllowed = 0;
    let proxyBlocked = 0;
    let dnsTotal = 0;
    let dnsDenied = 0;
    let ingressTotal = 0;
    let ingressDenied = 0;

    for (const row of rows()) {
      const ev = row.event;
      if (isBlockedEvent(ev)) {
        proxyBlocked += 1;
      }
      if (ev.event === "http_request" && ev.status >= 200 && ev.status < 300) {
        httpAllowed += 1;
      } else if (ev.event === "dns_query") {
        dnsTotal += 1;
        if (!ev.allowed) dnsDenied += 1;
      } else if (
        ev.event === "ingress_tunnel" ||
        ev.event === "host_service_bridge"
      ) {
        ingressTotal += 1;
        if (!ev.allowed) ingressDenied += 1;
      }
    }

    return {
      httpAllowed,
      proxyBlocked,
      dnsTotal,
      dnsAllowed: dnsTotal - dnsDenied,
      dnsDenied,
      ingressTotal,
      ingressAllowed: ingressTotal - ingressDenied,
      ingressDenied,
      total: rows().length,
    };
  });

  const filteredRows = createMemo(() => {
    const cat = category();
    const q = search().trim().toLowerCase();
    return rows().filter((row) => {
      if (!matchesCategory(row.event, cat)) return false;
      if (q.length > 0 && !row.searchBlob.includes(q)) return false;
      return true;
    });
  });

  const handleClear = () => {
    setRows([]);
    setExpandedId(null);
  };

  const renderDetails = (ev: AuditEvent) => {
    switch (ev.event) {
      case "http_request": {
        const isErr = ev.status === 403 || ev.status >= 400;
        const sizeLabel =
          ev.request_bytes > 0
            ? `↑${formatBytes(ev.request_bytes)} ↓${formatBytes(ev.response_bytes)}`
            : formatBytes(ev.response_bytes);
        return (
          <div class="audit-detail-line">
            <span class="audit-meta-secondary">{ev.method}</span>
            <span>
              {ev.host}
              {ev.path}
            </span>
            <Show when={isErr}>
              <span class="audit-meta-crimson">→ {ev.status}</span>
            </Show>
            <span class="audit-meta-muted">{sizeLabel}</span>
            <Show when={ev.auth_injected}>
              <span class="pill pill-amber">auth injected</span>
            </Show>
          </div>
        );
      }
      case "dns_query":
        return (
          <div class="audit-detail-line">
            <span>{ev.fqdn}</span>
            <span class="audit-meta-muted">→</span>
            <Show
              when={ev.allowed}
              fallback={
                <span class="audit-meta-crimson">NXDOMAIN (blocked)</span>
              }
            >
              <span class="audit-meta-cyan">
                {ev.synthetic_ip ?? "allowed"}
              </span>
            </Show>
          </div>
        );
      case "auth_mismatch":
        return (
          <div class="audit-detail-line">
            <span>
              {ev.host}
              {ev.path}
            </span>
            <span class="audit-meta-crimson">{ev.reason}</span>
          </div>
        );
      case "postgres_query":
        return (
          <div class="audit-detail-line">
            <span class="audit-meta-amber">
              {ev.host}:{ev.port}
            </span>
            <span class="audit-meta-secondary">
              {ev.statement || `[${ev.message_type}]`}
            </span>
          </div>
        );
      case "ingress_tunnel":
        return (
          <div class="audit-detail-line">
            <span>port {ev.guest_port}</span>
            <span class="audit-meta-secondary">
              in {formatBytes(ev.bytes_in)} / out {formatBytes(ev.bytes_out)}
            </span>
            <Show when={!ev.allowed}>
              <span class="audit-meta-crimson">(blocked)</span>
            </Show>
          </div>
        );
      case "host_service_bridge":
        return (
          <div class="audit-detail-line">
            <span>
              {ev.name} :{ev.guest_port} → {ev.target}
            </span>
            <span class="audit-meta-secondary">
              in {formatBytes(ev.bytes_in)} / out {formatBytes(ev.bytes_out)}
            </span>
            <Show when={!ev.allowed}>
              <span class="audit-meta-crimson">(blocked)</span>
            </Show>
          </div>
        );
      case "exec_command":
        return (
          <div class="audit-detail-line">
            <span>{ev.cmd.join(" ")}</span>
            <Show when={ev.cwd}>
              {(cwd) => <span class="audit-meta-muted">cwd={cwd()}</span>}
            </Show>
            <Show when={ev.background}>
              <span class="pill">bg</span>
            </Show>
            <Show when={ev.exit_code !== null}>
              <span
                class={
                  ev.exit_code === 0
                    ? "audit-meta-emerald"
                    : "audit-meta-crimson"
                }
              >
                exit {ev.exit_code}
              </span>
            </Show>
            <Show when={ev.duration_ms !== null}>
              <span class="audit-meta-muted">
                {formatDurationMs(ev.duration_ms ?? 0)}
              </span>
            </Show>
          </div>
        );
      case "file_transfer":
        return (
          <div class="audit-detail-line">
            <span class="audit-meta-cyan">{ev.direction}</span>
            <span>{ev.path}</span>
            <span class="audit-meta-muted">
              {formatBytes(ev.bytes)} · {ev.files}{" "}
              {ev.files === 1 ? "file" : "files"}
            </span>
          </div>
        );
      case "unpacker_rejection":
        return (
          <div class="audit-detail-line">
            <span>{ev.path}</span>
            <span class="audit-meta-crimson">{ev.reason}</span>
          </div>
        );
      case "sandbox_lifecycle":
        return (
          <div class="audit-detail-line">
            <span class="audit-meta-emerald">{ev.phase}</span>
            <Show when={ev.details}>
              {(d) => <span class="audit-meta-secondary">{d()}</span>}
            </Show>
            <Show when={ev.image_roothash}>
              {(rh) => (
                <span class="audit-meta-muted">
                  verity:{shortHash(rh(), 12)}
                </span>
              )}
            </Show>
          </div>
        );
      case "vmm_fatal_exit":
        return (
          <div class="audit-detail-line">
            <span class="audit-meta-crimson">{ev.reason}</span>
            <Show when={ev.exit_detail}>
              <span class="audit-meta-secondary">{ev.exit_detail}</span>
            </Show>
          </div>
        );
      case "guest_port1001":
        return (
          <div class="audit-detail-line">
            <span class="audit-meta-cyan">
              {ev.frame.source}/{ev.frame.kind}
            </span>
            <span class="audit-meta-muted">
              {formatGuestPayload(ev.frame.payload)}
            </span>
          </div>
        );
    }
  };

  const showSandboxColumn = createMemo(() => !targetSandboxId());
  const colSpan = createMemo(() => (showSandboxColumn() ? 5 : 4));

  return (
    <div class="stack">
      {/* Summary Strip */}
      <section class="audit-summary-strip" aria-label="Audit Event Summary">
        <div class="audit-stat-card">
          <span class="audit-stat-label">HTTP Allowed</span>
          <span class="audit-stat-value" style={{ color: "var(--emerald)" }}>
            {summary().httpAllowed}
          </span>
          <span class="audit-stat-sub">2xx egress</span>
        </div>

        <div class="audit-stat-card">
          <span class="audit-stat-label">Blocked</span>
          <span
            class="audit-stat-value"
            style={{
              color:
                summary().proxyBlocked > 0
                  ? "var(--crimson)"
                  : "var(--text-primary)",
            }}
          >
            {summary().proxyBlocked}
          </span>
          <span class="audit-stat-sub">403 · DNS · Auth</span>
        </div>

        <div class="audit-stat-card">
          <span class="audit-stat-label">DNS</span>
          <span class="audit-stat-value" style={{ color: "var(--cyan)" }}>
            {summary().dnsTotal}
          </span>
          <span class="audit-stat-sub">
            {summary().dnsAllowed} allow · {summary().dnsDenied} deny
          </span>
        </div>

        <div class="audit-stat-card">
          <span class="audit-stat-label">Ingress / Bridges</span>
          <span class="audit-stat-value" style={{ color: "var(--emerald)" }}>
            {summary().ingressTotal}
          </span>
          <span class="audit-stat-sub">
            {summary().ingressAllowed} allow · {summary().ingressDenied} deny
          </span>
        </div>

        <div class="audit-stat-card">
          <span class="audit-stat-label">Events</span>
          <span class="audit-stat-value">{summary().total}</span>
          <span class="audit-stat-sub">
            {filteredRows().length === summary().total
              ? `cap ${MAX_EVENTS}`
              : `showing ${filteredRows().length}`}
          </span>
        </div>
      </section>

      <Show when={streamError()}>
        {(err) => (
          <div class="banner banner-warn mono">
            <span>
              Audit stream interrupted ({err()}) — retrying automatically…
            </span>
          </div>
        )}
      </Show>

      {/* Main Stream Panel */}
      <div class="panel">
        <div class="audit-toolbar">
          <div class="row-wrap" style={{ "justify-content": "space-between" }}>
            <div class="audit-chips" role="group" aria-label="Event Category">
              <For each={CATEGORY_CHIPS}>
                {(chip) => {
                  const isActive = () => category() === chip.id;
                  return (
                    <button
                      type="button"
                      class={`filter-chip ${
                        isActive()
                          ? chip.danger
                            ? "active-danger"
                            : "active"
                          : ""
                      }`}
                      onClick={() => setCategory(chip.id)}
                    >
                      <span>{chip.label}</span>
                    </button>
                  );
                }}
              </For>
            </div>

            <div class="row-wrap">
              <span
                class={
                  connState() === "live"
                    ? "pill pill-emerald"
                    : connState() === "paused"
                      ? "pill"
                      : "pill pill-amber"
                }
              >
                <span
                  class={
                    connState() === "live"
                      ? "dot dot-running"
                      : connState() === "paused"
                        ? "dot dot-muted"
                        : "dot dot-starting"
                  }
                />
                {connState() === "live"
                  ? "LIVE"
                  : connState() === "paused"
                    ? "PAUSED"
                    : connState() === "reconnecting"
                      ? "RECONNECTING"
                      : "CONNECTING"}
              </span>

              <button
                type="button"
                class={`btn btn-sm ${live() ? "" : "btn-primary"}`}
                onClick={() => setLive((prev) => !prev)}
                title={live() ? "Pause stream" : "Resume stream"}
              >
                <Show when={live()} fallback={<IconPlay size={12} />}>
                  <IconPause size={12} />
                </Show>
                <span>{live() ? "Pause" : "Resume"}</span>
              </button>

              <button
                type="button"
                class={`btn btn-sm ${autoScroll() ? "btn-amber" : ""}`}
                onClick={() => setAutoScroll((prev) => !prev)}
                title="Keep newest events in view"
              >
                <span>Auto-scroll</span>
              </button>

              <button
                type="button"
                class="btn btn-sm"
                onClick={handleClear}
                disabled={rows().length === 0}
                title="Clear events"
              >
                <IconTrash size={12} />
                <span>Clear</span>
              </button>
            </div>
          </div>

          <div class="row">
            <input
              type="search"
              class="input mono"
              placeholder="Filter events…"
              value={search()}
              onInput={(e) => setSearch(e.currentTarget.value)}
            />
          </div>
        </div>

        <div class="audit-stream-wrap" ref={streamWrapRef}>
          <Show
            when={filteredRows().length > 0}
            fallback={
              <div
                style={{
                  padding: "42px 20px",
                  "text-align": "center",
                  color: "var(--text-muted)",
                  "font-size": "12px",
                }}
              >
                {rows().length === 0
                  ? live()
                    ? "Waiting for live proxy & audit events from blackwall-daemon…"
                    : "Stream paused with no buffered events."
                  : "No audit events match the active filter or search query."}
              </div>
            }
          >
            <table class="audit-table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Event</th>
                  <th>Origin</th>
                  <Show when={showSandboxColumn()}>
                    <th>Sandbox</th>
                  </Show>
                  <th>Details</th>
                </tr>
              </thead>
              <tbody>
                <For each={filteredRows()}>
                  {(row) => {
                    const ev = row.event;
                    const badge = badgeForEvent(ev);
                    const origin = originBadge(ev.origin);
                    const blocked = isBlockedEvent(ev);
                    const isExpanded = () => expandedId() === row.id;
                    return (
                      <>
                        <tr
                          class={`audit-row ${blocked ? "audit-row-blocked" : ""}`}
                          onClick={() =>
                            setExpandedId((prev) =>
                              prev === row.id ? null : row.id,
                            )
                          }
                          title="Click to inspect raw JSON event"
                        >
                          <td class="audit-time-cell">
                            {formatTimestampMs(ev.timestamp_ms)}
                          </td>
                          <td class="audit-badge-cell">
                            <span class={badge.cls}>{badge.label}</span>
                          </td>
                          <td class="audit-origin-cell">
                            <Show
                              when={origin}
                              fallback={<span class="audit-meta-muted">—</span>}
                            >
                              {(o) => (
                                <span class={o().cls} title={o().title}>
                                  {o().label}
                                </span>
                              )}
                            </Show>
                          </td>
                          <Show when={showSandboxColumn()}>
                            <td class="audit-sandbox-cell">
                              <button
                                type="button"
                                class="audit-sandbox-btn"
                                title={`Jump to sandbox ${ev.sandbox_id}`}
                                onClick={(e) => {
                                  e.stopPropagation();
                                  props.onSelectSandbox?.(ev.sandbox_id);
                                }}
                              >
                                {shortId(ev.sandbox_id)}
                              </button>
                            </td>
                          </Show>
                          <td class="audit-detail-cell">{renderDetails(ev)}</td>
                        </tr>
                        <Show when={isExpanded()}>
                          <tr class="audit-detail-row">
                            <td colSpan={colSpan()}>
                              <pre
                                class="code-block"
                                style={{ "max-height": "220px" }}
                              >
                                {JSON.stringify(ev, null, 2)}
                              </pre>
                            </td>
                          </tr>
                        </Show>
                      </>
                    );
                  }}
                </For>
              </tbody>
            </table>
          </Show>
        </div>
      </div>
    </div>
  );
}
