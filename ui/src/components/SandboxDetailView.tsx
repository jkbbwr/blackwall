import {
  createEffect,
  createMemo,
  createResource,
  createSignal,
  Match,
  on,
  onCleanup,
  Show,
  Switch,
} from "solid-js";
import { getSandbox } from "../api/client";
import type { SandboxDetail } from "../api/types";
import { copyToClipboard } from "../utils/format";
import { AuditLogPanel } from "./AuditLogPanel";
import { ExecConsoleTab } from "./detail/ExecConsoleTab";
import { FilesTab } from "./detail/FilesTab";
import { IngressPortsTab } from "./detail/IngressPortsTab";
import { OverviewSecurityTab } from "./detail/OverviewSecurityTab";
import { ProcessesTab } from "./detail/ProcessesTab";
import { PtyTerminalTab } from "./detail/PtyTerminalTab";
import {
  IconActivity,
  IconArrowLeft,
  IconCheck,
  IconCopy,
  IconFileText,
  IconFolder,
  IconGlobe,
  IconRefresh,
  IconShield,
  IconTerminal,
  IconTrash,
} from "./Icons";

export type DetailTab =
  | "overview"
  | "exec"
  | "terminal"
  | "processes"
  | "files"
  | "ingress"
  | "logs";

export interface SandboxDetailViewProps {
  sandboxId: string;
  initialTab?: DetailTab;
  onTabChange?: (tab: DetailTab) => void;
  onBack: () => void;
  onDestroy: (id: string) => Promise<void>;
  onDetailLoaded?: (detail: SandboxDetail) => void;
}

export function SandboxDetailView(props: SandboxDetailViewProps) {
  const [activeTab, setActiveTab] = createSignal<DetailTab>(
    props.initialTab ?? "overview",
  );
  const [ptyMounted, setPtyMounted] = createSignal(false);
  const [confirmDestroy, setConfirmDestroy] = createSignal(false);
  const [destroying, setDestroying] = createSignal(false);
  const [copiedId, setCopiedId] = createSignal(false);

  const selectTab = (tab: DetailTab) => {
    setActiveTab(tab);
    props.onTabChange?.(tab);
  };

  createEffect(() => {
    if (props.initialTab) {
      setActiveTab(props.initialTab);
    }
  });

  // Reset confirm & PTY mount state when switching sandboxes
  createEffect(
    on(
      () => props.sandboxId,
      () => {
        setConfirmDestroy(false);
        setPtyMounted(activeTab() === "terminal");
      },
      { defer: true },
    ),
  );

  // Mount PTY lazily on first Terminal tab visit and keep alive across tab switches
  createEffect(() => {
    if (activeTab() === "terminal") {
      setPtyMounted(true);
    }
  });

  const [detail, { refetch }] = createResource(
    () => props.sandboxId,
    async (id) => {
      const data = await getSandbox(id);
      props.onDetailLoaded?.(data);
      return data;
    },
  );

  // Live 2.5s telemetry refresh while viewing sandbox
  const poller = window.setInterval(() => {
    if (!destroying()) {
      void refetch();
    }
  }, 2500);
  onCleanup(() => window.clearInterval(poller));

  const handleCopyId = async () => {
    if (await copyToClipboard(props.sandboxId)) {
      setCopiedId(true);
      window.setTimeout(() => setCopiedId(false), 1500);
    }
  };

  const handleDestroy = async () => {
    setDestroying(true);
    try {
      await props.onDestroy(props.sandboxId);
    } finally {
      setDestroying(false);
      setConfirmDestroy(false);
    }
  };

  const isRunning = createMemo(() => detail()?.state === "running");

  const ingressCount = () => {
    const d = detail();
    if (!d) return 0;
    return (d.ingress_allow_ports ?? d.ingress?.allow_ports ?? []).length;
  };

  return (
    <>
      <header class="page-header">
        <div class="page-title-group">
          <button
            type="button"
            class="btn btn-ghost btn-sm"
            onClick={() => props.onBack()}
            title="Back to Fleet Overview"
          >
            <IconArrowLeft size={14} />
          </button>
          <div style={{ "min-width": 0 }}>
            <div class="row" style={{ gap: "8px" }}>
              <Show when={detail()}>
                {(d) => <span class={`dot dot-${d().state}`} />}
              </Show>
              <h1 class="page-title mono truncate">{props.sandboxId}</h1>
              <button
                type="button"
                class="btn btn-ghost btn-xs"
                onClick={() => void handleCopyId()}
                title="Copy sandbox ID"
              >
                <Show when={copiedId()} fallback={<IconCopy size={12} />}>
                  <IconCheck size={12} />
                </Show>
              </button>
              <Show when={detail()}>
                {(d) => (
                  <>
                    <span class="pill">{d().profile}</span>
                    <span
                      class={
                        d().state === "running"
                          ? "pill pill-emerald"
                          : d().state === "stopped"
                            ? "pill pill-crimson"
                            : "pill pill-amber"
                      }
                    >
                      {d().state}
                    </span>
                  </>
                )}
              </Show>
            </div>
          </div>
        </div>

        <div class="toolbar-actions">
          <button
            type="button"
            class="btn btn-sm"
            onClick={() => void refetch()}
          >
            <IconRefresh size={13} />
            <span>Sync</span>
          </button>

          <Show
            when={confirmDestroy()}
            fallback={
              <button
                type="button"
                class="btn btn-danger btn-sm"
                onClick={() => setConfirmDestroy(true)}
              >
                <IconTrash size={13} />
                <span>Destroy VM</span>
              </button>
            }
          >
            <button
              type="button"
              class="btn btn-ghost btn-sm"
              onClick={() => setConfirmDestroy(false)}
              disabled={destroying()}
            >
              Cancel
            </button>
            <button
              type="button"
              class="btn btn-danger btn-sm"
              onClick={() => void handleDestroy()}
              disabled={destroying()}
            >
              {destroying() ? "Wiping VM…" : "Confirm Wipe"}
            </button>
          </Show>
        </div>
      </header>

      <nav class="tabs-bar" aria-label="Sandbox Inspector Tabs">
        <button
          type="button"
          class={`tab-btn ${activeTab() === "overview" ? "active" : ""}`}
          onClick={() => selectTab("overview")}
        >
          <IconShield size={14} />
          <span>Overview</span>
        </button>

        <button
          type="button"
          class={`tab-btn ${activeTab() === "exec" ? "active" : ""}`}
          onClick={() => selectTab("exec")}
        >
          <IconTerminal size={14} />
          <span>Exec</span>
        </button>

        <button
          type="button"
          class={`tab-btn ${activeTab() === "terminal" ? "active" : ""}`}
          onClick={() => selectTab("terminal")}
        >
          <IconTerminal size={14} />
          <span>Terminal</span>
        </button>

        <button
          type="button"
          class={`tab-btn ${activeTab() === "processes" ? "active" : ""}`}
          onClick={() => selectTab("processes")}
        >
          <IconActivity size={14} />
          <span>Processes</span>
          <Show when={(detail()?.processes.length ?? 0) > 0}>
            <span class="nav-count">{detail()?.processes.length}</span>
          </Show>
        </button>

        <button
          type="button"
          class={`tab-btn ${activeTab() === "files" ? "active" : ""}`}
          onClick={() => selectTab("files")}
        >
          <IconFolder size={14} />
          <span>Files</span>
        </button>

        <button
          type="button"
          class={`tab-btn ${activeTab() === "ingress" ? "active" : ""}`}
          onClick={() => selectTab("ingress")}
        >
          <IconGlobe size={14} />
          <span>Ingress</span>
          <Show when={ingressCount() > 0}>
            <span class="nav-count">{ingressCount()}</span>
          </Show>
        </button>

        <button
          type="button"
          class={`tab-btn ${activeTab() === "logs" ? "active" : ""}`}
          onClick={() => selectTab("logs")}
        >
          <IconFileText size={14} />
          <span>Proxy &amp; Logs</span>
        </button>
      </nav>

      <div class="page-scroll">
        <Show when={detail.error}>
          <div class="banner banner-error mono" style={{ "margin-bottom": "14px" }}>
            Failed to load sandbox "{props.sandboxId}": {String(detail.error)}
          </div>
        </Show>

        <Show
          when={detail()}
          fallback={
            <div class="empty-state">
              {detail.loading
                ? "Fetching sandbox inspection telemetry…"
                : "Sandbox unavailable."}
            </div>
          }
        >
          {(d) => (
            <>
              <Switch>
                <Match when={activeTab() === "overview"}>
                  <OverviewSecurityTab
                    detail={d()}
                    onActivity={() => void refetch()}
                  />
                </Match>
                <Match when={activeTab() === "exec"}>
                  <ExecConsoleTab
                    sandboxId={props.sandboxId}
                    running={isRunning()}
                    onActivity={() => void refetch()}
                  />
                </Match>
                <Match when={activeTab() === "processes"}>
                  <ProcessesTab
                    sandboxId={props.sandboxId}
                    initialProcesses={d().processes}
                    running={isRunning()}
                    onActivity={() => void refetch()}
                  />
                </Match>
                <Match when={activeTab() === "files"}>
                  <FilesTab
                    sandboxId={props.sandboxId}
                    running={isRunning()}
                    onActivity={() => void refetch()}
                  />
                </Match>
                <Match when={activeTab() === "ingress"}>
                  <IngressPortsTab
                    detail={d()}
                    onActivity={() => void refetch()}
                  />
                </Match>
                <Match when={activeTab() === "logs"}>
                  <AuditLogPanel sandboxId={props.sandboxId} />
                </Match>
              </Switch>
              <Show when={ptyMounted()}>
                <div
                  style={{
                    display: activeTab() === "terminal" ? "block" : "none",
                  }}
                >
                  <PtyTerminalTab
                    sandboxId={props.sandboxId}
                    running={isRunning()}
                  />
                </div>
              </Show>
            </>
          )}
        </Show>
      </div>
    </>
  );
}
