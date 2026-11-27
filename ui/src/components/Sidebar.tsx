import { For, Show } from "solid-js";
import type { PrincipalRole, SandboxSummary } from "../api/types";
import { shortId } from "../utils/format";
import {
  IconCube,
  IconDisc,
  IconFileText,
  IconLayers,
  IconPlus,
  IconRefresh,
} from "./Icons";

export type NavSection = "sandboxes" | "logs" | "profiles" | "images";

export interface SidebarProps {
  activeSection: NavSection;
  selectedSandboxId: string | null;
  sandboxes: SandboxSummary[];
  profileCount: number;
  imageCount: number;
  daemonOnline: boolean;
  daemonLatencyMs: number | null;
  daemonError: string | null;
  refreshing: boolean;
  role?: PrincipalRole;
  policyLocked?: boolean;
  mobileOpen?: boolean;
  onCloseMobile?: () => void;
  onSelectSection: (section: NavSection) => void;
  onSelectSandbox: (id: string) => void;
  onOpenCreateModal: () => void;
  onRefresh: () => void;
}

export function Sidebar(props: SidebarProps) {
  const handleSelectSection = (section: NavSection) => {
    props.onSelectSection(section);
    props.onCloseMobile?.();
  };

  const handleSelectSandbox = (id: string) => {
    props.onSelectSandbox(id);
    props.onCloseMobile?.();
  };

  const handleOpenCreate = () => {
    props.onOpenCreateModal();
    props.onCloseMobile?.();
  };

  return (
    <aside class={`sidebar ${props.mobileOpen ? "open" : ""}`}>
      <div class="sidebar-brand">
        <div class="brand-mark">
          <div class="brand-logo">BW</div>
          <div>
            <div class="brand-title">BLACKWALL</div>
            <div class="brand-sub">MicroVM Control Plane</div>
          </div>
        </div>
        <button
          type="button"
          class="btn btn-ghost btn-xs"
          title="Refresh daemon telemetry"
          onClick={() => props.onRefresh()}
          disabled={props.refreshing}
        >
          <IconRefresh size={13} />
        </button>
      </div>

      <div class="sidebar-status">
        <div class="status-indicator">
          <span
            class={props.daemonOnline ? "dot dot-running" : "dot dot-error"}
          />
          <span
            style={{
              color: props.daemonOnline ? "var(--emerald)" : "var(--crimson)",
            }}
          >
            {props.daemonOnline ? "DAEMON ONLINE" : "DAEMON OFFLINE"}
          </span>
        </div>
        <div class="row" style={{ gap: "6px" }}>
          <Show when={props.policyLocked}>
            <span
              class="pill pill-amber"
              style={{ padding: "0 5px", "font-size": "9.5px" }}
              title={props.role ? `Policy locked (${props.role})` : "Policy locked"}
            >
              locked
            </span>
          </Show>
          <Show
            when={props.daemonOnline && props.daemonLatencyMs !== null}
            fallback={
              <span class="mono" style={{ color: "var(--text-muted)" }}>
                /v1
              </span>
            }
          >
            <span class="mono" style={{ color: "var(--text-muted)" }}>
              {props.daemonLatencyMs}ms
            </span>
          </Show>
        </div>
      </div>

      <Show when={props.daemonError}>
        {(err) => (
          <div
            style={{
              padding: "6px 12px",
              background: "var(--crimson-dim)",
              "border-bottom": "1px solid var(--crimson-border)",
              color: "#fca5a5",
              "font-size": "11px",
              "word-break": "break-word",
            }}
          >
            {err()}
          </div>
        )}
      </Show>

      <nav class="sidebar-nav" aria-label="Primary Navigation">
        <button
          type="button"
          class={`nav-item ${props.activeSection === "sandboxes" && !props.selectedSandboxId ? "active" : ""}`}
          onClick={() => handleSelectSection("sandboxes")}
        >
          <span class="nav-item-left">
            <IconCube size={15} />
            <span>Sandboxes</span>
          </span>
          <span class="nav-count">{props.sandboxes.length}</span>
        </button>

        <button
          type="button"
          class={`nav-item ${props.activeSection === "logs" && !props.selectedSandboxId ? "active" : ""}`}
          onClick={() => handleSelectSection("logs")}
        >
          <span class="nav-item-left">
            <IconFileText size={15} />
            <span>Proxy &amp; Logs</span>
          </span>
          <span class="pill pill-emerald" style={{ padding: "0 5px", "font-size": "9.5px" }}>
            LIVE
          </span>
        </button>

        <button
          type="button"
          class={`nav-item ${props.activeSection === "profiles" && !props.selectedSandboxId ? "active" : ""}`}
          onClick={() => handleSelectSection("profiles")}
        >
          <span class="nav-item-left">
            <IconLayers size={15} />
            <span>Profiles</span>
          </span>
          <span class="nav-count">{props.profileCount}</span>
        </button>

        <button
          type="button"
          class={`nav-item ${props.activeSection === "images" && !props.selectedSandboxId ? "active" : ""}`}
          onClick={() => handleSelectSection("images")}
        >
          <span class="nav-item-left">
            <IconDisc size={15} />
            <span>Images</span>
          </span>
          <span class="nav-count">{props.imageCount}</span>
        </button>
      </nav>

      <div class="sidebar-fleet-header">
        <span>Active Fleet</span>
        <span class="mono">{props.sandboxes.length}</span>
      </div>

      <div class="sidebar-fleet-list">
        <Show
          when={props.sandboxes.length > 0}
          fallback={
            <div
              style={{
                padding: "14px 8px",
                color: "var(--text-muted)",
                "font-size": "11.5px",
                "text-align": "center",
              }}
            >
              No running sandboxes
            </div>
          }
        >
          <For each={props.sandboxes}>
            {(sb) => (
              <button
                type="button"
                class={`fleet-row ${props.selectedSandboxId === sb.id ? "active" : ""}`}
                onClick={() => handleSelectSandbox(sb.id)}
                title={`${sb.id} (${sb.profile})`}
              >
                <span class="fleet-row-left">
                  <span class={`dot dot-${sb.state}`} />
                  <span class="fleet-row-id truncate">{shortId(sb.id)}</span>
                </span>
                <span class="pill">{sb.profile}</span>
              </button>
            )}
          </For>
        </Show>
      </div>

      <div class="sidebar-footer">
        <button
          type="button"
          class="btn btn-primary btn-full"
          onClick={() => handleOpenCreate()}
        >
          <IconPlus size={14} />
          <span>New Sandbox</span>
        </button>
      </div>
    </aside>
  );
}
