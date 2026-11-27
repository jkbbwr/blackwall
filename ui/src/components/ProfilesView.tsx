import {
  createEffect,
  createResource,
  createSignal,
  For,
  Show,
} from "solid-js";
import { deleteProfile, getProfile } from "../api/client";
import type { AuthSpec, SandboxSpec } from "../api/types";
import { formatBytes, formatDurationSec, formatMib } from "../utils/format";
import { CreateProfileModal } from "./CreateProfileModal";
import {
  IconLayers,
  IconLock,
  IconPlus,
  IconRefresh,
  IconShield,
  IconTrash,
} from "./Icons";

export interface ProfilesViewProps {
  profiles: string[];
  readonlyProfiles?: boolean;
  onRefresh: () => Promise<void> | void;
  onLaunchFromProfile: (profileName: string) => void;
  onNotify?: (kind: "ok" | "error", message: string) => void;
}

function formatAuthSpec(auth: AuthSpec | null | undefined): string {
  if (!auth) return "none";
  switch (auth.kind) {
    case "bearer":
      return `bearer (${auth.secret})`;
    case "header":
      return `header:${auth.name} (${auth.secret})`;
    case "basic":
      return `basic:${auth.username} (${auth.secret})`;
  }
}

export function ProfilesView(props: ProfilesViewProps) {
  const [selectedName, setSelectedName] = createSignal<string>(
    props.profiles[0] ?? "base",
  );
  const [pendingSelect, setPendingSelect] = createSignal<string | null>(null);
  const [viewMode, setViewMode] = createSignal<"policy" | "json">("policy");
  const [createOpen, setCreateOpen] = createSignal(false);
  const [confirmDelete, setConfirmDelete] = createSignal(false);
  const [deleting, setDeleting] = createSignal(false);
  const [actionError, setActionError] = createSignal<string | null>(null);

  createEffect(() => {
    const list = props.profiles;
    const pending = pendingSelect();
    if (pending) {
      if (list.includes(pending)) {
        setSelectedName(pending);
        setPendingSelect(null);
      }
      return;
    }
    if (list.length > 0 && !list.includes(selectedName())) {
      setSelectedName(list[0] ?? "base");
    }
  });

  createEffect(() => {
    void selectedName();
    setConfirmDelete(false);
    setActionError(null);
  });

  const [spec, { refetch }] = createResource(selectedName, (name) =>
    getProfile(name),
  );

  const handleProfileCreated = async (created: SandboxSpec) => {
    setCreateOpen(false);
    setPendingSelect(created.name);
    setSelectedName(created.name);
    props.onNotify?.("ok", `Created profile "${created.name}"`);
    await props.onRefresh();
    void refetch();
  };

  const handleDeleteProfile = async (name: string) => {
    if (name === "base" || deleting()) return;
    setDeleting(true);
    setActionError(null);
    try {
      await deleteProfile(name);
      setConfirmDelete(false);
      props.onNotify?.("ok", `Deleted profile "${name}"`);
      const fallback = props.profiles.find((p) => p !== name) ?? "base";
      setSelectedName(fallback);
      await props.onRefresh();
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setActionError(msg);
      props.onNotify?.("error", `Failed to delete profile: ${msg}`);
    } finally {
      setDeleting(false);
    }
  };

  return (
    <>
      <header class="page-header">
        <div class="page-title-group">
          <h1 class="page-title">Profiles</h1>
          <Show when={props.readonlyProfiles}>
            <span class="pill pill-amber">
              <IconLock size={11} /> Read-only
            </span>
          </Show>
        </div>
        <div class="toolbar-actions">
          <div class="segmented">
            <button
              type="button"
              class={`segmented-btn ${viewMode() === "policy" ? "active" : ""}`}
              onClick={() => setViewMode("policy")}
            >
              Policy
            </button>
            <button
              type="button"
              class={`segmented-btn ${viewMode() === "json" ? "active" : ""}`}
              onClick={() => setViewMode("json")}
            >
              JSON
            </button>
          </div>
          <button
            type="button"
            class="btn"
            onClick={() => {
              void props.onRefresh();
              void refetch();
            }}
          >
            <IconRefresh size={14} />
            <span>Refresh</span>
          </button>
          <Show when={!props.readonlyProfiles}>
            <button
              type="button"
              class="btn btn-primary"
              onClick={() => setCreateOpen(true)}
            >
              <IconPlus size={14} />
              <span>New Profile</span>
            </button>
          </Show>
        </div>
      </header>

      <div class="page-scroll">
        <div class="split-view">
          {/* Profile List */}
          <div class="panel">
            <div class="panel-header">
              <span class="panel-title">
                <IconLayers size={13} /> Profiles ({props.profiles.length})
              </span>
            </div>
            <div class="panel-body list-menu">
              <For each={props.profiles.length > 0 ? props.profiles : ["base"]}>
                {(name) => (
                  <button
                    type="button"
                    class={`list-menu-item ${selectedName() === name ? "active" : ""}`}
                    onClick={() => setSelectedName(name)}
                  >
                    <span class="truncate">{name}</span>
                    <Show when={name === "base"}>
                      <span class="pill">default</span>
                    </Show>
                  </button>
                )}
              </For>
            </div>
          </div>

          {/* Selected Profile Inspector */}
          <div class="stack">
            <Show when={actionError()}>
              {(err) => <div class="banner banner-error mono">{err()}</div>}
            </Show>

            <Show when={spec.error}>
              <div class="banner banner-error mono">
                Failed to load profile "{selectedName()}": {String(spec.error)}
              </div>
            </Show>

            <Show
              when={spec()}
              fallback={
                <div class="empty-state">
                  {spec.loading
                    ? "Resolving profile policy…"
                    : "Select a profile to inspect."}
                </div>
              }
            >
              {(resolved) => (
                <>
                  <div class="panel">
                    <div class="panel-header">
                      <div class="row-wrap">
                        <span
                          class="mono"
                          style={{ "font-weight": 700, "font-size": "14px" }}
                        >
                          {resolved().name}
                        </span>
                        <span class="pill">v{resolved().version}</span>
                        <span
                          class={
                            resolved().network.mode === "egress"
                              ? "pill pill-amber"
                              : resolved().network.mode === "none"
                                ? "pill pill-emerald"
                                : "pill pill-cyan"
                          }
                        >
                          net:{resolved().network.mode}
                        </span>
                        <Show when={resolved().policy.locked}>
                          <span class="pill pill-amber">
                            <IconLock size={11} /> locked
                          </span>
                        </Show>
                      </div>

                      <div class="row">
                        <Show when={!props.readonlyProfiles && resolved().name !== "base"}>
                          <Show
                            when={confirmDelete()}
                            fallback={
                              <button
                                type="button"
                                class="btn btn-danger btn-sm"
                                onClick={() => setConfirmDelete(true)}
                                disabled={deleting()}
                              >
                                <IconTrash size={12} />
                                <span>Delete</span>
                              </button>
                            }
                          >
                            <button
                              type="button"
                              class="btn btn-ghost btn-sm"
                              onClick={() => setConfirmDelete(false)}
                              disabled={deleting()}
                            >
                              Cancel
                            </button>
                            <button
                              type="button"
                              class="btn btn-danger btn-sm"
                              onClick={() =>
                                void handleDeleteProfile(resolved().name)
                              }
                              disabled={deleting()}
                            >
                              {deleting() ? "Deleting…" : "Confirm Delete"}
                            </button>
                          </Show>
                        </Show>

                        <button
                          type="button"
                          class="btn btn-primary btn-sm"
                          onClick={() =>
                            props.onLaunchFromProfile(resolved().name)
                          }
                        >
                          <IconPlus size={13} />
                          <span>Launch Sandbox</span>
                        </button>
                      </div>
                    </div>

                    <Show
                      when={viewMode() === "policy"}
                      fallback={
                        <div class="panel-body">
                          <pre class="code-block">
                            {JSON.stringify(resolved(), null, 2)}
                          </pre>
                        </div>
                      }
                    >
                      <div class="panel-body stack">
                        {/* Image & Compute */}
                        <div class="grid-2">
                          <div class="panel">
                            <div class="panel-header">
                              <span class="panel-title">Image</span>
                            </div>
                            <div class="panel-body kv-grid">
                              <div class="kv-item">
                                <span class="kv-label">Base / Ref</span>
                                <span class="kv-value">
                                  {resolved().image.ref ??
                                    resolved().image.base ??
                                    "—"}
                                </span>
                              </div>
                              <div class="kv-item">
                                <span class="kv-label">
                                  Packages ({resolved().image.packages.length})
                                </span>
                                <span class="kv-value">
                                  {resolved().image.packages.length > 0
                                    ? resolved().image.packages.join(", ")
                                    : "None"}
                                </span>
                              </div>
                              <Show when={resolved().image.run.length > 0}>
                                <div
                                  class="kv-item"
                                  style={{ "grid-column": "1 / -1" }}
                                >
                                  <span class="kv-label">
                                    Build Run Steps ({resolved().image.run.length})
                                  </span>
                                  <pre
                                    class="code-block"
                                    style={{ "max-height": "140px" }}
                                  >
                                    {resolved().image.run.join("\n")}
                                  </pre>
                                </div>
                              </Show>
                            </div>
                          </div>

                          <div class="panel">
                            <div class="panel-header">
                              <span class="panel-title">Compute &amp; Limits</span>
                            </div>
                            <div class="panel-body kv-grid">
                              <div class="kv-item">
                                <span class="kv-label">vCPUs</span>
                                <span class="kv-value">
                                  {resolved().compute.vcpus}
                                  {resolved().policy.max_vcpus
                                    ? ` (max ${resolved().policy.max_vcpus})`
                                    : ""}
                                </span>
                              </div>
                              <div class="kv-item">
                                <span class="kv-label">Memory</span>
                                <span class="kv-value">
                                  {formatMib(resolved().compute.memory_mib)}
                                  {resolved().policy.max_memory_mib
                                    ? ` (max ${formatMib(resolved().policy.max_memory_mib ?? 0)})`
                                    : ""}
                                </span>
                              </div>
                              <div class="kv-item">
                                <span class="kv-label">Workspace</span>
                                <span class="kv-value">
                                  {formatMib(resolved().compute.workspace_mib)}
                                </span>
                              </div>
                              <div class="kv-item">
                                <span class="kv-label">Idle / Wall Timeout</span>
                                <span class="kv-value">
                                  {formatDurationSec(
                                    resolved().compute.idle_timeout_sec,
                                  )}{" "}
                                  /{" "}
                                  {formatDurationSec(
                                    resolved().compute.max_wall_time_sec,
                                  )}
                                </span>
                              </div>
                              <div class="kv-item">
                                <span class="kv-label">Ingress Allow Ports</span>
                                <span class="kv-value">
                                  {(resolved().ingress?.allow_ports?.length ??
                                    0) > 0
                                    ? resolved().ingress?.allow_ports.join(", ")
                                    : "None"}
                                </span>
                              </div>
                              <div class="kv-item">
                                <span class="kv-label">Export Bounds</span>
                                <span class="kv-value">
                                  {formatBytes(resolved().export.max_bytes)} /{" "}
                                  {resolved().export.max_files.toLocaleString()}{" "}
                                  files
                                </span>
                              </div>
                            </div>
                          </div>
                        </div>

                        {/* Egress HTTP & Postgres Rules */}
                        <div class="panel">
                          <div class="panel-header">
                            <span class="panel-title">
                              <IconShield size={13} /> HTTP Egress (
                              {resolved().network.http.length})
                            </span>
                          </div>
                          <Show
                            when={resolved().network.http.length > 0}
                            fallback={
                              <div
                                class="panel-body"
                                style={{ color: "var(--text-muted)" }}
                              >
                                No outbound HTTP rules declared.
                              </div>
                            }
                          >
                            <table class="data-table">
                              <thead>
                                <tr>
                                  <th>Host:Port</th>
                                  <th>Methods</th>
                                  <th>Path Prefixes</th>
                                  <th>Brokered Auth</th>
                                </tr>
                              </thead>
                              <tbody>
                                <For each={resolved().network.http}>
                                  {(rule) => (
                                    <tr>
                                      <td class="mono">
                                        {rule.host}:{rule.port}
                                      </td>
                                      <td class="mono">
                                        {rule.methods.join(", ")}
                                      </td>
                                      <td class="mono">
                                        {rule.path_prefixes.join(", ")}
                                      </td>
                                      <td class="mono">
                                        {formatAuthSpec(rule.auth)}
                                      </td>
                                    </tr>
                                  )}
                                </For>
                              </tbody>
                            </table>
                          </Show>
                        </div>

                        <Show when={resolved().network.postgres.length > 0}>
                          <div class="panel">
                            <div class="panel-header">
                              <span class="panel-title">
                                Postgres Egress (
                                {resolved().network.postgres.length})
                              </span>
                            </div>
                            <table class="data-table">
                              <thead>
                                <tr>
                                  <th>Host:Port</th>
                                  <th>Secret</th>
                                  <th>Upstream TLS</th>
                                </tr>
                              </thead>
                              <tbody>
                                <For each={resolved().network.postgres}>
                                  {(pg) => (
                                    <tr>
                                      <td class="mono">
                                        {pg.host}:{pg.port}
                                      </td>
                                      <td class="mono">{pg.secret}</td>
                                      <td>
                                        <span
                                          class={
                                            pg.require_upstream_tls
                                              ? "pill pill-emerald"
                                              : "pill pill-amber"
                                          }
                                        >
                                          {pg.require_upstream_tls
                                            ? "required"
                                            : "optional"}
                                        </span>
                                      </td>
                                    </tr>
                                  )}
                                </For>
                              </tbody>
                            </table>
                          </div>
                        </Show>

                        <Show when={(resolved().host_services?.length ?? 0) > 0}>
                          <div class="panel">
                            <div class="panel-header">
                              <span class="panel-title">
                                Host Services (
                                {resolved().host_services?.length ?? 0})
                              </span>
                            </div>
                            <table class="data-table">
                              <thead>
                                <tr>
                                  <th>Name</th>
                                  <th>Guest Port</th>
                                  <th>Host Target</th>
                                </tr>
                              </thead>
                              <tbody>
                                <For each={resolved().host_services ?? []}>
                                  {(svc) => (
                                    <tr>
                                      <td class="mono">{svc.name}</td>
                                      <td class="mono">
                                        127.0.0.1:{svc.guest_port}
                                      </td>
                                      <td class="mono">{svc.target}</td>
                                    </tr>
                                  )}
                                </For>
                              </tbody>
                            </table>
                          </div>
                        </Show>

                        {/* Secrets & Env */}
                        <div class="grid-2">
                          <div class="panel">
                            <div class="panel-header">
                              <span class="panel-title">
                                Secrets ({Object.keys(resolved().secrets).length})
                              </span>
                            </div>
                            <div class="panel-body">
                              <Show
                                when={
                                  Object.keys(resolved().secrets).length > 0
                                }
                                fallback={
                                  <span style={{ color: "var(--text-muted)" }}>
                                    No secrets declared
                                  </span>
                                }
                              >
                                <div class="stack" style={{ gap: "6px" }}>
                                  <For
                                    each={Object.entries(resolved().secrets)}
                                  >
                                    {([key, sec]) => (
                                      <div
                                        class="row"
                                        style={{
                                          "justify-content": "space-between",
                                        }}
                                      >
                                        <span
                                          class="mono"
                                          style={{ "font-weight": 600 }}
                                        >
                                          {key}
                                        </span>
                                        <span class="pill">
                                          prefix:{sec.placeholder_prefix}
                                        </span>
                                      </div>
                                    )}
                                  </For>
                                </div>
                              </Show>
                            </div>
                          </div>

                          <div class="panel">
                            <div class="panel-header">
                              <span class="panel-title">
                                Environment ({Object.keys(resolved().env).length})
                              </span>
                            </div>
                            <div class="panel-body">
                              <Show
                                when={Object.keys(resolved().env).length > 0}
                                fallback={
                                  <span style={{ color: "var(--text-muted)" }}>
                                    No static env vars
                                  </span>
                                }
                              >
                                <div class="stack" style={{ gap: "5px" }}>
                                  <For each={Object.entries(resolved().env)}>
                                    {([k, v]) => (
                                      <div
                                        class="mono"
                                        style={{
                                          "font-size": "11.5px",
                                          "word-break": "break-all",
                                        }}
                                      >
                                        <span style={{ color: "var(--cyan)" }}>
                                          {k}
                                        </span>
                                        <span
                                          style={{ color: "var(--text-muted)" }}
                                        >
                                          =
                                        </span>
                                        <span>{v}</span>
                                      </div>
                                    )}
                                  </For>
                                </div>
                              </Show>
                            </div>
                          </div>
                        </div>

                        {/* Export Deny Globs */}
                        <div class="panel">
                          <div class="panel-header">
                            <span class="panel-title">
                              Export Deny Globs (
                              {resolved().export.deny_touch_globs.length})
                            </span>
                          </div>
                          <div class="panel-body row-wrap">
                            <For each={resolved().export.deny_touch_globs}>
                              {(glob) => <span class="pill">{glob}</span>}
                            </For>
                          </div>
                        </div>
                      </div>
                    </Show>
                  </div>
                </>
              )}
            </Show>
          </div>
        </div>
      </div>

      <Show when={createOpen() && !props.readonlyProfiles}>
        <CreateProfileModal
          existingProfiles={props.profiles}
          onClose={() => setCreateOpen(false)}
          onCreated={(created) => void handleProfileCreated(created)}
        />
      </Show>
    </>
  );
}
