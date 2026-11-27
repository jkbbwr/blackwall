import {
  createEffect,
  createMemo,
  createResource,
  createSignal,
  For,
  Show,
} from "solid-js";
import { createSandbox, getProfile } from "../api/client";
import type {
  AuthSpec,
  HttpRule,
  NetworkMode,
  ProfileDraft,
  SandboxSummary,
  SecretSpec,
} from "../api/types";
import { IconGlobe, IconLock, IconPlus, IconTrash, IconX } from "./Icons";

interface EnvRow {
  id: number;
  key: string;
  value: string;
}

type SecretMode = "sealed" | "ephemeral";

interface SecretRow {
  id: number;
  name: string;
  placeholderPrefix: string;
  mode: SecretMode;
  sealed: string;
  ephemeral: string;
  reveal: boolean;
}

type AuthKindOption = "none" | "bearer" | "header" | "basic";

interface HttpRuleRow {
  id: number;
  host: string;
  port: string;
  methods: string;
  pathPrefixes: string;
  authKind: AuthKindOption;
  authSecret: string;
  authHeaderName: string;
  authHeaderPrefix: string;
  authUsername: string;
}

export interface CreateSandboxModalProps {
  profiles: string[];
  initialProfile?: string;
  onClose: () => void;
  onCreated: (sandbox: SandboxSummary) => void;
}

const PRESET_PORTS = [3000, 5173, 8000, 8080, 8787] as const;

function buildHttpRulesFromRows(rows: HttpRuleRow[]): HttpRule[] {
  const rules: HttpRule[] = [];
  for (const row of rows) {
    const host = row.host.trim();
    if (!host) continue;

    const rawPort = Number(row.port.trim());
    const port =
      Number.isInteger(rawPort) && rawPort >= 1 && rawPort <= 65535
        ? rawPort
        : 443;

    const methods = row.methods
      .split(/[,\s]+/)
      .map((m) => m.trim().toUpperCase())
      .filter(Boolean);

    const pathPrefixes = row.pathPrefixes
      .split(/[,\s]+/)
      .map((p) => p.trim())
      .filter(Boolean);

    let auth: AuthSpec | undefined;
    const secret = row.authSecret.trim();
    if (row.authKind === "bearer" && secret) {
      auth = { kind: "bearer", secret };
    } else if (row.authKind === "header" && secret && row.authHeaderName.trim()) {
      const prefix = row.authHeaderPrefix.trim();
      auth = {
        kind: "header",
        secret,
        name: row.authHeaderName.trim(),
        ...(prefix ? { prefix } : {}),
      };
    } else if (row.authKind === "basic" && secret && row.authUsername.trim()) {
      auth = {
        kind: "basic",
        secret,
        username: row.authUsername.trim(),
      };
    }

    rules.push({
      host,
      port,
      methods: methods.length > 0 ? methods : ["GET"],
      path_prefixes: pathPrefixes.length > 0 ? pathPrefixes : ["/"],
      ...(auth ? { auth } : {}),
    });
  }
  return rules;
}

export function CreateSandboxModal(props: CreateSandboxModalProps) {
  let nextRowId = 1;

  const [selectedProfile, setSelectedProfile] = createSignal(
    props.initialProfile && props.profiles.includes(props.initialProfile)
      ? props.initialProfile
      : props.profiles[0] ?? "base",
  );
  const [extraExtends, setExtraExtends] = createSignal<string[]>([]);

  // Compute overrides (empty string = inherit from profile)
  const [vcpus, setVcpus] = createSignal("");
  const [memoryMib, setMemoryMib] = createSignal("");
  const [workspaceMib, setWorkspaceMib] = createSignal("");
  const [idleTimeoutSec, setIdleTimeoutSec] = createSignal("");
  const [maxWallTimeSec, setMaxWallTimeSec] = createSignal("");

  // Network & Ingress overrides
  const [networkMode, setNetworkMode] = createSignal<"" | NetworkMode>("");
  const [ingressPortsInput, setIngressPortsInput] = createSignal("");
  const [portsTouched, setPortsTouched] = createSignal(false);

  // HTTP Egress, Env & Secrets
  const [httpRules, setHttpRules] = createSignal<HttpRuleRow[]>([]);
  const [envRows, setEnvRows] = createSignal<EnvRow[]>([]);
  const [secretRows, setSecretRows] = createSignal<SecretRow[]>([]);

  const [showAdvanced, setShowAdvanced] = createSignal(false);
  const [showJsonPreview, setShowJsonPreview] = createSignal(false);
  const [submitting, setSubmitting] = createSignal(false);
  const [errorMsg, setErrorMsg] = createSignal<string | null>(null);

  const [profileSpec] = createResource(selectedProfile, (name) =>
    getProfile(name),
  );

  // Keep ingress ports synced to selected profile until user edits them
  createEffect(() => {
    const spec = profileSpec();
    if (!portsTouched()) {
      setIngressPortsInput((spec?.ingress?.allow_ports ?? []).join(", "));
    }
  });

  const parsedPorts = createMemo<number[]>(() => {
    const raw = ingressPortsInput().trim();
    if (!raw) return [];
    const seen = new Set<number>();
    const out: number[] = [];
    for (const part of raw.split(/[,\s]+/)) {
      if (!part) continue;
      const n = Number(part);
      if (Number.isInteger(n) && n >= 1 && n <= 65535 && !seen.has(n)) {
        seen.add(n);
        out.push(n);
      }
    }
    return out;
  });

  const availableSecretNames = createMemo(() => {
    const names = new Set<string>(Object.keys(profileSpec()?.secrets ?? {}));
    for (const row of secretRows()) {
      const n = row.name.trim();
      if (n) names.add(n);
    }
    return [...names];
  });

  const advancedOverrideCount = createMemo(() => {
    let count = 0;
    for (const val of [
      vcpus(),
      memoryMib(),
      workspaceMib(),
      idleTimeoutSec(),
      maxWallTimeSec(),
    ]) {
      if (val.trim() !== "") count++;
    }
    for (const rule of httpRules()) {
      if (rule.host.trim() !== "") count++;
    }
    for (const row of envRows()) {
      if (row.key.trim() !== "") count++;
    }
    for (const row of secretRows()) {
      const hasValue =
        row.mode === "sealed"
          ? row.sealed.trim().length > 0
          : row.ephemeral.length > 0;
      if (row.name.trim() !== "" && hasValue) count++;
    }
    return count;
  });

  const togglePresetPort = (port: number) => {
    setPortsTouched(true);
    const current = parsedPorts();
    if (current.includes(port)) {
      setIngressPortsInput(current.filter((p) => p !== port).join(", "));
    } else {
      setIngressPortsInput([...current, port].sort((a, b) => a - b).join(", "));
    }
  };

  const toggleExtraExtend = (name: string) => {
    setExtraExtends((prev) =>
      prev.includes(name) ? prev.filter((p) => p !== name) : [...prev, name],
    );
  };

  const buildDraft = (redactSecrets: boolean): ProfileDraft => {
    const extendsList = [
      selectedProfile(),
      ...extraExtends().filter((p) => p !== selectedProfile()),
    ];

    const draft: ProfileDraft = {
      extends: extendsList,
    };

    const parsePositiveInt = (raw: string): number | undefined => {
      const trimmed = raw.trim();
      if (!trimmed) return undefined;
      const n = Number(trimmed);
      return Number.isInteger(n) && n > 0 ? n : undefined;
    };

    const computePatch = {
      vcpus: parsePositiveInt(vcpus()),
      memory_mib: parsePositiveInt(memoryMib()),
      workspace_mib: parsePositiveInt(workspaceMib()),
      idle_timeout_sec: parsePositiveInt(idleTimeoutSec()),
      max_wall_time_sec: parsePositiveInt(maxWallTimeSec()),
    };
    const hasCompute = Object.values(computePatch).some((v) => v !== undefined);
    if (hasCompute) {
      draft.compute = {};
      if (computePatch.vcpus !== undefined) draft.compute.vcpus = computePatch.vcpus;
      if (computePatch.memory_mib !== undefined) {
        draft.compute.memory_mib = computePatch.memory_mib;
      }
      if (computePatch.workspace_mib !== undefined) {
        draft.compute.workspace_mib = computePatch.workspace_mib;
      }
      if (computePatch.idle_timeout_sec !== undefined) {
        draft.compute.idle_timeout_sec = computePatch.idle_timeout_sec;
      }
      if (computePatch.max_wall_time_sec !== undefined) {
        draft.compute.max_wall_time_sec = computePatch.max_wall_time_sec;
      }
    }

    const mode = networkMode();
    const rules = buildHttpRulesFromRows(httpRules());
    const profileMode = profileSpec()?.network.mode;
    if (mode !== "" || rules.length > 0) {
      draft.network = {};
      if (mode !== "") {
        draft.network.mode = mode;
      } else if (rules.length > 0 && profileMode !== "egress") {
        draft.network.mode = "egress";
      }
      if (rules.length > 0) {
        draft.network.http = rules;
      }
    }

    const ports = parsedPorts();
    if (ports.length > 0) {
      draft.ingress = { allow_ports: ports };
    }

    const envMap: Record<string, string> = {};
    for (const row of envRows()) {
      const k = row.key.trim();
      if (k) {
        envMap[k] = row.value;
      }
    }
    if (Object.keys(envMap).length > 0) {
      draft.env = envMap;
    }

    const secretsMap: Record<string, SecretSpec> = {};
    for (const row of secretRows()) {
      const name = row.name.trim();
      if (!name) continue;
      if (row.mode === "sealed") {
        const sealedVal = row.sealed.trim();
        if (sealedVal.length > 0) {
          secretsMap[name] = {
            placeholder_prefix: row.placeholderPrefix.trim() || "bw_sec_",
            sealed: sealedVal,
          };
        }
      } else if (row.ephemeral.length > 0) {
        secretsMap[name] = {
          placeholder_prefix: row.placeholderPrefix.trim() || "bw_ephem_",
          ephemeral: redactSecrets ? "<redacted>" : row.ephemeral,
        };
      }
    }
    if (Object.keys(secretsMap).length > 0) {
      draft.secrets = secretsMap;
    }

    return draft;
  };

  const previewJson = createMemo(() =>
    JSON.stringify(buildDraft(true), null, 2),
  );

  const addHttpRuleRow = () => {
    setHttpRules((prev) => [
      ...prev,
      {
        id: nextRowId++,
        host: "",
        port: "443",
        methods: "GET, POST",
        pathPrefixes: "/",
        authKind: "none",
        authSecret: "",
        authHeaderName: "",
        authHeaderPrefix: "",
        authUsername: "",
      },
    ]);
  };

  const updateHttpRuleRow = <K extends keyof HttpRuleRow>(
    id: number,
    field: K,
    value: HttpRuleRow[K],
  ) => {
    setHttpRules((prev) =>
      prev.map((row) => (row.id === id ? { ...row, [field]: value } : row)),
    );
  };

  const removeHttpRuleRow = (id: number) => {
    setHttpRules((prev) => prev.filter((row) => row.id !== id));
  };

  const addEnvRow = () => {
    setEnvRows((prev) => [...prev, { id: nextRowId++, key: "", value: "" }]);
  };

  const updateEnvRow = (id: number, field: "key" | "value", value: string) => {
    setEnvRows((prev) =>
      prev.map((row) => (row.id === id ? { ...row, [field]: value } : row)),
    );
  };

  const removeEnvRow = (id: number) => {
    setEnvRows((prev) => prev.filter((row) => row.id !== id));
  };

  const addSecretRow = () => {
    setSecretRows((prev) => [
      ...prev,
      {
        id: nextRowId++,
        name: "",
        placeholderPrefix: "bw_sec_",
        mode: "sealed",
        sealed: "",
        ephemeral: "",
        reveal: false,
      },
    ]);
  };

  const updateSecretRow = <K extends keyof SecretRow>(
    id: number,
    field: K,
    value: SecretRow[K],
  ) => {
    setSecretRows((prev) =>
      prev.map((row) => (row.id === id ? { ...row, [field]: value } : row)),
    );
  };

  const removeSecretRow = (id: number) => {
    setSecretRows((prev) => prev.filter((row) => row.id !== id));
  };

  const handleSubmit = async (ev: SubmitEvent) => {
    ev.preventDefault();
    setErrorMsg(null);
    setSubmitting(true);
    try {
      const draft = buildDraft(false);
      const summary = await createSandbox(draft);
      // Immediately clear secret values from component state
      setSecretRows([]);
      props.onCreated(summary);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : String(err));
    } finally {
      setSubmitting(false);
    }
  };

  const renderHttpRulesPanel = () => (
    <div class="panel">
      <div class="panel-header">
        <span class="panel-title">
          <IconGlobe size={12} /> HTTP Egress Rules
        </span>
        <button type="button" class="btn btn-xs" onClick={addHttpRuleRow}>
          <IconPlus size={12} /> Add Rule
        </button>
      </div>
      <Show when={httpRules().length > 0}>
        <div class="panel-body stack" style={{ gap: "10px" }}>
          <For each={httpRules()}>
            {(rule) => (
              <div class="builder-row-card">
                <div class="row" style={{ gap: "8px" }}>
                  <input
                    type="text"
                    class="input mono"
                    placeholder="httpbin.org"
                    value={rule.host}
                    onInput={(e) =>
                      updateHttpRuleRow(rule.id, "host", e.currentTarget.value)
                    }
                  />
                  <input
                    type="number"
                    min="1"
                    max="65535"
                    class="input mono"
                    style={{ width: "86px", "flex-shrink": 0 }}
                    placeholder="443"
                    value={rule.port}
                    onInput={(e) =>
                      updateHttpRuleRow(rule.id, "port", e.currentTarget.value)
                    }
                  />
                  <button
                    type="button"
                    class="btn btn-ghost btn-sm"
                    onClick={() => removeHttpRuleRow(rule.id)}
                    title="Remove HTTP rule"
                  >
                    <IconTrash size={13} />
                  </button>
                </div>

                <div class="grid-2" style={{ gap: "8px" }}>
                  <div class="field">
                    <span class="field-label">Methods</span>
                    <input
                      type="text"
                      class="input mono"
                      placeholder="GET, POST"
                      value={rule.methods}
                      onInput={(e) =>
                        updateHttpRuleRow(
                          rule.id,
                          "methods",
                          e.currentTarget.value,
                        )
                      }
                    />
                  </div>
                  <div class="field">
                    <span class="field-label">Path Prefixes</span>
                    <input
                      type="text"
                      class="input mono"
                      placeholder="/anything"
                      value={rule.pathPrefixes}
                      onInput={(e) =>
                        updateHttpRuleRow(
                          rule.id,
                          "pathPrefixes",
                          e.currentTarget.value,
                        )
                      }
                    />
                  </div>
                </div>

                <div class="row-wrap" style={{ gap: "8px" }}>
                  <select
                    class="select mono"
                    style={{ width: "120px" }}
                    value={rule.authKind}
                    onChange={(e) =>
                      updateHttpRuleRow(
                        rule.id,
                        "authKind",
                        e.currentTarget.value as AuthKindOption,
                      )
                    }
                  >
                    <option value="none">Auth: None</option>
                    <option value="bearer">Bearer</option>
                    <option value="header">Header</option>
                    <option value="basic">Basic</option>
                  </select>

                  <Show when={rule.authKind !== "none"}>
                    <input
                      type="text"
                      class="input mono"
                      style={{ flex: "1 1 130px" }}
                      list="bw-sandbox-secret-names"
                      placeholder="SECRET_NAME"
                      value={rule.authSecret}
                      onInput={(e) =>
                        updateHttpRuleRow(
                          rule.id,
                          "authSecret",
                          e.currentTarget.value,
                        )
                      }
                    />
                  </Show>

                  <Show when={rule.authKind === "header"}>
                    <input
                      type="text"
                      class="input mono"
                      style={{ flex: "1 1 120px" }}
                      placeholder="X-Api-Key"
                      value={rule.authHeaderName}
                      onInput={(e) =>
                        updateHttpRuleRow(
                          rule.id,
                          "authHeaderName",
                          e.currentTarget.value,
                        )
                      }
                    />
                    <input
                      type="text"
                      class="input mono"
                      style={{ width: "100px" }}
                      placeholder="Prefix"
                      value={rule.authHeaderPrefix}
                      onInput={(e) =>
                        updateHttpRuleRow(
                          rule.id,
                          "authHeaderPrefix",
                          e.currentTarget.value,
                        )
                      }
                    />
                  </Show>

                  <Show when={rule.authKind === "basic"}>
                    <input
                      type="text"
                      class="input mono"
                      style={{ flex: "1 1 120px" }}
                      placeholder="username"
                      value={rule.authUsername}
                      onInput={(e) =>
                        updateHttpRuleRow(
                          rule.id,
                          "authUsername",
                          e.currentTarget.value,
                        )
                      }
                    />
                  </Show>
                </div>
              </div>
            )}
          </For>
        </div>
      </Show>
    </div>
  );

  return (
    <div
      class="modal-backdrop"
      onClick={(ev) => {
        if (ev.target === ev.currentTarget && !submitting()) {
          props.onClose();
        }
      }}
    >
      <form class="modal-card" onSubmit={handleSubmit}>
        <datalist id="bw-sandbox-secret-names">
          <For each={availableSecretNames()}>
            {(name) => <option value={name} />}
          </For>
        </datalist>

        <div class="modal-header">
          <div style={{ "font-weight": 600, "font-size": "14px" }}>
            New Sandbox
          </div>
          <button
            type="button"
            class="btn btn-ghost btn-sm"
            onClick={() => props.onClose()}
            disabled={submitting()}
            aria-label="Close modal"
          >
            <IconX size={15} />
          </button>
        </div>

        <div class="modal-body">
          <Show when={errorMsg()}>
            {(err) => (
              <div class="banner banner-error">
                <span class="mono">{err()}</span>
              </div>
            )}
          </Show>

          {/* Profile & Network Selection */}
          <div class="grid-2">
            <div class="field">
              <label class="field-label" for="bw-profile-select">
                Profile
              </label>
              <select
                id="bw-profile-select"
                class="select mono"
                value={selectedProfile()}
                onChange={(e) => {
                  setSelectedProfile(e.currentTarget.value);
                  setPortsTouched(false);
                }}
              >
                <For each={props.profiles.length > 0 ? props.profiles : ["base"]}>
                  {(name) => <option value={name}>{name}</option>}
                </For>
              </select>
            </div>

            <div class="field">
              <label class="field-label" for="bw-network-mode">
                Network
              </label>
              <select
                id="bw-network-mode"
                class="select mono"
                value={networkMode()}
                onChange={(e) =>
                  setNetworkMode(e.currentTarget.value as "" | NetworkMode)
                }
              >
                <option value="">
                  Inherit ({profileSpec()?.network.mode ?? "loopback"})
                </option>
                <option value="none">none</option>
                <option value="loopback">loopback</option>
                <option value="egress">egress</option>
              </select>
            </div>
          </div>

          {/* Mixin Profiles */}
          <Show when={props.profiles.length > 1}>
            <div class="field">
              <div class="field-label">Mixins</div>
              <div class="row-wrap">
                <For
                  each={props.profiles.filter(
                    (p) => p !== selectedProfile() && p !== "base",
                  )}
                >
                  {(name) => {
                    const active = () => extraExtends().includes(name);
                    return (
                      <button
                        type="button"
                        class={`btn btn-xs mono ${active() ? "btn-primary" : ""}`}
                        onClick={() => toggleExtraExtend(name)}
                      >
                        {active() ? "✓ " : "+ "}
                        {name}
                      </button>
                    );
                  }}
                </For>
              </div>
            </div>
          </Show>

          <Show when={profileSpec()}>
            {(spec) => (
              <div class="banner">
                <div class="row-wrap">
                  <Show when={extraExtends().filter((p) => p !== selectedProfile()).length > 0}>
                    <span class="pill pill-cyan">
                      {[
                        selectedProfile(),
                        ...extraExtends().filter((p) => p !== selectedProfile()),
                      ].join(" + ")}
                    </span>
                  </Show>
                  <span class="pill">
                    img: {spec().image.ref ?? spec().image.base ?? "default"}
                  </span>
                  <span class="pill">
                    {spec().compute.vcpus} vCPU · {spec().compute.memory_mib} MiB RAM ·{" "}
                    {spec().compute.workspace_mib} MiB /workspace
                  </span>
                  <Show when={spec().policy.locked}>
                    <span class="pill pill-amber">
                      <IconLock size={11} /> locked
                    </span>
                  </Show>
                </div>
              </div>
            )}
          </Show>

          {/* Ingress Ports */}
          <div class="field">
            <label class="field-label" for="bw-ingress-ports">
              Ingress Ports
            </label>
            <input
              id="bw-ingress-ports"
              type="text"
              class="input mono"
              placeholder="e.g. 3000, 5173, 8080, 8787"
              value={ingressPortsInput()}
              onInput={(e) => {
                setPortsTouched(true);
                setIngressPortsInput(e.currentTarget.value);
              }}
            />
            <div class="row-wrap">
              <For each={PRESET_PORTS}>
                {(port) => {
                  const selected = () => parsedPorts().includes(port);
                  return (
                    <button
                      type="button"
                      class={`btn btn-xs mono ${selected() ? "btn-primary" : ""}`}
                      onClick={() => togglePresetPort(port)}
                    >
                      :{port}
                    </button>
                  );
                }}
              </For>
            </div>
          </div>

          {/* Show HTTP Egress Rules directly when egress is chosen */}
          <Show when={networkMode() === "egress"}>
            {renderHttpRulesPanel()}
          </Show>

          {/* Collapsible Advanced Overrides */}
          <button
            type="button"
            class="disclosure-btn"
            aria-expanded={showAdvanced()}
            onClick={() => setShowAdvanced((v) => !v)}
          >
            <span class="row">
              <span class="disclosure-caret" classList={{ open: showAdvanced() }}>
                ▸
              </span>
              <span>Advanced Overrides</span>
            </span>
            <span
              class={
                advancedOverrideCount() > 0 ? "pill pill-emerald" : "pill"
              }
            >
              {advancedOverrideCount() > 0
                ? `${advancedOverrideCount()} set`
                : "0"}
            </span>
          </button>

          <Show when={showAdvanced()}>
            <div class="stack">
              {/* Compute */}
              <div class="panel">
                <div class="panel-header">
                  <span class="panel-title">Compute</span>
                </div>
                <div class="panel-body">
                  <div class="grid-3">
                    <div class="field">
                      <label class="field-label" for="bw-vcpus">vCPUs</label>
                      <input
                        id="bw-vcpus"
                        type="number"
                        min="1"
                        max="64"
                        class="input mono"
                        placeholder={String(profileSpec()?.compute.vcpus ?? 2)}
                        value={vcpus()}
                        onInput={(e) => setVcpus(e.currentTarget.value)}
                      />
                    </div>
                    <div class="field">
                      <label class="field-label" for="bw-ram">Memory (MiB)</label>
                      <input
                        id="bw-ram"
                        type="number"
                        min="64"
                        step="256"
                        class="input mono"
                        placeholder={String(profileSpec()?.compute.memory_mib ?? 2048)}
                        value={memoryMib()}
                        onInput={(e) => setMemoryMib(e.currentTarget.value)}
                      />
                    </div>
                    <div class="field">
                      <label class="field-label" for="bw-ws">Workspace (MiB)</label>
                      <input
                        id="bw-ws"
                        type="number"
                        min="16"
                        step="256"
                        class="input mono"
                        placeholder={String(profileSpec()?.compute.workspace_mib ?? 1024)}
                        value={workspaceMib()}
                        onInput={(e) => setWorkspaceMib(e.currentTarget.value)}
                      />
                    </div>
                  </div>
                  <div class="grid-2" style={{ "margin-top": "10px" }}>
                    <div class="field">
                      <label class="field-label" for="bw-idle">Idle Timeout (sec)</label>
                      <input
                        id="bw-idle"
                        type="number"
                        min="10"
                        class="input mono"
                        placeholder={String(profileSpec()?.compute.idle_timeout_sec ?? 600)}
                        value={idleTimeoutSec()}
                        onInput={(e) => setIdleTimeoutSec(e.currentTarget.value)}
                      />
                    </div>
                    <div class="field">
                      <label class="field-label" for="bw-wall">Max Wall Time (sec)</label>
                      <input
                        id="bw-wall"
                        type="number"
                        min="10"
                        class="input mono"
                        placeholder={String(profileSpec()?.compute.max_wall_time_sec ?? 3600)}
                        value={maxWallTimeSec()}
                        onInput={(e) => setMaxWallTimeSec(e.currentTarget.value)}
                      />
                    </div>
                  </div>
                </div>
              </div>

              {/* HTTP Egress Rules (shown here when not already lifted above) */}
              <Show when={networkMode() !== "egress"}>
                {renderHttpRulesPanel()}
              </Show>

              {/* Secrets */}
              <div class="panel">
                <div class="panel-header">
                  <span class="panel-title">
                    <IconLock size={12} /> Secrets
                  </span>
                  <button
                    type="button"
                    class="btn btn-xs"
                    onClick={addSecretRow}
                  >
                    <IconPlus size={12} /> Add
                  </button>
                </div>
                <Show when={secretRows().length > 0}>
                  <div class="panel-body stack" style={{ gap: "10px" }}>
                    <For each={secretRows()}>
                      {(row) => (
                        <div class="builder-row-card">
                          <div class="row-wrap" style={{ gap: "8px" }}>
                            <input
                              type="text"
                              class="input mono"
                              placeholder="SECRET_NAME"
                              style={{ flex: "1 1 150px" }}
                              value={row.name}
                              onInput={(e) =>
                                updateSecretRow(
                                  row.id,
                                  "name",
                                  e.currentTarget.value,
                                )
                              }
                            />
                            <input
                              type="text"
                              class="input mono"
                              placeholder="prefix_"
                              style={{ width: "120px" }}
                              value={row.placeholderPrefix}
                              onInput={(e) =>
                                updateSecretRow(
                                  row.id,
                                  "placeholderPrefix",
                                  e.currentTarget.value,
                                )
                              }
                            />
                            <div class="segmented">
                              <button
                                type="button"
                                class={`segmented-btn ${row.mode === "sealed" ? "active" : ""}`}
                                onClick={() =>
                                  updateSecretRow(row.id, "mode", "sealed")
                                }
                              >
                                Sealed
                              </button>
                              <button
                                type="button"
                                class={`segmented-btn ${row.mode === "ephemeral" ? "active" : ""}`}
                                onClick={() =>
                                  updateSecretRow(row.id, "mode", "ephemeral")
                                }
                              >
                                Ephemeral
                              </button>
                            </div>
                            <button
                              type="button"
                              class="btn btn-ghost btn-sm"
                              onClick={() => removeSecretRow(row.id)}
                              title="Remove secret"
                            >
                              <IconTrash size={13} />
                            </button>
                          </div>

                          <Show
                            when={row.mode === "sealed"}
                            fallback={
                              <div class="row">
                                <input
                                  type={row.reveal ? "text" : "password"}
                                  class="input mono"
                                  placeholder="ephemeral secret value"
                                  autocomplete="off"
                                  value={row.ephemeral}
                                  onInput={(e) =>
                                    updateSecretRow(
                                      row.id,
                                      "ephemeral",
                                      e.currentTarget.value,
                                    )
                                  }
                                />
                                <button
                                  type="button"
                                  class="btn btn-xs"
                                  onClick={() =>
                                    updateSecretRow(
                                      row.id,
                                      "reveal",
                                      !row.reveal,
                                    )
                                  }
                                >
                                  {row.reveal ? "Hide" : "Show"}
                                </button>
                              </div>
                            }
                          >
                            <textarea
                              class="textarea mono"
                              style={{ "min-height": "54px" }}
                              placeholder="seal1_..."
                              spellcheck={false}
                              value={row.sealed}
                              onInput={(e) =>
                                updateSecretRow(
                                  row.id,
                                  "sealed",
                                  e.currentTarget.value,
                                )
                              }
                            />
                          </Show>
                        </div>
                      )}
                    </For>
                  </div>
                </Show>
              </div>

              {/* Environment */}
              <div class="panel">
                <div class="panel-header">
                  <span class="panel-title">Environment</span>
                  <button
                    type="button"
                    class="btn btn-xs"
                    onClick={addEnvRow}
                  >
                    <IconPlus size={12} /> Add
                  </button>
                </div>
                <Show when={envRows().length > 0}>
                  <div class="panel-body stack" style={{ gap: "8px" }}>
                    <For each={envRows()}>
                      {(row) => (
                        <div class="row">
                          <input
                            type="text"
                            class="input mono"
                            placeholder="KEY"
                            value={row.key}
                            onInput={(e) =>
                              updateEnvRow(row.id, "key", e.currentTarget.value)
                            }
                          />
                          <input
                            type="text"
                            class="input mono"
                            placeholder="value"
                            value={row.value}
                            onInput={(e) =>
                              updateEnvRow(row.id, "value", e.currentTarget.value)
                            }
                          />
                          <button
                            type="button"
                            class="btn btn-ghost btn-sm"
                            onClick={() => removeEnvRow(row.id)}
                            title="Remove env var"
                          >
                            <IconTrash size={13} />
                          </button>
                        </div>
                      )}
                    </For>
                  </div>
                </Show>
              </div>
            </div>
          </Show>

          <Show when={showJsonPreview()}>
            <div class="field">
              <div class="field-label">Request Payload</div>
              <pre class="code-block">{previewJson()}</pre>
            </div>
          </Show>
        </div>

        <div class="modal-footer">
          <button
            type="button"
            class="btn btn-ghost btn-sm mono"
            onClick={() => setShowJsonPreview((v) => !v)}
          >
            {showJsonPreview() ? "Hide JSON" : "Inspect JSON"}
          </button>
          <div class="row">
            <button
              type="button"
              class="btn"
              onClick={() => props.onClose()}
              disabled={submitting()}
            >
              Cancel
            </button>
            <button
              type="submit"
              class="btn btn-primary"
              disabled={submitting()}
            >
              {submitting() ? "Launching…" : "Launch"}
            </button>
          </div>
        </div>
      </form>
    </div>
  );
}
