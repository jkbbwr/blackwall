import { createMemo, createSignal, For, Show } from "solid-js";
import { createProfile } from "../api/client";
import type {
  AuthSpec,
  HttpRule,
  NetworkMode,
  ProfileDraft,
  SandboxSpec,
  SecretSpec,
} from "../api/types";
import { IconGlobe, IconLock, IconPlus, IconTrash, IconX } from "./Icons";

interface EnvRow {
  id: number;
  key: string;
  value: string;
}

interface SealedSecretRow {
  id: number;
  name: string;
  placeholderPrefix: string;
  sealed: string;
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

export interface CreateProfileModalProps {
  existingProfiles: string[];
  onClose: () => void;
  onCreated: (spec: SandboxSpec) => void;
}

const PRESET_PORTS = [3000, 5173, 8000, 8080, 8787] as const;

function tomlStr(val: string): string {
  return JSON.stringify(val);
}

function tomlKey(key: string): string {
  return /^[A-Za-z0-9_-]+$/.test(key) ? key : tomlStr(key);
}

function parsePositiveInt(raw: string): number | undefined {
  const trimmed = raw.trim();
  if (!trimmed) return undefined;
  const n = Number(trimmed);
  return Number.isInteger(n) && n > 0 ? n : undefined;
}

function buildHttpRules(rows: HttpRuleRow[]): HttpRule[] {
  const out: HttpRule[] = [];
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

    out.push({
      host,
      port,
      methods: methods.length > 0 ? methods : ["GET"],
      path_prefixes: pathPrefixes.length > 0 ? pathPrefixes : ["/"],
      ...(auth ? { auth } : {}),
    });
  }
  return out;
}

function serializeAuthToml(auth: AuthSpec): string {
  switch (auth.kind) {
    case "bearer":
      return `{ kind = "bearer", secret = ${tomlStr(auth.secret)} }`;
    case "header":
      return auth.prefix
        ? `{ kind = "header", secret = ${tomlStr(auth.secret)}, name = ${tomlStr(auth.name)}, prefix = ${tomlStr(auth.prefix)} }`
        : `{ kind = "header", secret = ${tomlStr(auth.secret)}, name = ${tomlStr(auth.name)} }`;
    case "basic":
      return `{ kind = "basic", secret = ${tomlStr(auth.secret)}, username = ${tomlStr(auth.username)} }`;
  }
}

export function CreateProfileModal(props: CreateProfileModalProps) {
  let nextRowId = 1;

  const [editorMode, setEditorMode] = createSignal<"form" | "toml">("form");
  const [name, setName] = createSignal("");
  const [extendsList, setExtendsList] = createSignal<string[]>(["base"]);

  // Image
  const [baseImage, setBaseImage] = createSignal("");
  const [packagesInput, setPackagesInput] = createSignal("");
  const [runInput, setRunInput] = createSignal("");

  // Compute
  const [vcpus, setVcpus] = createSignal("");
  const [memoryMib, setMemoryMib] = createSignal("");
  const [workspaceMib, setWorkspaceMib] = createSignal("");
  const [idleTimeoutSec, setIdleTimeoutSec] = createSignal("");
  const [maxWallTimeSec, setMaxWallTimeSec] = createSignal("");

  // Network & Ingress
  const [networkMode, setNetworkMode] = createSignal<"" | NetworkMode>("");
  const [httpRules, setHttpRules] = createSignal<HttpRuleRow[]>([]);
  const [ingressPortsInput, setIngressPortsInput] = createSignal("");

  // Secrets & Env
  const [secretRows, setSecretRows] = createSignal<SealedSecretRow[]>([]);
  const [envRows, setEnvRows] = createSignal<EnvRow[]>([]);

  // TOML direct mode
  const [tomlText, setTomlText] = createSignal("");
  const [tomlDirty, setTomlDirty] = createSignal(false);

  const [submitting, setSubmitting] = createSignal(false);
  const [errorMsg, setErrorMsg] = createSignal<string | null>(null);

  const parsedPackages = createMemo(() =>
    packagesInput()
      .split(/[,\s]+/)
      .map((p) => p.trim())
      .filter(Boolean),
  );

  const parsedRunSteps = createMemo(() =>
    runInput()
      .split("\n")
      .map((line) => line.trim())
      .filter(Boolean),
  );

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

  const secretNames = createMemo(() =>
    secretRows()
      .map((r) => r.name.trim())
      .filter(Boolean),
  );

  const toggleExtend = (profileName: string) => {
    setExtendsList((prev) =>
      prev.includes(profileName)
        ? prev.filter((p) => p !== profileName)
        : [...prev, profileName],
    );
  };

  const togglePresetPort = (port: number) => {
    const current = parsedPorts();
    if (current.includes(port)) {
      setIngressPortsInput(current.filter((p) => p !== port).join(", "));
    } else {
      setIngressPortsInput([...current, port].sort((a, b) => a - b).join(", "));
    }
  };

  const buildDraft = (): ProfileDraft => {
    const profileName = name().trim();
    const draft: ProfileDraft = {
      version: 1,
      name: profileName,
    };

    const exts = extendsList();
    if (exts.length > 0) {
      draft.extends = exts;
    }

    const base = baseImage().trim();
    const pkgs = parsedPackages();
    const runs = parsedRunSteps();
    if (base || pkgs.length > 0 || runs.length > 0) {
      draft.image = {};
      if (base) draft.image.base = base;
      if (pkgs.length > 0) draft.image.packages = pkgs;
      if (runs.length > 0) draft.image.run = runs;
    }

    const computePatch = {
      vcpus: parsePositiveInt(vcpus()),
      memory_mib: parsePositiveInt(memoryMib()),
      workspace_mib: parsePositiveInt(workspaceMib()),
      idle_timeout_sec: parsePositiveInt(idleTimeoutSec()),
      max_wall_time_sec: parsePositiveInt(maxWallTimeSec()),
    };
    if (Object.values(computePatch).some((v) => v !== undefined)) {
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
    const rules = buildHttpRules(httpRules());
    if (mode !== "" || rules.length > 0) {
      draft.network = {};
      if (mode !== "") {
        draft.network.mode = mode;
      } else if (rules.length > 0) {
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

    const secretsMap: Record<string, SecretSpec> = {};
    for (const row of secretRows()) {
      const sName = row.name.trim();
      const sVal = row.sealed.trim();
      if (sName && sVal) {
        secretsMap[sName] = {
          placeholder_prefix: row.placeholderPrefix.trim() || "bw_sec_",
          sealed: sVal,
        };
      }
    }
    if (Object.keys(secretsMap).length > 0) {
      draft.secrets = secretsMap;
    }

    const envMap: Record<string, string> = {};
    for (const row of envRows()) {
      const k = row.key.trim();
      if (k) envMap[k] = row.value;
    }
    if (Object.keys(envMap).length > 0) {
      draft.env = envMap;
    }

    return draft;
  };

  const generateTomlFromForm = (): string => {
    const draft = buildDraft();
    const lines: string[] = [];
    lines.push("version = 1");
    lines.push(`name = ${tomlStr(draft.name || "custom")}`);
    if (draft.extends && draft.extends.length > 0) {
      lines.push(`extends = [${draft.extends.map(tomlStr).join(", ")}]`);
    }

    if (draft.image) {
      lines.push("");
      lines.push("[image]");
      if (draft.image.base) {
        lines.push(`base = ${tomlStr(draft.image.base)}`);
      }
      if (draft.image.packages && draft.image.packages.length > 0) {
        lines.push(
          `packages = [${draft.image.packages.map(tomlStr).join(", ")}]`,
        );
      }
      if (draft.image.run && draft.image.run.length > 0) {
        lines.push("run = [");
        for (const step of draft.image.run) {
          lines.push(`  ${tomlStr(step)},`);
        }
        lines.push("]");
      }
    }

    if (draft.compute) {
      lines.push("");
      lines.push("[compute]");
      if (draft.compute.vcpus !== undefined) {
        lines.push(`vcpus = ${draft.compute.vcpus}`);
      }
      if (draft.compute.memory_mib !== undefined) {
        lines.push(`memory_mib = ${draft.compute.memory_mib}`);
      }
      if (draft.compute.workspace_mib !== undefined) {
        lines.push(`workspace_mib = ${draft.compute.workspace_mib}`);
      }
      if (draft.compute.idle_timeout_sec !== undefined) {
        lines.push(`idle_timeout_sec = ${draft.compute.idle_timeout_sec}`);
      }
      if (draft.compute.max_wall_time_sec !== undefined) {
        lines.push(`max_wall_time_sec = ${draft.compute.max_wall_time_sec}`);
      }
    }

    if (draft.network) {
      if (draft.network.mode) {
        lines.push("");
        lines.push("[network]");
        lines.push(`mode = ${tomlStr(draft.network.mode)}`);
      }
      if (draft.network.http && draft.network.http.length > 0) {
        for (const rule of draft.network.http) {
          lines.push("");
          lines.push("[[network.http]]");
          lines.push(`host = ${tomlStr(rule.host)}`);
          lines.push(`port = ${rule.port}`);
          lines.push(
            `methods = [${rule.methods.map(tomlStr).join(", ")}]`,
          );
          lines.push(
            `path_prefixes = [${rule.path_prefixes.map(tomlStr).join(", ")}]`,
          );
          if (rule.auth) {
            lines.push(`auth = ${serializeAuthToml(rule.auth)}`);
          }
        }
      }
    }

    if (draft.ingress?.allow_ports && draft.ingress.allow_ports.length > 0) {
      lines.push("");
      lines.push("[ingress]");
      lines.push(`allow_ports = [${draft.ingress.allow_ports.join(", ")}]`);
    }

    if (draft.secrets) {
      for (const [secName, sec] of Object.entries(draft.secrets)) {
        lines.push("");
        lines.push(`[secrets.${tomlKey(secName)}]`);
        lines.push(`placeholder_prefix = ${tomlStr(sec.placeholder_prefix)}`);
        if (sec.sealed) {
          lines.push(`sealed = ${tomlStr(sec.sealed)}`);
        }
      }
    }

    if (draft.env && Object.keys(draft.env).length > 0) {
      lines.push("");
      lines.push("[env]");
      for (const [k, v] of Object.entries(draft.env)) {
        lines.push(`${tomlKey(k)} = ${tomlStr(v)}`);
      }
    }

    return `${lines.join("\n")}\n`;
  };

  const switchMode = (next: "form" | "toml") => {
    if (next === "toml" && !tomlDirty()) {
      setTomlText(generateTomlFromForm());
    }
    setEditorMode(next);
  };

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

  const addSecretRow = () => {
    setSecretRows((prev) => [
      ...prev,
      {
        id: nextRowId++,
        name: "",
        placeholderPrefix: "bw_sec_",
        sealed: "",
      },
    ]);
  };

  const updateSecretRow = <K extends keyof SealedSecretRow>(
    id: number,
    field: K,
    value: SealedSecretRow[K],
  ) => {
    setSecretRows((prev) =>
      prev.map((row) => (row.id === id ? { ...row, [field]: value } : row)),
    );
  };

  const removeSecretRow = (id: number) => {
    setSecretRows((prev) => prev.filter((row) => row.id !== id));
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

  const handleSubmit = async (ev: SubmitEvent) => {
    ev.preventDefault();
    const profileName = name().trim();
    if (!profileName) {
      setErrorMsg("Profile name is required.");
      return;
    }
    if (profileName === "base") {
      setErrorMsg('Profile name "base" is reserved.');
      return;
    }
    if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]*$/.test(profileName)) {
      setErrorMsg("Use letters, numbers, hyphens, dots, or underscores.");
      return;
    }

    setErrorMsg(null);
    setSubmitting(true);
    try {
      const payload =
        editorMode() === "toml"
          ? { name: profileName, toml: tomlText() }
          : { name: profileName, draft: buildDraft() };
      const spec = await createProfile(payload);
      props.onCreated(spec);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : String(err));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div
      class="modal-backdrop"
      onClick={(ev) => {
        if (ev.target === ev.currentTarget && !submitting()) {
          props.onClose();
        }
      }}
    >
      <form class="modal-card modal-card-wide" onSubmit={handleSubmit}>
        <datalist id="bw-profile-secret-names">
          <For each={secretNames()}>
            {(s) => <option value={s} />}
          </For>
        </datalist>

        <div class="modal-header">
          <div class="row" style={{ gap: "12px" }}>
            <div style={{ "font-weight": 600, "font-size": "14px" }}>
              New Profile
            </div>
            <div class="segmented">
              <button
                type="button"
                class={`segmented-btn ${editorMode() === "form" ? "active" : ""}`}
                onClick={() => switchMode("form")}
              >
                Form
              </button>
              <button
                type="button"
                class={`segmented-btn ${editorMode() === "toml" ? "active" : ""}`}
                onClick={() => switchMode("toml")}
              >
                TOML
              </button>
            </div>
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
              <div class="banner banner-error mono">{err()}</div>
            )}
          </Show>

          {/* Profile Name (always visible) */}
          <div class="field">
            <label class="field-label" for="bw-new-profile-name">
              Profile Name
            </label>
            <input
              id="bw-new-profile-name"
              type="text"
              class="input mono"
              placeholder="e.g. python-dev"
              value={name()}
              onInput={(e) => setName(e.currentTarget.value)}
              autofocus
            />
          </div>

          <Show
            when={editorMode() === "form"}
            fallback={
              <div class="field">
                <div
                  class="row"
                  style={{ "justify-content": "space-between" }}
                >
                  <label class="field-label" for="bw-profile-toml">
                    Profile TOML
                  </label>
                  <Show when={tomlDirty()}>
                    <button
                      type="button"
                      class="btn btn-ghost btn-xs"
                      onClick={() => {
                        setTomlText(generateTomlFromForm());
                        setTomlDirty(false);
                      }}
                    >
                      Sync from Form
                    </button>
                  </Show>
                </div>
                <textarea
                  id="bw-profile-toml"
                  class="textarea mono toml-editor"
                  spellcheck={false}
                  value={tomlText()}
                  onInput={(e) => {
                    setTomlDirty(true);
                    setTomlText(e.currentTarget.value);
                  }}
                />
              </div>
            }
          >
            {/* Extends */}
            <div class="field">
              <div class="field-label">Extends</div>
              <div class="row-wrap">
                <For
                  each={
                    props.existingProfiles.length > 0
                      ? props.existingProfiles
                      : ["base"]
                  }
                >
                  {(p) => {
                    const active = () => extendsList().includes(p);
                    return (
                      <button
                        type="button"
                        class={`btn btn-xs mono ${active() ? "btn-primary" : ""}`}
                        onClick={() => toggleExtend(p)}
                      >
                        {active() ? "✓ " : "+ "}
                        {p}
                      </button>
                    );
                  }}
                </For>
              </div>
            </div>

            {/* Image */}
            <div class="panel">
              <div class="panel-header">
                <span class="panel-title">Image</span>
              </div>
              <div class="panel-body stack" style={{ gap: "10px" }}>
                <div class="grid-2">
                  <div class="field">
                    <label class="field-label" for="bw-prof-base">
                      Base Image
                    </label>
                    <input
                      id="bw-prof-base"
                      type="text"
                      class="input mono"
                      placeholder="debian:bookworm-slim"
                      value={baseImage()}
                      onInput={(e) => setBaseImage(e.currentTarget.value)}
                    />
                  </div>
                  <div class="field">
                    <label class="field-label" for="bw-prof-pkgs">
                      Packages
                    </label>
                    <input
                      id="bw-prof-pkgs"
                      type="text"
                      class="input mono"
                      placeholder="git, curl, python3, ripgrep"
                      value={packagesInput()}
                      onInput={(e) => setPackagesInput(e.currentTarget.value)}
                    />
                  </div>
                </div>
                <div class="field">
                  <label class="field-label" for="bw-prof-run">
                    Build Run Steps
                  </label>
                  <textarea
                    id="bw-prof-run"
                    class="textarea mono"
                    style={{ "min-height": "54px" }}
                    placeholder="One shell command per line"
                    spellcheck={false}
                    value={runInput()}
                    onInput={(e) => setRunInput(e.currentTarget.value)}
                  />
                </div>
              </div>
            </div>

            {/* Compute */}
            <div class="panel">
              <div class="panel-header">
                <span class="panel-title">Compute</span>
              </div>
              <div class="panel-body">
                <div class="grid-3">
                  <div class="field">
                    <label class="field-label" for="bw-prof-vcpus">vCPUs</label>
                    <input
                      id="bw-prof-vcpus"
                      type="number"
                      min="1"
                      max="64"
                      class="input mono"
                      placeholder="2"
                      value={vcpus()}
                      onInput={(e) => setVcpus(e.currentTarget.value)}
                    />
                  </div>
                  <div class="field">
                    <label class="field-label" for="bw-prof-ram">Memory (MiB)</label>
                    <input
                      id="bw-prof-ram"
                      type="number"
                      min="64"
                      step="256"
                      class="input mono"
                      placeholder="2048"
                      value={memoryMib()}
                      onInput={(e) => setMemoryMib(e.currentTarget.value)}
                    />
                  </div>
                  <div class="field">
                    <label class="field-label" for="bw-prof-ws">Workspace (MiB)</label>
                    <input
                      id="bw-prof-ws"
                      type="number"
                      min="16"
                      step="256"
                      class="input mono"
                      placeholder="1024"
                      value={workspaceMib()}
                      onInput={(e) => setWorkspaceMib(e.currentTarget.value)}
                    />
                  </div>
                </div>
                <div class="grid-2" style={{ "margin-top": "10px" }}>
                  <div class="field">
                    <label class="field-label" for="bw-prof-idle">Idle Timeout (sec)</label>
                    <input
                      id="bw-prof-idle"
                      type="number"
                      min="10"
                      class="input mono"
                      placeholder="600"
                      value={idleTimeoutSec()}
                      onInput={(e) => setIdleTimeoutSec(e.currentTarget.value)}
                    />
                  </div>
                  <div class="field">
                    <label class="field-label" for="bw-prof-wall">Max Wall Time (sec)</label>
                    <input
                      id="bw-prof-wall"
                      type="number"
                      min="10"
                      class="input mono"
                      placeholder="3600"
                      value={maxWallTimeSec()}
                      onInput={(e) => setMaxWallTimeSec(e.currentTarget.value)}
                    />
                  </div>
                </div>
              </div>
            </div>

            {/* Network & Ingress */}
            <div class="grid-2">
              <div class="field">
                <label class="field-label" for="bw-prof-net">
                  Network Mode
                </label>
                <select
                  id="bw-prof-net"
                  class="select mono"
                  value={networkMode()}
                  onChange={(e) =>
                    setNetworkMode(e.currentTarget.value as "" | NetworkMode)
                  }
                >
                  <option value="">Inherit</option>
                  <option value="none">none</option>
                  <option value="loopback">loopback</option>
                  <option value="egress">egress</option>
                </select>
              </div>
              <div class="field">
                <label class="field-label" for="bw-prof-ports">
                  Ingress Ports
                </label>
                <input
                  id="bw-prof-ports"
                  type="text"
                  class="input mono"
                  placeholder="3000, 5173, 8080"
                  value={ingressPortsInput()}
                  onInput={(e) => setIngressPortsInput(e.currentTarget.value)}
                />
                <div class="row-wrap">
                  <For each={PRESET_PORTS}>
                    {(port) => {
                      const active = () => parsedPorts().includes(port);
                      return (
                        <button
                          type="button"
                          class={`btn btn-xs mono ${active() ? "btn-primary" : ""}`}
                          onClick={() => togglePresetPort(port)}
                        >
                          :{port}
                        </button>
                      );
                    }}
                  </For>
                </div>
              </div>
            </div>

            {/* HTTP Egress Rules */}
            <div class="panel">
              <div class="panel-header">
                <span class="panel-title">
                  <IconGlobe size={12} /> HTTP Egress Rules
                </span>
                <button
                  type="button"
                  class="btn btn-xs"
                  onClick={addHttpRuleRow}
                >
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
                            placeholder="api.openai.com"
                            value={rule.host}
                            onInput={(e) =>
                              updateHttpRuleRow(
                                rule.id,
                                "host",
                                e.currentTarget.value,
                              )
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
                              updateHttpRuleRow(
                                rule.id,
                                "port",
                                e.currentTarget.value,
                              )
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
                              placeholder="/v1"
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
                              list="bw-profile-secret-names"
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

            {/* Sealed Secrets */}
            <div class="panel">
              <div class="panel-header">
                <span class="panel-title">
                  <IconLock size={12} /> Sealed Secrets
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
                        <div class="row" style={{ gap: "8px" }}>
                          <input
                            type="text"
                            class="input mono"
                            placeholder="SECRET_NAME"
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
                            style={{ width: "130px", "flex-shrink": 0 }}
                            placeholder="prefix_"
                            value={row.placeholderPrefix}
                            onInput={(e) =>
                              updateSecretRow(
                                row.id,
                                "placeholderPrefix",
                                e.currentTarget.value,
                              )
                            }
                          />
                          <button
                            type="button"
                            class="btn btn-ghost btn-sm"
                            onClick={() => removeSecretRow(row.id)}
                            title="Remove secret"
                          >
                            <IconTrash size={13} />
                          </button>
                        </div>
                        <textarea
                          class="textarea mono"
                          style={{ "min-height": "52px" }}
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
                <button type="button" class="btn btn-xs" onClick={addEnvRow}>
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
          </Show>
        </div>

        <div class="modal-footer">
          <span class="field-hint mono">
            {editorMode() === "toml" ? "TOML mode" : "Form mode"}
          </span>
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
              disabled={submitting() || name().trim().length === 0}
            >
              {submitting() ? "Saving…" : "Create Profile"}
            </button>
          </div>
        </div>
      </form>
    </div>
  );
}
