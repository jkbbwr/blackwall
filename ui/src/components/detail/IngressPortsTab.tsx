import {
  createEffect,
  createMemo,
  createSignal,
  For,
  on,
  onCleanup,
  Show,
} from "solid-js";
import {
  allowIngressPort,
  attachHostBridge,
  buildProxyUrl,
  closeIngressPort,
  detachHostBridge,
  getPreviewOrigin,
  listHostBridges,
  listSandboxPorts,
  probeProxyPort,
} from "../../api/client";
import type {
  HostServiceSpec,
  ListeningPort,
  PortProbeResult,
  SandboxDetail,
} from "../../api/types";
import { copyToClipboard } from "../../utils/format";
import {
  IconCheck,
  IconCopy,
  IconExternalLink,
  IconGlobe,
  IconPlus,
  IconRefresh,
  IconTrash,
  IconX,
  IconZap,
} from "../Icons";

export interface IngressPortsTabProps {
  detail: SandboxDetail;
  onActivity?: () => void;
}

const NON_HTTP_TCP_PORTS = new Set<number>([
  5432, 5433, 5434, 5435, 3306, 6379, 27017, 9042, 11211,
]);

function formatBindEndpoint(port: number, address?: string): string {
  if (!address) return `127.0.0.1:${port}`;
  if (address.endsWith(`:${port}`)) return address;
  return `${address}:${port}`;
}

export function IngressPortsTab(props: IngressPortsTabProps) {
  let scanController: AbortController | null = null;
  let bridgesController: AbortController | null = null;

  const [listeningPorts, setListeningPorts] = createSignal<ListeningPort[]>([]);
  const [loadingPorts, setLoadingPorts] = createSignal(false);
  const [portsError, setPortsError] = createSignal<string | null>(null);

  const [fetchedBridges, setFetchedBridges] = createSignal<
    HostServiceSpec[] | null
  >(null);
  const [loadingBridges, setLoadingBridges] = createSignal(false);
  const [bridgesError, setBridgesError] = createSignal<string | null>(null);
  const [bridgePortInput, setBridgePortInput] = createSignal("");
  const [bridgeTargetInput, setBridgeTargetInput] = createSignal("");
  const [bridgeNameInput, setBridgeNameInput] = createSignal("");
  const [attachingBridge, setAttachingBridge] = createSignal(false);
  const [detachingPort, setDetachingPort] = createSignal<number | null>(null);

  const [probeSubPath, setProbeSubPath] = createSignal<Record<number, string>>(
    {},
  );
  const [probeResults, setProbeResults] = createSignal<
    Record<number, PortProbeResult>
  >({});
  const [probingPort, setProbingPort] = createSignal<number | null>(null);
  const [copiedPort, setCopiedPort] = createSignal<number | null>(null);

  const [overrideAllowedPorts, setOverrideAllowedPorts] = createSignal<
    number[] | null
  >(null);
  const [allowPortInput, setAllowPortInput] = createSignal("");
  const [allowingPort, setAllowingPort] = createSignal<number | null>(null);
  const [allowFormSubmitting, setAllowFormSubmitting] = createSignal(false);
  const [closingPort, setClosingPort] = createSignal<number | null>(null);
  const [ingressError, setIngressError] = createSignal<string | null>(null);

  const sandboxId = createMemo(() => props.detail.id);
  const isRunning = createMemo(() => props.detail.state === "running");
  const isNetworkNone = createMemo(() => props.detail.network_mode === "none");
  const isIsolatedPreview = createMemo(() => {
    const origin = getPreviewOrigin();
    return origin !== null && origin !== window.location.origin;
  });

  const activeBridges = createMemo<HostServiceSpec[]>(() => {
    const list = fetchedBridges() ?? props.detail.host_services ?? [];
    return [...list].sort((a, b) => a.guest_port - b.guest_port);
  });

  const loadBridges = async (id = sandboxId()) => {
    if (!isRunning()) {
      setFetchedBridges(null);
      setBridgesError(null);
      return;
    }
    bridgesController?.abort();
    const controller = new AbortController();
    bridgesController = controller;

    setLoadingBridges(true);
    setBridgesError(null);
    try {
      const list = await listHostBridges(id, controller.signal);
      if (controller.signal.aborted) return;
      setFetchedBridges(list);
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") return;
      setBridgesError(err instanceof Error ? err.message : String(err));
    } finally {
      if (bridgesController === controller) {
        setLoadingBridges(false);
      }
    }
  };

  const scanPorts = async (id = sandboxId()) => {
    if (!isRunning()) {
      setListeningPorts([]);
      setPortsError(null);
      return;
    }
    scanController?.abort();
    const controller = new AbortController();
    scanController = controller;

    setLoadingPorts(true);
    setPortsError(null);
    try {
      const discovered = await listSandboxPorts(id, controller.signal);
      if (controller.signal.aborted) return;
      setListeningPorts(discovered);
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") return;
      setPortsError(err instanceof Error ? err.message : String(err));
    } finally {
      if (scanController === controller) {
        setLoadingPorts(false);
      }
    }
  };

  createEffect(() => {
    const id = sandboxId();
    setOverrideAllowedPorts(null);
    setAllowPortInput("");
    setIngressError(null);
    setProbeResults({});
    setListeningPorts([]);
    setFetchedBridges(null);
    setBridgesError(null);
    void scanPorts(id);
    void loadBridges(id);
  });

  onCleanup(() => {
    scanController?.abort();
    bridgesController?.abort();
  });

  const detailAllowedPorts = createMemo<number[]>(
    () => {
      const raw =
        props.detail.ingress_allow_ports ??
        props.detail.ingress?.allow_ports ??
        [];
      return [...new Set(raw)].sort((a, b) => a - b);
    },
    [],
    {
      equals: (a, b) =>
        a.length === b.length && a.every((v, i) => v === b[i]),
    },
  );

  createEffect(
    on(
      detailAllowedPorts,
      () => {
        setOverrideAllowedPorts(null);
      },
      { defer: true },
    ),
  );

  const allowedPorts = createMemo<number[]>(
    () => {
      const raw = overrideAllowedPorts() ?? detailAllowedPorts();
      return [...new Set(raw)].sort((a, b) => a - b);
    },
    [],
    {
      equals: (a, b) =>
        a.length === b.length && a.every((v, i) => v === b[i]),
    },
  );

  const listeningByPort = createMemo(() => {
    const map = new Map<number, ListeningPort>();
    for (const lp of listeningPorts()) {
      map.set(lp.port, lp);
    }
    return map;
  });

  const allDisplayPorts = createMemo<number[]>(
    () => {
      const merged = new Set([
        ...allowedPorts(),
        ...listeningPorts().map((p) => p.port),
      ]);
      return [...merged].sort((a, b) => a - b);
    },
    [],
    {
      equals: (a, b) =>
        a.length === b.length && a.every((v, i) => v === b[i]),
    },
  );

  const getSubPath = (port: number): string => probeSubPath()[port] ?? "/";

  const setPortSubPath = (port: number, value: string) => {
    setProbeSubPath((prev) => ({ ...prev, [port]: value }));
  };

  const handleCopyForward = async (port: number) => {
    const cmd = `blackwall forward ${sandboxId()} ${port}`;
    if (await copyToClipboard(cmd)) {
      setCopiedPort(port);
      window.setTimeout(() => {
        setCopiedPort((prev) => (prev === port ? null : prev));
      }, 1500);
    }
  };

  const handleProbe = async (port: number) => {
    setProbingPort(port);
    try {
      const res = await probeProxyPort(
        sandboxId(),
        port,
        getSubPath(port),
      );
      setProbeResults((prev) => ({ ...prev, [port]: res }));
    } finally {
      setProbingPort((prev) => (prev === port ? null : prev));
    }
  };

  const handleAllowPort = async (port: number, fromForm = false) => {
    if (
      isNetworkNone() ||
      !isRunning() ||
      allowingPort() !== null ||
      closingPort() !== null
    ) {
      return;
    }
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      setIngressError("Port must be an integer between 1 and 65535.");
      return;
    }
    const id = sandboxId();
    setAllowingPort(port);
    if (fromForm) {
      setAllowFormSubmitting(true);
    }
    setIngressError(null);
    try {
      const updated = await allowIngressPort(id, port);
      if (sandboxId() !== id) return;
      setOverrideAllowedPorts(updated);
      setListeningPorts((prev) =>
        prev.map((lp) => (lp.port === port ? { ...lp, allowed: true } : lp)),
      );
      if (fromForm) {
        setAllowPortInput("");
      }
      await scanPorts(id);
      props.onActivity?.();
    } catch (err) {
      if (sandboxId() !== id) return;
      setIngressError(err instanceof Error ? err.message : String(err));
    } finally {
      setAllowingPort(null);
      if (fromForm) {
        setAllowFormSubmitting(false);
      }
    }
  };

  const handleAllowPortSubmit = async (ev: SubmitEvent) => {
    ev.preventDefault();
    const raw = allowPortInput().trim();
    const port = Number(raw);
    if (!raw || !Number.isInteger(port) || port < 1 || port > 65535) {
      setIngressError("Port must be an integer between 1 and 65535.");
      return;
    }
    await handleAllowPort(port, true);
  };

  const handleClosePort = async (port: number) => {
    if (!isRunning() || closingPort() !== null || allowingPort() !== null) {
      return;
    }
    const id = sandboxId();
    setClosingPort(port);
    setIngressError(null);
    try {
      await closeIngressPort(id, port);
      if (sandboxId() !== id) return;
      setOverrideAllowedPorts(allowedPorts().filter((p) => p !== port));
      setListeningPorts((prev) =>
        prev.map((lp) => (lp.port === port ? { ...lp, allowed: false } : lp)),
      );
      await scanPorts(id);
      props.onActivity?.();
    } catch (err) {
      if (sandboxId() !== id) return;
      setIngressError(err instanceof Error ? err.message : String(err));
    } finally {
      setClosingPort(null);
    }
  };

  const handleAttachBridge = async (ev: SubmitEvent) => {
    ev.preventDefault();
    if (isNetworkNone() || !isRunning() || attachingBridge()) return;

    const guestPort = Number(bridgePortInput().trim());
    const target = bridgeTargetInput().trim();
    const name = bridgeNameInput().trim();

    if (!Number.isInteger(guestPort) || guestPort < 1 || guestPort > 65535) {
      setBridgesError("Guest port must be an integer between 1 and 65535.");
      return;
    }
    if (!target) {
      setBridgesError(
        "Target is required (e.g. 127.0.0.1:5435 or unix:///run/pg.sock).",
      );
      return;
    }

    setAttachingBridge(true);
    setBridgesError(null);
    try {
      const created = await attachHostBridge(sandboxId(), {
        guest_port: guestPort,
        target,
        ...(name ? { name } : {}),
      });
      setFetchedBridges((prev) => {
        const base = prev ?? props.detail.host_services ?? [];
        return [
          ...base.filter((b) => b.guest_port !== created.guest_port),
          created,
        ];
      });
      setBridgePortInput("");
      setBridgeTargetInput("");
      setBridgeNameInput("");
    } catch (err) {
      setBridgesError(err instanceof Error ? err.message : String(err));
    } finally {
      setAttachingBridge(false);
    }
  };

  const handleDetachBridge = async (guestPort: number) => {
    if (!isRunning() || detachingPort() !== null) return;
    setDetachingPort(guestPort);
    setBridgesError(null);
    try {
      await detachHostBridge(sandboxId(), guestPort);
      setFetchedBridges((prev) =>
        (prev ?? props.detail.host_services ?? []).filter(
          (b) => b.guest_port !== guestPort,
        ),
      );
    } catch (err) {
      setBridgesError(err instanceof Error ? err.message : String(err));
    } finally {
      setDetachingPort(null);
    }
  };

  return (
    <div class="stack">
      <div class="panel">
        <div class="panel-header">
          <div class="row-wrap">
            <span class="panel-title">
              <IconGlobe size={13} /> Ingress Ports
            </span>
            <Show when={listeningPorts().length > 0}>
              <span class="pill pill-emerald">
                <span class="dot dot-running" />
                {listeningPorts().length} listening
              </span>
            </Show>
            <Show when={isIsolatedPreview()}>
              <span
                class="pill pill-cyan"
                title={`Previews are served from isolated origin ${getPreviewOrigin()}`}
              >
                isolated preview
              </span>
            </Show>
          </div>
          <div class="row-wrap">
            <button
              type="button"
              class="btn btn-xs"
              onClick={() => {
                void scanPorts();
                props.onActivity?.();
              }}
              disabled={!isRunning() || loadingPorts()}
              title="Scan listening TCP ports inside VM"
            >
              <IconRefresh size={12} class={loadingPorts() ? "spin" : undefined} />
              <span>{loadingPorts() ? "Scanning…" : "Refresh"}</span>
            </button>
            <form class="row" onSubmit={(e) => void handleAllowPortSubmit(e)}>
              <input
                type="number"
                min="1"
                max="65535"
                class="input mono"
                style={{ width: "124px", padding: "4px 8px", "font-size": "11.5px" }}
                placeholder="Port (1-65535)"
                aria-label="Allow ingress port"
                value={allowPortInput()}
                onInput={(e) => setAllowPortInput(e.currentTarget.value)}
                disabled={
                  isNetworkNone() ||
                  !isRunning() ||
                  allowingPort() !== null ||
                  closingPort() !== null
                }
                title={
                  isNetworkNone()
                    ? "Ingress ports are unavailable when network_mode is none"
                    : "Enter a TCP port (1-65535) to allowlist for ingress"
                }
              />
              <button
                type="submit"
                class="btn btn-primary btn-sm"
                disabled={
                  isNetworkNone() ||
                  !isRunning() ||
                  allowingPort() !== null ||
                  closingPort() !== null
                }
                title={
                  isNetworkNone()
                    ? "Ingress ports are unavailable when network_mode is none"
                    : "Allow ingress traffic on this port"
                }
              >
                <IconPlus size={12} />
                <span>
                  {allowFormSubmitting() ? "Allowing…" : "Allow Port"}
                </span>
              </button>
            </form>
          </div>
        </div>

        <div class="panel-body stack">
          <Show when={isNetworkNone()}>
            <div class="banner banner-warn">
              <span>
                Ingress ports are unavailable when{" "}
                <code class="mono">network_mode</code> is{" "}
                <code class="mono">none</code>.
              </span>
            </div>
          </Show>

          <Show when={ingressError()}>
            {(err) => (
              <div class="banner banner-error mono">
                Ingress error: {err()}
              </div>
            )}
          </Show>

          <Show when={portsError()}>
            {(err) => (
              <div class="banner banner-error mono">
                Port scan error: {err()}
              </div>
            )}
          </Show>

          <Show
            when={allDisplayPorts().length > 0}
            fallback={
              <div class="empty-state">
                <IconGlobe size={26} />
                <div class="empty-state-title">
                  {loadingPorts()
                    ? "Scanning listening ports…"
                    : "No listening or allowlisted ports"}
                </div>
                <div style={{ "font-size": "12px" }}>
                  Allow a port above, allowlist ports at sandbox creation, or start a server inside the VM.
                </div>
              </div>
            }
          >
            <div class="stack">
              <For each={allDisplayPorts()}>
                {(port) => {
                  const listening = () => listeningByPort().get(port);
                  const isListening = () => listening() !== undefined;
                  const isAllowed = () =>
                    allowedPorts().includes(port) ||
                    (listening()?.allowed ?? false);
                  const isBlocked = () => isListening() && !isAllowed();
                  const isNonHttpTcp = () => NON_HTTP_TCP_PORTS.has(port);
                  const proxyUrl = () => {
                    const sub = getSubPath(port);
                    const reported = listening()?.proxy_url;
                    if (sub === "/" && reported) {
                      if (/^https?:\/\//i.test(reported)) {
                        return reported;
                      }
                      const origin = getPreviewOrigin();
                      if (origin && reported.startsWith("/")) {
                        return `${origin}${reported}`;
                      }
                      return reported;
                    }
                    return buildProxyUrl(sandboxId(), port, sub);
                  };
                  const forwardCmd = () =>
                    `blackwall forward ${sandboxId()} ${port}`;
                  const probe = () => probeResults()[port];

                  return (
                    <div class="panel" style={{ background: "var(--bg-inset)" }}>
                      <div class="panel-header">
                        <div class="row-wrap">
                          <span
                            class="mono"
                            style={{ "font-weight": 700, "font-size": "13.5px" }}
                          >
                            {formatBindEndpoint(port, listening()?.address)}
                          </span>

                          <Show
                            when={isListening()}
                            fallback={
                              <span class="pill">
                                <span class="dot dot-muted" />
                                not listening
                              </span>
                            }
                          >
                            <span class="pill pill-emerald">
                              <span class="dot dot-running" />
                              listening
                            </span>
                          </Show>

                          <Show when={isNonHttpTcp()}>
                            <span
                              class="pill pill-cyan"
                              title="Non-HTTP TCP service — use blackwall forward CLI tunnel"
                            >
                              TCP
                            </span>
                          </Show>

                          <Show
                            when={isAllowed()}
                            fallback={
                              <Show when={isBlocked()}>
                                <span
                                  class="pill pill-crimson"
                                  title="Bound inside VM but not in ingress_allow_ports"
                                >
                                  blocked
                                </span>
                              </Show>
                            }
                          >
                            <span class="pill pill-emerald">allowlisted</span>
                          </Show>
                        </div>
                        <div class="row">
                          <Show when={isBlocked()}>
                            <button
                              type="button"
                              class="btn btn-primary btn-sm"
                              onClick={() => void handleAllowPort(port)}
                              disabled={
                                isNetworkNone() ||
                                !isRunning() ||
                                allowingPort() !== null ||
                                closingPort() !== null
                              }
                              title={
                                isNetworkNone()
                                  ? "Ingress ports are unavailable when network_mode is none"
                                  : `Allow ingress traffic on port ${port}`
                              }
                            >
                              <IconPlus size={12} />
                              <span>
                                {allowingPort() === port ? "Allowing…" : "Allow"}
                              </span>
                            </button>
                          </Show>

                          <Show when={!isNonHttpTcp()}>
                            <a
                              href={proxyUrl()}
                              target="_blank"
                              rel="noopener noreferrer"
                              class={`btn btn-sm ${isBlocked() ? "" : "btn-primary"}`}
                              style={{ "text-decoration": "none" }}
                            >
                              <IconExternalLink size={12} />
                              <span>Open</span>
                            </a>
                            <Show when={!isIsolatedPreview()}>
                              <button
                                type="button"
                                class="btn btn-sm"
                                onClick={() => void handleProbe(port)}
                                disabled={probingPort() === port}
                              >
                                <IconZap size={12} />
                                <span>
                                  {probingPort() === port ? "Probing…" : "Probe"}
                                </span>
                              </button>
                            </Show>
                          </Show>

                          <Show when={isAllowed()}>
                            <button
                              type="button"
                              class="btn btn-danger btn-sm"
                              onClick={() => void handleClosePort(port)}
                              disabled={
                                !isRunning() ||
                                closingPort() !== null ||
                                allowingPort() !== null
                              }
                              title={`Remove port ${port} from ingress allowlist`}
                            >
                              <IconX size={12} />
                              <span>
                                {closingPort() === port ? "Closing…" : "Close"}
                              </span>
                            </button>
                          </Show>
                        </div>
                      </div>

                      <div class="panel-body stack" style={{ gap: "10px" }}>
                        <Show when={isBlocked()}>
                          <div class="banner banner-warn">
                            <span>
                              Port <code class="mono">{port}</code> is bound inside the VM but not allowlisted in{" "}
                              <code class="mono">ingress.allow_ports</code>. Click{" "}
                              <strong>Allow</strong> to expose it.
                            </span>
                          </div>
                        </Show>

                        <Show
                          when={!isNonHttpTcp()}
                          fallback={
                            <div class="field">
                              <span class="kv-label">CLI Tunnel</span>
                              <div class="row">
                                <code
                                  class="mono truncate"
                                  style={{
                                    "font-size": "11.5px",
                                    color: "var(--text-primary)",
                                  }}
                                >
                                  {forwardCmd()}
                                </code>
                                <button
                                  type="button"
                                  class="btn btn-xs"
                                  onClick={() => void handleCopyForward(port)}
                                  title="Copy blackwall forward command"
                                >
                                  <Show
                                    when={copiedPort() === port}
                                    fallback={<IconCopy size={11} />}
                                  >
                                    <IconCheck size={11} />
                                  </Show>
                                </button>
                              </div>
                            </div>
                          }
                        >
                          <div class="grid-2">
                            <div class="field">
                              <span class="kv-label">Proxy URL</span>
                              <div class="row">
                                <span
                                  class="mono truncate"
                                  style={{
                                    "font-size": "11.5px",
                                    color: "var(--cyan)",
                                  }}
                                  title={proxyUrl()}
                                >
                                  {proxyUrl()}
                                </span>
                              </div>
                            </div>

                            <div class="field">
                              <span class="kv-label">CLI Tunnel</span>
                              <div class="row">
                                <code
                                  class="mono truncate"
                                  style={{
                                    "font-size": "11.5px",
                                    color: "var(--text-primary)",
                                  }}
                                >
                                  {forwardCmd()}
                                </code>
                                <button
                                  type="button"
                                  class="btn btn-xs"
                                  onClick={() => void handleCopyForward(port)}
                                  title="Copy blackwall forward command"
                                >
                                  <Show
                                    when={copiedPort() === port}
                                    fallback={<IconCopy size={11} />}
                                  >
                                    <IconCheck size={11} />
                                  </Show>
                                </button>
                              </div>
                            </div>
                          </div>

                          <div class="row">
                            <span class="kv-label" style={{ "white-space": "nowrap" }}>
                              {isIsolatedPreview() ? "Preview Path:" : "Probe Path:"}
                            </span>
                            <input
                              type="text"
                              class="input mono"
                              style={{
                                "max-width": "260px",
                                padding: "4px 8px",
                                "font-size": "11.5px",
                              }}
                              value={getSubPath(port)}
                              onInput={(e) =>
                                setPortSubPath(port, e.currentTarget.value)
                              }
                            />
                          </div>

                          <Show when={!isIsolatedPreview() ? probe() : undefined}>
                            {(result) => (
                              <div
                                class={`banner ${
                                  result().ok ? "banner-ok" : "banner-error"
                                }`}
                                style={{ "flex-direction": "column" }}
                              >
                                <div class="row-wrap">
                                  <span class="mono" style={{ "font-weight": 700 }}>
                                    HTTP {result().status || "ERR"} {result().statusText}
                                  </span>
                                  <span class="pill">{result().latencyMs}ms</span>
                                  <Show when={result().contentType}>
                                    <span class="pill">{result().contentType}</span>
                                  </Show>
                                </div>
                                <Show when={result().error}>
                                  {(e) => (
                                    <div class="mono" style={{ "font-size": "11.5px" }}>
                                      {e()}
                                    </div>
                                  )}
                                </Show>
                                <Show when={result().bodyPreview}>
                                  <pre
                                    class="code-block"
                                    style={{
                                      width: "100%",
                                      "max-height": "140px",
                                      "margin-top": "6px",
                                    }}
                                  >
                                    {result().bodyPreview}
                                  </pre>
                                </Show>
                              </div>
                            )}
                          </Show>
                        </Show>
                      </div>
                    </div>
                  );
                }}
              </For>
            </div>
          </Show>
        </div>
      </div>

      {/* Host Service Bridges (Guest → Host) */}
      <div class="panel">
        <div class="panel-header">
          <div class="row-wrap">
            <span class="panel-title">
              <IconZap size={13} /> Host Service Bridges (Guest → Host)
            </span>
            <Show when={activeBridges().length > 0}>
              <span class="pill pill-emerald">
                <span class="dot dot-running" />
                {activeBridges().length} active
              </span>
            </Show>
          </div>
          <div class="row-wrap">
            <button
              type="button"
              class="btn btn-xs"
              onClick={() => void loadBridges()}
              disabled={!isRunning() || loadingBridges()}
              title="Refresh active host service bridges"
            >
              <IconRefresh
                size={12}
                class={loadingBridges() ? "spin" : undefined}
              />
              <span>{loadingBridges() ? "Loading…" : "Refresh"}</span>
            </button>
          </div>
        </div>

        <div class="panel-body stack">
          <Show when={isNetworkNone()}>
            <div class="banner banner-warn">
              <span>
                Host service bridges are unavailable when{" "}
                <code class="mono">network_mode</code> is{" "}
                <code class="mono">none</code>. Use{" "}
                <code class="mono">loopback</code> or{" "}
                <code class="mono">egress</code> to bridge host services into the
                VM.
              </span>
            </div>
          </Show>

          <Show when={bridgesError()}>
            {(err) => (
              <div class="banner banner-error mono">
                Host bridge error: {err()}
              </div>
            )}
          </Show>

          <Show
            when={activeBridges().length > 0}
            fallback={
              <div
                style={{
                  color: "var(--text-muted)",
                  "font-size": "12px",
                  padding: "6px 0",
                }}
              >
                {loadingBridges()
                  ? "Loading host service bridges…"
                  : "No active host service bridges. Attach a bridge below to expose a host TCP port or Unix socket on guest loopback."}
              </div>
            }
          >
            <table class="data-table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Inside VM</th>
                  <th>Host Target</th>
                  <th style={{ width: "90px", "text-align": "right" }}>
                    Action
                  </th>
                </tr>
              </thead>
              <tbody>
                <For each={activeBridges()}>
                  {(svc) => (
                    <tr>
                      <td class="mono" style={{ "font-weight": 600 }}>
                        {svc.name}
                      </td>
                      <td class="mono" style={{ color: "var(--cyan)" }}>
                        127.0.0.1:{svc.guest_port}
                      </td>
                      <td class="mono">→ {svc.target}</td>
                      <td style={{ "text-align": "right" }}>
                        <button
                          type="button"
                          class="btn btn-danger btn-xs"
                          onClick={() => void handleDetachBridge(svc.guest_port)}
                          disabled={
                            !isRunning() || detachingPort() !== null
                          }
                          title={`Detach host service bridge on guest port ${svc.guest_port}`}
                        >
                          <IconTrash size={11} />
                          <span>
                            {detachingPort() === svc.guest_port
                              ? "Detaching…"
                              : "Detach"}
                          </span>
                        </button>
                      </td>
                    </tr>
                  )}
                </For>
              </tbody>
            </table>
          </Show>

          <form
            class="row-wrap"
            style={{
              gap: "8px",
              "padding-top": "8px",
              "border-top": "1px solid var(--border-subtle, var(--border))",
              "align-items": "center",
            }}
            onSubmit={(e) => void handleAttachBridge(e)}
          >
            <input
              type="number"
              min="1"
              max="65535"
              class="input mono"
              style={{
                width: "110px",
                padding: "5px 8px",
                "font-size": "11.5px",
              }}
              placeholder="Guest Port"
              aria-label="Guest Port"
              value={bridgePortInput()}
              onInput={(e) => setBridgePortInput(e.currentTarget.value)}
              disabled={isNetworkNone() || !isRunning() || attachingBridge()}
            />
            <input
              type="text"
              class="input mono"
              style={{
                flex: "1 1 240px",
                padding: "5px 8px",
                "font-size": "11.5px",
              }}
              placeholder="127.0.0.1:5435 or unix:///run/pg.sock"
              aria-label="Target"
              value={bridgeTargetInput()}
              onInput={(e) => setBridgeTargetInput(e.currentTarget.value)}
              disabled={isNetworkNone() || !isRunning() || attachingBridge()}
            />
            <input
              type="text"
              class="input mono"
              style={{
                width: "150px",
                padding: "5px 8px",
                "font-size": "11.5px",
              }}
              placeholder="Name (optional)"
              aria-label="Name (optional)"
              value={bridgeNameInput()}
              onInput={(e) => setBridgeNameInput(e.currentTarget.value)}
              disabled={isNetworkNone() || !isRunning() || attachingBridge()}
            />
            <button
              type="submit"
              class="btn btn-primary btn-sm"
              disabled={isNetworkNone() || !isRunning() || attachingBridge()}
            >
              <IconPlus size={12} />
              <span>{attachingBridge() ? "Attaching…" : "Attach Bridge"}</span>
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}
