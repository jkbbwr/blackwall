import {
  batch,
  createEffect,
  createSignal,
  ErrorBoundary,
  For,
  Match,
  onCleanup,
  onMount,
  Show,
  Switch,
} from "solid-js";
import { createStore, reconcile } from "solid-js/store";
import {
  ApiError,
  deleteSandbox,
  getAuthStatus,
  getSandbox,
  listImages,
  listProfiles,
  listSandboxes,
  loginWithToken,
  setPreviewOrigin,
  setUnauthorizedHandler,
} from "./api/client";
import type {
  AuthStatus,
  BuiltImage,
  SandboxDetail,
  SandboxRunStats,
  SandboxSummary,
} from "./api/types";
import { AuditLogPanel } from "./components/AuditLogPanel";
import { CreateSandboxModal } from "./components/CreateSandboxModal";
import { IconLock, IconMenu } from "./components/Icons";
import { ImagesView } from "./components/ImagesView";
import { ProfilesView } from "./components/ProfilesView";
import {
  type DetailTab,
  SandboxDetailView,
} from "./components/SandboxDetailView";
import { SandboxOverview } from "./components/SandboxOverview";
import { type NavSection, Sidebar } from "./components/Sidebar";

interface Toast {
  id: number;
  kind: "ok" | "error";
  message: string;
}

const VALID_DETAIL_TABS = new Set<DetailTab>([
  "overview",
  "exec",
  "terminal",
  "processes",
  "files",
  "ingress",
  "logs",
]);

interface ParsedRoute {
  section: NavSection;
  sandboxId: string | null;
  tab: DetailTab;
}

function parseHash(rawHash: string): ParsedRoute {
  const cleaned = rawHash.replace(/^#\/?/, "").replace(/\/+$/, "");
  if (!cleaned) {
    return { section: "sandboxes", sandboxId: null, tab: "overview" };
  }
  const parts = cleaned.split("/").map((part) => {
    try {
      return decodeURIComponent(part);
    } catch {
      return part;
    }
  });
  const head = parts[0];
  if (head === "logs" || head === "profiles" || head === "images") {
    return { section: head, sandboxId: null, tab: "overview" };
  }
  if (head === "sandboxes") {
    if (parts.length >= 2 && parts[1]) {
      const candidateTab = parts[2] as DetailTab | undefined;
      const tab: DetailTab =
        candidateTab && VALID_DETAIL_TABS.has(candidateTab)
          ? candidateTab
          : "overview";
      return { section: "sandboxes", sandboxId: parts[1], tab };
    }
    return { section: "sandboxes", sandboxId: null, tab: "overview" };
  }
  return { section: "sandboxes", sandboxId: null, tab: "overview" };
}

function buildHash(
  section: NavSection,
  sandboxId: string | null,
  tab: DetailTab,
): string {
  if (sandboxId) {
    const encodedId = encodeURIComponent(sandboxId);
    return tab === "overview"
      ? `#/sandboxes/${encodedId}`
      : `#/sandboxes/${encodedId}/${tab}`;
  }
  return `#/${section}`;
}

export function App() {
  let nextToastId = 1;
  let pollController: AbortController | null = null;
  let authController: AbortController | null = null;
  let fleetPoller: number | null = null;
  let hasCompletedInitialFetch = false;

  const initialRoute = parseHash(window.location.hash);

  const [authChecked, setAuthChecked] = createSignal(false);
  const [authRequired, setAuthRequired] = createSignal(false);
  const [authStatus, setAuthStatus] = createSignal<AuthStatus | null>(null);
  const [tokenInput, setTokenInput] = createSignal("");
  const [authError, setAuthError] = createSignal<string | null>(null);
  const [unlocking, setUnlocking] = createSignal(false);

  const [section, setSection] = createSignal<NavSection>(initialRoute.section);
  const [selectedSandboxId, setSelectedSandboxId] = createSignal<string | null>(
    initialRoute.sandboxId,
  );
  const [detailTab, setDetailTab] = createSignal<DetailTab>(initialRoute.tab);
  const [mobileNavOpen, setMobileNavOpen] = createSignal(false);

  const [sandboxStore, setSandboxStore] = createStore<{
    items: SandboxSummary[];
  }>({ items: [] });
  const [statsById, setStatsById] = createSignal<
    Record<string, SandboxRunStats>
  >({});
  const [profiles, setProfiles] = createSignal<string[]>(["base"]);
  const [images, setImages] = createSignal<BuiltImage[]>([]);
  const [imagesError, setImagesError] = createSignal<string | null>(null);

  const [daemonOnline, setDaemonOnline] = createSignal(false);
  const [daemonLatencyMs, setDaemonLatencyMs] = createSignal<number | null>(
    null,
  );
  const [daemonError, setDaemonError] = createSignal<string | null>(null);
  const [refreshing, setRefreshing] = createSignal(false);

  const [createModalOpen, setCreateModalOpen] = createSignal(false);
  const [createInitialProfile, setCreateInitialProfile] = createSignal<
    string | undefined
  >(undefined);

  const [toasts, setToasts] = createSignal<Toast[]>([]);

  // Keep URL hash in sync with navigation state without spamming history
  createEffect(() => {
    const currentSection = section();
    const currentSandboxId = selectedSandboxId();
    const currentTab = detailTab();
    const parsed = parseHash(window.location.hash);
    if (
      parsed.section === currentSection &&
      parsed.sandboxId === currentSandboxId &&
      parsed.tab === currentTab
    ) {
      return;
    }
    const nextHash = buildHash(currentSection, currentSandboxId, currentTab);
    if (window.location.hash !== nextHash) {
      window.location.hash = nextHash;
    }
  });

  const pushToast = (kind: "ok" | "error", message: string) => {
    const id = nextToastId++;
    setToasts((prev) => [...prev.slice(-3), { id, kind, message }]);
    window.setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, 4000);
  };

  const refreshFleetStats = async (
    list: SandboxSummary[],
    signal: AbortSignal,
  ) => {
    // Hydrate SandboxRunStats for active sandboxes so overview telemetry stays accurate
    const active = list.slice(0, 12);
    const results = await Promise.allSettled(
      active.map((sb) => getSandbox(sb.id, signal)),
    );
    const nextStats: Record<string, SandboxRunStats> = {};
    for (const r of results) {
      if (r.status === "fulfilled" && r.value.stats) {
        nextStats[r.value.id] = r.value.stats;
      }
    }
    if (!signal.aborted) {
      setStatsById(nextStats);
    }
  };

  const stopPolling = () => {
    if (fleetPoller !== null) {
      window.clearInterval(fleetPoller);
      fleetPoller = null;
    }
    pollController?.abort();
    pollController = null;
  };

  const startPolling = () => {
    if (fleetPoller !== null) {
      window.clearInterval(fleetPoller);
    }
    fleetPoller = window.setInterval(() => {
      void refreshAll(false);
    }, 3500);
  };

  const enterAuthRequired = () => {
    stopPolling();
    batch(() => {
      setAuthStatus(null);
      setAuthRequired(true);
      setAuthChecked(true);
      setRefreshing(false);
      setDaemonOnline(false);
      setDaemonLatencyMs(null);
      setDaemonError(null);
    });
  };

  const refreshAll = async (includeMetadata = false) => {
    if (authRequired()) {
      return;
    }
    pollController?.abort();
    const controller = new AbortController();
    pollController = controller;

    setRefreshing(true);
    const t0 = performance.now();
    try {
      const sbList = await listSandboxes(controller.signal);
      if (controller.signal.aborted) {
        return;
      }
      const latency = Math.round(performance.now() - t0);
      setSandboxStore("items", reconcile(sbList, { key: "id" }));
      setDaemonOnline(true);
      setDaemonLatencyMs(latency);
      setDaemonError(null);
      hasCompletedInitialFetch = true;

      // Clear selection only after the initial fetch confirms the sandbox disappeared
      const currentSelected = selectedSandboxId();
      if (
        hasCompletedInitialFetch &&
        currentSelected &&
        !sbList.some((item) => item.id === currentSelected)
      ) {
        batch(() => {
          setSelectedSandboxId(null);
          setDetailTab("overview");
        });
      }

      // Hydrate fleet metrics when on overview
      if (!selectedSandboxId() && section() === "sandboxes") {
        void refreshFleetStats(sbList, controller.signal);
      }

      if (includeMetadata) {
        const [profRes, imgRes] = await Promise.allSettled([
          listProfiles(controller.signal),
          listImages(controller.signal),
        ]);
        if (
          (profRes.status === "rejected" &&
            profRes.reason instanceof ApiError &&
            profRes.reason.status === 401) ||
          (imgRes.status === "rejected" &&
            imgRes.reason instanceof ApiError &&
            imgRes.reason.status === 401)
        ) {
          enterAuthRequired();
          return;
        }
        if (profRes.status === "fulfilled") {
          setProfiles(profRes.value.length > 0 ? profRes.value : ["base"]);
        }
        if (imgRes.status === "fulfilled") {
          setImages(imgRes.value);
          setImagesError(null);
        } else {
          setImagesError(
            imgRes.reason instanceof Error
              ? imgRes.reason.message
              : String(imgRes.reason),
          );
        }
      }
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") {
        return;
      }
      if (err instanceof ApiError && err.status === 401) {
        enterAuthRequired();
        return;
      }
      setDaemonOnline(false);
      setDaemonLatencyMs(null);
      setDaemonError(err instanceof Error ? err.message : String(err));
    } finally {
      if (pollController === controller) {
        setRefreshing(false);
      }
    }
  };

  const handleUnlockSubmit = async (ev: SubmitEvent) => {
    ev.preventDefault();
    const token = tokenInput().trim();
    if (!token || unlocking()) {
      return;
    }
    setUnlocking(true);
    setAuthError(null);
    try {
      const status = await loginWithToken(token);
      setPreviewOrigin(status.preview_origin);
      if (status.authenticated) {
        batch(() => {
          setAuthStatus(status);
          setTokenInput("");
          setAuthError(null);
          setAuthRequired(false);
          setAuthChecked(true);
        });
        void refreshAll(true);
        startPolling();
      } else {
        setAuthError("Authentication failed. Verify your daemon token.");
      }
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        setAuthError(err.message || "Invalid daemon token.");
      } else {
        setAuthError(err instanceof Error ? err.message : String(err));
      }
    } finally {
      setUnlocking(false);
    }
  };

  const handleDestroySandbox = async (id: string) => {
    try {
      await deleteSandbox(id);
      pushToast("ok", `Destroyed sandbox ${id.slice(0, 12)}`);
      if (selectedSandboxId() === id) {
        batch(() => {
          setSelectedSandboxId(null);
          setDetailTab("overview");
        });
      }
      await refreshAll(false);
    } catch (err) {
      pushToast(
        "error",
        `Failed to destroy sandbox: ${err instanceof Error ? err.message : String(err)}`,
      );
      throw err;
    }
  };

  const handleSandboxCreated = (sb: SandboxSummary) => {
    setCreateModalOpen(false);
    setCreateInitialProfile(undefined);
    pushToast("ok", `Booted sandbox ${sb.id.slice(0, 12)} (${sb.profile})`);
    batch(() => {
      setSection("sandboxes");
      setDetailTab("overview");
      setSelectedSandboxId(sb.id);
    });
    void refreshAll(false);
  };

  const handleDetailLoaded = (detail: SandboxDetail) => {
    if (detail.stats) {
      const s = detail.stats;
      setStatsById((prev) => ({ ...prev, [detail.id]: s }));
    }
  };

  onMount(() => {
    if (!window.location.hash) {
      window.history.replaceState(
        null,
        "",
        buildHash(section(), selectedSandboxId(), detailTab()),
      );
    }

    setUnauthorizedHandler(() => {
      enterAuthRequired();
    });

    const bootstrapAuth = async () => {
      authController?.abort();
      const controller = new AbortController();
      authController = controller;
      try {
        const status = await getAuthStatus(controller.signal);
        if (controller.signal.aborted) return;
        setPreviewOrigin(status.preview_origin);
        if (status.authenticated) {
          batch(() => {
            setAuthStatus(status);
            setAuthRequired(false);
            setAuthChecked(true);
          });
          void refreshAll(true);
          startPolling();
        } else {
          enterAuthRequired();
        }
      } catch (err) {
        if (err instanceof DOMException && err.name === "AbortError") {
          return;
        }
        if (err instanceof ApiError && err.status === 401) {
          enterAuthRequired();
          return;
        }
        batch(() => {
          setAuthRequired(false);
          setAuthChecked(true);
          setDaemonOnline(false);
          setDaemonError(err instanceof Error ? err.message : String(err));
        });
        startPolling();
      }
    };

    void bootstrapAuth();

    const onHashChange = () => {
      const next = parseHash(window.location.hash);
      batch(() => {
        setSection(next.section);
        setSelectedSandboxId(next.sandboxId);
        setDetailTab(next.tab);
      });
      if (
        !authRequired() &&
        authChecked() &&
        (next.section === "profiles" || next.section === "images")
      ) {
        void refreshAll(true);
      }
    };
    window.addEventListener("hashchange", onHashChange);

    const onKeyDown = (ev: KeyboardEvent) => {
      if (ev.key === "Escape") {
        if (createModalOpen()) {
          setCreateModalOpen(false);
        } else if (mobileNavOpen()) {
          setMobileNavOpen(false);
        }
      }
    };
    window.addEventListener("keydown", onKeyDown);

    onCleanup(() => {
      setUnauthorizedHandler(null);
      stopPolling();
      authController?.abort();
      authController = null;
      window.removeEventListener("hashchange", onHashChange);
      window.removeEventListener("keydown", onKeyDown);
    });
  });

  return (
    <ErrorBoundary
      fallback={(err, reset) => (
        <div
          style={{
            padding: "32px",
            "max-width": "640px",
            margin: "48px auto",
          }}
        >
          <div class="panel">
            <div class="panel-header">
              <span class="panel-title" style={{ color: "var(--crimson)" }}>
                Dashboard Runtime Error
              </span>
            </div>
            <div class="panel-body stack">
              <pre class="code-block">{String(err)}</pre>
              <div>
                <button type="button" class="btn btn-primary" onClick={reset}>
                  Reload Control Plane
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    >
      <Switch>
        <Match when={!authChecked()}>
          <div class="auth-screen">
            <div class="row" style={{ gap: "10px", color: "var(--text-muted)" }}>
              <div class="brand-logo">BW</div>
              <span class="mono" style={{ "font-size": "12px" }}>
                Connecting to blackwall-daemon…
              </span>
            </div>
          </div>
        </Match>

        <Match when={authRequired()}>
          <div class="auth-screen">
            <div class="panel auth-card">
              <div class="auth-header">
                <div class="brand-mark">
                  <div class="brand-logo">BW</div>
                  <div>
                    <div class="brand-title">BLACKWALL</div>
                    <div class="brand-sub">Unlock Blackwall</div>
                  </div>
                </div>
                <span class="pill">
                  <IconLock size={11} />
                  <span>Auth Required</span>
                </span>
              </div>
              <form class="auth-body" onSubmit={(e) => void handleUnlockSubmit(e)}>
                <p class="auth-hint">
                  Open the URL printed by <code class="mono">blackwall-daemon</code>, or paste the token from{" "}
                  <code class="mono">$XDG_RUNTIME_DIR/blackwall-http.token</code>
                </p>

                <div class="field">
                  <label class="field-label" for="bw-unlock-token">
                    Daemon Token
                  </label>
                  <input
                    id="bw-unlock-token"
                    type="password"
                    class="input mono"
                    placeholder="Paste per-boot daemon token…"
                    autocomplete="current-password"
                    autofocus
                    value={tokenInput()}
                    onInput={(e) => setTokenInput(e.currentTarget.value)}
                    disabled={unlocking()}
                  />
                </div>

                <Show when={authError()}>
                  {(err) => (
                    <div class="banner banner-error mono">{err()}</div>
                  )}
                </Show>

                <button
                  type="submit"
                  class="btn btn-primary btn-full"
                  disabled={unlocking() || tokenInput().trim().length === 0}
                >
                  <IconLock size={13} />
                  <span>{unlocking() ? "Unlocking…" : "Unlock"}</span>
                </button>
              </form>
            </div>
          </div>
        </Match>

        <Match when={authChecked() && !authRequired()}>
          <div class="app-shell">
        <Show when={mobileNavOpen()}>
          <div
            class="sidebar-backdrop"
            onClick={() => setMobileNavOpen(false)}
          />
        </Show>

        <Sidebar
          activeSection={section()}
          selectedSandboxId={selectedSandboxId()}
          sandboxes={sandboxStore.items}
          profileCount={profiles().length}
          imageCount={images().length}
          daemonOnline={daemonOnline()}
          daemonLatencyMs={daemonLatencyMs()}
          daemonError={daemonError()}
          refreshing={refreshing()}
          role={authStatus()?.role}
          policyLocked={Boolean(
            authStatus()?.readonly_profiles ||
              authStatus()?.require_locked_profiles ||
              authStatus()?.has_policy_ceiling,
          )}
          mobileOpen={mobileNavOpen()}
          onCloseMobile={() => setMobileNavOpen(false)}
          onSelectSection={(next) => {
            batch(() => {
              setSection(next);
              setSelectedSandboxId(null);
              setDetailTab("overview");
            });
            if (next === "profiles" || next === "images") {
              void refreshAll(true);
            }
          }}
          onSelectSandbox={(id) => {
            batch(() => {
              setSection("sandboxes");
              setDetailTab("overview");
              setSelectedSandboxId(id);
            });
          }}
          onOpenCreateModal={() => {
            setCreateInitialProfile(undefined);
            setCreateModalOpen(true);
          }}
          onRefresh={() => void refreshAll(true)}
        />

        <main class="main-viewport">
          <div class="mobile-topbar">
            <button
              type="button"
              class="btn btn-ghost btn-sm mobile-menu-btn"
              aria-label="Open navigation"
              onClick={() => setMobileNavOpen(true)}
            >
              <IconMenu size={16} />
            </button>
            <div class="row" style={{ gap: "8px" }}>
              <div
                class="brand-logo"
                style={{
                  width: "22px",
                  height: "22px",
                  "font-size": "10px",
                }}
              >
                BW
              </div>
              <span class="brand-title">BLACKWALL</span>
            </div>
            <span
              class={daemonOnline() ? "dot dot-running" : "dot dot-error"}
              title={daemonOnline() ? "Daemon online" : "Daemon offline"}
            />
          </div>

          <Switch>
            <Match when={selectedSandboxId()}>
              {(id) => (
                <SandboxDetailView
                  sandboxId={id()}
                  initialTab={detailTab()}
                  onTabChange={(tab) => setDetailTab(tab)}
                  onBack={() => {
                    batch(() => {
                      setSelectedSandboxId(null);
                      setDetailTab("overview");
                    });
                  }}
                  onDestroy={handleDestroySandbox}
                  onDetailLoaded={handleDetailLoaded}
                />
              )}
            </Match>

            <Match when={section() === "logs"}>
              <header class="page-header">
                <div class="page-title-group">
                  <div>
                    <h1 class="page-title">Proxy &amp; Logs</h1>
                    <div class="page-subtitle">
                      Live proxy, DNS, ingress, and sandbox events
                    </div>
                  </div>
                </div>
              </header>
              <div class="page-scroll">
                <AuditLogPanel
                  onSelectSandbox={(id) => {
                    batch(() => {
                      setSection("sandboxes");
                      setDetailTab("overview");
                      setSelectedSandboxId(id);
                    });
                  }}
                />
              </div>
            </Match>

            <Match when={section() === "profiles"}>
              <ProfilesView
                profiles={profiles()}
                readonlyProfiles={authStatus()?.readonly_profiles ?? false}
                onRefresh={() => refreshAll(true)}
                onLaunchFromProfile={(profileName) => {
                  setCreateInitialProfile(profileName);
                  setCreateModalOpen(true);
                }}
                onNotify={pushToast}
              />
            </Match>

            <Match when={section() === "images"}>
              <ImagesView
                images={images()}
                sandboxes={sandboxStore.items}
                profiles={profiles()}
                allowImageBuild={authStatus()?.allow_image_build ?? true}
                loading={refreshing()}
                error={imagesError()}
                onRefresh={() => refreshAll(true)}
                onSelectSandbox={(id) => {
                  batch(() => {
                    setSection("sandboxes");
                    setDetailTab("overview");
                    setSelectedSandboxId(id);
                  });
                }}
                onNotify={pushToast}
              />
            </Match>

            <Match when={section() === "sandboxes"}>
              <SandboxOverview
                sandboxes={sandboxStore.items}
                statsById={statsById()}
                loading={refreshing()}
                onInspect={(id, tab) => {
                  batch(() => {
                    setSection("sandboxes");
                    setDetailTab(tab ?? "overview");
                    setSelectedSandboxId(id);
                  });
                }}
                onDestroy={handleDestroySandbox}
                onOpenCreate={() => {
                  setCreateInitialProfile(undefined);
                  setCreateModalOpen(true);
                }}
                onRefresh={() => void refreshAll(true)}
              />
            </Match>
          </Switch>
        </main>
      </div>

      <Show when={createModalOpen()}>
        <CreateSandboxModal
          profiles={profiles()}
          initialProfile={createInitialProfile()}
          onClose={() => {
            setCreateModalOpen(false);
            setCreateInitialProfile(undefined);
          }}
          onCreated={handleSandboxCreated}
        />
      </Show>
        </Match>
      </Switch>

      <Show when={toasts().length > 0}>
        <div class="toast-container" aria-live="polite">
          <For each={toasts()}>
            {(t) => (
              <div class={`toast ${t.kind === "ok" ? "toast-ok" : "toast-error"}`}>
                <span
                  class={`dot ${t.kind === "ok" ? "dot-running" : "dot-error"}`}
                />
                <span class="mono">{t.message}</span>
              </div>
            )}
          </For>
        </div>
      </Show>
    </ErrorBoundary>
  );
}
