import { createEffect, createMemo, createSignal, For, Show } from "solid-js";
import { buildImage, deleteImage } from "../api/client";
import type { BuiltImage, SandboxSummary } from "../api/types";
import { copyToClipboard, formatBytes, shortHash, shortId } from "../utils/format";
import {
  IconCheck,
  IconCopy,
  IconCube,
  IconDisc,
  IconLock,
  IconPlus,
  IconRefresh,
  IconShield,
  IconTrash,
} from "./Icons";

export interface ImagesViewProps {
  images: BuiltImage[];
  sandboxes: SandboxSummary[];
  profiles: string[];
  allowImageBuild?: boolean;
  loading: boolean;
  error: string | null;
  onRefresh: () => Promise<void> | void;
  onSelectSandbox: (id: string) => void;
  onNotify?: (kind: "ok" | "error", message: string) => void;
}

export function ImagesView(props: ImagesViewProps) {
  const [copiedKey, setCopiedKey] = createSignal<string | null>(null);

  // Build bar state
  const [buildMode, setBuildMode] = createSignal<"oci" | "profile">("oci");
  const [ociRefInput, setOciRefInput] = createSignal("");
  const [selectedProfile, setSelectedProfile] = createSignal(
    props.profiles[0] ?? "base",
  );
  const [building, setBuilding] = createSignal(false);
  const [buildError, setBuildError] = createSignal<string | null>(null);

  // Delete state
  const [confirmDeleteHash, setConfirmDeleteHash] = createSignal<string | null>(
    null,
  );
  const [deletingHash, setDeletingHash] = createSignal<string | null>(null);
  const [deleteError, setDeleteError] = createSignal<string | null>(null);

  createEffect(() => {
    const list = props.profiles;
    if (list.length > 0 && !list.includes(selectedProfile())) {
      setSelectedProfile(list[0] ?? "base");
    }
  });

  const totalFootprintBytes = createMemo(() =>
    props.images.reduce(
      (sum, img) => sum + img.verity.data_blocks * img.verity.data_block_size,
      0,
    ),
  );

  const handleCopy = async (key: string, value: string) => {
    if (await copyToClipboard(value)) {
      setCopiedKey(key);
      window.setTimeout(() => {
        setCopiedKey((prev) => (prev === key ? null : prev));
      }, 1600);
    }
  };

  const handleBuildImage = async (ev: SubmitEvent) => {
    ev.preventDefault();
    if (building()) return;

    const mode = buildMode();
    if (mode === "oci" && ociRefInput().trim().length === 0) return;

    setBuilding(true);
    setBuildError(null);
    try {
      const targetLabel =
        mode === "oci" ? ociRefInput().trim() : `profile:${selectedProfile()}`;
      const built = await buildImage(
        mode === "oci"
          ? { oci_ref: ociRefInput().trim() }
          : { profile: selectedProfile() },
      );
      if (mode === "oci") {
        setOciRefInput("");
      }
      props.onNotify?.(
        "ok",
        `Built image ${shortHash(built.content_hash, 12)} (${targetLabel})`,
      );
      await props.onRefresh();
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setBuildError(msg);
      props.onNotify?.("error", `Image build failed: ${msg}`);
    } finally {
      setBuilding(false);
    }
  };

  const handleDeleteImage = async (contentHash: string) => {
    if (deletingHash()) return;
    setDeletingHash(contentHash);
    setDeleteError(null);
    try {
      await deleteImage(contentHash);
      setConfirmDeleteHash(null);
      props.onNotify?.(
        "ok",
        `Deleted image ${shortHash(contentHash, 12)}`,
      );
      await props.onRefresh();
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setDeleteError(msg);
      props.onNotify?.("error", `Failed to delete image: ${msg}`);
    } finally {
      setDeletingHash(null);
    }
  };

  return (
    <>
      <header class="page-header">
        <div class="page-title-group">
          <h1 class="page-title">Images</h1>
          <Show when={props.allowImageBuild === false}>
            <span class="pill pill-amber">
              <IconLock size={11} /> Builds locked
            </span>
          </Show>
        </div>
        <div class="toolbar-actions">
          <button
            type="button"
            class="btn"
            onClick={() => void props.onRefresh()}
            disabled={props.loading}
          >
            <IconRefresh size={14} class={props.loading ? "spin" : undefined} />
            <span>Refresh</span>
          </button>
        </div>
      </header>

      <div class="page-scroll">
        {/* Compact Summary Strip */}
        <div class="metrics-grid" style={{ "grid-template-columns": "repeat(2, minmax(180px, 260px))" }}>
          <div class="metric-card">
            <div class="metric-label">
              <span>Cached Images</span>
              <IconDisc size={13} />
            </div>
            <div class="metric-value">{props.images.length}</div>
          </div>

          <div class="metric-card">
            <div class="metric-label">
              <span>Total Footprint</span>
              <IconShield size={13} />
            </div>
            <div class="metric-value">{formatBytes(totalFootprintBytes())}</div>
          </div>
        </div>

        {/* Build Image Panel */}
        <Show when={props.allowImageBuild !== false}>
          <div class="panel" style={{ "margin-bottom": "16px" }}>
            <div class="panel-header">
              <span class="panel-title">
                <IconPlus size={13} /> Build Image
              </span>
              <div class="segmented">
                <button
                  type="button"
                  class={`segmented-btn ${buildMode() === "oci" ? "active" : ""}`}
                  onClick={() => setBuildMode("oci")}
                  disabled={building()}
                >
                  OCI Ref
                </button>
                <button
                  type="button"
                  class={`segmented-btn ${buildMode() === "profile" ? "active" : ""}`}
                  onClick={() => setBuildMode("profile")}
                  disabled={building()}
                >
                  Profile
                </button>
              </div>
            </div>
            <form class="panel-body stack" style={{ gap: "10px" }} onSubmit={handleBuildImage}>
              <div class="row-wrap" style={{ gap: "8px" }}>
                <Show
                  when={buildMode() === "oci"}
                  fallback={
                    <select
                      class="select mono"
                      style={{ flex: "1 1 240px" }}
                      value={selectedProfile()}
                      onChange={(e) => setSelectedProfile(e.currentTarget.value)}
                      disabled={building()}
                    >
                      <For
                        each={
                          props.profiles.length > 0 ? props.profiles : ["base"]
                        }
                      >
                        {(p) => <option value={p}>{p}</option>}
                      </For>
                    </select>
                  }
                >
                  <input
                    type="text"
                    class="input mono"
                    style={{ flex: "1 1 260px" }}
                    placeholder="python:3.12-slim"
                    value={ociRefInput()}
                    onInput={(e) => setOciRefInput(e.currentTarget.value)}
                    disabled={building()}
                  />
                </Show>

                <button
                  type="submit"
                  class="btn btn-primary"
                  disabled={
                    building() ||
                    (buildMode() === "oci" && ociRefInput().trim().length === 0)
                  }
                >
                  <Show
                    when={building()}
                    fallback={<IconPlus size={13} />}
                  >
                    <IconRefresh size={13} class="spin" />
                  </Show>
                  <span>{building() ? "Building…" : "Build Image"}</span>
                </button>
              </div>

              <Show when={building()}>
                <div class="banner">
                  <span class="mono" style={{ color: "var(--cyan)" }}>
                    Pulling layers and building EROFS + dm-verity image…
                  </span>
                </div>
              </Show>

              <Show when={buildError()}>
                {(err) => <div class="banner banner-error mono">{err()}</div>}
              </Show>
            </form>
          </div>
        </Show>

        <Show when={props.error}>
          {(err) => (
            <div
              class="banner banner-error mono"
              style={{ "margin-bottom": "14px" }}
            >
              {err()}
            </div>
          )}
        </Show>

        <Show when={deleteError()}>
          {(err) => (
            <div
              class="banner banner-error mono"
              style={{ "margin-bottom": "14px" }}
            >
              {err()}
            </div>
          )}
        </Show>

        <Show
          when={props.images.length > 0}
          fallback={
            <div class="empty-state">
              <IconDisc size={28} />
              <div class="empty-state-title">
                No cached EROFS + dm-verity images found
              </div>
              <div style={{ "font-size": "12px" }}>
                {props.allowImageBuild === false
                  ? "Launch a sandbox to populate the local image cache."
                  : "Build an image above or launch a sandbox to populate the local image cache."}
              </div>
            </div>
          }
        >
          <div class="stack">
            <For each={props.images}>
              {(img) => {
                const approxBytes = () =>
                  img.verity.data_blocks * img.verity.data_block_size;
                const rootCopyKey = `root:${img.content_hash}`;
                const contentCopyKey = `hash:${img.content_hash}`;
                const matchingSandboxes = createMemo(() =>
                  props.sandboxes.filter(
                    (sb) =>
                      sb.image_roothash === img.verity.roothash_hex ||
                      (sb.image_content_hash !== undefined &&
                        sb.image_content_hash === img.content_hash),
                  ),
                );
                const inUse = () => matchingSandboxes().length > 0;
                const isConfirming = () =>
                  confirmDeleteHash() === img.content_hash;
                const isDeleting = () => deletingHash() === img.content_hash;

                return (
                  <div class="panel">
                    <div class="panel-header">
                      <div class="row-wrap">
                        <IconShield size={14} />
                        <span class="mono" style={{ "font-weight": 600 }}>
                          {shortHash(img.content_hash, 24)}
                        </span>
                        <span class="pill pill-emerald">dm-verity</span>
                        <span class="pill">{formatBytes(approxBytes())}</span>
                        <Show when={inUse()}>
                          <span class="pill pill-amber">In use</span>
                        </Show>
                      </div>

                      <div class="row">
                        <button
                          type="button"
                          class="btn btn-xs mono"
                          onClick={() =>
                            void handleCopy(contentCopyKey, img.content_hash)
                          }
                        >
                          <Show
                            when={copiedKey() === contentCopyKey}
                            fallback={<IconCopy size={11} />}
                          >
                            <IconCheck size={11} />
                          </Show>
                          <span>
                            {copiedKey() === contentCopyKey
                              ? "Copied"
                              : "Copy Hash"}
                          </span>
                        </button>

                        <Show
                          when={isConfirming() && !inUse()}
                          fallback={
                            <button
                              type="button"
                              class="btn btn-danger btn-xs"
                              disabled={inUse() || deletingHash() !== null}
                              title={
                                inUse()
                                  ? "In use by active sandbox"
                                  : "Delete cached image"
                              }
                              onClick={() => {
                                setDeleteError(null);
                                setConfirmDeleteHash(img.content_hash);
                              }}
                            >
                              <IconTrash size={11} />
                              <span>Delete</span>
                            </button>
                          }
                        >
                          <button
                            type="button"
                            class="btn btn-ghost btn-xs"
                            onClick={() => setConfirmDeleteHash(null)}
                            disabled={isDeleting()}
                          >
                            Cancel
                          </button>
                          <button
                            type="button"
                            class="btn btn-danger btn-xs"
                            onClick={() =>
                              void handleDeleteImage(img.content_hash)
                            }
                            disabled={isDeleting()}
                          >
                            {isDeleting() ? "Deleting…" : "Confirm"}
                          </button>
                        </Show>
                      </div>
                    </div>

                    <div class="panel-body stack">
                      <Show when={matchingSandboxes().length > 0}>
                        <div class="row-wrap" style={{ gap: "6px" }}>
                          <span class="kv-label" style={{ "margin-right": "4px" }}>
                            Active VMs
                          </span>
                          <For each={matchingSandboxes()}>
                            {(sb) => (
                              <button
                                type="button"
                                class="sandbox-link-pill"
                                onClick={() => props.onSelectSandbox(sb.id)}
                                title={`Inspect ${sb.id} (${sb.profile})`}
                              >
                                <span class={`dot dot-${sb.state}`} />
                                <IconCube size={11} />
                                <span>{shortId(sb.id)}</span>
                              </button>
                            )}
                          </For>
                        </div>
                      </Show>

                      <div class="kv-grid">
                        <div class="kv-item" style={{ "grid-column": "1 / -1" }}>
                          <span class="kv-label">Verity Root Hash</span>
                          <div class="row">
                            <span
                              class="kv-value"
                              style={{ color: "var(--emerald)" }}
                            >
                              {img.verity.roothash_hex}
                            </span>
                            <button
                              type="button"
                              class="btn btn-xs"
                              onClick={() =>
                                void handleCopy(
                                  rootCopyKey,
                                  img.verity.roothash_hex,
                                )
                              }
                            >
                              <Show
                                when={copiedKey() === rootCopyKey}
                                fallback={<IconCopy size={11} />}
                              >
                                <IconCheck size={11} />
                              </Show>
                            </button>
                          </div>
                        </div>

                        <div class="kv-item" style={{ "grid-column": "1 / -1" }}>
                          <span class="kv-label">Image Path</span>
                          <span class="kv-value">{img.erofs_path}</span>
                        </div>

                        <div class="kv-item">
                          <span class="kv-label">Data Blocks</span>
                          <span class="kv-value">
                            {img.verity.data_blocks.toLocaleString()}
                          </span>
                        </div>

                        <div class="kv-item">
                          <span class="kv-label">Hash Start Block</span>
                          <span class="kv-value">
                            {img.verity.hash_start_block.toLocaleString()}
                          </span>
                        </div>

                        <div class="kv-item">
                          <span class="kv-label">Data / Hash Block Size</span>
                          <span class="kv-value">
                            {img.verity.data_block_size} B /{" "}
                            {img.verity.hash_block_size} B
                          </span>
                        </div>

                        <div class="kv-item">
                          <span class="kv-label">Verity Salt</span>
                          <span class="kv-value" title={img.verity.salt_hex}>
                            {shortHash(img.verity.salt_hex, 24)}
                          </span>
                        </div>
                      </div>
                    </div>
                  </div>
                );
              }}
            </For>
          </div>
        </Show>
      </div>
    </>
  );
}
