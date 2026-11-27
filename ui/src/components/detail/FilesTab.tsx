import {
  createEffect,
  createMemo,
  createSignal,
  For,
  onCleanup,
  Show,
} from "solid-js";
import {
  downloadFile,
  execSync,
  inferUploadContentType,
  listSandboxDir,
  uploadFile,
} from "../../api/client";
import type { DownloadMeta, FsEntry } from "../../api/types";
import {
  copyToClipboard,
  extractFilenameFromPath,
  formatBytes,
  triggerBlobDownload,
} from "../../utils/format";
import {
  IconCheck,
  IconCopy,
  IconDownload,
  IconFileText,
  IconFolder,
  IconPlus,
  IconRefresh,
  IconTrash,
  IconUpload,
  IconX,
} from "../Icons";

export interface FilesTabProps {
  sandboxId: string;
  running: boolean;
  onActivity?: () => void;
}

type PreviewContent =
  | { kind: "text"; text: string; truncated: boolean; lineCount: number }
  | { kind: "image"; objectUrl: string; mime: string }
  | { kind: "binary"; hexDump: string; truncated: boolean };

interface LoadedFile {
  path: string;
  name: string;
  size: number;
  sha256: string | null;
  preview: PreviewContent;
  rawBytes: Uint8Array;
}

const MAX_PREVIEW_BYTES = 256 * 1024; // 256 KiB

const READ_FILE_SCRIPT = [
  'f="$1"',
  '[ -f "$f" ] || { echo "Not a regular file: $f" >&2; exit 2; }',
  'sz=$(stat -c "%s" "$f" 2>/dev/null || wc -c < "$f")',
  'printf "%s\\n" "$sz"',
  `head -c ${MAX_PREVIEW_BYTES} -- "$f" | base64`,
].join("\n");

function joinPath(dir: string, name: string): string {
  if (dir === "/") return `/${name}`;
  return `${dir.replace(/\/+$/, "")}/${name}`;
}

function parentPath(dir: string): string {
  const clean = dir.replace(/\/+$/, "");
  if (!clean || clean === "/") return "/";
  const idx = clean.lastIndexOf("/");
  return idx <= 0 ? "/" : clean.slice(0, idx);
}

function isInsideWorkspace(path: string): boolean {
  return path === "/workspace" || path.startsWith("/workspace/");
}

function guessImageMime(name: string): string | null {
  const lower = name.toLowerCase();
  if (lower.endsWith(".png")) return "image/png";
  if (lower.endsWith(".jpg") || lower.endsWith(".jpeg")) return "image/jpeg";
  if (lower.endsWith(".gif")) return "image/gif";
  if (lower.endsWith(".webp")) return "image/webp";
  if (lower.endsWith(".svg")) return "image/svg+xml";
  if (lower.endsWith(".ico")) return "image/x-icon";
  return null;
}

function looksBinary(bytes: Uint8Array): boolean {
  const sample = bytes.subarray(0, Math.min(bytes.length, 4096));
  let suspicious = 0;
  for (let i = 0; i < sample.length; i++) {
    const b = sample[i]!;
    if (b === 0) return true;
    if (b < 7 || (b > 14 && b < 32 && b !== 27)) {
      suspicious++;
    }
  }
  return sample.length > 0 && suspicious / sample.length > 0.1;
}

function formatHexDump(bytes: Uint8Array, maxBytes = 512): string {
  const slice = bytes.subarray(0, Math.min(bytes.length, maxBytes));
  const lines: string[] = [];
  for (let offset = 0; offset < slice.length; offset += 16) {
    const chunk = slice.subarray(offset, offset + 16);
    const addr = offset.toString(16).padStart(6, "0");
    const hexParts: string[] = [];
    let ascii = "";
    for (let i = 0; i < 16; i++) {
      if (i < chunk.length) {
        const b = chunk[i]!;
        hexParts.push(b.toString(16).padStart(2, "0"));
        ascii += b >= 32 && b <= 126 ? String.fromCharCode(b) : ".";
      } else {
        hexParts.push("  ");
      }
    }
    lines.push(
      `${addr}  ${hexParts.slice(0, 8).join(" ")}  ${hexParts.slice(8).join(" ")}  |${ascii}|`,
    );
  }
  return lines.join("\n");
}

function decodeBase64ToBytes(b64: string): Uint8Array {
  const clean = b64.replace(/\s+/g, "");
  if (!clean) return new Uint8Array(0);
  const bin = atob(clean);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    out[i] = bin.charCodeAt(i);
  }
  return out;
}

function buildPreview(
  name: string,
  bytes: Uint8Array,
  totalSize: number,
): PreviewContent {
  const truncated = totalSize > bytes.length;
  const imgMime = !truncated ? guessImageMime(name) : null;
  if (imgMime && bytes.length > 0) {
    const copy = new Uint8Array(bytes.byteLength);
    copy.set(bytes);
    const blob = new Blob([copy.buffer], { type: imgMime });
    return {
      kind: "image",
      objectUrl: URL.createObjectURL(blob),
      mime: imgMime,
    };
  }
  if (!looksBinary(bytes)) {
    const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
    const lineCount = text.length === 0 ? 0 : text.split("\n").length;
    return { kind: "text", text, truncated, lineCount };
  }
  return {
    kind: "binary",
    hexDump: formatHexDump(bytes),
    truncated: totalSize > 512,
  };
}

export function FilesTab(props: FilesTabProps) {
  let fileInputRef: HTMLInputElement | undefined;
  let activeObjectUrl: string | null = null;
  let listController: AbortController | null = null;
  let fileController: AbortController | null = null;

  const sandboxId = createMemo(() => props.sandboxId);

  const [cwd, setCwd] = createSignal("/workspace");
  const [entries, setEntries] = createSignal<FsEntry[]>([]);
  const [loadingDir, setLoadingDir] = createSignal(false);
  const [dirError, setDirError] = createSignal<string | null>(null);
  const [filter, setFilter] = createSignal("");
  const [showHidden, setShowHidden] = createSignal(true);

  const [selectedPath, setSelectedPath] = createSignal<string | null>(null);
  const [loadedFile, setLoadedFile] = createSignal<LoadedFile | null>(null);
  const [loadingFile, setLoadingFile] = createSignal(false);
  const [fileError, setFileError] = createSignal<string | null>(null);

  // Inline editor state (for UTF-8 files in /workspace)
  const [editing, setEditing] = createSignal(false);
  const [editDraft, setEditDraft] = createSignal("");
  const [saving, setSaving] = createSignal(false);

  // Upload / mkdir / delete / download state
  const [dragging, setDragging] = createSignal(false);
  const [uploading, setUploading] = createSignal(false);
  const [statusBanner, setStatusBanner] = createSignal<{
    kind: "ok" | "error";
    text: string;
  } | null>(null);
  const [creatingDir, setCreatingDir] = createSignal(false);
  const [newDirName, setNewDirName] = createSignal("");
  const [creatingFile, setCreatingFile] = createSignal(false);
  const [newFileName, setNewFileName] = createSignal("");
  const [creatingFileBusy, setCreatingFileBusy] = createSignal(false);
  const [confirmDeletePath, setConfirmDeletePath] = createSignal<string | null>(
    null,
  );
  const [copiedContent, setCopiedContent] = createSignal(false);
  const [downloadingPath, setDownloadingPath] = createSignal<string | null>(
    null,
  );
  const [lastExport, setLastExport] = createSignal<DownloadMeta | null>(null);

  const revokeActiveUrl = () => {
    if (activeObjectUrl) {
      URL.revokeObjectURL(activeObjectUrl);
      activeObjectUrl = null;
    }
  };

  onCleanup(() => {
    listController?.abort();
    fileController?.abort();
    revokeActiveUrl();
  });

  const flashStatus = (kind: "ok" | "error", text: string) => {
    setStatusBanner({ kind, text });
    if (kind === "ok") {
      window.setTimeout(() => {
        setStatusBanner((prev) => (prev?.text === text ? null : prev));
      }, 3500);
    }
  };

  const loadDirectory = async (dir: string) => {
    if (!props.running) return;
    listController?.abort();
    const controller = new AbortController();
    listController = controller;

    setLoadingDir(true);
    setDirError(null);
    try {
      const list = await listSandboxDir(sandboxId(), dir, controller.signal);
      if (controller.signal.aborted) return;
      const sorted = [...list].sort((a, b) => {
        if (a.is_dir !== b.is_dir) return a.is_dir ? -1 : 1;
        return a.name.localeCompare(b.name);
      });
      setEntries(sorted);
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") return;
      setDirError(err instanceof Error ? err.message : String(err));
      setEntries([]);
    } finally {
      if (listController === controller) {
        setLoadingDir(false);
      }
    }
  };

  const openFile = async (entry: FsEntry) => {
    if (!props.running) return;
    fileController?.abort();
    const controller = new AbortController();
    fileController = controller;

    setSelectedPath(entry.path);
    setConfirmDeletePath(null);
    setLoadingFile(true);
    setFileError(null);
    setEditing(false);

    try {
      let bytes: Uint8Array;
      let totalSize = entry.size;
      let sha256: string | null = null;

      if (isInsideWorkspace(entry.path) && entry.size <= MAX_PREVIEW_BYTES) {
        const { blob, meta } = await downloadFile(
          sandboxId(),
          entry.path,
          "raw",
          controller.signal,
        );
        if (controller.signal.aborted) return;
        const buf = await blob.arrayBuffer();
        bytes = new Uint8Array(buf);
        totalSize = meta.bytes || bytes.length;
        sha256 = meta.sha256 || null;
      } else {
        const res = await execSync(
          sandboxId(),
          {
            cmd: ["sh", "-c", READ_FILE_SCRIPT, "_", entry.path],
            timeout_sec: 15,
          },
          controller.signal,
        );
        if (controller.signal.aborted) return;
        if (res.exit_code !== 0) {
          throw new Error(res.stderr.trim() || `Failed to read ${entry.path}`);
        }
        const nl = res.stdout.indexOf("\n");
        const sizeLine = nl >= 0 ? res.stdout.slice(0, nl).trim() : "0";
        const b64Body = nl >= 0 ? res.stdout.slice(nl + 1) : "";
        totalSize = Number.parseInt(sizeLine, 10) || entry.size;
        bytes = decodeBase64ToBytes(b64Body);
      }

      revokeActiveUrl();
      const preview = buildPreview(entry.name, bytes, totalSize);
      if (preview.kind === "image") {
        activeObjectUrl = preview.objectUrl;
      }
      setLoadedFile({
        path: entry.path,
        name: entry.name,
        size: totalSize,
        sha256,
        preview,
        rawBytes: bytes,
      });
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") return;
      setFileError(err instanceof Error ? err.message : String(err));
      setLoadedFile(null);
    } finally {
      if (fileController === controller) {
        setLoadingFile(false);
      }
    }
  };

  // Load initial /workspace directory when sandbox changes
  createEffect(() => {
    void sandboxId();
    setCwd("/workspace");
    setSelectedPath(null);
    setLoadedFile(null);
    setFileError(null);
    setEditing(false);
    setFilter("");
    setCreatingDir(false);
    setNewDirName("");
    setCreatingFile(false);
    setNewFileName("");
    setConfirmDeletePath(null);
    revokeActiveUrl();
    void loadDirectory("/workspace");
  });

  const navigateTo = (dir: string) => {
    const normalized = dir.length > 1 ? dir.replace(/\/+$/, "") : "/";
    setCwd(normalized);
    setFilter("");
    setCreatingDir(false);
    setCreatingFile(false);
    setConfirmDeletePath(null);
    void loadDirectory(normalized);
  };

  const breadcrumbs = createMemo(() => {
    const current = cwd();
    if (current === "/") return [{ label: "/", path: "/" }];
    const segments = current.split("/").filter(Boolean);
    const items = [{ label: "/", path: "/" }];
    let acc = "";
    for (const seg of segments) {
      acc += `/${seg}`;
      items.push({ label: seg, path: acc });
    }
    return items;
  });

  const visibleEntries = createMemo(() => {
    const q = filter().trim().toLowerCase();
    const hidden = showHidden();
    return entries().filter((e) => {
      if (!hidden && e.name.startsWith(".")) return false;
      if (q && !e.name.toLowerCase().includes(q)) return false;
      return true;
    });
  });

  const totalDirBytes = createMemo(() =>
    entries().reduce((acc, e) => acc + (e.is_dir ? 0 : e.size), 0),
  );

  const canWriteCwd = createMemo(() => isInsideWorkspace(cwd()));

  const handleUploadFiles = async (fileList: FileList | null | undefined) => {
    if (!fileList || fileList.length === 0 || uploading() || !props.running) {
      return;
    }
    const targetDir = canWriteCwd() ? cwd() : "/workspace";
    setUploading(true);
    setStatusBanner(null);

    try {
      let count = 0;
      let totalBytes = 0;
      for (const file of Array.from(fileList)) {
        const ct = inferUploadContentType(file.name);
        const dest =
          ct === "application/octet-stream"
            ? joinPath(targetDir, file.name)
            : targetDir;
        const res = await uploadFile(sandboxId(), dest, file, ct);
        count += res.files_written || 1;
        totalBytes += res.bytes_written;
      }
      flashStatus(
        "ok",
        `Uploaded ${count} file${count === 1 ? "" : "s"} (${formatBytes(totalBytes)}) to ${targetDir}`,
      );
      props.onActivity?.();
      await loadDirectory(cwd());
    } catch (err) {
      flashStatus("error", err instanceof Error ? err.message : String(err));
    } finally {
      setUploading(false);
      if (fileInputRef) fileInputRef.value = "";
    }
  };

  const handleDownloadTarget = async (
    targetPath: string,
    isDir: boolean,
  ) => {
    if (!props.running || downloadingPath()) return;
    if (!isInsideWorkspace(targetPath)) {
      flashStatus("error", "Exports are restricted to /workspace.");
      return;
    }
    const fmt = isDir ? "tar.gz" : "raw";
    setDownloadingPath(targetPath);
    try {
      const { blob, meta } = await downloadFile(sandboxId(), targetPath, fmt);
      const filename = extractFilenameFromPath(targetPath, fmt);
      triggerBlobDownload(blob, filename);
      setLastExport(meta);
      flashStatus(
        "ok",
        `Downloaded ${filename} (${formatBytes(meta.bytes)})`,
      );
      props.onActivity?.();
    } catch (err) {
      flashStatus("error", err instanceof Error ? err.message : String(err));
    } finally {
      setDownloadingPath(null);
    }
  };

  const handleCreateDir = async (ev: SubmitEvent) => {
    ev.preventDefault();
    const name = newDirName().trim();
    if (!name || name.includes("/") || name === "." || name === "..") return;
    const dest = joinPath(cwd(), name);
    if (!isInsideWorkspace(dest)) return;

    try {
      const res = await execSync(sandboxId(), {
        cmd: ["mkdir", "-p", "--", dest],
        timeout_sec: 10,
      });
      if (res.exit_code !== 0) {
        throw new Error(res.stderr.trim() || "Failed to create folder");
      }
      setNewDirName("");
      setCreatingDir(false);
      await loadDirectory(cwd());
    } catch (err) {
      flashStatus("error", err instanceof Error ? err.message : String(err));
    }
  };

  const handleCreateFile = async (ev: SubmitEvent) => {
    ev.preventDefault();
    if (creatingFileBusy()) return;
    const name = newFileName().trim();
    if (!name || name.includes("/") || name === "." || name === "..") return;
    const dest = joinPath(cwd(), name);
    if (!isInsideWorkspace(dest)) return;

    setCreatingFileBusy(true);
    try {
      await uploadFile(
        sandboxId(),
        dest,
        new Uint8Array(0),
        "application/octet-stream",
      );
      setNewFileName("");
      setCreatingFile(false);
      props.onActivity?.();
      await loadDirectory(cwd());
      const created = entries().find((e) => e.path === dest);
      if (created) {
        await openFile(created);
        const f = loadedFile();
        if (f && f.path === dest && f.preview.kind === "text") {
          setEditDraft(f.preview.text);
          setEditing(true);
        }
      }
    } catch (err) {
      flashStatus("error", err instanceof Error ? err.message : String(err));
    } finally {
      setCreatingFileBusy(false);
    }
  };

  const handleDeleteEntry = async (entry: FsEntry) => {
    if (!isInsideWorkspace(entry.path) || entry.path === "/workspace") return;
    setConfirmDeletePath(null);
    try {
      const res = await execSync(sandboxId(), {
        cmd: ["rm", "-rf", "--", entry.path],
        timeout_sec: 15,
      });
      if (res.exit_code !== 0) {
        throw new Error(res.stderr.trim() || `Failed to delete ${entry.name}`);
      }
      if (selectedPath() === entry.path) {
        setSelectedPath(null);
        setLoadedFile(null);
        setEditing(false);
        revokeActiveUrl();
      }
      flashStatus("ok", `Deleted ${entry.name}`);
      await loadDirectory(cwd());
    } catch (err) {
      flashStatus("error", err instanceof Error ? err.message : String(err));
    }
  };

  const handleSaveEdit = async () => {
    const file = loadedFile();
    if (!file || !isInsideWorkspace(file.path) || saving()) return;
    setSaving(true);
    try {
      const encoded = new TextEncoder().encode(editDraft());
      await uploadFile(
        sandboxId(),
        file.path,
        encoded,
        "application/octet-stream",
      );
      setEditing(false);
      flashStatus("ok", `Saved ${file.name} (${formatBytes(encoded.byteLength)})`);
      props.onActivity?.();
      await loadDirectory(cwd());
      const updated = entries().find((e) => e.path === file.path);
      if (updated) {
        await openFile(updated);
      }
    } catch (err) {
      flashStatus("error", err instanceof Error ? err.message : String(err));
    } finally {
      setSaving(false);
    }
  };

  const handleCopyContent = async () => {
    const file = loadedFile();
    if (!file || file.preview.kind !== "text") return;
    if (await copyToClipboard(file.preview.text)) {
      setCopiedContent(true);
      window.setTimeout(() => setCopiedContent(false), 1500);
    }
  };

  return (
    <div
      class="stack"
      onClick={() => {
        if (confirmDeletePath() !== null) {
          setConfirmDeletePath(null);
        }
      }}
    >
      <input
        ref={fileInputRef}
        type="file"
        multiple
        style={{ display: "none" }}
        onChange={(e) => void handleUploadFiles(e.currentTarget.files)}
      />

      <Show when={statusBanner()}>
        {(b) => (
          <div
            class={`banner mono ${b().kind === "ok" ? "banner-ok" : "banner-error"}`}
          >
            <span>{b().text}</span>
            <Show when={b().kind === "ok" ? lastExport() : null}>
              {(meta) => (
                <Show when={meta().sha256}>
                  <span style={{ opacity: 0.8 }}>
                    sha256:{meta().sha256.slice(0, 12)}
                  </span>
                </Show>
              )}
            </Show>
          </div>
        )}
      </Show>

      <div class="panel">
        {/* Explorer Top Bar */}
        <div class="fs-topbar">
          <div class="row-wrap" style={{ "min-width": 0, flex: "1 1 320px" }}>
            <div class="segmented">
              <button
                type="button"
                class={`segmented-btn mono ${isInsideWorkspace(cwd()) ? "active" : ""}`}
                onClick={() => navigateTo("/workspace")}
              >
                /workspace
              </button>
              <button
                type="button"
                class={`segmented-btn mono ${!isInsideWorkspace(cwd()) ? "active" : ""}`}
                onClick={() => navigateTo("/")}
              >
                /
              </button>
            </div>

            <nav class="fs-breadcrumbs" aria-label="Current Directory">
              <For each={breadcrumbs()}>
                {(crumb, idx) => (
                  <>
                    <Show when={idx() > 0}>
                      <span class="fs-crumb-sep">/</span>
                    </Show>
                    <button
                      type="button"
                      class={`fs-crumb ${crumb.path === cwd() ? "active" : ""}`}
                      onClick={() => navigateTo(crumb.path)}
                    >
                      {crumb.label}
                    </button>
                  </>
                )}
              </For>
            </nav>

            <span class={`pill ${canWriteCwd() ? "pill-emerald" : ""}`}>
              {canWriteCwd() ? "rw" : "ro"}
            </span>
          </div>

          <div class="row-wrap">
            <button
              type="button"
              class="btn btn-sm"
              onClick={() => void loadDirectory(cwd())}
              disabled={!props.running || loadingDir()}
              title="Refresh directory"
            >
              <IconRefresh size={12} />
            </button>

            <Show when={canWriteCwd()}>
              <button
                type="button"
                class="btn btn-sm"
                onClick={() => {
                  setCreatingDir(false);
                  setCreatingFile((v) => !v);
                  setConfirmDeletePath(null);
                }}
                disabled={!props.running}
              >
                <IconPlus size={12} />
                <span>New File</span>
              </button>

              <button
                type="button"
                class="btn btn-sm"
                onClick={() => {
                  setCreatingFile(false);
                  setCreatingDir((v) => !v);
                  setConfirmDeletePath(null);
                }}
                disabled={!props.running}
              >
                <IconPlus size={12} />
                <span>Folder</span>
              </button>

              <button
                type="button"
                class="btn btn-sm btn-primary"
                onClick={() => fileInputRef?.click()}
                disabled={!props.running || uploading()}
              >
                <IconUpload size={12} />
                <span>{uploading() ? "Uploading…" : "Upload"}</span>
              </button>

              <button
                type="button"
                class="btn btn-sm"
                onClick={() => void handleDownloadTarget(cwd(), true)}
                disabled={!props.running || downloadingPath() !== null}
                title="Download current directory as .tar.gz"
              >
                <IconDownload size={12} />
                <span>.tar.gz</span>
              </button>
            </Show>
          </div>
        </div>

        <Show when={creatingFile()}>
          <form class="fs-mkdir-bar" onSubmit={handleCreateFile}>
            <input
              type="text"
              class="input mono"
              placeholder="New file name…"
              value={newFileName()}
              onInput={(e) => setNewFileName(e.currentTarget.value)}
              disabled={creatingFileBusy()}
              autofocus
            />
            <button
              type="submit"
              class="btn btn-sm btn-primary"
              disabled={creatingFileBusy() || newFileName().trim().length === 0}
            >
              {creatingFileBusy() ? "Creating…" : "Create"}
            </button>
            <button
              type="button"
              class="btn btn-sm"
              onClick={() => {
                setCreatingFile(false);
                setNewFileName("");
              }}
              disabled={creatingFileBusy()}
            >
              Cancel
            </button>
          </form>
        </Show>

        <Show when={creatingDir()}>
          <form class="fs-mkdir-bar" onSubmit={handleCreateDir}>
            <input
              type="text"
              class="input mono"
              placeholder="New folder name…"
              value={newDirName()}
              onInput={(e) => setNewDirName(e.currentTarget.value)}
              autofocus
            />
            <button type="submit" class="btn btn-sm btn-primary">
              Create
            </button>
            <button
              type="button"
              class="btn btn-sm"
              onClick={() => {
                setCreatingDir(false);
                setNewDirName("");
              }}
            >
              Cancel
            </button>
          </form>
        </Show>

        {/* Split Explorer Layout */}
        <div class="fs-split">
          {/* Left Pane: Directory Tree */}
          <div
            class={`fs-tree-pane ${dragging() ? "dragging" : ""}`}
            onDragOver={(e) => {
              e.preventDefault();
              setDragging(true);
            }}
            onDragLeave={() => setDragging(false)}
            onDrop={(e) => {
              e.preventDefault();
              setDragging(false);
              void handleUploadFiles(e.dataTransfer?.files);
            }}
          >
            <div class="fs-tree-controls">
              <input
                type="search"
                class="input mono"
                style={{ padding: "5px 8px", "font-size": "11.5px" }}
                placeholder="Filter files…"
                value={filter()}
                onInput={(e) => setFilter(e.currentTarget.value)}
              />
              <button
                type="button"
                class={`btn btn-xs ${showHidden() ? "btn-amber" : ""}`}
                onClick={() => setShowHidden((v) => !v)}
                title="Toggle dotfiles"
              >
                .*
              </button>
            </div>

            <div class="fs-list">
              <Show when={cwd() !== "/"}>
                <button
                  type="button"
                  class="fs-row"
                  onClick={() => navigateTo(parentPath(cwd()))}
                >
                  <span class="fs-row-main">
                    <IconFolder size={14} class="fs-icon-dir" />
                    <span class="mono">..</span>
                  </span>
                </button>
              </Show>

              <Show when={dirError()}>
                {(err) => (
                  <div class="banner banner-error mono" style={{ margin: "8px" }}>
                    {err()}
                  </div>
                )}
              </Show>

              <Show
                when={!loadingDir() || entries().length > 0}
                fallback={
                  <div class="fs-empty mono">Loading {cwd()}…</div>
                }
              >
                <Show
                  when={visibleEntries().length > 0}
                  fallback={
                    <div class="fs-empty">
                      {entries().length === 0
                        ? "Empty directory"
                        : "No matching entries"}
                    </div>
                  }
                >
                  <For each={visibleEntries()}>
                    {(entry) => {
                      const isSelected = () => selectedPath() === entry.path;
                      const isConfirmingDelete = () =>
                        confirmDeletePath() === entry.path;
                      return (
                        <div
                          class={`fs-row ${isSelected() ? "active" : ""}`}
                          onClick={() => {
                            setConfirmDeletePath(null);
                            if (entry.is_dir) {
                              navigateTo(entry.path);
                            } else {
                              void openFile(entry);
                            }
                          }}
                        >
                          <span class="fs-row-main">
                            <Show
                              when={entry.is_dir}
                              fallback={
                                <IconFileText size={14} class="fs-icon-file" />
                              }
                            >
                              <IconFolder size={14} class="fs-icon-dir" />
                            </Show>
                            <span class="fs-row-name mono truncate">
                              {entry.name}
                              {entry.kind === "symlink" ||
                              entry.kind === "symlink_dir"
                                ? " @"
                                : ""}
                            </span>
                          </span>

                          <span class="fs-row-meta mono">
                            <Show when={!entry.is_dir && !isConfirmingDelete()}>
                              <span>{formatBytes(entry.size)}</span>
                            </Show>
                            <Show when={isInsideWorkspace(entry.path)}>
                              <span
                                class="fs-row-actions"
                                style={
                                  isConfirmingDelete()
                                    ? { opacity: 1 }
                                    : undefined
                                }
                              >
                                <Show
                                  when={isConfirmingDelete()}
                                  fallback={
                                    <>
                                      <button
                                        type="button"
                                        class="btn btn-ghost btn-xs"
                                        title="Download"
                                        onClick={(e) => {
                                          e.stopPropagation();
                                          setConfirmDeletePath(null);
                                          void handleDownloadTarget(
                                            entry.path,
                                            entry.is_dir,
                                          );
                                        }}
                                      >
                                        <IconDownload size={11} />
                                      </button>
                                      <button
                                        type="button"
                                        class="btn btn-ghost btn-xs"
                                        title="Delete"
                                        onClick={(e) => {
                                          e.stopPropagation();
                                          setConfirmDeletePath(entry.path);
                                        }}
                                      >
                                        <IconTrash size={11} />
                                      </button>
                                    </>
                                  }
                                >
                                  <button
                                    type="button"
                                    class="btn btn-danger btn-xs"
                                    onClick={(e) => {
                                      e.stopPropagation();
                                      void handleDeleteEntry(entry);
                                    }}
                                  >
                                    Delete?
                                  </button>
                                  <button
                                    type="button"
                                    class="btn btn-ghost btn-xs"
                                    title="Cancel delete"
                                    onClick={(e) => {
                                      e.stopPropagation();
                                      setConfirmDeletePath(null);
                                    }}
                                  >
                                    <IconX size={11} />
                                  </button>
                                </Show>
                              </span>
                            </Show>
                          </span>
                        </div>
                      );
                    }}
                  </For>
                </Show>
              </Show>
            </div>

            <div class="fs-tree-footer mono">
              <span>{entries().length} items</span>
              <span>{formatBytes(totalDirBytes())}</span>
            </div>
          </div>

          {/* Right Pane: File Preview / Editor */}
          <div class="fs-viewer-pane">
            <Show
              when={selectedPath()}
              fallback={
                <div class="fs-viewer-empty">
                  <IconFileText size={24} />
                  <div class="fs-viewer-empty-title">No file selected</div>
                  <div class="field-hint">
                    Select a file, or drop files to upload to{" "}
                    <span class="mono">{canWriteCwd() ? cwd() : "/workspace"}</span>.
                  </div>
                </div>
              }
            >
              {(path) => (
                <>
                  <div class="fs-viewer-header">
                    <div class="row" style={{ "min-width": 0 }}>
                      <span class="mono truncate" style={{ "font-size": "12px", color: "var(--text-primary)" }}>
                        {path()}
                      </span>
                      <Show when={loadedFile()}>
                        {(f) => (
                          <span class="pill">{formatBytes(f().size)}</span>
                        )}
                      </Show>
                    </div>

                    <div class="row">
                      <Show when={loadedFile()?.preview.kind === "text"}>
                        <Show
                          when={editing()}
                          fallback={
                            <>
                              <button
                                type="button"
                                class="btn btn-xs"
                                onClick={() => void handleCopyContent()}
                              >
                                <Show
                                  when={copiedContent()}
                                  fallback={<IconCopy size={11} />}
                                >
                                  <IconCheck size={11} />
                                </Show>
                                <span>{copiedContent() ? "Copied" : "Copy"}</span>
                              </button>

                              <Show
                                when={
                                  isInsideWorkspace(path()) &&
                                  loadedFile()?.preview.kind === "text" &&
                                  !(loadedFile()?.preview as { truncated?: boolean }).truncated
                                }
                              >
                                <button
                                  type="button"
                                  class="btn btn-xs"
                                  onClick={() => {
                                    const f = loadedFile();
                                    if (f && f.preview.kind === "text") {
                                      setEditDraft(f.preview.text);
                                      setEditing(true);
                                    }
                                  }}
                                >
                                  Edit
                                </button>
                              </Show>
                            </>
                          }
                        >
                          <button
                            type="button"
                            class="btn btn-xs btn-primary"
                            onClick={() => void handleSaveEdit()}
                            disabled={saving()}
                          >
                            {saving() ? "Saving…" : "Save"}
                          </button>
                          <button
                            type="button"
                            class="btn btn-xs"
                            onClick={() => setEditing(false)}
                            disabled={saving()}
                          >
                            Cancel
                          </button>
                        </Show>
                      </Show>

                      <Show when={isInsideWorkspace(path())}>
                        <button
                          type="button"
                          class="btn btn-xs"
                          onClick={() => void handleDownloadTarget(path(), false)}
                          disabled={downloadingPath() !== null}
                        >
                          <IconDownload size={11} />
                          <span>Download</span>
                        </button>
                      </Show>
                    </div>
                  </div>

                  <div class="fs-viewer-body">
                    <Show when={loadingFile()}>
                      <div class="fs-empty mono">Loading…</div>
                    </Show>

                    <Show when={!loadingFile() && fileError()}>
                      {(err) => (
                        <div class="banner banner-error mono" style={{ margin: "12px" }}>
                          {err()}
                        </div>
                      )}
                    </Show>

                    <Show when={!loadingFile() && loadedFile()}>
                      {(file) => {
                        const preview = file().preview;
                        if (preview.kind === "image") {
                          return (
                            <div class="fs-image-preview">
                              <img src={preview.objectUrl} alt={file().name} />
                            </div>
                          );
                        }
                        if (preview.kind === "binary") {
                          return (
                            <div class="stack" style={{ padding: "12px" }}>
                              <div class="field-hint mono">
                                Binary file ({formatBytes(file().size)}) — hex preview
                              </div>
                              <pre class="fs-code-pre">{preview.hexDump}</pre>
                            </div>
                          );
                        }
                        if (editing()) {
                          return (
                            <textarea
                              class="fs-editor-textarea mono"
                              value={editDraft()}
                              onInput={(e) => setEditDraft(e.currentTarget.value)}
                              spellcheck={false}
                            />
                          );
                        }
                        const lines = preview.text.split("\n");
                        return (
                          <>
                            <Show when={preview.truncated}>
                              <div
                                class="banner banner-warn mono"
                                style={{ margin: "10px 12px 0" }}
                              >
                                Truncated to {formatBytes(MAX_PREVIEW_BYTES)} of{" "}
                                {formatBytes(file().size)}
                              </div>
                            </Show>
                            <div class="fs-code-wrap">
                              <table class="fs-code-table">
                                <tbody>
                                  <For each={lines}>
                                    {(line, idx) => (
                                      <tr>
                                        <td class="fs-line-num">{idx() + 1}</td>
                                        <td class="fs-line-text">
                                          {line || " "}
                                        </td>
                                      </tr>
                                    )}
                                  </For>
                                </tbody>
                              </table>
                            </div>
                          </>
                        );
                      }}
                    </Show>
                  </div>
                </>
              )}
            </Show>
          </div>
        </div>
      </div>
    </div>
  );
}
