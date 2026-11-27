import { createSignal } from "solid-js";
import type {
  ApiErrorBody,
  AttachHostBridgeRequest,
  AuditEvent,
  AuthStatus,
  BackgroundProcess,
  BuildImageRequest,
  BuiltImage,
  CreateProfileRequest,
  DownloadFormatQuery,
  DownloadMeta,
  ExecNdjsonEvent,
  ExecRequest,
  ExecResult,
  FsEntry,
  HostServiceSpec,
  KeepaliveResponse,
  ListeningPort,
  PortProbeResult,
  ProcessInfo,
  ProfileDraft,
  SandboxDetail,
  SandboxSpec,
  SandboxSummary,
  SignalKind,
  UploadContentType,
  UploadResult,
} from "./types";

const [previewOriginSignal, setPreviewOriginSignal] = createSignal<string | null>(
  null,
);

export function getPreviewOrigin(): string | null {
  return previewOriginSignal();
}

export function setPreviewOrigin(origin: string | null): void {
  const normalized = origin ? origin.trim().replace(/\/+$/, "") : null;
  setPreviewOriginSignal(normalized && normalized.length > 0 ? normalized : null);
}

let unauthorizedHandler: (() => void) | null = null;

export function setUnauthorizedHandler(handler: (() => void) | null): void {
  unauthorizedHandler = handler;
}

export class ApiError extends Error {
  public readonly status: number;
  public readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}

async function parseErrorResponse(
  res: Response,
  opts?: { notifyAuth?: boolean },
): Promise<ApiError> {
  if (res.status === 401 && opts?.notifyAuth !== false) {
    unauthorizedHandler?.();
  }
  const contentType = res.headers.get("content-type") ?? "";
  if (contentType.includes("application/json")) {
    try {
      const body = (await res.json()) as Partial<ApiErrorBody>;
      if (typeof body.message === "string") {
        return new ApiError(
          res.status,
          typeof body.code === "string" ? body.code : `http_${res.status}`,
          body.message,
        );
      }
    } catch {
      // Fall through to text body
    }
  }
  const text = await res.text().catch(() => "");
  return new ApiError(
    res.status,
    `http_${res.status}`,
    text.trim() || res.statusText || `Request failed with HTTP ${res.status}`,
  );
}

async function requestJson<T>(
  path: string,
  init?: RequestInit,
  opts?: { notifyAuth?: boolean },
): Promise<T> {
  const res = await fetch(path, {
    credentials: "same-origin",
    ...init,
    headers: {
      Accept: "application/json",
      ...(init?.body !== undefined && !(init.body instanceof FormData)
        ? { "Content-Type": "application/json" }
        : {}),
      ...(init?.headers ?? {}),
    },
  });
  if (!res.ok) {
    throw await parseErrorResponse(res, opts);
  }
  return (await res.json()) as T;
}

async function requestNoContent(
  path: string,
  init?: RequestInit,
): Promise<void> {
  const res = await fetch(path, {
    credentials: "same-origin",
    ...init,
    headers: {
      Accept: "application/json",
      ...(init?.body !== undefined ? { "Content-Type": "application/json" } : {}),
      ...(init?.headers ?? {}),
    },
  });
  if (!res.ok) {
    throw await parseErrorResponse(res);
  }
}

// ---------------------------------------------------------------------------
// 0. Control-Plane Auth & Preview Origin
// ---------------------------------------------------------------------------

export function getAuthStatus(signal?: AbortSignal): Promise<AuthStatus> {
  return requestJson<AuthStatus>("/v1/auth/status", { signal });
}

export function loginWithToken(
  token: string,
  signal?: AbortSignal,
): Promise<AuthStatus> {
  return requestJson<AuthStatus>(
    "/v1/auth/login",
    {
      method: "POST",
      body: JSON.stringify({ token }),
      signal,
    },
    { notifyAuth: false },
  );
}

/** Incrementally parse an `application/x-ndjson` response body line-by-line. */
async function readJsonLinesStream<T>(
  res: Response,
  isValid: (value: unknown) => value is T,
  onItem: (item: T) => void,
  signal?: AbortSignal,
  onOpen?: () => void,
): Promise<void> {
  if (!res.ok) {
    throw await parseErrorResponse(res);
  }
  onOpen?.();
  const body = res.body;
  if (!body) {
    return;
  }

  const reader = body.getReader();
  const decoder = new TextDecoder("utf-8");
  let buffer = "";

  const handleLine = (rawLine: string) => {
    const trimmed = rawLine.trim();
    if (!trimmed) return;
    try {
      const parsed: unknown = JSON.parse(trimmed);
      if (isValid(parsed)) {
        onItem(parsed);
      }
    } catch {
      // Ignore malformed trailing fragments
    }
  };

  try {
    while (true) {
      if (signal?.aborted) {
        break;
      }
      const { value, done } = await reader.read();
      if (done) {
        break;
      }
      if (value) {
        buffer += decoder.decode(value, { stream: true });
        let newlineIdx = buffer.indexOf("\n");
        while (newlineIdx !== -1) {
          const line = buffer.slice(0, newlineIdx);
          buffer = buffer.slice(newlineIdx + 1);
          handleLine(line);
          newlineIdx = buffer.indexOf("\n");
        }
      }
    }
    buffer += decoder.decode();
    if (buffer.trim().length > 0) {
      handleLine(buffer);
    }
  } finally {
    reader.releaseLock();
  }
}

function isExecNdjsonEvent(value: unknown): value is ExecNdjsonEvent {
  return (
    typeof value === "object" &&
    value !== null &&
    "type" in value &&
    typeof (value as { type?: unknown }).type === "string"
  );
}

function isAuditEvent(value: unknown): value is AuditEvent {
  return (
    typeof value === "object" &&
    value !== null &&
    "event" in value &&
    "timestamp_ms" in value &&
    "sandbox_id" in value &&
    typeof (value as { event?: unknown }).event === "string"
  );
}

/** Incrementally parse an exec/process `application/x-ndjson` response body. */
async function readNdjsonStream(
  res: Response,
  onEvent: (event: ExecNdjsonEvent) => void,
  signal?: AbortSignal,
): Promise<void> {
  await readJsonLinesStream(res, isExecNdjsonEvent, onEvent, signal);
}

// ---------------------------------------------------------------------------
// 1. Sandbox Lifecycle
// ---------------------------------------------------------------------------

export function listSandboxes(signal?: AbortSignal): Promise<SandboxSummary[]> {
  return requestJson<SandboxSummary[]>("/v1/sandboxes", { signal });
}

export function getSandbox(id: string, signal?: AbortSignal): Promise<SandboxDetail> {
  return requestJson<SandboxDetail>(`/v1/sandboxes/${encodeURIComponent(id)}`, {
    signal,
  });
}

export function createSandbox(draft: ProfileDraft): Promise<SandboxSummary> {
  return requestJson<SandboxSummary>("/v1/sandboxes", {
    method: "POST",
    body: JSON.stringify(draft),
  });
}

export function deleteSandbox(id: string): Promise<void> {
  return requestNoContent(`/v1/sandboxes/${encodeURIComponent(id)}`, {
    method: "DELETE",
  });
}

export function keepaliveSandbox(id: string): Promise<KeepaliveResponse> {
  return requestJson<KeepaliveResponse>(
    `/v1/sandboxes/${encodeURIComponent(id)}/keepalive`,
    { method: "POST" },
  );
}

// ---------------------------------------------------------------------------
// 2. Command Execution & Background Processes
// ---------------------------------------------------------------------------

export function execSync(
  id: string,
  req: ExecRequest,
  signal?: AbortSignal,
): Promise<ExecResult> {
  const payload: ExecRequest = { ...req, background: false };
  return requestJson<ExecResult>(
    `/v1/sandboxes/${encodeURIComponent(id)}/exec`,
    {
      method: "POST",
      body: JSON.stringify(payload),
      signal,
    },
  );
}

export function execBackground(
  id: string,
  req: ExecRequest,
  signal?: AbortSignal,
): Promise<BackgroundProcess> {
  const payload: ExecRequest = { ...req, background: true };
  return requestJson<BackgroundProcess>(
    `/v1/sandboxes/${encodeURIComponent(id)}/exec`,
    {
      method: "POST",
      body: JSON.stringify(payload),
      signal,
    },
  );
}

export async function execStream(
  id: string,
  req: ExecRequest,
  onEvent: (event: ExecNdjsonEvent) => void,
  signal?: AbortSignal,
): Promise<void> {
  const payload: ExecRequest = { ...req, background: false };
  const res = await fetch(
    `/v1/sandboxes/${encodeURIComponent(id)}/exec?stream=true`,
    {
      method: "POST",
      credentials: "same-origin",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/x-ndjson",
      },
      body: JSON.stringify(payload),
      signal,
    },
  );
  await readNdjsonStream(res, onEvent, signal);
}

export function listProcesses(
  id: string,
  signal?: AbortSignal,
): Promise<ProcessInfo[]> {
  return requestJson<ProcessInfo[]>(
    `/v1/sandboxes/${encodeURIComponent(id)}/processes`,
    { signal },
  );
}

export async function processLogsStream(
  id: string,
  procId: string,
  opts: { tail?: number; follow?: boolean; signal?: AbortSignal },
  onEvent: (event: ExecNdjsonEvent) => void,
): Promise<void> {
  const params = new URLSearchParams();
  if (opts.tail !== undefined) {
    params.set("tail", String(opts.tail));
  }
  if (opts.follow) {
    params.set("follow", "true");
  }
  const qs = params.toString();
  const url = `/v1/sandboxes/${encodeURIComponent(id)}/processes/${encodeURIComponent(procId)}/logs${qs ? `?${qs}` : ""}`;
  const res = await fetch(url, {
    method: "GET",
    credentials: "same-origin",
    headers: { Accept: "application/x-ndjson" },
    signal: opts.signal,
  });
  await readNdjsonStream(res, onEvent, opts.signal);
}

export function signalProcess(
  id: string,
  procId: string,
  signalKind: SignalKind,
): Promise<void> {
  return requestNoContent(
    `/v1/sandboxes/${encodeURIComponent(id)}/processes/${encodeURIComponent(procId)}/signal`,
    {
      method: "POST",
      body: JSON.stringify({ signal: signalKind }),
    },
  );
}

export function deleteProcess(id: string, procId: string): Promise<void> {
  return requestNoContent(
    `/v1/sandboxes/${encodeURIComponent(id)}/processes/${encodeURIComponent(procId)}`,
    { method: "DELETE" },
  );
}

// ---------------------------------------------------------------------------
// 3. File Upload & Sanitized Download
// ---------------------------------------------------------------------------

export function inferUploadContentType(filename: string): UploadContentType {
  const lower = filename.toLowerCase();
  if (lower.endsWith(".tar.gz") || lower.endsWith(".tgz") || lower.endsWith(".gz")) {
    return "application/gzip";
  }
  if (lower.endsWith(".tar")) {
    return "application/x-tar";
  }
  return "application/octet-stream";
}

export async function uploadFile(
  id: string,
  destPath: string,
  data: Blob | ArrayBuffer | Uint8Array,
  contentType: UploadContentType,
  signal?: AbortSignal,
): Promise<UploadResult> {
  const params = new URLSearchParams({ path: destPath });
  const body: BodyInit =
    data instanceof Uint8Array
      ? new Uint8Array(data).buffer
      : data;
  const res = await fetch(
    `/v1/sandboxes/${encodeURIComponent(id)}/files?${params.toString()}`,
    {
      method: "PUT",
      credentials: "same-origin",
      headers: {
        "Content-Type": contentType,
        Accept: "application/json",
      },
      body,
      signal,
    },
  );
  if (!res.ok) {
    throw await parseErrorResponse(res);
  }
  return (await res.json()) as UploadResult;
}

export async function downloadFile(
  id: string,
  path: string,
  format: DownloadFormatQuery,
  signal?: AbortSignal,
): Promise<{ blob: Blob; meta: DownloadMeta }> {
  const params = new URLSearchParams({ path, format });
  const res = await fetch(
    `/v1/sandboxes/${encodeURIComponent(id)}/files?${params.toString()}`,
    {
      method: "GET",
      credentials: "same-origin",
      signal,
    },
  );
  if (!res.ok) {
    throw await parseErrorResponse(res);
  }
  const blob = await res.blob();
  const parseNum = (header: string, fallback: number): number => {
    const raw = res.headers.get(header);
    if (!raw) return fallback;
    const n = Number(raw);
    return Number.isFinite(n) ? n : fallback;
  };

  const meta: DownloadMeta = {
    sandbox_id: res.headers.get("x-blackwall-sandbox-id") ?? id,
    path,
    format,
    bytes: parseNum("x-blackwall-bytes", blob.size),
    files: parseNum("x-blackwall-files", format === "raw" ? 1 : 0),
    dirs: parseNum("x-blackwall-dirs", 0),
    sha256: res.headers.get("x-blackwall-sha256") ?? "",
    duration_ms: parseNum("x-blackwall-duration-ms", 0),
  };

  return { blob, meta };
}

export function listSandboxDir(
  id: string,
  path = "/workspace",
  signal?: AbortSignal,
): Promise<FsEntry[]> {
  const params = new URLSearchParams({ path });
  return requestJson<FsEntry[]>(
    `/v1/sandboxes/${encodeURIComponent(id)}/fs?${params.toString()}`,
    { signal },
  );
}

export function listSandboxPorts(
  id: string,
  signal?: AbortSignal,
): Promise<ListeningPort[]> {
  return requestJson<ListeningPort[]>(
    `/v1/sandboxes/${encodeURIComponent(id)}/ports`,
    { signal },
  );
}

export function listIngressPorts(
  id: string,
  signal?: AbortSignal,
): Promise<number[]> {
  return requestJson<number[]>(
    `/v1/sandboxes/${encodeURIComponent(id)}/ingress`,
    { signal },
  );
}

export function allowIngressPort(
  id: string,
  port: number,
): Promise<number[]> {
  return requestJson<number[]>(
    `/v1/sandboxes/${encodeURIComponent(id)}/ingress`,
    {
      method: "POST",
      body: JSON.stringify({ port }),
    },
  );
}

export function closeIngressPort(id: string, port: number): Promise<void> {
  return requestNoContent(
    `/v1/sandboxes/${encodeURIComponent(id)}/ingress/${encodeURIComponent(String(port))}`,
    { method: "DELETE" },
  );
}

export function listHostBridges(
  id: string,
  signal?: AbortSignal,
): Promise<HostServiceSpec[]> {
  return requestJson<HostServiceSpec[]>(
    `/v1/sandboxes/${encodeURIComponent(id)}/bridges`,
    { signal },
  );
}

export function attachHostBridge(
  id: string,
  req: AttachHostBridgeRequest,
): Promise<HostServiceSpec> {
  return requestJson<HostServiceSpec>(
    `/v1/sandboxes/${encodeURIComponent(id)}/bridges`,
    {
      method: "POST",
      body: JSON.stringify(req),
    },
  );
}

export function detachHostBridge(
  id: string,
  guestPort: number,
): Promise<void> {
  return requestNoContent(
    `/v1/sandboxes/${encodeURIComponent(id)}/bridges/${encodeURIComponent(String(guestPort))}`,
    { method: "DELETE" },
  );
}

// ---------------------------------------------------------------------------
// 4. Profiles & Images
// ---------------------------------------------------------------------------

export function listProfiles(signal?: AbortSignal): Promise<string[]> {
  return requestJson<string[]>("/v1/profiles", { signal });
}

export function getProfile(
  name: string,
  signal?: AbortSignal,
): Promise<SandboxSpec> {
  return requestJson<SandboxSpec>(
    `/v1/profiles/${encodeURIComponent(name)}`,
    { signal },
  );
}

export function createProfile(req: CreateProfileRequest): Promise<SandboxSpec> {
  return requestJson<SandboxSpec>("/v1/profiles", {
    method: "POST",
    body: JSON.stringify(req),
  });
}

export function deleteProfile(name: string): Promise<void> {
  return requestNoContent(`/v1/profiles/${encodeURIComponent(name)}`, {
    method: "DELETE",
  });
}

export function listImages(signal?: AbortSignal): Promise<BuiltImage[]> {
  return requestJson<BuiltImage[]>("/v1/images", { signal });
}

export function buildImage(req: BuildImageRequest): Promise<BuiltImage> {
  return requestJson<BuiltImage>("/v1/images/build", {
    method: "POST",
    body: JSON.stringify(req),
  });
}

export function deleteImage(contentHash: string): Promise<void> {
  return requestNoContent(`/v1/images/${encodeURIComponent(contentHash)}`, {
    method: "DELETE",
  });
}

// ---------------------------------------------------------------------------
// 5. PTY WebSocket & Ingress Proxy Helpers
// ---------------------------------------------------------------------------

export function buildPtyWsUrl(
  sandboxId: string,
  params: { cols: number; rows: number; cmd?: string; cwd?: string },
): string {
  const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
  const qs = new URLSearchParams({
    cols: String(Math.max(1, Math.floor(params.cols))),
    rows: String(Math.max(1, Math.floor(params.rows))),
  });
  if (params.cmd && params.cmd.trim().length > 0) {
    qs.set("cmd", params.cmd.trim());
  }
  if (params.cwd && params.cwd.trim().length > 0) {
    qs.set("cwd", params.cwd.trim());
  }
  return `${proto}//${window.location.host}/v1/sandboxes/${encodeURIComponent(sandboxId)}/pty?${qs.toString()}`;
}

export function buildProxyUrl(
  sandboxId: string,
  port: number,
  subPath = "/",
): string {
  const cleanSub = subPath.startsWith("/") ? subPath : `/${subPath}`;
  const origin = getPreviewOrigin();
  if (origin) {
    try {
      const parsed = new URL(origin);
      if (
        parsed.hostname === "127.0.0.1" ||
        parsed.hostname === "localhost" ||
        parsed.hostname === "::1" ||
        parsed.hostname === "[::1]"
      ) {
        const portSuffix = parsed.port ? `:${parsed.port}` : "";
        return `${parsed.protocol}//${port}-${encodeURIComponent(sandboxId)}.localhost${portSuffix}${cleanSub}`;
      }
    } catch {
      // Fall back to path-prefix preview URL if preview_origin isn't a standard URL.
    }
    return `${origin}/v1/sandboxes/${encodeURIComponent(sandboxId)}/proxy/${port}${cleanSub}`;
  }
  return `/v1/sandboxes/${encodeURIComponent(sandboxId)}/proxy/${port}${cleanSub}`;
}

export async function probeProxyPort(
  sandboxId: string,
  port: number,
  subPath = "/",
  signal?: AbortSignal,
): Promise<PortProbeResult> {
  const url = buildProxyUrl(sandboxId, port, subPath);
  const start = performance.now();
  try {
    const res = await fetch(url, {
      method: "GET",
      credentials: "same-origin",
      cache: "no-store",
      signal,
    });
    const latencyMs = Math.round(performance.now() - start);
    const contentType = res.headers.get("content-type") ?? "unknown";
    let bodyPreview = "";
    try {
      const text = await res.text();
      bodyPreview = text.length > 600 ? `${text.slice(0, 600)}…` : text;
    } catch {
      bodyPreview = "<unreadable body>";
    }
    return {
      ok: res.ok,
      status: res.status,
      statusText: res.statusText,
      latencyMs,
      contentType,
      bodyPreview,
    };
  } catch (err) {
    const latencyMs = Math.round(performance.now() - start);
    return {
      ok: false,
      status: 0,
      statusText: "Network Error",
      latencyMs,
      contentType: "",
      bodyPreview: "",
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

// ---------------------------------------------------------------------------
// 6. Proxy & Audit Logs
// ---------------------------------------------------------------------------

function buildAuditUrl(opts: {
  sandboxId?: string;
  limit?: number;
  follow: boolean;
}): string {
  const params = new URLSearchParams();
  if (opts.limit !== undefined) {
    params.set("limit", String(Math.max(1, Math.floor(opts.limit))));
  }
  params.set("follow", opts.follow ? "true" : "false");
  const qs = params.toString();
  if (opts.sandboxId) {
    return `/v1/sandboxes/${encodeURIComponent(opts.sandboxId)}/audit?${qs}`;
  }
  return `/v1/audit?${qs}`;
}

export function listAuditEvents(opts?: {
  sandboxId?: string;
  limit?: number;
  signal?: AbortSignal;
}): Promise<AuditEvent[]> {
  const url = buildAuditUrl({
    sandboxId: opts?.sandboxId,
    limit: opts?.limit,
    follow: false,
  });
  return requestJson<AuditEvent[]>(url, { signal: opts?.signal });
}

export async function streamAuditEvents(opts: {
  sandboxId?: string;
  limit?: number;
  onEvent: (ev: AuditEvent) => void;
  onOpen?: () => void;
  signal?: AbortSignal;
}): Promise<void> {
  const url = buildAuditUrl({
    sandboxId: opts.sandboxId,
    limit: opts.limit,
    follow: true,
  });
  const res = await fetch(url, {
    method: "GET",
    credentials: "same-origin",
    headers: { Accept: "application/x-ndjson" },
    signal: opts.signal,
  });
  await readJsonLinesStream(
    res,
    isAuditEvent,
    opts.onEvent,
    opts.signal,
    opts.onOpen,
  );
}
