// Complete TypeScript definitions matching blackwall-core, blackwall-policy,
// blackwall-proto, blackwall-oci, and blackwall-daemon JSON schemas.

export type SandboxState = "starting" | "running" | "stopping" | "stopped";

export type NetworkMode = "none" | "loopback" | "egress";

export type SignalKind = "SIGTERM" | "SIGKILL" | "SIGINT";

export type UploadKind = "raw" | "tar" | "targz";

export type UploadContentType =
  | "application/octet-stream"
  | "application/x-tar"
  | "application/gzip";

export type DownloadFormat = "raw" | "targz";

export type DownloadFormatQuery = "raw" | "tar.gz";

export type ProcessState = "running" | "exited";

export type CtrlErrorCode =
  | "invalid_request"
  | "not_found"
  | "permission_denied"
  | "path_violation"
  | "limit_exceeded"
  | "timeout"
  | "internal";

export interface ComputeSpec {
  vcpus: number;
  memory_mib: number;
  workspace_mib: number;
  idle_timeout_sec: number;
  max_wall_time_sec: number;
}

export interface ImageSpec {
  ref?: string | null;
  base?: string | null;
  packages: string[];
  run: string[];
}

export type AuthSpec =
  | {
      kind: "bearer";
      secret: string;
    }
  | {
      kind: "header";
      secret: string;
      name: string;
      prefix?: string | null;
    }
  | {
      kind: "basic";
      secret: string;
      username: string;
    };

export interface HttpRule {
  host: string;
  port: number;
  methods: string[];
  path_prefixes: string[];
  max_request_bytes?: number | null;
  auth?: AuthSpec | null;
}

export interface PostgresRule {
  host: string;
  port: number;
  secret: string;
  require_upstream_tls: boolean;
}

export interface NetworkSpec {
  mode: NetworkMode;
  http: HttpRule[];
  postgres: PostgresRule[];
}

export interface IngressSpec {
  allow_ports: number[];
}

export interface HostServiceSpec {
  name: string;
  guest_port: number;
  target: string; // e.g. "127.0.0.1:5435" or "unix:///run/pg.sock"
}

export interface AttachHostBridgeRequest {
  name?: string;
  guest_port: number;
  target: string;
}

export interface SecretSpec {
  placeholder_prefix: string;
  sealed?: string | null;
  ephemeral?: string | null;
}

export interface ExportSpec {
  max_bytes: number;
  max_files: number;
  deny_touch_globs: string[];
}

export interface PolicyGovernance {
  locked: boolean;
  max_vcpus?: number | null;
  max_memory_mib?: number | null;
  max_workspace_mib?: number | null;
  max_idle_timeout_sec?: number | null;
  max_wall_time_sec?: number | null;
  max_export_bytes?: number | null;
  max_export_files?: number | null;
}

export interface SandboxSpec {
  version: number;
  name: string;
  image: ImageSpec;
  compute: ComputeSpec;
  network: NetworkSpec;
  ingress?: IngressSpec;
  host_services?: HostServiceSpec[];
  secrets: Record<string, SecretSpec>;
  env: Record<string, string>;
  export: ExportSpec;
  policy: PolicyGovernance;
}

export interface ImagePatch {
  ref?: string;
  base?: string;
  packages?: string[];
  run?: string[];
}

export interface ComputePatch {
  vcpus?: number;
  memory_mib?: number;
  workspace_mib?: number;
  idle_timeout_sec?: number;
  max_wall_time_sec?: number;
}

export interface NetworkPatch {
  mode?: NetworkMode;
  http?: HttpRule[];
  postgres?: PostgresRule[];
  restrict_hosts?: string[];
}

export interface IngressPatch {
  allow_ports?: number[];
}

export interface ExportPatch {
  max_bytes?: number;
  max_files?: number;
  deny_touch_globs?: string[];
}

export interface ProfileDraft {
  version?: number;
  name?: string;
  extends?: string[];
  image?: ImagePatch;
  compute?: ComputePatch;
  network?: NetworkPatch;
  ingress?: IngressPatch;
  host_services?: HostServiceSpec[];
  secrets?: Record<string, SecretSpec>;
  env?: Record<string, string>;
  export?: ExportPatch;
  policy?: Partial<PolicyGovernance>;
}

export interface SandboxRunStats {
  exec_count: number;
  exec_failed_count: number;
  total_exec_duration_ms: number;
  background_spawned_count: number;
  pty_sessions_count: number;
  ingress_connections_count?: number;
  upload_count: number;
  upload_bytes: number;
  download_count: number;
  download_bytes: number;
  last_activity_at: number;
}

export interface ProcessInfo {
  proc_id: string;
  pid: number;
  cmd: string[];
  state: ProcessState;
  exit_code: number | null;
}

export interface SandboxSummary {
  id: string;
  profile: string;
  state: SandboxState;
  image_roothash: string;
  image_content_hash?: string;
  kernel_profile?: string;
  vmm_backend?: string;
  vmm_pid?: number;
  proxy_pid?: number | null;
  proxy_isolated?: boolean;
  boot_duration_ms?: number;
  guest_init_version?: string;
  workspace_mounted?: boolean;
  netbridge_ready?: boolean;
  compute: ComputeSpec;
  network_mode: NetworkMode;
  allowed_hosts?: string[];
  ingress_allow_ports?: number[];
  host_services?: HostServiceSpec[];
  created_at: number;
  expires_at: number;
  idle_deadline_at: number;
  uptime_sec?: number;
  idle_remaining_sec?: number;
  wall_remaining_sec?: number;
}

export interface SandboxDetail {
  id: string;
  profile: string;
  state: SandboxState;
  image_roothash: string;
  image_content_hash?: string;
  kernel_profile?: string;
  vmm_backend?: string;
  proxy_pid?: number | null;
  proxy_isolated?: boolean;
  boot_duration_ms?: number;
  guest_init_version?: string;
  workspace_mounted?: boolean;
  netbridge_ready?: boolean;
  created_at: number;
  expires_at: number;
  idle_deadline_at: number;
  uptime_sec?: number;
  idle_remaining_sec?: number;
  wall_remaining_sec?: number;
  compute: ComputeSpec;
  network_mode: NetworkMode;
  allowed_hosts: string[];
  ingress_allow_ports?: number[];
  ingress?: IngressSpec;
  host_services?: HostServiceSpec[];
  pinned_dns?: Record<string, string[]>;
  configured_secrets?: string[];
  export: ExportSpec;
  processes: ProcessInfo[];
  vmm_pid: number;
  stats?: SandboxRunStats;
}

export interface ExecRequest {
  cmd: string[];
  cwd?: string;
  env?: Record<string, string>;
  stdin?: string;
  timeout_sec?: number;
  background?: boolean;
}

export interface ExecResult {
  sandbox_id?: string;
  cmd?: string[];
  cwd?: string;
  exit_code: number;
  success?: boolean;
  stdout: string;
  stderr: string;
  stdout_bytes_len?: number;
  stderr_bytes_len?: number;
  timed_out: boolean;
  duration_ms: number;
  started_at_ms?: number;
  finished_at_ms?: number;
}

export type ExecNdjsonEvent =
  | { type: "stdout"; data: string }
  | { type: "stderr"; data: string }
  | { type: "exit"; exit_code: number; timed_out: boolean; duration_ms: number }
  | { type: "end" }
  | { type: "error"; code: CtrlErrorCode | string; message: string };

export interface BackgroundProcess {
  sandbox_id?: string;
  proc_id: string;
  pid: number;
  cmd?: string[];
  cwd?: string;
  started_at_ms?: number;
}

export interface UploadResult {
  sandbox_id?: string;
  path?: string;
  kind?: UploadKind;
  bytes_written: number;
  files_written: number;
  duration_ms?: number;
}

export interface DownloadMeta {
  sandbox_id: string;
  path: string;
  format: DownloadFormatQuery;
  bytes: number;
  files: number;
  dirs: number;
  sha256: string;
  duration_ms: number;
}

export interface DmVerityConfig {
  roothash_hex: string;
  salt_hex: string;
  data_blocks: number;
  hash_start_block: number;
  data_block_size: number;
  hash_block_size: number;
}

export interface BuiltImage {
  content_hash: string;
  erofs_path: string;
  verity: DmVerityConfig;
}

export interface FsEntry {
  name: string;
  path: string;
  kind: "dir" | "file" | "symlink" | "symlink_dir" | "other";
  mode: string;
  mtime: number;
  size: number;
  is_dir: boolean;
}

export interface KeepaliveResponse {
  id: string;
  idle_deadline_at: number;
  idle_remaining_sec: number;
  expires_at: number;
  wall_remaining_sec: number;
}

export interface ListeningPort {
  port: number;
  address: string;
  allowed: boolean;
  proxy_url: string;
}

export interface CreateProfileRequest {
  name: string;
  toml?: string;
  draft?: ProfileDraft;
}

export interface BuildImageRequest {
  oci_ref?: string;
  profile?: string;
}

export interface ApiErrorBody {
  code: string;
  message: string;
}

export type PtyClientMessage = {
  type: "resize";
  cols: number;
  rows: number;
};

export type PtyServerMessage = {
  type: "exit";
  code: number;
};

export interface PortProbeResult {
  ok: boolean;
  status: number;
  statusText: string;
  latencyMs: number;
  contentType: string;
  bodyPreview: string;
  error?: string;
}

export type PrincipalRole = "operator" | "user" | "agent";

export interface AuthStatus {
  authenticated: boolean;
  preview_origin: string | null;
  role?: PrincipalRole;
  readonly_profiles?: boolean;
  require_locked_profiles?: boolean;
  has_policy_ceiling?: boolean;
  allow_image_build?: boolean;
}

export type AuditOrigin =
  | "daemon"
  | "proxy"
  | "unpacker"
  | "vmm"
  | "guest_untrusted";

export type TransferDirection = "upload" | "download";

export interface GuestAuditFrame {
  timestamp_ns: number;
  source: string;
  kind: string;
  payload: unknown;
}

export interface AuditEventBase {
  timestamp_ms: number;
  sandbox_id: string;
  origin?: AuditOrigin;
}

export interface HostServiceBridgeAuditEvent extends AuditEventBase {
  event: "host_service_bridge";
  name: string;
  guest_port: number;
  target: string;
  bytes_in: number;
  bytes_out: number;
  allowed: boolean;
}

export type AuditEvent =
  | (AuditEventBase & {
      event: "http_request";
      host: string;
      method: string;
      path: string;
      status: number;
      request_bytes: number;
      response_bytes: number;
      auth_injected: boolean;
    })
  | (AuditEventBase & {
      event: "dns_query";
      fqdn: string;
      allowed: boolean;
      synthetic_ip: string | null;
    })
  | (AuditEventBase & {
      event: "auth_mismatch";
      host: string;
      path: string;
      reason: string;
    })
  | (AuditEventBase & {
      event: "postgres_query";
      host: string;
      port: number;
      message_type: string;
      statement: string;
    })
  | (AuditEventBase & {
      event: "ingress_tunnel";
      guest_port: number;
      bytes_in: number;
      bytes_out: number;
      allowed: boolean;
    })
  | HostServiceBridgeAuditEvent
  | (AuditEventBase & {
      event: "exec_command";
      cmd: string[];
      cwd: string | null;
      background: boolean;
      exit_code: number | null;
      duration_ms: number | null;
    })
  | (AuditEventBase & {
      event: "file_transfer";
      direction: TransferDirection;
      path: string;
      bytes: number;
      files: number;
    })
  | (AuditEventBase & {
      event: "unpacker_rejection";
      path: string;
      reason: string;
    })
  | (AuditEventBase & {
      event: "sandbox_lifecycle";
      phase: string;
      image_roothash: string | null;
      details: string | null;
    })
  | (AuditEventBase & {
      event: "vmm_fatal_exit";
      reason: string;
      exit_detail: string;
    })
  | (AuditEventBase & {
      event: "guest_port1001";
      frame: GuestAuditFrame;
    });

export type AuditEventKindName = AuditEvent["event"];
