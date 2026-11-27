export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"] as const;
  let value = bytes;
  let idx = 0;
  while (value >= 1024 && idx < units.length - 1) {
    value /= 1024;
    idx += 1;
  }
  const unit = units[idx] ?? "B";
  return `${value >= 100 || idx === 0 ? value.toFixed(0) : value.toFixed(1)} ${unit}`;
}

export function formatMib(mib: number): string {
  if (mib >= 1024) {
    const gib = mib / 1024;
    return `${Number.isInteger(gib) ? gib : gib.toFixed(1)} GiB`;
  }
  return `${mib} MiB`;
}

export function formatDurationSec(totalSec: number): string {
  const sec = Math.max(0, Math.floor(totalSec));
  const hours = Math.floor(sec / 3600);
  const mins = Math.floor((sec % 3600) / 60);
  const rem = sec % 60;
  if (hours > 0) {
    return `${hours}h ${String(mins).padStart(2, "0")}m ${String(rem).padStart(2, "0")}s`;
  }
  if (mins > 0) {
    return `${mins}m ${String(rem).padStart(2, "0")}s`;
  }
  return `${rem}s`;
}

export function formatDurationMs(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(2)}s`;
  return formatDurationSec(ms / 1000);
}

export function formatUnixTime(unixSec: number): string {
  if (!unixSec || unixSec <= 0) return "—";
  const d = new Date(unixSec * 1000);
  return d.toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
}

export function formatTimestampMs(tsMs: number): string {
  if (!Number.isFinite(tsMs) || tsMs <= 0) return "—";
  const d = new Date(tsMs);
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");
  const ss = String(d.getSeconds()).padStart(2, "0");
  const mmm = String(d.getMilliseconds()).padStart(3, "0");
  return `${hh}:${mm}:${ss}.${mmm}`;
}

export function formatUnixDateTime(unixSec: number): string {
  if (!unixSec || unixSec <= 0) return "—";
  const d = new Date(unixSec * 1000);
  return `${d.toISOString().replace("T", " ").slice(0, 19)} UTC`;
}

export function shortHash(hash: string | undefined | null, chars = 16): string {
  if (!hash) return "—";
  if (hash.length <= chars) return hash;
  return `${hash.slice(0, chars)}…`;
}

export function shortId(id: string): string {
  return id.length > 12 ? id.slice(0, 12) : id;
}

/** Parse a command line into argv tokens respecting single/double quotes and backslash escapes. */
export function parseCommandLine(input: string): string[] {
  const args: string[] = [];
  let current = "";
  let inSingle = false;
  let inDouble = false;
  let escaped = false;
  let hasToken = false;

  for (let i = 0; i < input.length; i += 1) {
    const ch = input[i];
    if (ch === undefined) continue;

    if (escaped) {
      current += ch;
      escaped = false;
      hasToken = true;
      continue;
    }

    if (ch === "\\" && !inSingle) {
      escaped = true;
      hasToken = true;
      continue;
    }

    if (ch === "'" && !inDouble) {
      inSingle = !inSingle;
      hasToken = true;
      continue;
    }

    if (ch === '"' && !inSingle) {
      inDouble = !inDouble;
      hasToken = true;
      continue;
    }

    if (/\s/.test(ch) && !inSingle && !inDouble) {
      if (hasToken) {
        args.push(current);
        current = "";
        hasToken = false;
      }
      continue;
    }

    current += ch;
    hasToken = true;
  }

  if (hasToken) {
    args.push(current);
  }
  return args;
}

export async function copyToClipboard(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    try {
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      const ok = document.execCommand("copy");
      document.body.removeChild(ta);
      return ok;
    } catch {
      return false;
    }
  }
}

export function extractFilenameFromPath(path: string, format: "raw" | "tar.gz"): string {
  const trimmed = path.replace(/\/+$/, "");
  const parts = trimmed.split("/").filter(Boolean);
  const last = parts[parts.length - 1] ?? "workspace";
  if (format === "tar.gz") {
    return last.endsWith(".tar.gz") || last.endsWith(".tgz")
      ? last
      : `${last}.tar.gz`;
  }
  return last;
}

export function triggerBlobDownload(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  window.setTimeout(() => URL.revokeObjectURL(url), 5000);
}
