# Blackwall — Engineering Roadmap & Workspace Blueprint

> **Build Strategy:** Ship a rock-solid, 100% rootless **Linux KVM (`cloud-hypervisor`)** interactive LLM sandbox end-to-end first (Phases 1–4), then expand to **Apple Silicon macOS (HVF)** in Phase 5 and warm pools / pluggable audit backends in Phase 6.

---

## 1. Rust Workspace & Repository Layout

```text
blackwall/
├── Cargo.toml                        # Workspace root (panic = "abort", overflow-checks = true, LTO)
├── docs/
│   ├── ARCHITECTURE.md               # System topology, rootless jails, 2-disk I/O, Pingora, vsock mux
│   ├── API.md                        # Composable SandboxSpec profiles + HTTP-over-UDS interactive API
│   ├── THREAT_MODEL.md               # TCB definition & containment vs. detection matrix
│   ├── KERNEL_HARDENING.md           # vmlinux-lo & vmlinux-noinet 6.12+ Kconfig + forced cmdline spec
│   └── ROADMAP.md                    # Phased Linux-first build & verification plan
├── kernel/
│   ├── configs/
│   │   ├── common-hardened.config    # KSPP + minimal virtio + erofs/verity/crypt + SYSVIPC + lockdown
│   │   ├── loopback-tun.fragment     # Default interactive profile (CONFIG_INET=y + TUN, zero NICs/netfilter)
│   │   ├── noinet.fragment           # Strict offline profile (CONFIG_INET=n, CONFIG_TUN=n)
│   │   ├── x86_64.fragment           # KVM x86_64 (CONFIG_MITIGATION_*, IBT, SEV-SNP/TDX guest)
│   │   └── aarch64.fragment          # ARM64 / Apple Silicon HVF (PAC/BTI/SCS)
│   └── scripts/build-kernel.sh       # Reproducible `make LLVM=1 LLVM_IAS=1` kernel + initramfs builder
├── crates/
│   ├── blackwall-proto/              # `#![no_std]`-friendly Port 1000/1001/1002 wire framing & RPC schemas
│   ├── blackwall-audit/              # `AuditSink` trait, strongly typed `AuditEvent` structs, no-op/JSONL default
│   ├── blackwall-policy/             # Composable `SandboxSpec` + `base` defaults + `extends` merge & narrow-only lock
│   ├── blackwall-secrets/            # HPKE X25519 `seal1_` seal/open + `memfd_secret` + random SDK placeholders
│   ├── blackwall-oci/                # OCI -> stripped `erofs + dm-verity` rootfs (`vda`) builder
│   ├── blackwall-unpacker/           # Jailed canonical file / `.tar.gz` validator & re-packer + `deny_touch_globs`
│   ├── blackwall-proxy/              # Per-VM rootless Pingora TLS MITM + auth strip/pin + Postgres SCRAM proxy
│   ├── blackwall-vmm/                # Unified `VmmBackend` trait + host-initiated `vsock` handshake
│   ├── blackwall-vmm-linux/          # Rootless `cloud-hypervisor` driver (pre-exec userns/netns/Landlock/seccomp/PR_SCHED_CORE)
│   ├── blackwall-vmm-macos/          # (Phase 5) Apple Silicon HVF VMM (`libkrun`/`rust-vmm`) + Seatbelt jail
│   ├── blackwall-core/               # Embeddable Rust SDK orchestrating sandbox + per-VM proxy/unpacker jails
│   ├── blackwall-daemon/             # Rootless HTTP-over-UDS interactive API + out-of-process DNS -> `nftables` IP-sets
│   └── blackwall-cli/                # `blackwall` CLI (`create`, `exec`, `shell`, `upload`, `download`, `destroy`, `image`, `secret`)
└── guest/                            # Cross-compiled static `musl` binaries embedded into initramfs (NEVER vda)
    ├── blackwall-init/               # PID 1: vsock handshake, dm-verity vda, RNG dm-crypt vdb, exec/bg-procs/PTY/files
    └── blackwall-netbridge/          # `tun0` + `smoltcp` userspace TCP/UDP/DNS bridge -> Port 1000
```

---

## 2. Phased Implementation Plan

### Phase 1: Hardened Guest Kernels, `blackwall-proto` & Rootless Linux VMM Bringup
**Goal:** Boot `vmlinux-lo` and `vmlinux-noinet` (`6.12+`) into initramfs `blackwall-init` on Linux KVM in `<150ms` and establish host-initiated `vsock` streams (`Ports 1000, 1001, 1002`) inside a 100% rootless `cloud-hypervisor` jail.
- [ ] Initialize Git repo, Rust workspace `Cargo.toml`, and `blackwall-audit` trait hooks (`AuditSink` + `AuditEvent` + default no-op/JSONL sink).
- [ ] Build `kernel/scripts/build-kernel.sh` (`make LLVM=1 LLVM_IAS=1`) producing `vmlinux-lo` and `vmlinux-noinet` (`x86_64`) with `CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY=y`, `# CONFIG_USER_NS is not set`, `CONFIG_IO_URING=n`, and forced built-in cmdline.
- [ ] Implement `blackwall-proto`: Port 1000 stream mux framing (`12-byte` header), Port 1001 unidirectional audit framing, and Port 1002 session control/exec/PTY/file RPC schemas (fuzz-tested with `cargo-fuzz`).
- [ ] Implement `blackwall-vmm` + `blackwall-vmm-linux`: launch `cloud-hypervisor` inside a pre-`exec` rootless jail (`CLONE_NEWUSER`, empty `CLONE_NEWNET`, `CLONE_NEWPID`, `pivot_root` with bind-mounted 1-file `vsock-dir/`, Landlock, `PR_SET_DUMPABLE=0`, `PR_SCHED_CORE`, `seccomp-bpf` allowing `accept4` and denying `connect()`), complete `CONNECT 1000/1001/1002\n` handshake, unlink `vsock.sock`, and `shutdown(SHUT_WR)` on Port 1001.
- **Verification Gate:** Prove `cloud-hypervisor` boots end-to-end rootless with `connect()` blocked by `seccomp-bpf`; verify `vmlinux-noinet` returns `EAFNOSUPPORT` on `socket(AF_INET, ...)` and `unshare(CLONE_NEWUSER)` returns `EINVAL` in both kernels.

---

### Phase 2: 2-Disk Storage (`vda`/`vdb`), Interactive `Port 1002` Sessions & Jailed `blackwall-unpacker`
**Goal:** Run real interactive multi-command sessions (`exec`, background processes, PTY) and safe file `upload`/`download` (`file` or `tar.gz`) with zero `virtiofs` and zero host filesystem mounts of writable guest disks.
- [ ] Implement `blackwall-oci`: build declarative `[image]` (`base`/`packages`/`run` via `docker build`/`podman build` at build time, content-addressed cache) or import existing OCI/Docker image -> strip setuid/caps -> `erofs + dm-verity` rootfs (`vda`) via `mkfs.erofs` + `veritysetup`.
- [ ] Extend `blackwall-init` (initramfs):
  - Receive `vda` `dm-verity` params over `Port 1002`, map `vda` via direct `/dev/mapper/control` ioctl (`DM_VERITY_MODE_PANIC`), and `switch_root` / pivot into `vda`.
  - Initialize unlinked `vdb` (`O_TMPFILE`) via direct `dm-crypt` (`aes-xts-plain64`, 256-bit guest-RAM key) + `ext4` mounted at `/workspace`.
  - Serve `Port 1002` session RPCs: synchronous/streaming `exec`, tracked background process handles (`proc_id`, log ring buffer, signals), interactive `PTY` with resize, and streaming `upload` / `download` (`file` or `tar.gz`).
- [ ] Implement jailed `blackwall-unpacker`: streaming validation and canonical `.tar.gz` re-packing enforcing `max_bytes`/`max_files`, rejecting `..`/symlinks/hardlinks/devices/setuid, and checking ASCII-case + Unicode-normalized `deny_touch_globs` when unpacking onto host disk.
- **Verification Gate:** Confirm flipping 1 byte in `vda` triggers immediate `dm-verity` kernel panic; run multi-turn `exec` + background server + PTY + 50 MB upload/download cleanly; confirm `blackwall-unpacker` rejects path traversal, symlinks, zip-bombs, and `.GitHub/workflows/ci.yml` / `.ENVRC` case-bypass attempts.

---

### Phase 3: `tun0`/`smoltcp` Egress Bridge & Rootless Per-VM Pingora + Postgres Proxy
**Goal:** Unmodified coding agents run local dev servers and PostgreSQL natively on `127.0.0.1` inside `vmlinux-lo`, while all outbound HTTPS, `git push`, and Postgres connections enforce identity pinning, zero-secret-in-guest brokering, and kernel `nftables` IP-set containment.
- [ ] Implement `blackwall-netbridge` (initramfs): configure `tun0` (`198.18.0.1/15`), synthetic DNS (`198.18.0.53`), and `smoltcp` userspace TCP/UDP termination bridging allowed FQDNs onto `Port 1000`.
- [ ] Implement `blackwall-secrets`: HPKE X25519 `seal1_` offline seal/open + ephemeral `0600`-socket secret intake -> `memfd_secret(0)` storage + SDK-shaped 256-bit random per-VM placeholders.
- [ ] Implement per-VM rootless jailed `blackwall-proxy`:
  - Rootless `CLONE_NEWUSER + CLONE_NEWNET + CLONE_NEWPID` bridged via `pasta`; out-of-process DNS resolver populates `nftables` IP-sets before setup drops all caps (`PR_SET_NO_NEW_PRIVS=1`), sets `PR_SET_DUMPABLE=0`, and installs Landlock + `seccomp-bpf` (blocking `unshare`/`setns`/netlink).
  - **Pingora** HTTP/1.1 & HTTP/2 + ephemeral ECDSA P-256 SNI MITM CA dialing exact resolver-pinned IPs, enforcing `methods`/`path_prefixes`/`max_request_bytes`, stripping guest auth, and injecting brokered header/Basic credentials.
  - Sibling Tokio **Postgres wire proxy**: downstream TLS + `AuthenticationCleartextPassword` placeholder validation -> upstream TLS (`sslmode=verify-full`) + `SCRAM-SHA-256` + `'Q'`/`'P'`/`'B'`/`'E'` `AuditEvent` emission.
- **Verification Gate:** Run local Postgres + `cargo test` binding `127.0.0.1:0` natively inside `vmlinux-lo`; verify guest sending `Authorization: Bearer ghp_ATTACKER` to `api.github.com` is stripped/pinned; verify `git push` over HTTPS and `psql` SCRAM work using random placeholders; verify simulated RCE inside `blackwall-proxy` cannot reach `127.0.0.1`, `169.254.169.254`, unapproved IPs, or flush its own `nftables`.

---

### Phase 4: Composable Policy Profiles, Daemon API, SDK & CLI (Linux MVP Complete)
**Goal:** Ergonomic, scriptable, fail-closed interactive LLM sandbox ready for real agent harnesses.
- [ ] Implement `blackwall-policy`: built-in `base` profile (`debian:bookworm-slim`, 1 GiB workspace, `network.mode = "loopback"` fail-closed offline), `extends = [...]` left-to-right composition with conflict detection, derived DNS allowlists, and `locked = true` narrow-only override ceilings.
- [ ] Implement rootless `blackwall-daemon`: HTTP/1.1 + JSON + NDJSON + WebSocket API on `$XDG_RUNTIME_DIR/blackwall.sock` (`0600`) covering lifecycle, `exec`, background processes, PTY, `PUT/GET /files`, profiles, and images, with `idle_timeout_sec` and `max_wall_time_sec` reaping.
- [ ] Ship `blackwall-core` Rust SDK and `blackwall-cli` (`create`, `exec`, `logs`, `shell`, `upload`, `download`, `destroy`, `image build`, `secret seal`).
- **Verification Gate:** Drive a full multi-turn interactive LLM coding session over the Unix socket (upload repo -> run background server + tests -> commit/push or download sanitized `.tar.gz` -> idle reap).

---

### Phase 5: Apple Silicon macOS Backend & Hardware Mitigations
**Goal:** First-class consumer Mac support using the exact same guest kernel, initramfs, proxy, and API.
- [ ] Implement `blackwall-vmm-macos`: boot `aarch64` `vmlinux-lo`/`vmlinux-noinet` on `Hypervisor.framework` (building on `libkrun` / `rust-vmm` HVF + `virtio-mmio` crates) with pre-opened `socketpair` vsock channels locked under `(deny default)` Seatbelt.
- [ ] Replace `mkfs.erofs` + `veritysetup` shell-outs in `blackwall-oci` with a deterministic pure-Rust `erofs` + `dm-verity` writer so image builds work identically on macOS and Linux.
- [ ] Opportunistically enable **AMD SEV-SNP / Intel TDX** on supported Linux servers, and ARM64 PAC/BTI + **M5+ EMTE (Memory Integrity Enforcement)** on macOS.

---

### Phase 6: Warm Pre-Booted Pool & Pluggable Extensions
**Goal:** `<15ms` cold-start dispatch and optional enterprise observability/storage plugins without bloating core isolation.
- [ ] Per-`(image_roothash, kernel_profile, vcpu_mem_shape)` warm pool of independently cold-booted VMs paused at `Handshake` (each with unique KASLR and empty encrypted `vdb` already mounted).
- [ ] Optional read-only `.erofs` `[[volumes]]` attachment for multi-GB immutable datasets.
- [ ] Optional `AuditSink` plugins: in-guest `blackwall-ebpf` (Aya `BPF_PROG_TYPE_LSM` + `tp_btf` compatible with `lockdown=confidentiality` on `Port 1001`), local BLAKE3 RFC 6962 Merkle spool + SQLite index, and remote `immudb` (`VerifiableExecAll`) witnessing.
- [ ] **Multi-Tier Auth Stack (`Operator -> User -> Agent`):** Extend the authorization seam already wired in `crates/blackwall-daemon/src/auth.rs` (`CallerContext` / `PrincipalRole` / `Capability` / `attach_default_operator_context`) with scoped bearer tokens and tiered Unix sockets so operators manage profiles/images, human users manage sandboxes/bridges/ingress, and autonomous agents are restricted to `CreateSandbox` + `OperateSandbox` under operator-enforced `--readonly-profiles`, `--require-locked-profiles`, and `--policy-ceiling` guardrails.
