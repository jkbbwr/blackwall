# Blackwall — Threat Model & Bug-Assumption Matrix

> **Guiding Premise:** Guest userspace, the guest Linux kernel, the VMM, Rust crates, and Pingora are all assumed to contain exploitable bugs. **The host hypervisor kernel (`KVM` on Linux, `XNU + Hypervisor.framework` on macOS) and CPU silicon form the Trusted Computing Base (TCB).** Every control below separates **hard containment** from **detection / observability**.

---

## 1. Assets Protected

1. **Host Integrity & Confidentiality:** Host OS, user home directory, sibling VMs, and bare-metal control planes (eliminating any root daemon on Linux).
2. **Host-Execution Surfaces on File Extraction:** VCS internals (`.git/**`), CI workflows (`.github/**`), shell/direnv loaders (`.envrc`), IDE configs (`.vscode/**`), and build hooks (`.cargo/config.toml`, `Makefile`) when extracting files onto host disk.
3. **Third-Party Secrets:** API keys (Anthropic, OpenAI, GitHub, Stripe) and database credentials (`PostgreSQL` passwords) used on behalf of sandboxed workloads.
4. **Internal Network Reachability:** Host loopback (`127.0.0.1`), cloud instance metadata (`169.254.169.254`), link-local networks, and unapproved RFC1918 LAN services.
5. **Audit Integrity (via `AuditSink` Hooks):** Authoritative host-side record of session commands, network calls, SQL queries, and file extractions, extensible to tamper-evident remote witnessing (`immudb`).

---

## 2. Trusted Computing Base (TCB) & Explicit Hardware Limits

- **Host Kernel Hypervisor Is the TCB:** Host-side rootless jails (`userns`, `netns`, `pidns`, `nftables`, `Landlock`, `seccomp-bpf` on Linux; `Seatbelt`, optional `pf` on macOS) are enforced *by* the host kernel. A ring-0 vulnerability in `KVM` or `XNU`/`Hypervisor.framework` compromises the compute host. Blackwall shrinks hypervisor attack surface by avoiding host-kernel `vhost` drivers (`vhost-net`, `vhost-vsock`), disabling nested virtualization, stripping legacy emulated hardware, and isolating SMT siblings via `PR_SCHED_CORE` on Linux.
- **Zero Root Daemon on Linux:** Unlike container runtimes that rely on a privileged `root` daemon (a single high-value privilege-escalation target), `blackwall-daemon`, VMMs, `blackwall-proxy`, `pasta`, and `blackwall-unpacker` run 100% unprivileged.
- **Consumer Hardware Confidential Computing Limits:** Consumer x86 and Apple Silicon lack AMD SEV-SNP / Intel TDX; a malicious host administrator can inspect guest RAM on those machines. On EPYC/Xeon servers supporting SEV-SNP or TDX, Blackwall opportunistically enables confidential VM memory encryption.
- **Microarchitectural Side Channels on macOS:** XNU does not expose Linux `PR_SCHED_CORE` cookies; Apple Silicon relies on architectural isolation (PAC + BTI, SPTM on M2+, and EMTE/MIE on M5+).

---

## 3. Component Compromise Matrix

### Scenario A: Guest Userspace RCE -> Credential Theft, BYO-Token Exfil & Unauthorized Egress

| Attack Vector | Hard Containment Mechanism | Residual Risk & Detection (Not Containment) |
| :--- | :--- | :--- |
| **Dump `/proc/self/environ` or guest memory for API keys / DB passwords** | Secrets (`seal1_...` or ephemeral `0600`-socket secrets) are held exclusively inside that VM's per-VM `blackwall-proxy` `memfd_secret`/`mlock` memory. Guest holds only a **256-bit random per-VM placeholder** (`ghp_bw00<random>`) carrying zero cryptographic link to the real secret. | Attacker can invoke the permitted upstream API within the VM's TTL and byte/rate budgets. |
| **Bring-Your-Own-Credential Exfiltration to an Allowlisted Host** (e.g., sending `Authorization: Bearer ghp_ATTACKER_TOKEN` to `api.github.com` to push code to an attacker gist/repo) | **Mandatory Auth Stripping & Identity Pinning:** On every `[[network.http]]` rule with an `auth` block, `blackwall-proxy` verifies the guest's random placeholder, strips all guest-supplied auth headers/cookies (`Authorization`, `Cookie`, `X-Api-Key`, `Proxy-*`, `x-amz-*`), and overwrites them with the host-brokered credential restricted to tenant-pinned `path_prefixes` (e.g., `/repos/my-org/my-repo/` or `/my-org/my-repo.git/`). | **Residual L7 Covert Channel:** If policy permits writes to a multi-tenant endpoint where the brokered token itself can write externally readable state (e.g., a public GitHub issue comment), data can be exfiltrated inside valid L7 payloads. Host-side `AuditSink` HTTP logging provides attribution, not prevention. |
| **Destructive SQL or Server-Side Exec on Allowed Postgres (`COPY ... TO PROGRAM`, `DROP TABLE`)** | 1) Downstream TLS cleartext -> upstream `SCRAM-SHA-256` pins the connection to a dedicated **least-privilege PostgreSQL `ROLE`**.<br/>2) **Database-enforced `GRANT`s, Row-Level Security (RLS), and revocation of `pg_execute_server_program` / superuser** enforce hard data & DDL boundaries. | Proxy parses Frontend `'Q'`/`'P'`/`'B'`/`'E'` frames strictly for `AuditSink` logging — never relying on SQL regex blocklists. |
| **Bypass `HTTP_PROXY` / `LD_PRELOAD` with static binaries or raw syscalls** | Guest kernel has zero external NICs (`CONFIG_VIRTIO_NET=n`, `CONFIG_NETFILTER=n`, `CONFIG_PACKET=n`, `CONFIG_IO_URING=n`). In `egress` mode, all non-loopback packets route exclusively into `tun0` -> `blackwall-netbridge` -> `Port 1000` -> `blackwall-proxy`. In `loopback` mode, no egress path or proxy exists. In `none` mode (`CONFIG_INET=n`), all `AF_INET`/`AF_INET6` syscalls return `EAFNOSUPPORT`. | Zero unmediated network path exists inside the VM. |

---

### Scenario B: Malicious Extracted Files / Archives (`Port 1002` Download)

| Attack Vector | Hard Containment Mechanism | Residual Risk & Operational Guidance |
| :--- | :--- | :--- |
| **Archive traversal (`..`), symlink escape, device nodes, setuid bits, or zip-bomb on `GET /files`** | Jailed `blackwall-unpacker` validates every entry from `Port 1002` in a streaming pass, enforces `export.max_bytes` / `export.max_files`, rejects symlinks, hardlinks, FIFOs, char/block devices, absolute/`..` paths, and **canonically re-packs** `.tar.gz` outputs so host tools never parse raw guest-generated archive bytes. | Bounded output size only; callers receive inert files/archives. |
| **Extracted files overwrite host-execution hooks (`.github/workflows`, `.envrc`, `.cargo/config.toml`, `Makefile`) or bypass globs via macOS APFS case-insensitivity (`.GitHub`, `.ENVRC`)** | Whenever unpacking onto a host directory, `blackwall-unpacker` normalizes **ASCII case + Unicode (NFC/NFD)**, rejects case-colliding paths, and blocks paths matching `export.deny_touch_globs` unless explicitly approved by a human. | **Residual Code-Execution Risk:** Normal source files (`build.rs`, proc-macros, tests, scripts) *will* execute on the host if a developer runs them outside a sandbox. Run verification builds/tests inside a fresh Blackwall VM before trusting outputs. |
| **Accidentally uploading host secrets (`.env`, `.git/config`) into a sandbox** | Upload is explicit via `PUT /files` (zero ambient host bind mounts). The CLI/SDK `--exclude-secrets` upload filter skips `.env*`, `.npmrc`, `.pypirc`, `.netrc`, `.git/config`, `*.pem`, `*.key`, and `id_*` before bytes ever cross `Port 1002`. | Secrets hardcoded inside regular source files uploaded by the caller enter `/workspace` like any other file. |

---

### Scenario C: Guest Linux Kernel 0-Day (Arbitrary Ring-0 Execution Inside Guest)

Once an attacker achieves ring-0 inside the guest, **every in-guest component (`blackwall-init`, `blackwall-netbridge`, `tun0`, guest namespaces, and any future Layer 1 BPF LSM plugin on `Port 1001`) is completely untrusted.**

*(Note on `vmlinux-lo` vs `vmlinux-noinet`: `loopback` and `egress` modes retain minimal in-kernel loopback TCP/UDP (+ `tun` for `egress`) for 100% POSIX compatibility with zero `netfilter`/`packet`/`xfrm`/`io_uring`. Because guest ring-0 is already assumed compromisable, host containment relies strictly on the hypervisor and host jails below. Maximum-hardening offline workloads use `network.mode = "none"` on `vmlinux-noinet` with `CONFIG_INET=n`.)*

What still holds outside the VM:
1. **No Host Filesystem Mount of `vdb`:** The encrypted `/workspace` disk is an unlinked host `O_TMPFILE` whose `dm-crypt` key exists only in guest RAM. Even if ring-0 writes weaponized `ext4` superblocks to `vdb`, the host kernel never mounts or parses `vdb` — it simply `close()`s the fd on teardown (and ephemeral encryption provides cryptographic erasure on host crash/power loss).
2. **Immutable Base Image (`vda`):** Attached read-only (`O_RDONLY` fd) at the VMM `virtio-blk` layer; guest ring-0 writes to `vda` are rejected by the VMM regardless of bypassing `dm-verity` inside the guest.
3. **Host-Enforced Network & File Extraction:** All bytes leaving `virtio-vsock` still terminate exclusively in that VM's dedicated jailed `blackwall-proxy` and `blackwall-unpacker` processes.

---

### Scenario D: VMM 0-Day (`cloud-hypervisor` / HVF) or Pingora Parser 0-Day

`Port 1000` carries attacker-controlled TLS, HTTP/1.1, HTTP/2, and Postgres wire bytes straight into `blackwall-proxy`. Both the VMM and `blackwall-proxy` are isolated **per-VM** under the assumption that either process can be compromised:

| Compromised Host Process | Containment Boundary Enforced by Host OS (Rootless Linux) |
| :--- | :--- |
| **VMM Process RCE** (`virtio-blk` / `virtio-vsock` / MMIO emulation bug) | • **Zero Network:** Empty `CLONE_NEWNET` (not even `lo`) + `seccomp-bpf` (`connect()` denied; only `accept4` on the ephemeral handshake socket before host `unlink()`).<br/>• **Zero Host Filesystem & Zero Cross-VM Ptrace:** Pre-`exec` `pivot_root` into empty tmpfs + Landlock + `CLONE_NEWUSER` + `CLONE_NEWPID` + `PR_SET_DUMPABLE=0`.<br/>• **SMT Isolation:** Per-VM `PR_SCHED_CORE` cookie blocks cross-hyperthread L1/MDS leakage against sibling VMs or host tasks. |
| **Per-VM `blackwall-proxy` (Pingora) RCE** (HTTP/2, TLS, or SQL parser bug) | • **Strictly 1 Process Per VM:** Exposes *only* that single VM's ephemeral CA and secrets — zero cross-VM visibility (`CLONE_NEWPID`, `PR_SET_DUMPABLE=0`).<br/>• **Kernel-Enforced Rootless Outbound IP Pinning:** Setup helper configures `nftables` inside the proxy's `CLONE_NEWUSER + CLONE_NEWNET` (bridged via `pasta`) to allow only exact resolver-pinned allowlisted IP:port pairs (hard-blocking `127.0.0.0/8`, `169.254.169.254`, RFC1918, and arbitrary attacker C2 IPs), then drops all capabilities (`PR_SET_NO_NEW_PRIVS=1`) and blocks `unshare`/`setns`/netlink via `seccomp-bpf` before `exec`ing Pingora — so shellcode inside Pingora **cannot** modify its own `nftables`.<br/>• **Zero Host Disk Access:** Runs in an empty `pivot_root` + Landlock jail with zero host filesystem visibility. |

---

### Scenario E: Hypervisor Traps & Audit Integrity

1. **Deterministic Hypervisor Trap Handling:** The VMM halts immediately on architecturally invalid exits (`KVM_EXIT_INTERNAL_ERROR`, `KVM_EXIT_UNKNOWN`, triple fault, unhandled MMIO outside registered `virtio` windows, and guest `oops=panic`), emitting a `VmmFatalExit` event to `AuditSink`.
2. **Post-Compromise Log Tampering:** If a TCB 0-day (`KVM` / `XNU`) compromises the compute host itself, local logs on that host can no longer be trusted going forward. Blackwall's `AuditSink` trait is designed so production deployments can plug in a remote append-only witness (e.g., `immudb` with `VerifiableExecAll` consistency proofs) on a separate administrative host without modifying the core runtime.
