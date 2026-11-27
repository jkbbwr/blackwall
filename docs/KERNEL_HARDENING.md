# Blackwall — Hardened Guest Linux Kernel Specification

Blackwall builds two minimal, reproducible hardened Linux guest kernels (`7.3+`) per target architecture (`x86_64` first, `aarch64` alongside/Phase 5), compiled with Clang/LLVM via **`make LLVM=1 LLVM_IAS=1`** (which auto-detects `CC_IS_CLANG` in Kbuild):

1. **`vmlinux-lo` (Primary Default — used by `loopback` and `egress` modes):** Minimal `CONFIG_INET=y` + `CONFIG_TUN=y` with **zero hardware/virtio NICs, zero Netfilter, zero `AF_PACKET`, zero XFRM, zero `io_uring`**. Provides 100% native POSIX loopback (`127.0.0.1`, `::1`, `0.0.0.0`); in `egress` mode, non-loopback traffic routes through in-guest `tun0` -> `blackwall-netbridge` (`smoltcp`) -> `AF_VSOCK` `Port 1000`.
2. **`vmlinux-noinet` (Strict Offline Profile — used by `none` mode):** Identical hardening baseline with **`CONFIG_INET=n`**, **`CONFIG_IPV6=n`**, and **`CONFIG_TUN=n`** — compiling out the entire TCP/IP stack while retaining `AF_UNIX` and `AF_VSOCK`.

---

## 1. Network Profile Fragments (`loopback`/`egress` vs. `none`)

### Shared Socket Base (`common-hardened.config`)
```kconfig
# Core socket layer kept for AF_UNIX and AF_VSOCK
CONFIG_NET=y
CONFIG_UNIX=y
CONFIG_VSOCKETS=y
CONFIG_VIRTIO_VSOCKETS=y
CONFIG_VIRTIO_VSOCKETS_COMMON=y

# High-CVE networking subsystems permanently compiled out in BOTH profiles
# CONFIG_NETFILTER is not set
# CONFIG_PACKET is not set
# CONFIG_NETLINK_DIAG is not set
# CONFIG_WIRELESS is not set
# CONFIG_BT is not set
# CONFIG_VIRTIO_NET is not set
# CONFIG_TLS is not set
# CONFIG_XFRM is not set
# CONFIG_SCTP is not set
# CONFIG_TIPC is not set
# CONFIG_RDS is not set
# CONFIG_L2TP is not set
```

### `loopback-tun.fragment` (Default Interactive Sandbox Kernel: `vmlinux-lo`)
```kconfig
# Minimal TCP/IP loopback + in-guest TUN device for blackwall-netbridge (smoltcp -> vsock)
CONFIG_INET=y
CONFIG_IPV6=y
CONFIG_NETDEVICES=y
CONFIG_NET_CORE=y
CONFIG_TUN=y
# Zero physical/virtual NIC drivers (no virtio-net, no e1000, no veth, no bridge)
# CONFIG_ETHERNET is not set
# CONFIG_VETH is not set
# CONFIG_BRIDGE is not set
```

### `noinet.fragment` (Strict Offline Kernel: `vmlinux-noinet`)
```kconfig
# Entire TCP/IP & TUN stack physically compiled out (socket(AF_INET, ...) -> EAFNOSUPPORT)
# CONFIG_INET is not set
# CONFIG_IPV6 is not set
# CONFIG_NETDEVICES is not set
# CONFIG_TUN is not set
```

---

## 2. Attack-Surface Elimination (`common-hardened.config`)

```kconfig
# No loadable modules, no kexec, no hibernation, no raw kernel memory access
# CONFIG_MODULES is not set
# CONFIG_KEXEC is not set
# CONFIG_KEXEC_FILE is not set
# CONFIG_HIBERNATION is not set
# CONFIG_SUSPEND is not set
# CONFIG_DEVMEM is not set
# CONFIG_PROC_KCORE is not set
# CONFIG_KALLSYMS_ALL is not set

# Disable io_uring (major kernel CVE surface)
# CONFIG_IO_URING is not set

# Disable high-risk / legacy syscall surfaces
# CONFIG_POSIX_MQUEUE is not set
# CONFIG_USERFAULTFD is not set
# CONFIG_AIO is not set
# CONFIG_BINFMT_MISC is not set
# CONFIG_IA32_EMULATION is not set       # Pure 64-bit only on x86_64
# CONFIG_COMPAT is not set               # Pure AArch64 EL0 only on ARM64
# CONFIG_MODIFY_LDT_SYSCALL is not set
# CONFIG_X86_VSYSCALL_EMULATION is not set
CONFIG_LEGACY_VSYSCALL_NONE=y

# Keep System V IPC isolated via CLONE_NEWIPC so local PostgreSQL starts cleanly
CONFIG_SYSVIPC=y
CONFIG_IPC_NS=y

# No swap (ephemeral tmpfs pages never spill unencrypted)
# CONFIG_SWAP is not set

# Strip hardware buses not needed in microVMs (boot speed + attack surface)
# CONFIG_USB_SUPPORT is not set
# CONFIG_SOUND is not set
# CONFIG_DRM is not set
# CONFIG_FB is not set
# CONFIG_INPUT_KEYBOARD is not set
# CONFIG_INPUT_MOUSE is not set
# CONFIG_WLAN is not set
# CONFIG_EFI is not set
```

---

## 3. KSPP, CFI & Speculation Mitigations (`Linux 7.3+`)

```kconfig
# Clang ThinLTO & Fine-Grained KCFI (built with `make LLVM=1 LLVM_IAS=1`)
CONFIG_LTO_CLANG_THIN=y
CONFIG_CFI=y

# Architecture-specific hardware protections
# -- On x86_64 (Linux KVM servers; 6.9+ CONFIG_MITIGATION_* naming):
CONFIG_X86_KERNEL_IBT=y
CONFIG_MITIGATION_PAGE_TABLE_ISOLATION=y
CONFIG_MITIGATION_RETPOLINE=y
CONFIG_MITIGATION_SLS=y

# -- On aarch64 (Apple Silicon HVF & ARM64 servers):
CONFIG_ARM64_PTR_AUTH=y
CONFIG_ARM64_PTR_AUTH_KERNEL=y
CONFIG_ARM64_BTI=y
CONFIG_ARM64_BTI_KERNEL=y
CONFIG_SHADOW_CALL_STACK=y
CONFIG_UNMAP_KERNEL_AT_EL0=y
CONFIG_RODATA_FULL_DEFAULT_ENABLED=y

# Memory allocator, stack & heap hardening
CONFIG_SLAB_FREELIST_RANDOM=y
CONFIG_SLAB_FREELIST_HARDENED=y
CONFIG_SLAB_BUCKETS=y
CONFIG_KMALLOC_PARTITION_CACHES=y  # auto-selects TYPED on Clang 22+, RANDOM on Clang < 22
CONFIG_SHUFFLE_PAGE_ALLOCATOR=y
CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y
CONFIG_INIT_ON_FREE_DEFAULT_ON=y
CONFIG_INIT_STACK_ALL_ZERO=y
CONFIG_ZERO_CALL_USED_REGS=y
CONFIG_RANDOMIZE_BASE=y
CONFIG_RANDOMIZE_KSTACK_OFFSET=y
CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT=y
CONFIG_STACKPROTECTOR=y
CONFIG_STACKPROTECTOR_STRONG=y
CONFIG_VMAP_STACK=y
CONFIG_SCHED_STACK_END_CHECK=y
CONFIG_HARDENED_USERCOPY=y
CONFIG_FORTIFY_SOURCE=y
CONFIG_LIST_HARDENED=y
CONFIG_BUG_ON_DATA_CORRUPTION=y
CONFIG_STRICT_KERNEL_RWX=y
```

---

## 4. Storage, Crypto, Lockdown & Namespace Primitives

```kconfig
# Minimal Virtio transport + devices
CONFIG_VIRTIO=y
CONFIG_VIRTIO_MMIO=y
CONFIG_VIRTIO_PCI=y                      # Used on x86_64 Cloud Hypervisor; MMIO used on macOS HVF
CONFIG_VIRTIO_BLK=y
CONFIG_VIRTIO_CONSOLE=y
CONFIG_HW_RANDOM=y
CONFIG_HW_RANDOM_VIRTIO=y

# Embedded initramfs carrying blackwall-init & blackwall-netbridge
# (NEVER injected into vda; initramfs maps dm-verity on vda before pivot/switch_root)
CONFIG_BLK_DEV_INITRD=y

# 2-Disk Model: Immutable Rootfs (vda: erofs + dm-verity) + Encrypted /workspace (vdb: dm-crypt + ext4)
# (No overlayfs required for /workspace)
CONFIG_BLK_DEV_DM=y
CONFIG_DM_VERITY=y
CONFIG_DM_CRYPT=y
CONFIG_EROFS_FS=y
CONFIG_EROFS_FS_ZIP=y                    # Selects LZ4_DECOMPRESS (handles LZ4 & LZ4HC)
CONFIG_EXT4_FS=y
CONFIG_TMPFS=y
CONFIG_TMPFS_POSIX_ACL=y
CONFIG_UNIX98_PTYS=y                     # Required for interactive /pty sessions
# CONFIG_LEGACY_PTYS is not set

# Hardware-accelerated crypto for dm-crypt & dm-verity (AES-XTS + SHA256)
CONFIG_CRYPTO_AES=y
CONFIG_CRYPTO_XTS=y
CONFIG_CRYPTO_SHA256=y
# Plus arch-specific AES-NI / ARMv8 Crypto Extensions (CONFIG_CRYPTO_AES_NI_INTEL=y / CONFIG_CRYPTO_AES_ARM64_CE_BLK=y)

# Confidentiality Lockdown, Landlock, Yama & Namespaces
CONFIG_SECCOMP=y
CONFIG_SECCOMP_FILTER=y
CONFIG_SECURITY=y
CONFIG_SECURITY_LOCKDOWN_LSM=y
CONFIG_SECURITY_LOCKDOWN_LSM_EARLY=y
CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY=y
CONFIG_SECURITY_LANDLOCK=y
CONFIG_SECURITY_YAMA=y
CONFIG_CGROUPS=y
CONFIG_NAMESPACES=y                      # Includes mount namespaces (CLONE_NEWNS)
CONFIG_PID_NS=y
CONFIG_UTS_NS=y
# CONFIG_USER_NS is not set              # Unprivileged userns compiled out entirely (unshare(CLONE_NEWUSER) -> EINVAL)
```

### Optional Future BPF LSM Hooks (Phase 6+ Profile Fragment)
When enabling optional in-guest BPF LSM telemetry plugins later (`bpf-lsm.fragment`: `CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_BPF_JIT=y`, `CONFIG_BPF_JIT_ALWAYS_ON=y`, `CONFIG_BPF_UNPRIV_DEFAULT_OFF=y`, `CONFIG_BPF_LSM=y`, `CONFIG_DEBUG_INFO_BTF=y` + `pahole >= 1.27`):
- Because `CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY=y` activates `LOCKDOWN_BPF_READ_KERNEL`, `LOCKDOWN_KPROBES`, `LOCKDOWN_PERF`, and `LOCKDOWN_TRACEFS`, the kernel blocks `kprobes`, `uprobes`, `perf_event_open`, `tracefs`, `bpf_probe_read_kernel()`, and `bpf_probe_read_kernel_str()`.
- Future BPF plugins must therefore stick strictly to **`BPF_PROG_TYPE_LSM`** (sleepable `lsm.s/`) and **`tp_btf`** using verifier-checked direct BTF scalar/struct dereferences, `bpf_d_path()`, `bpf_get_current_comm()`, and `bpf_probe_read_user*()` (for `argv`).

---

## 5. Forced Built-In Kernel Command Line (Both Architectures)

Both architectures force the built-in command line (**`x86_64`: `CONFIG_CMDLINE_BOOL=y` + `CONFIG_CMDLINE_OVERRIDE=y`; `arm64`: `CONFIG_CMDLINE_FORCE=y`**) so no runtime cmdline injection is possible. All per-VM runtime parameters (including `vda` `dm-verity` roothash, session env, and random secret placeholders) are delivered by the host over `Port 1002` during `Handshake`.

```text
console=hvc0
lockdown=confidentiality
lsm=lockdown,yama,landlock
slab_nomerge
init_on_alloc=1
init_on_free=1
page_alloc.shuffle=1
randomize_kstack_offset=on
vsyscall=none
debugfs=off
oops=panic
panic=-1
mitigations=auto,nosmt
random.trust_cpu=on
random.trust_bootloader=off
```

- `oops=panic panic=-1`: Any kernel `BUG()` or `Oops` inside the guest halts the VM immediately rather than allowing heap-spray or exploitation retries across crashed kernel threads.
