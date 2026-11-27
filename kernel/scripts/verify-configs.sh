#!/usr/bin/env bash
set -euo pipefail

# Blackwall Kernel Config & Build Script Verification Suite
# Verifies syntax of build-kernel.sh, all Kconfig invariants from docs/KERNEL_HARDENING.md
# across all 5 config/fragment files, and executes build-kernel.sh --check-only.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KERNEL_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
CONFIGS_DIR="${KERNEL_DIR}/configs"

COMMON_CFG="${CONFIGS_DIR}/common-hardened.config"
LO_FRAG="${CONFIGS_DIR}/loopback-tun.fragment"
NOINET_FRAG="${CONFIGS_DIR}/noinet.fragment"
X86_FRAG="${CONFIGS_DIR}/x86_64.fragment"
ARM64_FRAG="${CONFIGS_DIR}/aarch64.fragment"
BUILD_SCRIPT="${SCRIPT_DIR}/build-kernel.sh"

EXPECTED_CMDLINE="console=hvc0 lockdown=confidentiality lsm=lockdown,yama,landlock slab_nomerge init_on_alloc=1 init_on_free=1 page_alloc.shuffle=1 randomize_kstack_offset=on vsyscall=none debugfs=off oops=panic panic=-1 mitigations=auto,nosmt random.trust_cpu=on random.trust_bootloader=off"

FAILURES=0

pass() {
    printf '[PASS] %s\n' "$*"
}

fail() {
    printf '[FAIL] %s\n' "$*" >&2
    FAILURES=$((FAILURES + 1))
}

assert_line() {
    local file="$1"
    local line="$2"
    if ! grep -Fxq "${line}" "${file}"; then
        fail "$(basename "${file}") missing required setting: ${line}"
    fi
}

assert_absent_regex() {
    local file="$1"
    local pattern="$2"
    local desc="$3"
    if grep -Eq "${pattern}" "${file}"; then
        fail "$(basename "${file}") violates forbidden invariant (${desc}): matched '${pattern}'"
    fi
}

check_kconfig_syntax() {
    local file="$1"
    [[ -f "${file}" ]] || { fail "Missing config file: ${file}"; return; }

    # Ensure no malformed Kconfig directives, no inline comments on directives, and no duplicate symbols
    if ! awk '
        /^[[:space:]]*$/ { next }
        /^# CONFIG_[A-Za-z0-9_]+ is not set$/ {
            sym = $2
            if (sym in seen) {
                printf("Duplicate symbol %s in %s:%d\n", sym, FILENAME, FNR) > "/dev/stderr"
                bad = 1
            }
            seen[sym] = 1
            next
        }
        /^# CONFIG_[A-Za-z0-9_]+ is not set/ {
            printf("Trailing text on unset directive in %s:%d: %s\n", FILENAME, FNR, $0) > "/dev/stderr"
            bad = 1
            next
        }
        /^#/ { next }
        /^CONFIG_[A-Za-z0-9_]+=("[^"]*"|[^[:space:]#]+)$/ {
            split($0, p, "=")
            sym = p[1]
            if (sym in seen) {
                printf("Duplicate symbol %s in %s:%d\n", sym, FILENAME, FNR) > "/dev/stderr"
                bad = 1
            }
            seen[sym] = 1
            next
        }
        {
            printf("Invalid Kconfig line in %s:%d: %s\n", FILENAME, FNR, $0) > "/dev/stderr"
            bad = 1
        }
        END { exit bad }
    ' "${file}"; then
        fail "Kconfig syntax/duplicate check failed for $(basename "${file}")"
    else
        pass "Kconfig syntax clean: $(basename "${file}")"
    fi
}

# 1. Bash syntax check & executability
if [[ ! -x "${BUILD_SCRIPT}" ]]; then
    fail "build-kernel.sh is not executable"
elif bash -n "${BUILD_SCRIPT}"; then
    pass "bash -n build-kernel.sh"
else
    fail "bash -n build-kernel.sh failed"
fi

if bash -n "${BASH_SOURCE[0]}"; then
    pass "bash -n verify-configs.sh"
else
    fail "bash -n verify-configs.sh failed"
fi

# 2. Syntax & duplicate checks across all 5 config/fragment files
ALL_FILES=("${COMMON_CFG}" "${LO_FRAG}" "${NOINET_FRAG}" "${X86_FRAG}" "${ARM64_FRAG}")
for f in "${ALL_FILES[@]}"; do
    check_kconfig_syntax "${f}"
done

# 3. Verify common-hardened.config invariants
COMMON_REQUIRED=(
    # Section 1: Shared socket base
    "CONFIG_NET=y"
    "CONFIG_UNIX=y"
    "CONFIG_VSOCKETS=y"
    "CONFIG_VIRTIO_VSOCKETS=y"
    "CONFIG_VIRTIO_VSOCKETS_COMMON=y"
    "# CONFIG_NETFILTER is not set"
    "# CONFIG_PACKET is not set"
    "# CONFIG_NETLINK_DIAG is not set"
    "# CONFIG_WIRELESS is not set"
    "# CONFIG_BT is not set"
    "# CONFIG_VIRTIO_NET is not set"
    "# CONFIG_TLS is not set"
    "# CONFIG_XFRM is not set"
    "# CONFIG_SCTP is not set"
    "# CONFIG_TIPC is not set"
    "# CONFIG_RDS is not set"
    "# CONFIG_L2TP is not set"
    # Section 2: Attack-surface elimination
    "# CONFIG_MODULES is not set"
    "# CONFIG_KEXEC is not set"
    "# CONFIG_KEXEC_FILE is not set"
    "# CONFIG_HIBERNATION is not set"
    "# CONFIG_SUSPEND is not set"
    "# CONFIG_DEVMEM is not set"
    "# CONFIG_PROC_KCORE is not set"
    "# CONFIG_KALLSYMS_ALL is not set"
    "# CONFIG_IO_URING is not set"
    "# CONFIG_POSIX_MQUEUE is not set"
    "# CONFIG_USERFAULTFD is not set"
    "# CONFIG_AIO is not set"
    "# CONFIG_BINFMT_MISC is not set"
    "CONFIG_SYSVIPC=y"
    "CONFIG_IPC_NS=y"
    "# CONFIG_SWAP is not set"
    "# CONFIG_USB_SUPPORT is not set"
    "# CONFIG_SOUND is not set"
    "# CONFIG_DRM is not set"
    "# CONFIG_FB is not set"
    "# CONFIG_INPUT_KEYBOARD is not set"
    "# CONFIG_INPUT_MOUSE is not set"
    "# CONFIG_WLAN is not set"
    "# CONFIG_EFI is not set"
    # Section 3: KSPP, ThinLTO, KCFI & slab/stack/heap hardening
    "CONFIG_LTO_CLANG_THIN=y"
    "CONFIG_CFI_CLANG=y"
    "CONFIG_SLAB_FREELIST_RANDOM=y"
    "CONFIG_SLAB_FREELIST_HARDENED=y"
    "CONFIG_SLAB_BUCKETS=y"
    "CONFIG_RANDOM_KMALLOC_CACHES=y"
    "CONFIG_SHUFFLE_PAGE_ALLOCATOR=y"
    "CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y"
    "CONFIG_INIT_ON_FREE_DEFAULT_ON=y"
    "CONFIG_INIT_STACK_ALL_ZERO=y"
    "CONFIG_ZERO_CALL_USED_REGS=y"
    "CONFIG_RANDOMIZE_BASE=y"
    "CONFIG_RANDOMIZE_KSTACK_OFFSET=y"
    "CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT=y"
    "CONFIG_STACKPROTECTOR=y"
    "CONFIG_STACKPROTECTOR_STRONG=y"
    "CONFIG_VMAP_STACK=y"
    "CONFIG_SCHED_STACK_END_CHECK=y"
    "CONFIG_HARDENED_USERCOPY=y"
    "CONFIG_FORTIFY_SOURCE=y"
    "CONFIG_LIST_HARDENED=y"
    "CONFIG_BUG_ON_DATA_CORRUPTION=y"
    "CONFIG_STRICT_KERNEL_RWX=y"
    # Section 4: Storage, Virtio, Crypto, Lockdown & Namespaces
    "CONFIG_VIRTIO=y"
    "CONFIG_VIRTIO_MMIO=y"
    "CONFIG_VIRTIO_BLK=y"
    "CONFIG_VIRTIO_CONSOLE=y"
    "CONFIG_HW_RANDOM=y"
    "CONFIG_HW_RANDOM_VIRTIO=y"
    "CONFIG_BLK_DEV_INITRD=y"
    "CONFIG_BLK_DEV_DM=y"
    "CONFIG_DM_VERITY=y"
    "CONFIG_DM_CRYPT=y"
    "CONFIG_EROFS_FS=y"
    "CONFIG_EROFS_FS_ZIP=y"
    "CONFIG_EXT4_FS=y"
    "CONFIG_TMPFS=y"
    "CONFIG_TMPFS_POSIX_ACL=y"
    "CONFIG_UNIX98_PTYS=y"
    "# CONFIG_LEGACY_PTYS is not set"
    "CONFIG_CRYPTO_AES=y"
    "CONFIG_CRYPTO_XTS=y"
    "CONFIG_CRYPTO_SHA256=y"
    "CONFIG_SECCOMP=y"
    "CONFIG_SECCOMP_FILTER=y"
    "CONFIG_SECURITY=y"
    "CONFIG_SECURITY_LOCKDOWN_LSM=y"
    "CONFIG_SECURITY_LOCKDOWN_LSM_EARLY=y"
    "CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY=y"
    "CONFIG_SECURITY_LANDLOCK=y"
    "CONFIG_SECURITY_YAMA=y"
    "CONFIG_CGROUPS=y"
    "CONFIG_NAMESPACES=y"
    "CONFIG_PID_NS=y"
    "CONFIG_UTS_NS=y"
    "# CONFIG_USER_NS is not set"
    "# CONFIG_OVERLAY_FS is not set"
)

before_fail="${FAILURES}"
for line in "${COMMON_REQUIRED[@]}"; do
    assert_line "${COMMON_CFG}" "${line}"
done
if [[ "${FAILURES}" -eq "${before_fail}" ]]; then
    pass "common-hardened.config matches all ${#COMMON_REQUIRED[@]} required Kconfig entries"
fi

# 4. Verify loopback-tun.fragment invariants
LO_REQUIRED=(
    "CONFIG_INET=y"
    "CONFIG_IPV6=y"
    "CONFIG_NETDEVICES=y"
    "CONFIG_NET_CORE=y"
    "CONFIG_TUN=y"
    "# CONFIG_ETHERNET is not set"
    "# CONFIG_VETH is not set"
    "# CONFIG_BRIDGE is not set"
)
before_fail="${FAILURES}"
for line in "${LO_REQUIRED[@]}"; do
    assert_line "${LO_FRAG}" "${line}"
done
if [[ "${FAILURES}" -eq "${before_fail}" ]]; then
    pass "loopback-tun.fragment matches all ${#LO_REQUIRED[@]} required Kconfig entries"
fi

# 5. Verify noinet.fragment invariants
NOINET_REQUIRED=(
    "# CONFIG_INET is not set"
    "# CONFIG_IPV6 is not set"
    "# CONFIG_NETDEVICES is not set"
    "# CONFIG_TUN is not set"
)
before_fail="${FAILURES}"
for line in "${NOINET_REQUIRED[@]}"; do
    assert_line "${NOINET_FRAG}" "${line}"
done
if [[ "${FAILURES}" -eq "${before_fail}" ]]; then
    pass "noinet.fragment matches all ${#NOINET_REQUIRED[@]} required Kconfig entries"
fi

# 6. Verify x86_64.fragment invariants
X86_REQUIRED=(
    "CONFIG_VIRTIO_PCI=y"
    "CONFIG_X86_KERNEL_IBT=y"
    "CONFIG_MITIGATION_PAGE_TABLE_ISOLATION=y"
    "CONFIG_MITIGATION_RETPOLINE=y"
    "CONFIG_MITIGATION_SLS=y"
    "CONFIG_CRYPTO_AES_NI_INTEL=y"
    "# CONFIG_IA32_EMULATION is not set"
    "# CONFIG_MODIFY_LDT_SYSCALL is not set"
    "# CONFIG_X86_VSYSCALL_EMULATION is not set"
    "CONFIG_LEGACY_VSYSCALL_NONE=y"
    "CONFIG_CMDLINE_BOOL=y"
    "CONFIG_CMDLINE_OVERRIDE=y"
    "CONFIG_CMDLINE=\"${EXPECTED_CMDLINE}\""
)
before_fail="${FAILURES}"
for line in "${X86_REQUIRED[@]}"; do
    assert_line "${X86_FRAG}" "${line}"
done
if [[ "${FAILURES}" -eq "${before_fail}" ]]; then
    pass "x86_64.fragment matches all ${#X86_REQUIRED[@]} required Kconfig entries"
fi

# 7. Verify aarch64.fragment invariants
ARM64_REQUIRED=(
    "CONFIG_ARM64_PTR_AUTH=y"
    "CONFIG_ARM64_PTR_AUTH_KERNEL=y"
    "CONFIG_ARM64_BTI=y"
    "CONFIG_ARM64_BTI_KERNEL=y"
    "CONFIG_SHADOW_CALL_STACK=y"
    "CONFIG_UNMAP_KERNEL_AT_EL0=y"
    "CONFIG_RODATA_FULL_DEFAULT_ENABLED=y"
    "CONFIG_CRYPTO_AES_ARM64_CE_BLK=y"
    "# CONFIG_COMPAT is not set"
    "CONFIG_CMDLINE_FORCE=y"
    "CONFIG_CMDLINE=\"${EXPECTED_CMDLINE}\""
)
before_fail="${FAILURES}"
for line in "${ARM64_REQUIRED[@]}"; do
    assert_line "${ARM64_FRAG}" "${line}"
done
if [[ "${FAILURES}" -eq "${before_fail}" ]]; then
    pass "aarch64.fragment matches all ${#ARM64_REQUIRED[@]} required Kconfig entries"
fi

# 8. Verify forbidden MVP options are absent across ALL 5 files
before_fail="${FAILURES}"
for f in "${ALL_FILES[@]}"; do
    assert_absent_regex "${f}" '^CONFIG_BPF_LSM=y$' 'No BPF LSM in MVP configs'
    assert_absent_regex "${f}" '^CONFIG_BPF_SYSCALL=y$' 'No BPF_SYSCALL in MVP configs'
    assert_absent_regex "${f}" '^CONFIG_OVERLAY_FS=y$' 'No OVERLAY_FS in MVP configs'
    assert_absent_regex "${f}" '^CONFIG_IO_URING=y$' 'No IO_URING in MVP configs'
    assert_absent_regex "${f}" '^CONFIG_USER_NS=y$' 'No USER_NS in MVP configs'
    assert_absent_regex "${f}" '^CONFIG_MODULES=y$' 'No loadable MODULES in MVP configs'
done
if [[ "${FAILURES}" -eq "${before_fail}" ]]; then
    pass "Forbidden MVP options (BPF_LSM, OVERLAY_FS, IO_URING, USER_NS, MODULES) absent across all configs"
fi

# 9. Run build-kernel.sh --check-only for both architectures and both profiles
for arch in x86_64 aarch64; do
    if "${BUILD_SCRIPT}" --arch "${arch}" --profile all --check-only; then
        pass "build-kernel.sh --arch ${arch} --profile all --check-only"
    else
        fail "build-kernel.sh --arch ${arch} --profile all --check-only failed"
    fi
done

if [[ "${FAILURES}" -gt 0 ]]; then
    printf '\nVerification FAILED with %d error(s).\n' "${FAILURES}" >&2
    exit 1
fi

printf '\nAll kernel config and build-script verification checks PASSED.\n'
