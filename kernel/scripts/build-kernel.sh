#!/usr/bin/env bash
set -euo pipefail

# Blackwall Reproducible Hardened Guest Kernel Builder (Linux 6.12+, Clang/LLVM)
# Builds vmlinux-lo and/or vmlinux-noinet using `make LLVM=1 LLVM_IAS=1`.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KERNEL_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${KERNEL_DIR}/.." && pwd)"
CONFIGS_DIR="${KERNEL_DIR}/configs"

# Reproducible build environment
export LC_ALL=C
export TZ=UTC
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-0}"
export KBUILD_BUILD_TIMESTAMP="${KBUILD_BUILD_TIMESTAMP:-1970-01-01 00:00:00 UTC}"
export KBUILD_BUILD_USER="${KBUILD_BUILD_USER:-blackwall}"
export KBUILD_BUILD_HOST="${KBUILD_BUILD_HOST:-blackwall}"
export KBUILD_BUILD_VERSION="${KBUILD_BUILD_VERSION:-1}"

PROFILE="all"
ARCH=""
KERNEL_SRC="${KERNEL_SRC:-}"
INITRAMFS=""
OUT_DIR=""
JOBS=""
CHECK_ONLY=0
BUILD_INITRAMFS=0
INIT_BIN=""
NETBRIDGE_BIN=""
TMP_DIRS=()

cleanup_tmp_dirs() {
    local d
    for d in "${TMP_DIRS[@]+"${TMP_DIRS[@]}"}"; do
        if [[ -n "${d}" && -d "${d}" ]]; then
            rm -rf "${d}"
        fi
    done
}
trap cleanup_tmp_dirs EXIT

EXPECTED_CMDLINE="console=hvc0 lockdown=confidentiality lsm=lockdown,yama,landlock slab_nomerge init_on_alloc=1 init_on_free=1 page_alloc.shuffle=1 randomize_kstack_offset=on vsyscall=none debugfs=off oops=panic panic=-1 mitigations=auto,nosmt random.trust_cpu=on random.trust_bootloader=off"

usage() {
    cat <<'EOF'
Usage: build-kernel.sh [OPTIONS]

Build reproducible hardened Blackwall Linux guest kernels (vmlinux-lo, vmlinux-noinet)
using Clang/LLVM (`make LLVM=1 LLVM_IAS=1`).

Options:
  --profile <lo|noinet|all>   Kernel network profile to build (default: all)
  --arch <x86_64|aarch64>     Target guest architecture (default: host arch)
  --kernel-src <dir>          Path to Linux 6.12+ kernel source tree (or $KERNEL_SRC)
  --initramfs <cpio>          Path to existing initramfs cpio(.gz) to embed in kernel
  --build-initramfs           Build a reproducible initramfs cpio embedding static musl
                              blackwall-init (/init) and blackwall-netbridge (/sbin/blackwall-netbridge)
  --init-bin <path>           Prebuilt static musl blackwall-init binary (used with --build-initramfs)
  --netbridge-bin <path>      Prebuilt static musl blackwall-netbridge binary (used with --build-initramfs)
  --out-dir <dir>             Output directory (default: kernel/out/<arch>)
  --jobs <n>                  Parallel make jobs (default: nproc)
  --check-only                Validate LLVM toolchain & config merge/invariants without compiling
  -h, --help                  Show this help message
EOF
}

log() {
    printf '[build-kernel] %s\n' "$*"
}

die() {
    printf '[build-kernel] ERROR: %s\n' "$*" >&2
    exit 1
}

detect_host_arch() {
    local u
    u="$(uname -m)"
    case "${u}" in
        x86_64|amd64) printf 'x86_64\n' ;;
        aarch64|arm64) printf 'aarch64\n' ;;
        *) die "Unsupported host architecture '${u}'; specify --arch x86_64|aarch64" ;;
    esac
}

detect_jobs() {
    if command -v nproc >/dev/null 2>&1; then
        nproc
    elif command -v getconf >/dev/null 2>&1; then
        getconf _NPROCESSORS_ONLN
    else
        printf '1\n'
    fi
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --profile)
                [[ $# -ge 2 ]] || die "--profile requires an argument"
                PROFILE="$2"
                shift 2
                ;;
            --arch)
                [[ $# -ge 2 ]] || die "--arch requires an argument"
                ARCH="$2"
                shift 2
                ;;
            --kernel-src)
                [[ $# -ge 2 ]] || die "--kernel-src requires an argument"
                KERNEL_SRC="$2"
                shift 2
                ;;
            --initramfs)
                [[ $# -ge 2 ]] || die "--initramfs requires an argument"
                INITRAMFS="$2"
                shift 2
                ;;
            --build-initramfs)
                BUILD_INITRAMFS=1
                shift
                ;;
            --init-bin)
                [[ $# -ge 2 ]] || die "--init-bin requires an argument"
                INIT_BIN="$2"
                shift 2
                ;;
            --netbridge-bin)
                [[ $# -ge 2 ]] || die "--netbridge-bin requires an argument"
                NETBRIDGE_BIN="$2"
                shift 2
                ;;
            --out-dir)
                [[ $# -ge 2 ]] || die "--out-dir requires an argument"
                OUT_DIR="$2"
                shift 2
                ;;
            --jobs)
                [[ $# -ge 2 ]] || die "--jobs requires an argument"
                JOBS="$2"
                shift 2
                ;;
            --check-only)
                CHECK_ONLY=1
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                die "Unknown argument: $1 (use --help for usage)"
                ;;
        esac
    done

    case "${PROFILE}" in
        lo|noinet|all) ;;
        *) die "Invalid --profile '${PROFILE}'; expected lo, noinet, or all" ;;
    esac

    if [[ -z "${ARCH}" ]]; then
        ARCH="$(detect_host_arch)"
    fi
    case "${ARCH}" in
        x86_64|aarch64) ;;
        *) die "Invalid --arch '${ARCH}'; expected x86_64 or aarch64" ;;
    esac

    if [[ -z "${OUT_DIR}" ]]; then
        OUT_DIR="${KERNEL_DIR}/out/${ARCH}"
    fi

    if [[ -z "${JOBS}" ]]; then
        JOBS="$(detect_jobs)"
    fi

    if [[ -n "${INITRAMFS}" && "${BUILD_INITRAMFS}" -eq 1 ]]; then
        die "Cannot specify both --initramfs and --build-initramfs"
    fi
}

kernel_arch_for() {
    case "$1" in
        x86_64) printf 'x86_64\n' ;;
        aarch64) printf 'arm64\n' ;;
        *) die "Unsupported arch: $1" ;;
    esac
}

musl_target_for() {
    case "$1" in
        x86_64) printf 'x86_64-unknown-linux-musl\n' ;;
        aarch64) printf 'aarch64-unknown-linux-musl\n' ;;
        *) die "Unsupported arch: $1" ;;
    esac
}

profile_fragment_for() {
    case "$1" in
        lo) printf '%s/loopback-tun.fragment\n' "${CONFIGS_DIR}" ;;
        noinet) printf '%s/noinet.fragment\n' "${CONFIGS_DIR}" ;;
        *) die "Unsupported profile: $1" ;;
    esac
}

arch_fragment_for() {
    case "$1" in
        x86_64) printf '%s/x86_64.fragment\n' "${CONFIGS_DIR}" ;;
        aarch64) printf '%s/aarch64.fragment\n' "${CONFIGS_DIR}" ;;
        *) die "Unsupported arch: $1" ;;
    esac
}

check_toolchain() {
    local required_tools=(
        clang
        ld.lld
        llvm-ar
        llvm-nm
        llvm-objcopy
        llvm-objdump
        llvm-readelf
        llvm-strip
        make
    )
    local missing=()
    local tool
    for tool in "${required_tools[@]}"; do
        if ! command -v "${tool}" >/dev/null 2>&1; then
            missing+=("${tool}")
        fi
    done

    if [[ "${BUILD_INITRAMFS}" -eq 1 ]]; then
        for tool in cpio gzip find; do
            if ! command -v "${tool}" >/dev/null 2>&1; then
                missing+=("${tool}")
            fi
        done
    fi

    if [[ ${#missing[@]} -gt 0 ]]; then
        die "Missing required toolchain binaries: ${missing[*]}"
    fi

    local clang_ver
    clang_ver="$(clang --version | head -n 1)"
    log "Toolchain verified (${clang_ver})"
}

verify_static_elf() {
    local bin="$1"
    [[ -f "${bin}" ]] || die "Binary not found: ${bin}"
    if llvm-readelf -l "${bin}" 2>/dev/null | grep -q 'INTERP'; then
        die "Initramfs binary '${bin}' is dynamically linked (PT_INTERP found); must be static musl"
    fi
}

build_initramfs_cpio() {
    local out_cpio="$1"
    local musl_target
    musl_target="$(musl_target_for "${ARCH}")"

    local init_bin="${INIT_BIN}"
    local netbridge_bin="${NETBRIDGE_BIN}"

    if [[ -z "${init_bin}" || -z "${netbridge_bin}" ]]; then
        command -v cargo >/dev/null 2>&1 || die "cargo is required to build static musl guest binaries (or pass --init-bin and --netbridge-bin)"
        log "Building static musl blackwall-init and blackwall-netbridge for ${musl_target}"
        cargo build --manifest-path "${REPO_ROOT}/Cargo.toml" \
            --release --target "${musl_target}" \
            -p blackwall-init -p blackwall-netbridge
        init_bin="${init_bin:-${REPO_ROOT}/target/${musl_target}/release/blackwall-init}"
        netbridge_bin="${netbridge_bin:-${REPO_ROOT}/target/${musl_target}/release/blackwall-netbridge}"
    fi

    verify_static_elf "${init_bin}"
    verify_static_elf "${netbridge_bin}"

    local staging
    staging="$(mktemp -d)"
    TMP_DIRS+=("${staging}")

    mkdir -p "${staging}/sbin" "${staging}/dev" "${staging}/proc" "${staging}/sys" \
        "${staging}/mnt" "${staging}/newroot" "${staging}/run" "${staging}/tmp"
    chmod 0755 "${staging}/sbin" "${staging}/dev" "${staging}/proc" "${staging}/sys" \
        "${staging}/mnt" "${staging}/newroot" "${staging}/run"
    chmod 1777 "${staging}/tmp"

    install -m 0755 "${init_bin}" "${staging}/init"
    install -m 0755 "${netbridge_bin}" "${staging}/sbin/blackwall-netbridge"

    # Normalize timestamps for reproducible cpio archive output
    find "${staging}" -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} +

    local cpio_flags=(--create --format=newc --owner=0:0 --quiet)
    if cpio --help 2>&1 | grep -q -- '--reproducible'; then
        cpio_flags+=(--reproducible)
    fi

    mkdir -p "$(dirname "${out_cpio}")"
    local raw_cpio="${out_cpio%.gz}"
    local devnodes_cpio="${staging}/../devnodes.cpio"
    # Emit /dev/console (c 5 1) and /dev/null (c 1 3) as a reproducible newc cpio
    # without requiring root mknod (needed by kernel initial console and Rust std startup).
    python3 - "${devnodes_cpio}" "${SOURCE_DATE_EPOCH}" <<'PYEOF'
import sys, os
out_path, mtime = sys.argv[1], int(sys.argv[2])
def newc_entry(name, mode, rdev_maj, rdev_min, ino):
    nb = name.encode() + b"\x00"
    hdr = (
        f"070701{ino:08x}{mode:08x}{0:08x}{0:08x}{1:08x}{mtime:08x}"
        f"{0:08x}{0:08x}{0:08x}{rdev_maj:08x}{rdev_min:08x}{len(nb):08x}{0:08x}"
    ).encode()
    rec = hdr + nb
    rec += b"\x00" * ((4 - (len(rec) % 4)) % 4)
    return rec
with open(out_path, "wb") as f:
    f.write(newc_entry("dev", 0o040755, 0, 0, 1))
    f.write(newc_entry("dev/console", 0o020600, 5, 1, 2))
    f.write(newc_entry("dev/null", 0o020666, 1, 3, 3))
    f.write(newc_entry("TRAILER!!!", 0, 0, 0, 0))
PYEOF
    (
        cd "${staging}"
        find . -mindepth 1 -printf '%P\n' | LC_ALL=C sort | cpio "${cpio_flags[@]}"
    ) > "${raw_cpio}"
    cat "${devnodes_cpio}" >> "${raw_cpio}"
    rm -f "${devnodes_cpio}"
    gzip -n -9 -c "${raw_cpio}" > "${out_cpio}"

    log "Built reproducible initramfs: ${out_cpio} (and raw ${raw_cpio})"
}

# Dry-run deterministic Kconfig fragment merger matching merge_config.sh last-wins semantics.
# Used in --check-only mode when --kernel-src is not provided.
dry_run_merge_fragments() {
    local output_cfg="$1"
    shift
    local fragments=("$@")

    awk '
        function record(sym, line) {
            if (!(sym in seen)) {
                order[++count] = sym
                seen[sym] = 1
            }
            val[sym] = line
        }
        /^[[:space:]]*$/ { next }
        /^# CONFIG_[A-Za-z0-9_]+ is not set$/ {
            sym = $2
            record(sym, $0)
            next
        }
        /^#/ { next }
        /^CONFIG_[A-Za-z0-9_]+=/ {
            split($0, parts, "=")
            sym = parts[1]
            record(sym, $0)
            next
        }
        {
            printf("Malformed Kconfig line in %s:%d: %s\n", FILENAME, FNR, $0) > "/dev/stderr"
            exit 1
        }
        END {
            for (i = 1; i <= count; i++) {
                print val[order[i]]
            }
        }
    ' "${fragments[@]}" > "${output_cfg}"
}

assert_cfg_eq() {
    local cfg="$1"
    local sym="$2"
    local expected="$3"
    if ! grep -Fxq "${sym}=${expected}" "${cfg}"; then
        die "Security invariant failed in ${cfg}: expected ${sym}=${expected}"
    fi
}

assert_cfg_unset() {
    local cfg="$1"
    local sym="$2"
    if grep -Eq "^${sym}=" "${cfg}"; then
        local actual
        actual="$(grep -E "^${sym}=" "${cfg}" | head -n 1)"
        die "Security invariant failed in ${cfg}: expected ${sym} unset, found '${actual}'"
    fi
}

verify_resolved_config() {
    local cfg="$1"
    local profile="$2"
    local arch="$3"

    # Core security invariants that MUST survive Kconfig resolution in ALL profiles
    assert_cfg_eq "${cfg}" "CONFIG_NET" "y"
    assert_cfg_eq "${cfg}" "CONFIG_UNIX" "y"
    assert_cfg_eq "${cfg}" "CONFIG_VSOCKETS" "y"
    assert_cfg_eq "${cfg}" "CONFIG_VIRTIO_VSOCKETS" "y"
    assert_cfg_eq "${cfg}" "CONFIG_VIRTIO_VSOCKETS_COMMON" "y"
    assert_cfg_eq "${cfg}" "CONFIG_LTO_CLANG_THIN" "y"
    assert_cfg_eq "${cfg}" "CONFIG_CFI_CLANG" "y"
    assert_cfg_eq "${cfg}" "CONFIG_SYSVIPC" "y"
    assert_cfg_eq "${cfg}" "CONFIG_IPC_NS" "y"
    assert_cfg_eq "${cfg}" "CONFIG_BLK_DEV_INITRD" "y"
    assert_cfg_eq "${cfg}" "CONFIG_BLK_DEV_DM" "y"
    assert_cfg_eq "${cfg}" "CONFIG_DM_VERITY" "y"
    assert_cfg_eq "${cfg}" "CONFIG_DM_CRYPT" "y"
    assert_cfg_eq "${cfg}" "CONFIG_EROFS_FS" "y"
    assert_cfg_eq "${cfg}" "CONFIG_EROFS_FS_ZIP" "y"
    assert_cfg_eq "${cfg}" "CONFIG_EXT4_FS" "y"
    assert_cfg_eq "${cfg}" "CONFIG_TMPFS" "y"
    assert_cfg_eq "${cfg}" "CONFIG_UNIX98_PTYS" "y"
    assert_cfg_eq "${cfg}" "CONFIG_SECCOMP" "y"
    assert_cfg_eq "${cfg}" "CONFIG_SECCOMP_FILTER" "y"
    assert_cfg_eq "${cfg}" "CONFIG_SECURITY" "y"
    assert_cfg_eq "${cfg}" "CONFIG_SECURITY_LOCKDOWN_LSM" "y"
    assert_cfg_eq "${cfg}" "CONFIG_SECURITY_LOCKDOWN_LSM_EARLY" "y"
    assert_cfg_eq "${cfg}" "CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY" "y"
    assert_cfg_eq "${cfg}" "CONFIG_SECURITY_LANDLOCK" "y"
    assert_cfg_eq "${cfg}" "CONFIG_SECURITY_YAMA" "y"
    assert_cfg_eq "${cfg}" "CONFIG_CGROUPS" "y"
    assert_cfg_eq "${cfg}" "CONFIG_NAMESPACES" "y"
    assert_cfg_eq "${cfg}" "CONFIG_PID_NS" "y"
    assert_cfg_eq "${cfg}" "CONFIG_UTS_NS" "y"

    # High-risk surfaces that MUST remain disabled in ALL profiles
    assert_cfg_unset "${cfg}" "CONFIG_MODULES"
    assert_cfg_unset "${cfg}" "CONFIG_IO_URING"
    assert_cfg_unset "${cfg}" "CONFIG_USER_NS"
    assert_cfg_unset "${cfg}" "CONFIG_OVERLAY_FS"
    assert_cfg_unset "${cfg}" "CONFIG_NETFILTER"
    assert_cfg_unset "${cfg}" "CONFIG_PACKET"
    assert_cfg_unset "${cfg}" "CONFIG_VIRTIO_NET"
    assert_cfg_unset "${cfg}" "CONFIG_XFRM"
    assert_cfg_unset "${cfg}" "CONFIG_SWAP"
    assert_cfg_unset "${cfg}" "CONFIG_LEGACY_PTYS"
    assert_cfg_unset "${cfg}" "CONFIG_BPF_LSM"

    # Profile-specific invariants
    if [[ "${profile}" == "lo" ]]; then
        assert_cfg_eq "${cfg}" "CONFIG_INET" "y"
        assert_cfg_eq "${cfg}" "CONFIG_IPV6" "y"
        assert_cfg_eq "${cfg}" "CONFIG_NETDEVICES" "y"
        assert_cfg_eq "${cfg}" "CONFIG_NET_CORE" "y"
        assert_cfg_eq "${cfg}" "CONFIG_TUN" "y"
        assert_cfg_unset "${cfg}" "CONFIG_ETHERNET"
        assert_cfg_unset "${cfg}" "CONFIG_VETH"
        assert_cfg_unset "${cfg}" "CONFIG_BRIDGE"
    elif [[ "${profile}" == "noinet" ]]; then
        assert_cfg_unset "${cfg}" "CONFIG_INET"
        assert_cfg_unset "${cfg}" "CONFIG_IPV6"
        assert_cfg_unset "${cfg}" "CONFIG_NETDEVICES"
        assert_cfg_unset "${cfg}" "CONFIG_TUN"
    fi

    # Architecture-specific invariants
    if [[ "${arch}" == "x86_64" ]]; then
        assert_cfg_eq "${cfg}" "CONFIG_VIRTIO_PCI" "y"
        assert_cfg_eq "${cfg}" "CONFIG_X86_KERNEL_IBT" "y"
        assert_cfg_eq "${cfg}" "CONFIG_MITIGATION_PAGE_TABLE_ISOLATION" "y"
        assert_cfg_eq "${cfg}" "CONFIG_MITIGATION_RETPOLINE" "y"
        assert_cfg_eq "${cfg}" "CONFIG_MITIGATION_SLS" "y"
        assert_cfg_eq "${cfg}" "CONFIG_CRYPTO_AES_NI_INTEL" "y"
        assert_cfg_eq "${cfg}" "CONFIG_LEGACY_VSYSCALL_NONE" "y"
        assert_cfg_eq "${cfg}" "CONFIG_CMDLINE_BOOL" "y"
        assert_cfg_eq "${cfg}" "CONFIG_CMDLINE_OVERRIDE" "y"
        assert_cfg_unset "${cfg}" "CONFIG_IA32_EMULATION"
        assert_cfg_unset "${cfg}" "CONFIG_MODIFY_LDT_SYSCALL"
        assert_cfg_unset "${cfg}" "CONFIG_X86_VSYSCALL_EMULATION"
    elif [[ "${arch}" == "aarch64" ]]; then
        assert_cfg_eq "${cfg}" "CONFIG_ARM64_PTR_AUTH" "y"
        assert_cfg_eq "${cfg}" "CONFIG_ARM64_PTR_AUTH_KERNEL" "y"
        assert_cfg_eq "${cfg}" "CONFIG_ARM64_BTI" "y"
        assert_cfg_eq "${cfg}" "CONFIG_ARM64_BTI_KERNEL" "y"
        assert_cfg_eq "${cfg}" "CONFIG_SHADOW_CALL_STACK" "y"
        assert_cfg_eq "${cfg}" "CONFIG_UNMAP_KERNEL_AT_EL0" "y"
        assert_cfg_eq "${cfg}" "CONFIG_RODATA_FULL_DEFAULT_ENABLED" "y"
        assert_cfg_eq "${cfg}" "CONFIG_CRYPTO_AES_ARM64_CE_BLK" "y"
        assert_cfg_eq "${cfg}" "CONFIG_CMDLINE_FORCE" "y"
        assert_cfg_unset "${cfg}" "CONFIG_COMPAT"
    fi

    assert_cfg_eq "${cfg}" "CONFIG_CMDLINE" "\"${EXPECTED_CMDLINE}\""
    log "Verified security invariants for profile=${profile} arch=${arch}"
}

build_profile() {
    local profile="$1"
    local initramfs_path="$2"

    local common_cfg="${CONFIGS_DIR}/common-hardened.config"
    local prof_frag
    local arch_frag
    prof_frag="$(profile_fragment_for "${profile}")"
    arch_frag="$(arch_fragment_for "${ARCH}")"

    local f
    for f in "${common_cfg}" "${prof_frag}" "${arch_frag}"; do
        [[ -f "${f}" ]] || die "Required config file missing: ${f}"
    done

    local fragments=("${common_cfg}" "${prof_frag}" "${arch_frag}")

    local tmp_dir
    tmp_dir="$(mktemp -d)"
    TMP_DIRS+=("${tmp_dir}")

    if [[ -n "${initramfs_path}" ]]; then
        local abs_initramfs
        abs_initramfs="$(cd "$(dirname "${initramfs_path}")" && pwd)/$(basename "${initramfs_path}")"
        [[ -f "${abs_initramfs}" ]] || die "Initramfs file not found: ${abs_initramfs}"
        # Linux CONFIG_INITRAMFS_SOURCE requires an uncompressed .cpio archive;
        # decompress a .cpio.gz into tmp_dir if a sibling raw .cpio is not present.
        local embed_cpio="${abs_initramfs}"
        if [[ "${abs_initramfs}" == *.gz ]]; then
            if [[ -f "${abs_initramfs%.gz}" ]]; then
                embed_cpio="${abs_initramfs%.gz}"
            else
                embed_cpio="${tmp_dir}/initramfs.cpio"
                gzip -dc "${abs_initramfs}" > "${embed_cpio}"
            fi
        fi
        local initramfs_frag="${tmp_dir}/initramfs.fragment"
        {
            printf 'CONFIG_INITRAMFS_SOURCE="%s"\n' "${embed_cpio}"
            printf 'CONFIG_INITRAMFS_ROOT_UID=0\n'
            printf 'CONFIG_INITRAMFS_ROOT_GID=0\n'
            printf 'CONFIG_RD_GZIP=y\n'
            printf 'CONFIG_INITRAMFS_COMPRESSION_GZIP=y\n'
        } > "${initramfs_frag}"
        fragments+=("${initramfs_frag}")
    fi

    if [[ "${CHECK_ONLY}" -eq 1 && -z "${KERNEL_SRC}" ]]; then
        local merged_cfg="${tmp_dir}/merged-${profile}-${ARCH}.config"
        log "Dry-run merging fragments for vmlinux-${profile} (${ARCH})"
        dry_run_merge_fragments "${merged_cfg}" "${fragments[@]}"
        verify_resolved_config "${merged_cfg}" "${profile}" "${ARCH}"
        return 0
    fi

    [[ -n "${KERNEL_SRC}" ]] || die "--kernel-src <dir> (or \$KERNEL_SRC) is required unless --check-only is used"
    [[ -d "${KERNEL_SRC}" ]] || die "Kernel source directory not found: ${KERNEL_SRC}"
    local abs_kernel_src
    abs_kernel_src="$(cd "${KERNEL_SRC}" && pwd)"
    local merge_script="${abs_kernel_src}/scripts/kconfig/merge_config.sh"
    [[ -x "${merge_script}" ]] || die "Linux merge_config.sh not found or not executable: ${merge_script}"

    local karch
    karch="$(kernel_arch_for "${ARCH}")"
    local build_dir="${OUT_DIR}/build-${profile}"
    mkdir -p "${build_dir}" "${OUT_DIR}"

    log "Configuring vmlinux-${profile} (${ARCH} / ARCH=${karch}) via merge_config.sh"
    make -C "${abs_kernel_src}" O="${build_dir}" ARCH="${karch}" LLVM=1 LLVM_IAS=1 defconfig
    (
        cd "${abs_kernel_src}"
        ARCH="${karch}" LLVM=1 LLVM_IAS=1 "${merge_script}" -O "${build_dir}" "${build_dir}/.config" "${fragments[@]}"
    )
    make -C "${abs_kernel_src}" O="${build_dir}" ARCH="${karch}" LLVM=1 LLVM_IAS=1 olddefconfig

    verify_resolved_config "${build_dir}/.config" "${profile}" "${ARCH}"

    if [[ "${CHECK_ONLY}" -eq 1 ]]; then
        log "Check-only mode complete for vmlinux-${profile} (${ARCH})"
        return 0
    fi

    local targets=(vmlinux)
    if [[ "${karch}" == "arm64" ]]; then
        targets+=(Image)
    fi

    log "Building ${targets[*]} for vmlinux-${profile} (${ARCH}, jobs=${JOBS})"
    make -C "${abs_kernel_src}" O="${build_dir}" ARCH="${karch}" LLVM=1 LLVM_IAS=1 -j"${JOBS}" "${targets[@]}"

    local out_vmlinux="${OUT_DIR}/vmlinux-${profile}"
    cp -f "${build_dir}/vmlinux" "${out_vmlinux}"
    cp -f "${build_dir}/.config" "${OUT_DIR}/vmlinux-${profile}.config"
    if [[ "${karch}" == "arm64" && -f "${build_dir}/arch/arm64/boot/Image" ]]; then
        cp -f "${build_dir}/arch/arm64/boot/Image" "${OUT_DIR}/Image-${profile}"
    fi

    if command -v sha256sum >/dev/null 2>&1; then
        (cd "${OUT_DIR}" && sha256sum "vmlinux-${profile}" > "vmlinux-${profile}.sha256")
    fi

    log "Built ${out_vmlinux}"
}

main() {
    parse_args "$@"
    check_toolchain

    local initramfs_path="${INITRAMFS}"
    if [[ "${BUILD_INITRAMFS}" -eq 1 ]]; then
        if [[ "${CHECK_ONLY}" -eq 1 ]]; then
            log "Skipping initramfs build in --check-only mode"
        else
            initramfs_path="${OUT_DIR}/initramfs-${ARCH}.cpio.gz"
            build_initramfs_cpio "${initramfs_path}"
        fi
    fi

    local profiles=()
    if [[ "${PROFILE}" == "all" ]]; then
        profiles=(lo noinet)
    else
        profiles=("${PROFILE}")
    fi

    local p
    for p in "${profiles[@]}"; do
        build_profile "${p}" "${initramfs_path}"
    done

    log "All requested profiles succeeded (arch=${ARCH}, profile=${PROFILE}, check_only=${CHECK_ONLY})"
}

main "$@"
