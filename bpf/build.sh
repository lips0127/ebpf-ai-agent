#!/bin/bash
# eBPF Probe Build Script
# Automatically selects the right probe based on kernel version

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}"
KERNEL_VERSION=$(uname -r)

echo "=== eBPF Probe Build ==="
echo "Kernel: ${KERNEL_VERSION}"

# Detect kernel version family
detect_version() {
    local ver=$1
    local major=$(echo $ver | cut -d. -f1)
    local minor=$(echo $ver | cut -d. -f2)

    if [[ "$major" -lt 5 ]] || [[ "$major" -eq 5 && "$minor" -lt 4 ]]; then
        echo "unsupported"
    elif [[ "$major" -eq 5 && "$minor" -lt 8 ]]; then
        echo "5_4"
    elif [[ "$major" -eq 5 && "$minor" -lt 16 ]]; then
        echo "5_8"
    else
        echo "6_0"
    fi
}

VERSION=$(detect_version $KERNEL_VERSION)
echo "Detected version: $VERSION"

# Check for vmlinux.h
if [[ -f "${SCRIPT_DIR}/vmlinux.h" ]]; then
    echo "Using local vmlinux.h"
    VMLINUX_H="${SCRIPT_DIR}/vmlinux.h"
elif [[ -f "/tmp/vmlinux.h" ]]; then
    echo "Using /tmp/vmlinux.h"
    VMLINUX_H="/tmp/vmlinux.h"
elif [[ -f "/sys/kernel/btf/vmlinux" ]]; then
    echo "Generating vmlinux.h..."
    sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > /tmp/vmlinux.h
    VMLINUX_H="/tmp/vmlinux.h"
else
    echo "Warning: No vmlinux.h found"
    VMLINUX_H=""
fi

# Select probe source
case $VERSION in
    "5_4")
        echo "Building for kernel 5.4-5.7 (no BTF/CO-RE)"
        PROBE_FILE="probe_5_4.c"
        CC_FLAGS="-target bpf -O2 -g"
        if [[ -n "$VMLINUX_H" ]]; then
            CC_FLAGS="$CC_FLAGS -I${SCRIPT_DIR}"
        fi
        ;;
    "5_8")
        echo "Building for kernel 5.8-5.15 (ringbuf, no CO-RE)"
        PROBE_FILE="probe_5_8.c"
        CC_FLAGS="-target bpf -O2 -g -I${SCRIPT_DIR}"
        ;;
    "6_0")
        echo "Building for kernel 6.0+ (full CO-RE)"
        PROBE_FILE="probe_6_0.c"
        CC_FLAGS="-target bpf -O2 -g -I${SCRIPT_DIR}"
        ;;
    *)
        echo "Error: Unsupported kernel version"
        exit 1
        ;;
esac

echo "Using probe: $PROBE_FILE"

# Get architecture
ARCH=$(uname -m)
case $ARCH in
    x86_64)
        TARGET_ARCH="x86"
        ;;
    aarch64)
        TARGET_ARCH="arm64"
        ;;
    armv7l)
        TARGET_ARCH="arm"
        ;;
    *)
        TARGET_ARCH=$ARCH
        ;;
esac

CC_FLAGS="$CC_FLAGS -D__TARGET_ARCH_$TARGET_ARCH"

# Compile
OUTPUT="${OUTPUT_DIR}/probe_bpfel.o"
echo "Compiling to: $OUTPUT"
echo "CC flags: $CC_FLAGS"

clang $CC_FLAGS -c "${SCRIPT_DIR}/${PROBE_FILE}" -o "$OUTPUT"

echo "=== Build complete ==="
ls -la "$OUTPUT"
