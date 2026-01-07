#!/usr/bin/env bash
# Copyright (c) 2024, Qualcomm Innovation Center, Inc.
# All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause

set -euo pipefail

# Default host (native build)
HOST_ARCH="x86_64-linux-gnu"
PREFIX_DIR="$(pwd)/install"   # base install prefix
BUILD_BASE="$(pwd)/build"     # out-of-tree build root

usage() {
    cat <<EOF
Usage: $0 [--host <triplet>] [--prefix <path>]

Examples:
  # Native build on x86_64
  $0

  # Cross build for aarch64 glibc
  $0 --host aarch64-linux-gnu

  # Cross build for Android aarch64 (needs NDK_PATH and optional ANDROID_API)
  NDK_PATH=\$HOME/android-ndk-r26d ANDROID_API=21 $0 --host aarch64-linux-android

  # Custom prefix
  $0 --host aarch64-linux-gnu --prefix /tmp/qmi-install
EOF
}

while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --host)
            HOST_ARCH="$2"
            shift 2
            ;;
        --prefix)
            PREFIX_DIR="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Warning: Unknown parameter passed: $1" >&2
            shift 1
            ;;
    esac
done

echo "======================================="
echo " Host triplet  : ${HOST_ARCH}"
echo " Install prefix: ${PREFIX_DIR}"
echo " Build base    : ${BUILD_BASE}"
echo "======================================="

SRC_DIR="$(pwd)"
BUILD_DIR="${BUILD_BASE}/${HOST_ARCH}"
INSTALL_DIR="${PREFIX_DIR}/${HOST_ARCH}"

mkdir -p "${BUILD_DIR}" "${INSTALL_DIR}"

echo "Using build dir   : ${BUILD_DIR}"
echo "Using install dir : ${INSTALL_DIR}"
echo

# Optional: set toolchain based on host triplet.
CC_FOR_HOST=""
CXX_FOR_HOST=""

case "${HOST_ARCH}" in
    aarch64-linux-android)
        # For Android builds you must provide (or accept defaults):
        #   NDK_PATH   -> path to Android NDK root
        #   ANDROID_API -> Android API level (e.g. 21, 28, 30)
        : "${NDK_PATH:=$HOME/android-ndk-r26d}"
        : "${ANDROID_API:=21}"

        TOOLCHAIN="${NDK_PATH}/toolchains/llvm/prebuilt/linux-x86_64/bin"
        CC_FOR_HOST="${TOOLCHAIN}/aarch64-linux-android${ANDROID_API}-clang"
        CXX_FOR_HOST="${TOOLCHAIN}/aarch64-linux-android${ANDROID_API}-clang++"
        ;;

    aarch64-linux-gnu|arm64-linux-gnu)
        CC_FOR_HOST="aarch64-linux-gnu-gcc"
        CXX_FOR_HOST="aarch64-linux-gnu-g++"
        ;;

    arm-linux-gnueabihf|arm-linux-gnueabi)
        CC_FOR_HOST="arm-linux-gnueabihf-gcc"
        CXX_FOR_HOST="arm-linux-gnueabihf-g++"
        ;;

    x86_64-linux-gnu)
        CC_FOR_HOST="gcc"
        CXX_FOR_HOST="g++"
        ;;

    *)
        echo "Note: No specific toolchain mapping for host='${HOST_ARCH}'."
        echo "      Relying on environment CC/CXX (if set) or system defaults."
        ;;
esac

# Environment args for configure/make; passed via 'env'
env_args=()
[[ -n "${CC_FOR_HOST}" ]]  && env_args+=(CC="${CC_FOR_HOST}")
[[ -n "${CXX_FOR_HOST}" ]] && env_args+=(CXX="${CXX_FOR_HOST}")

echo "Toolchain env (for this build only):"
if [[ ${#env_args[@]} -eq 0 ]]; then
    echo "  (none, using system/default CC/CXX)"
else
    for v in "${env_args[@]}"; do
        echo "  $v"
    done
fi
echo

echo "Cleaning build directory for this host..."
rm -rf "${BUILD_DIR:?}"/*
cd "${BUILD_DIR}"

echo "Running autoreconf in source tree..."
(
    cd "${SRC_DIR}"
    autoreconf --install
)

echo "Running configure..."
env "${env_args[@]}" "${SRC_DIR}/configure" \
    --host="${HOST_ARCH}" \
    --prefix="${INSTALL_DIR}"

echo "Running make..."
env "${env_args[@]}" make -j"$(nproc)"

echo "Running make install..."
env "${env_args[@]}" make install

echo "Per-host build done."
echo "Artifacts:"
echo "  Build   : ${BUILD_DIR}"
echo "  Install : ${INSTALL_DIR}"
echo

# Optional deep clean of *generated* autotools files in the source tree.
# Enable via: DEEP_CLEAN=1 ./build_script.sh ...
if [[ "${DEEP_CLEAN:-0}" == "1" ]]; then
    echo "Performing deep clean of autotools artifacts in source tree..."
    cd "${SRC_DIR}"

    FILES_TO_CLEAN=(
        aclocal.m4 configure ar-lib config.h config.h.in config.log config.status libtool
        Makefile Makefile.in compile config.guess install-sh missing mkinstalldirs depcomp
        ltmain.sh stamp-h1 config.sub *subs.sh
    )
    DIRECTORIES_TO_CLEAN=(
        autom4te.cache
        m4
    )

    for file in "${FILES_TO_CLEAN[@]}"; do
        if [[ -f "$file" ]]; then
            rm -f "$file"
        fi
    done

    for dir in "${DIRECTORIES_TO_CLEAN[@]}"; do
        if [[ -d "$dir" ]]; then
            rm -rf "$dir"
        fi
    done

    # Aggressive find-based clean; only under DEEP_CLEAN
    find . -name '*.la'   -delete
    find . -name '*.o'    -delete
    find . -name '*.lo'   -delete
    find . -name '*.libs' -type d -exec rm -rf {} +
    find . -name '.deps'  -type d -exec rm -rf {} +
    find . -name '.dir'   -type d -exec rm -rf {} +
    find . -name 'Makefile'    -exec rm -f {} +
    find . -name 'Makefile.in' -exec rm -f {} +

    echo "Deep clean completed."
fi

echo "Build completed successfully for host='${HOST_ARCH}' "