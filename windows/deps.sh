#!/usr/bin/env bash
# Fetches and builds the Windows dependencies (run on Linux/WSL):
#   - OpenSSL, cross-compiled as a static libcrypto for mingw-w64
#   - Wintun, the signed layer-3 TUN driver used by WireGuard for Windows
# Everything lands in $WINDEPS (default ~/.cache/minivpn-windeps). Idempotent.
#
# Needs: apt install mingw-w64 nsis unzip
set -euo pipefail

OPENSSL_VERSION=3.5.9
WINTUN_VERSION=0.14.1
WINTUN_SHA256=07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51

WINDEPS=${WINDEPS:-$HOME/.cache/minivpn-windeps}
CROSS=x86_64-w64-mingw32-
mkdir -p "$WINDEPS/src"
cd "$WINDEPS/src"

command -v ${CROSS}gcc >/dev/null || { echo "missing ${CROSS}gcc: apt install mingw-w64"; exit 1; }

fetch() { # fetch URL FILE
    [[ -f $2 ]] || curl -fsSL --retry 3 -o "$2.part" "$1" && { [[ -f $2 ]] || mv "$2.part" "$2"; }
}

# ---- Wintun ---------------------------------------------------------------
if [[ ! -f $WINDEPS/wintun/bin/amd64/wintun.dll ]]; then
    fetch "https://www.wintun.net/builds/wintun-$WINTUN_VERSION.zip" "wintun-$WINTUN_VERSION.zip"
    echo "$WINTUN_SHA256  wintun-$WINTUN_VERSION.zip" | sha256sum -c --quiet
    rm -rf "$WINDEPS/wintun"
    unzip -q -o "wintun-$WINTUN_VERSION.zip" -d "$WINDEPS"
    echo "wintun $WINTUN_VERSION ready"
fi

# ---- OpenSSL (static libcrypto only) --------------------------------------
if [[ ! -f $WINDEPS/openssl/lib64/libcrypto.a && ! -f $WINDEPS/openssl/lib/libcrypto.a ]]; then
    tarball="openssl-$OPENSSL_VERSION.tar.gz"
    base="https://github.com/openssl/openssl/releases/download/openssl-$OPENSSL_VERSION"
    fetch "$base/$tarball" "$tarball"
    fetch "$base/$tarball.sha256" "$tarball.sha256"
    echo "$(awk '{print $1}' "$tarball.sha256")  $tarball" | sha256sum -c --quiet
    rm -rf "openssl-$OPENSSL_VERSION"
    tar xzf "$tarball"
    cd "openssl-$OPENSSL_VERSION"
    ./Configure mingw64 --cross-compile-prefix=$CROSS --prefix="$WINDEPS/openssl" \
        no-shared no-tests no-docs no-apps no-engine no-legacy no-module -static >/dev/null
    echo "building OpenSSL $OPENSSL_VERSION for Windows (a few minutes)..."
    make -j"$(nproc)" build_libs >/dev/null
    make install_dev >/dev/null
    echo "openssl $OPENSSL_VERSION ready"
fi

echo "Windows dependencies in $WINDEPS"
