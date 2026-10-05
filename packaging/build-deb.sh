#!/usr/bin/env bash
# Builds build/minivpn_<version>_<arch>.deb from an already-built tree.
#   make deb
set -euo pipefail

VERSION=${1:?usage: build-deb.sh VERSION}
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ARCH=$(dpkg --print-architecture)
MAINTAINER=${DEB_MAINTAINER:-"minivpn <support@example.com>"}
# Stage on a Linux filesystem: dpkg-deb rejects the 0777 modes that Windows
# mounts (/mnt/c under WSL) report for every file.
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
PKG="$STAGE/minivpn_${VERSION}_${ARCH}"
mkdir -p "$ROOT/build"
make -C "$ROOT" --no-print-directory DESTDIR="$PKG" PREFIX=/usr install
strip --strip-unneeded "$PKG/usr/sbin/minivpn"
install -D -m 0644 "$ROOT/README.md" "$PKG/usr/share/doc/minivpn/README.md"
install -D -m 0644 "$ROOT/docs/ADMIN-GUIDE.md" "$PKG/usr/share/doc/minivpn/ADMIN-GUIDE.md"
install -D -m 0644 "$ROOT/docs/PROTOCOL.md" "$PKG/usr/share/doc/minivpn/PROTOCOL.md"
install -D -m 0644 "$ROOT/LICENSE" "$PKG/usr/share/doc/minivpn/copyright"
install -D -m 0755 "$ROOT/scripts/server-nat.sh" "$PKG/usr/share/minivpn/server-nat.sh"

mkdir -p "$PKG/DEBIAN"
SIZE=$(du -sk "$PKG" --exclude=DEBIAN | cut -f1)
cat >"$PKG/DEBIAN/control" <<EOF
Package: minivpn
Version: $VERSION
Architecture: $ARCH
Maintainer: $MAINTAINER
Installed-Size: $SIZE
Depends: libc6, libssl3 | libssl3t64, python3 (>= 3.8), adduser
Section: net
Priority: optional
Homepage: https://example.com/minivpn
Description: self-hosted team VPN with web dashboard
 minivpn connects laptops, servers and offices into one private network.
 Each device gets its own key and fixed address and can be revoked
 instantly from the web dashboard or the minivpn-admin CLI.
 .
 Traffic is encrypted with X25519, ChaCha20-Poly1305 and HKDF-SHA256 with
 forward secrecy. The Community edition supports up to 5 devices; larger
 deployments use a Business license.
EOF

cat >"$PKG/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = configure ]; then
    if ! getent passwd minivpn >/dev/null; then
        adduser --system --group --no-create-home --home /nonexistent --quiet minivpn
    fi
    install -d -m 0750 -o root -g minivpn /etc/minivpn
    install -d -m 0700 -o root -g root /etc/minivpn/clients
    if [ -d /run/systemd/system ]; then
        systemctl daemon-reload >/dev/null || true
        # Upgrades: restart running services onto the new binary.
        systemctl try-restart minivpn-server.service minivpn-admin.service >/dev/null 2>&1 || true
    fi
    if [ ! -f /etc/minivpn/server.conf ]; then
        cat <<MSG

minivpn installed. To set up a server:
  sudo minivpn-admin init --endpoint <this server's public IP or hostname>
  sudo minivpn-admin add laptop -o laptop.conf
  sudo systemctl enable --now minivpn-server minivpn-admin
  Dashboard: ssh -L 8090:127.0.0.1:8090 <server>, then open http://localhost:8090

MSG
    fi
fi
exit 0
EOF

cat >"$PKG/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = remove ] && [ -d /run/systemd/system ]; then
    systemctl stop minivpn-admin.service minivpn-server.service 'minivpn-client@*.service' >/dev/null 2>&1 || true
fi
exit 0
EOF

cat >"$PKG/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = purge ]; then
    # Removes device keys, the license and the audit log.
    rm -rf /etc/minivpn
    if getent passwd minivpn >/dev/null; then deluser --system --quiet minivpn || true; fi
fi
if [ -d /run/systemd/system ]; then systemctl daemon-reload >/dev/null 2>&1 || true; fi
exit 0
EOF
chmod 0755 "$PKG/DEBIAN/postinst" "$PKG/DEBIAN/prerm" "$PKG/DEBIAN/postrm"

chmod -R u=rwX,go=rX "$PKG"
chmod 0755 "$PKG/DEBIAN" "$PKG/DEBIAN/postinst" "$PKG/DEBIAN/prerm" "$PKG/DEBIAN/postrm" \
    "$PKG/usr/sbin/minivpn" "$PKG/usr/sbin/minivpn-admin" "$PKG/usr/share/minivpn/server-nat.sh"
dpkg-deb --root-owner-group -Zxz --build "$PKG" "$ROOT/build/" >/dev/null
echo "built build/minivpn_${VERSION}_${ARCH}.deb"
