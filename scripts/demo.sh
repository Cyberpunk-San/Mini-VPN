#!/usr/bin/env bash
# Live product demo on one Linux machine (or WSL2): a VPN server, two
# employee devices and the web dashboard, provisioned with minivpn-admin.
# Background traffic keeps the dashboard's live graphs moving.
#
#   sudo ./scripts/demo.sh            then open http://localhost:8090
#                                     (from Windows too, when run in WSL2)

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/minivpn"
WORK="$(mktemp -d /tmp/minivpn-demo.XXXXXX)"
ETC="$WORK/etc"
ENDPOINT=10.255.0.1
PASSWORD=${DEMO_PASSWORD:-demo-password}
PORT=${DEMO_PORT:-8090}
PIDS=()

[[ $EUID -eq 0 ]] || { echo "run with sudo"; exit 1; }
[[ -x $BIN ]] || { echo "build first: make"; exit 1; }
export MINIVPN_BIN="$BIN"
admin() { python3 "$ROOT/admin/minivpn-admin" --etc "$ETC" "$@"; }

cleanup() {
    for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
    wait 2>/dev/null || true
    for ns in vpn-server vpn-alice vpn-bob; do ip netns del "$ns" 2>/dev/null || true; done
    rm -rf "$WORK"
    echo "demo stopped and cleaned up"
}
trap cleanup EXIT

for ns in vpn-server vpn-alice vpn-bob; do ip netns del "$ns" 2>/dev/null || true; ip netns add "$ns"; done
ip -n vpn-server link set lo up
ip -n vpn-server addr add "$ENDPOINT/32" dev lo
n=1
for ns in vpn-alice vpn-bob; do
    ip link add "srv$n" type veth peer name eth0 netns "$ns"
    ip link set "srv$n" netns vpn-server
    ip -n vpn-server addr add "172.30.$n.1/24" dev "srv$n"
    ip -n vpn-server link set "srv$n" up
    ip -n "$ns" addr add "172.30.$n.2/24" dev eth0
    ip -n "$ns" link set eth0 up
    ip -n "$ns" link set lo up
    ip -n "$ns" route add "$ENDPOINT/32" via "172.30.$n.1"
    n=$((n + 1))
done
chmod 711 "$WORK"

echo "$PASSWORD" | admin init --endpoint "$ENDPOINT" --user nobody --password-stdin >/dev/null
printf 'listen = %s\ncontrol_socket = %s/control.sock\n' "$ENDPOINT" "$WORK" >>"$ETC/server.conf"
admin add alice-laptop -o "$WORK/alice.conf" 2>/dev/null
admin add bob-desktop -o "$WORK/bob.conf" 2>/dev/null
admin add carol-phone -o /dev/null 2>/dev/null # registered, offline

ip netns exec vpn-server "$BIN" server --config "$ETC/server.conf" >"$WORK/server.log" 2>&1 &
PIDS+=("$!")
for _ in $(seq 25); do [[ -S $WORK/control.sock ]] && break; sleep 0.2; done
ip netns exec vpn-alice "$BIN" client --config "$WORK/alice.conf" --dev tun0 >"$WORK/alice.log" 2>&1 &
PIDS+=("$!")
ip netns exec vpn-bob "$BIN" client --config "$WORK/bob.conf" --dev tun0 >"$WORK/bob.log" 2>&1 &
PIDS+=("$!")
for _ in $(seq 50); do
    ip -n vpn-bob -4 addr show dev tun0 2>/dev/null | grep -q inet && break
    sleep 0.2
done

# Background traffic so the dashboard shows live throughput.
ip netns exec vpn-alice ping -q -i 0.05 -s 1200 10.8.0.3 >/dev/null 2>&1 &
PIDS+=("$!")
ip netns exec vpn-bob ping -q -i 0.2 -s 400 10.8.0.1 >/dev/null 2>&1 &
PIDS+=("$!")

# Started directly (not via admin()) so $! is python itself and cleanup kills it.
python3 "$ROOT/admin/minivpn-admin" --etc "$ETC" web --listen "127.0.0.1:$PORT" >"$WORK/web.log" 2>&1 &
PIDS+=("$!")
sleep 0.5

cat <<EOF

  minivpn demo is running
  -----------------------
  Dashboard   http://localhost:$PORT      user: admin   password: $PASSWORD

  server        namespace vpn-server   public $ENDPOINT   tunnel 10.8.0.1
  alice-laptop  namespace vpn-alice    tunnel 10.8.0.2
  bob-desktop   namespace vpn-bob      tunnel 10.8.0.3
  carol-phone   registered, not connected

  Try, in another terminal:
    sudo ip netns exec vpn-alice ping 10.8.0.3                       # alice -> bob over the VPN
    sudo MINIVPN_BIN=$BIN python3 $ROOT/admin/minivpn-admin --etc $ETC list
    sudo ip netns exec vpn-server tcpdump -ni srv1 -c 5 -X             # only encrypted UDP on the wire
    Click "Disable" on bob-desktop in the dashboard and watch his ping stop.

EOF
read -rp "Press Enter to stop the demo... " _
