#!/usr/bin/env bash
# End-to-end test of the whole product. Network namespaces stand in for
# separate machines; the server is reachable at 10.255.0.1 from every client:
#
#   mvpn-a (alice)  --veth 192.168.101.0/24--+
#   mvpn-b (bob)    --veth 192.168.102.0/24--+-- mvpn-srv (server 10.255.0.1)
#   mvpn-x (others) --veth 192.168.103.0/24--+
#
# Devices are provisioned with minivpn-admin exactly as a customer would.
# Requires root. KEEP_LOGS=1 keeps the logs.

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/minivpn"
WORK="$(mktemp -d /tmp/minivpn-test.XXXXXX)"
ETC="$WORK/etc"
CTL="$WORK/run/control.sock"
NS_S=mvpn-srv NS_A=mvpn-a NS_B=mvpn-b NS_X=mvpn-x
ENDPOINT=10.255.0.1
PIDS=()
PASS=0 FAIL=0

[[ $EUID -eq 0 ]] || { echo "must run as root (network namespaces + TUN)"; exit 1; }
[[ -x $BIN ]] || { echo "build first: make"; exit 1; }
export MINIVPN_BIN="$BIN"
admin() { python3 "$ROOT/admin/minivpn-admin" --etc "$ETC" "$@"; }

cleanup() {
    for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
    wait 2>/dev/null
    for ns in $NS_S $NS_A $NS_B $NS_X; do ip netns del "$ns" 2>/dev/null; done
    if [[ $FAIL -eq 0 && -z ${KEEP_LOGS:-} ]]; then rm -rf "$WORK"; else echo "logs kept in $WORK"; fi
}
trap cleanup EXIT

pass() { echo "  PASS  $*"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL  $*"; FAIL=$((FAIL + 1)); }
check() { local desc=$1; shift; if "$@" >/dev/null 2>&1; then pass "$desc"; else fail "$desc"; fi; }
check_not() { local desc=$1; shift; if "$@" >/dev/null 2>&1; then fail "$desc"; else pass "$desc"; fi; }

wait_for() { # wait_for SECONDS command...
    local deadline=$((SECONDS + $1)); shift
    while ((SECONDS < deadline)); do "$@" >/dev/null 2>&1 && return 0; sleep 0.2; done
    return 1
}

tun_ip() { ip -n "$1" -4 -o addr show dev mvpn0 2>/dev/null | awk '{print $4}' | cut -d/ -f1; }
has_ip() { [[ -n $(tun_ip "$1") ]]; }
ping_from() { ip netns exec "$1" ping -q -c "${3:-3}" -i 0.2 -W 2 "$2"; }
status_field() { admin status --json | python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }
tun_cidr_is() { [[ $(ip -n "$1" -4 -o addr show dev mvpn0 2>/dev/null | awk '{print $4}') == "$2" ]]; }
online_with_traffic_is() { [[ $(status_field 'sum(x["online"] and x["rx_bytes"] > 0 for x in d["devices"])') == "$1" ]]; }
alice_rx() { status_field 'next(x.get("rx_packets", 0) for x in d["devices"] if x["name"] == "alice")'; }
over_limit_is() { [[ $(status_field 'd["server"]["devices_over_limit"]') == "$1" ]]; }
active_devices_is() { [[ $(grep -c ' active ' "$ETC/devices") == "$1" ]]; }
file_mode_is() { [[ $(stat -c %a "$1") == "$2" ]]; }
log_count_at_least() { [[ $(grep -c "$2" "$1") -ge $3 ]]; }
audit_has_all() { local a; for a in "$@"; do grep -q "\"action\": \"$a\"" "$ETC/audit.log" || return 1; done; }

make_link() { # make_link NS N  -> veth pair on 192.168.N.0/24, route to the server endpoint
    local ns=$1 n=$2
    ip link add "vs$n" type veth peer name "vc$n"
    ip link set "vs$n" netns $NS_S
    ip link set "vc$n" netns "$ns"
    ip -n $NS_S addr add "192.168.$n.1/24" dev "vs$n"
    ip -n $NS_S link set "vs$n" up
    ip -n "$ns" addr add "192.168.$n.2/24" dev "vc$n"
    ip -n "$ns" link set "vc$n" up
    ip -n "$ns" link set lo up
    ip -n "$ns" route add "$ENDPOINT/32" via "192.168.$n.1"
}

start_server() {
    ip netns exec $NS_S "$BIN" server --config "$ETC/server.conf" -v >>"$WORK/server.log" 2>&1 &
    SERVER_PID=$!
    PIDS+=("$SERVER_PID")
    wait_for 5 test -S "$CTL"
}

start_client() { # start_client NS CONFIG [extra args]; sets CLIENT_PID
    local ns=$1 conf=$2; shift 2
    ip netns exec "$ns" "$BIN" client --config "$conf" --dev mvpn0 "$@" >>"$WORK/$ns.log" 2>&1 &
    CLIENT_PID=$!
    PIDS+=("$CLIENT_PID")
}

# Counts plaintext ICMP vs. tunnel UDP frames seen on a link.
sniff() { # sniff NS IFACE SECONDS -> "icmp=N udp=M"
    ip netns exec "$1" python3 - "$2" "$3" <<'EOF'
import socket, sys, time
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
s.bind((sys.argv[1], 0)); s.settimeout(0.2)
end, icmp, udp = time.time() + float(sys.argv[2]), 0, 0
while time.time() < end:
    try: f = s.recv(65535)
    except socket.timeout: continue
    icmp += f[23] == 1
    udp += f[23] == 17
print(f"icmp={icmp} udp={udp}")
EOF
}

echo "== setup"
for ns in $NS_S $NS_A $NS_B $NS_X; do ip netns del "$ns" 2>/dev/null; ip netns add "$ns"; done
ip -n $NS_S link set lo up
ip -n $NS_S addr add "$ENDPOINT/32" dev lo
make_link $NS_A 101
make_link $NS_B 102
make_link $NS_X 103
chmod 711 "$WORK" # the server drops to 'nobody' and must still reach its config
echo "        work dir $WORK"

echo "== provisioning (minivpn-admin)"
check "init creates the server configuration" \
    bash -c "echo 'integration-pass-123' | python3 '$ROOT/admin/minivpn-admin' --etc '$ETC' init \
             --endpoint $ENDPOINT --user nobody --password-stdin"
cat >>"$ETC/server.conf" <<EOF
listen = $ENDPOINT
control_socket = $CTL
EOF
check "add alice" admin add alice -o "$WORK/alice.conf"
check "add bob" admin add bob -o "$WORK/bob.conf"
check "device configs are private (0600)" file_mode_is "$WORK/alice.conf" 600
check "registry is readable by the service group only (0640)" file_mode_is "$ETC/devices" 640
check_not "duplicate device names are refused" admin add alice

echo "== handshake"
start_server
start_client $NS_A "$WORK/alice.conf" --rekey 5
ALICE_PID=$CLIENT_PID
start_client $NS_B "$WORK/bob.conf"
BOB_PID=$CLIENT_PID
check "alice gets her address (10.8.0.2)" wait_for 10 tun_cidr_is $NS_A 10.8.0.2/24
check "bob gets his address (10.8.0.3)" wait_for 10 tun_cidr_is $NS_B 10.8.0.3/24
check "server dropped root (runs as nobody)" bash -c "[[ \$(ps -o user= -p $SERVER_PID) == nobody ]]"

sed "s/^key = .*/key = $(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')/" "$WORK/alice.conf" >"$WORK/stolen-id.conf"
sed "s/^device_id = .*/device_id = $(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')/" "$WORK/alice.conf" >"$WORK/unknown.conf"
chmod 600 "$WORK/stolen-id.conf" "$WORK/unknown.conf"
start_client $NS_X "$WORK/stolen-id.conf"
FAKE_PID=$CLIENT_PID
check "a known device id with the wrong key is rejected" wait_for 5 grep -q "wrong device key" "$WORK/server.log"
kill "$FAKE_PID"; wait "$FAKE_PID" 2>/dev/null
sleep 10.5 # the server rate-limits rejection warnings to one per 10s
start_client $NS_X "$WORK/unknown.conf"
FAKE_PID=$CLIENT_PID
check "an unregistered device is rejected" wait_for 5 grep -q "unknown, revoked or disabled device" "$WORK/server.log"
check_not "rejected clients get no tunnel address" has_ip $NS_X
kill "$FAKE_PID"; wait "$FAKE_PID" 2>/dev/null

echo "== traffic"
check "alice -> server (10.8.0.1)" ping_from $NS_A 10.8.0.1
check "alice -> bob (device-to-device)" ping_from $NS_A 10.8.0.3
check "bob -> alice" ping_from $NS_B 10.8.0.2
check "1372-byte packets pass unfragmented (MTU 1400)" ip netns exec $NS_A ping -q -c 3 -i 0.2 -W 2 -s 1344 -M do 10.8.0.1
check_not "oversized DF packets are refused locally" ip netns exec $NS_A ping -q -c 1 -W 1 -s 1400 -M do 10.8.0.1

ip netns exec $NS_A ping -q -c 15 -i 0.1 10.8.0.1 >/dev/null 2>&1 &
WIRE=$(sniff $NS_S vs101 1.2)
wait $! 2>/dev/null
echo "        on the wire during ping: $WIRE"
check "the physical link carries only encrypted UDP" bash -c "[[ '$WIRE' =~ icmp=0\ udp=[1-9] ]]"

mkdir -p "$WORK/www"
head -c 8M /dev/urandom >"$WORK/www/blob"
ip netns exec $NS_B python3 -m http.server 8080 --bind 10.8.0.3 --directory "$WORK/www" >"$WORK/http.log" 2>&1 &
PIDS+=("$!")
wait_for 5 ip netns exec $NS_A python3 -c "import socket; socket.create_connection(('10.8.0.3', 8080), 1)"
SPEED=$(ip netns exec $NS_A python3 - "$WORK/fetched" <<'EOF'
import sys, time, urllib.request
t = time.time()
data = urllib.request.urlopen("http://10.8.0.3:8080/blob", timeout=60).read()
open(sys.argv[1], "wb").write(data)
print(f"{len(data) * 8 / (time.time() - t) / 1e6:.0f} Mbit/s")
EOF
)
echo "        8 MiB over TCP bob -> alice: ${SPEED:-failed}"
check "8 MiB TCP transfer arrives intact (sha256 match)" \
    bash -c "[[ \$(sha256sum <'$WORK/www/blob') == \$(sha256sum <'$WORK/fetched') ]]"

echo "== management API"
check "status reports 2 sessions with traffic counters" online_with_traffic_is 2
check "list shows alice online" bash -c "python3 '$ROOT/admin/minivpn-admin' --etc '$ETC' list | grep -E '^alice +10.8.0.2 +active +yes'"
admin kick alice >/dev/null
check "kick disconnects a device (it reconnects by itself)" wait_for 3 grep -q "alice.*disconnected by administrator" "$WORK/server.log"
check "kicked device reconnects" wait_for 15 ping_from $NS_A 10.8.0.1 1

echo "== rekey (alice rekeys every 5s)"
ping_from $NS_A 10.8.0.1 10 >/dev/null
RX_BEFORE=$(alice_rx)
REKEYS=$(grep -c "rekeyed" "$WORK/$NS_A.log")
check "alice rekeyed" wait_for 12 log_count_at_least "$WORK/$NS_A.log" "rekeyed" $((REKEYS + 1))
check "traffic flows after the rekey" ping_from $NS_A 10.8.0.3
check "traffic counters carry over across the rekey" bash -c "(( $(alice_rx) > $RX_BEFORE && $RX_BEFORE >= 10 ))"

echo "== access control"
admin disable bob >/dev/null
check "disabling bob disconnects him immediately" wait_for 3 grep -q "bob.*access revoked" "$WORK/server.log"
check_not "disabled bob cannot reach the network" ping_from $NS_B 10.8.0.1 2
admin enable bob >/dev/null
check "re-enabled bob reconnects on his own" wait_for 25 ping_from $NS_B 10.8.0.1 1
echo y | admin revoke bob >/dev/null
check "revoking bob disconnects him" wait_for 3 log_count_at_least "$WORK/server.log" "bob.*access revoked" 2
check_not "revoked bob is gone from the registry" grep -q " bob$" "$ETC/devices"
check "alice is unaffected" ping_from $NS_A 10.8.0.1

echo "== licensing"
for d in d3 d4 d5 d6; do admin add $d -o /dev/null >/dev/null 2>&1; done
check "Community edition: 5 devices fit" active_devices_is 5
check_not "Community edition: the 6th device is refused" admin add d7
# A hand-edited registry can't bypass the limit: the server enforces it too.
printf '%s %s 10.8.0.99 active %s handmade\n' "$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')" \
    "$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')" "$(date +%s)" >>"$ETC/devices"
admin reload >/dev/null
check "server refuses to load devices beyond the license" over_limit_is 1
if [[ -x $ROOT/tools/license-tool && -f $ROOT/vendor/license-signing.key ]]; then
    (cd "$ROOT" && ./tools/license-tool sign --customer "Integration Test Ltd" --devices 10 --days 30) >"$WORK/license.key"
    sed 's/max_devices = 10/max_devices = 1000/' "$WORK/license.key" >"$WORK/forged.key"
    check_not "a tampered license is refused" admin license install "$WORK/forged.key"
    check "a genuine Business license installs" admin license install "$WORK/license.key"
    check "server picks up the license without a restart" over_limit_is 0
    check "status shows the Business edition" \
        bash -c "python3 '$ROOT/admin/minivpn-admin' --etc '$ETC' status | grep -q 'business edition licensed to Integration Test Ltd for 10 devices'"
    check "devices beyond 5 are now accepted" admin add d7 -o /dev/null
else
    echo "  SKIP  license signing (no vendor key; run: make vendor-key)"
fi

echo "== web dashboard"
# Started directly (not via the admin() function) so $! is python itself and cleanup kills it.
python3 "$ROOT/admin/minivpn-admin" --etc "$ETC" web --listen 127.0.0.1:18090 >"$WORK/web.log" 2>&1 &
PIDS+=("$!")
wait_for 5 python3 -c "import socket; socket.create_connection(('127.0.0.1', 18090), 1)"
check "dashboard login + live overview from the running server" python3 - <<'EOF'
import http.cookiejar, json, re, urllib.parse, urllib.request
jar = http.cookiejar.CookieJar()
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
page = op.open("http://127.0.0.1:18090/login", urllib.parse.urlencode(
    {"username": "admin", "password": "integration-pass-123"}).encode()).read().decode()
assert 'name="csrf"' in page, "login failed"
ov = json.load(op.open("http://127.0.0.1:18090/api/overview"))
assert ov["server"] and ov["server"]["interface"] == "mvpn0", ov["server"]
alice = next(d for d in ov["devices"] if d["name"] == "alice")
assert alice["online"] and alice["rx_bytes"] > 0, alice
EOF

echo "== server restart"
kill -TERM "$SERVER_PID"
wait "$SERVER_PID"
SERVER_RC=$?
check "server exits cleanly on SIGTERM" test "$SERVER_RC" -eq 0
check "clients are told the server went away" wait_for 3 grep -q "server closed the session" "$WORK/$NS_A.log"
start_server
check "alice reconnects with the same address" wait_for 20 ping_from $NS_A 10.8.0.1 1
check "alice keeps 10.8.0.2" tun_cidr_is $NS_A 10.8.0.2/24

echo "== full tunnel (--redirect-gateway)"
# A fresh device in namespace X sends ALL traffic via the VPN; the server
# forwards it to bob's physical network, standing in for "the internet".
kill -TERM "$BOB_PID" 2>/dev/null
wait "$BOB_PID" 2>/dev/null
admin revoke -y d3 >/dev/null
admin revoke -y handmade >/dev/null
admin add roadwarrior -o "$WORK/road.conf" >/dev/null 2>&1
ip -n $NS_X route del "$ENDPOINT/32" # the client must pin this route itself
ip -n $NS_X route add default via 192.168.103.1
ip netns exec $NS_S sysctl -qw net.ipv4.ip_forward=1
ip -n $NS_B route add 10.8.0.0/24 via 192.168.102.1
start_client $NS_X "$WORK/road.conf" --redirect-gateway
X_PID=$CLIENT_PID
check "full-tunnel device connects" wait_for 10 has_ip $NS_X
check "0.0.0.0/1 and 128.0.0.0/1 point into the tunnel" \
    bash -c "ip -n $NS_X route | grep -q '^0.0.0.0/1 dev mvpn0' && ip -n $NS_X route | grep -q '^128.0.0.0/1 dev mvpn0'"
check "server endpoint stays pinned to the old gateway" \
    bash -c "ip -n $NS_X route | grep -q '^$ENDPOINT via 192.168.103.1 dev vc103'"
ip netns exec $NS_X ping -q -c 15 -i 0.1 192.168.102.2 >/dev/null 2>&1 &
WIRE=$(sniff $NS_S vs103 1.2)
wait $! 2>/dev/null
echo "        on the wire during ping: $WIRE"
check "\"internet\" host is reached through the tunnel" \
    bash -c "[[ '$WIRE' =~ icmp=0\ udp=[1-9] ]] && ip netns exec $NS_X ping -q -c 2 -W 2 192.168.102.2"
kill -TERM "$X_PID"
wait "$X_PID" 2>/dev/null
check "pinned route is removed on exit" bash -c "! ip -n $NS_X route | grep -q '^$ENDPOINT via 192.168.103.1'"

echo "== disconnect"
kill -TERM "$ALICE_PID"
check "server sees alice leave" wait_for 3 grep -q "alice.*client disconnected" "$WORK/server.log"
check "alice's interface is gone" wait_for 3 bash -c "! ip -n $NS_A link show mvpn0"
check "audit log recorded the admin actions" audit_has_all add kick disable enable revoke license login

echo
echo "$PASS passed, $FAIL failed"
exit $((FAIL > 0))
