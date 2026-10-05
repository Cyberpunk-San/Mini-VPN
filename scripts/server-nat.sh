#!/usr/bin/env bash
# Lets VPN clients reach the internet through the server (needed for
# `minivpn client --redirect-gateway`). Enables IPv4 forwarding and masquerades
# tunnel traffic leaving the server's uplink.
#
#   sudo ./scripts/server-nat.sh up   [SUBNET] [UPLINK]
#   sudo ./scripts/server-nat.sh down [SUBNET] [UPLINK]
#
# SUBNET defaults to 10.8.0.0/24; UPLINK to the interface of the default route.

set -euo pipefail

ACTION=${1:-}
SUBNET=${2:-10.8.0.0/24}
UPLINK=${3:-$(ip -4 route show default | awk '{for (i = 1; i < NF; i++) if ($i == "dev") { print $(i + 1); exit }}')}

[[ $EUID -eq 0 ]] || { echo "run with sudo"; exit 1; }
[[ -n $UPLINK ]] || { echo "could not detect the uplink interface; pass it explicitly"; exit 1; }
command -v iptables >/dev/null || { echo "iptables not found (apt install iptables)"; exit 1; }

rules() {
    local op=$1
    iptables -t nat "$op" POSTROUTING -s "$SUBNET" -o "$UPLINK" -j MASQUERADE
    iptables "$op" FORWARD -s "$SUBNET" -o "$UPLINK" -j ACCEPT
    iptables "$op" FORWARD -d "$SUBNET" -i "$UPLINK" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
}

case $ACTION in
up)
    sysctl -qw net.ipv4.ip_forward=1
    rules -C 2>/dev/null || rules -A
    echo "NAT enabled: $SUBNET -> $UPLINK"
    ;;
down)
    rules -D 2>/dev/null || true
    echo "NAT rules for $SUBNET on $UPLINK removed (ip_forward left as is)"
    ;;
*)
    echo "usage: $0 up|down [SUBNET] [UPLINK]"
    exit 2
    ;;
esac
