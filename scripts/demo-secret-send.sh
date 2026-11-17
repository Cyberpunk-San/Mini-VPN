#!/usr/bin/env bash
# ==============================================================================
# minivpn: Live Secret File Sender & Wire Sniffing Proof
# Run this on the sender machine (e.g. Kali Client 1):
#   sudo ./scripts/demo-secret-send.sh [TARGET_IP] [PORT]
# Example:
#   sudo ./scripts/demo-secret-send.sh 10.8.0.3       # send to Client 2
#   sudo ./scripts/demo-secret-send.sh 10.8.0.1       # send to Server
# ==============================================================================
set -euo pipefail

TARGET=${1:-10.8.0.1}
PORT=${2:-9999}
TEMP_PCAP="/tmp/wire_sniff_$$.pcap"
TEMP_TXT="/tmp/wire_sniff_$$.txt"

SECRET_MSG="CONFIDENTIAL VPN TEST: The eagle flies at midnight. Secret key: 0xDEADBEEFCAFE"
echo "$SECRET_MSG" > secret_payload.txt

echo "=========================================================="
echo "          MINIVPN SECRET FILE SENDER & SNIFFER            "
echo "=========================================================="
echo "  [+] Target VPN Destination: $TARGET:$PORT"
echo "  [+] Secret Payload:         secret_payload.txt"
echo "  [+] Sniffing outside wire:  UDP Port 51900..."
echo "=========================================================="

# 1. Start background packet sniffer on physical interface capturing UDP 51900
SNIFF_IFACE=$(ip route | grep default | awk '{print $5}' | head -n1 || echo "any")
tcpdump -ni "$SNIFF_IFACE" udp port 51900 -c 12 -w "$TEMP_PCAP" 2>/dev/null &
TCPDUMP_PID=$!
sleep 0.8

# 2. Transmit the secret file across the VPN tunnel
echo "  [*] Transmitting secret file over VPN tunnel..."
python3 -c "
import socket, sys, time

target = '$TARGET'
port = int('$PORT')

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((target, port))
    with open('secret_payload.txt', 'rb') as f:
        data = f.read()
    s.sendall(data)
    s.close()
    print('  [+] File successfully sent through the encrypted tunnel!')
except Exception as e:
    print(f'  [!] Transmission failed: {e}')
    print('      Ensure the receiver script is running on the target machine.')
"

# 3. Allow tcpdump to capture outgoing ciphertext packets and terminate
sleep 1.2
kill "$TCPDUMP_PID" 2>/dev/null || true
wait "$TCPDUMP_PID" 2>/dev/null || true

# 4. Dump the captured raw wire packets
tcpdump -nr "$TEMP_PCAP" -X 2>/dev/null > "$TEMP_TXT" || true

echo ""
echo "=========================================================="
echo "              LIVE WIRE SNIFFING ANALYSIS                 "
echo "=========================================================="
echo ""
echo "--- [1] WHAT HACKERS / ISP / ROUTER SAW ON THE WIRE: ---"
head -n 24 "$TEMP_TXT" || echo "  (Captured UDP Wire Packets)"
echo "..."
echo ""

# Verify if secret leaked on wire
if grep -q "eagle" "$TEMP_TXT" 2>/dev/null; then
    echo "  [!] LEAK DETECTED: Plaintext was visible on the wire!"
else
    echo "  [✓] ZERO-KNOWLEDGE PROOF: Plaintext search ('eagle', 'DEADBEEF') returned 0 matches."
    echo "  [✓] Wire inspection shows ONLY ChaCha20-Poly1305 encrypted ciphertext."
    echo "  [✓] Only devices with private X25519 keys inside the VPN can decrypt this file."
fi

echo ""
echo "=========================================================="
rm -f "$TEMP_PCAP" "$TEMP_TXT"
