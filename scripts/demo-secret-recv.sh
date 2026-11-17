#!/usr/bin/env bash
# ==============================================================================
# minivpn: Live Secret File Receiver
# Run this on the receiving machine (e.g. Kali Client 2 or WSL Server):
#   sudo ./scripts/demo-secret-recv.sh [PORT]
# ==============================================================================
set -euo pipefail

PORT=${1:-9999}

# Check for tun0/mvpn0
TUN_IP=$(ip -4 -o addr show dev tun0 2>/dev/null | awk '{print $4}' | cut -d/ -f1 || true)
if [ -z "$TUN_IP" ]; then
    TUN_IP=$(ip -4 -o addr show dev mvpn0 2>/dev/null | awk '{print $4}' | cut -d/ -f1 || true)
fi

echo "=========================================================="
echo "          MINIVPN SECRET FILE RECEIVER                    "
echo "=========================================================="
if [ -n "$TUN_IP" ]; then
    echo "  [+] VPN Tunnel Active: $TUN_IP"
else
    echo "  [!] Note: Ensure your minivpn client/server is running"
fi
echo "  [+] Listening on port: $PORT"
echo "  [+] Waiting for incoming encrypted transmission..."
echo "=========================================================="

python3 -c "
import socket, sys, hashlib

port = int('$PORT')
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', port))
s.listen(1)

conn, addr = s.accept()
data = bytearray()
while True:
    chunk = conn.recv(4096)
    if not chunk:
        break
    data.extend(chunk)
conn.close()
s.close()

text = data.decode('utf-8', errors='replace')
h = hashlib.sha256(data).hexdigest()

with open('received_secret.txt', 'wb') as f:
    f.write(data)

print('\n' + '='*58)
print('  >>> TRANSMISSION RECEIVED SUCCESSFULLY! <<<')
print('='*58)
print(f'  From VPN Peer:  {addr[0]}:{addr[1]}')
print(f'  Payload Size:   {len(data)} bytes')
print(f'  SHA-256 Hash:   {h}')
print('----------------------------------------------------------')
print('  [DECRYPTED FILE CONTENT]:')
print(text.strip())
print('----------------------------------------------------------')
print('  Saved to: received_secret.txt')
print('='*58 + '\n')
"
