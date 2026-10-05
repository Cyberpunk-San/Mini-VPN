# minivpn wire protocol, version 2

All integers are big-endian. Transport is UDP, port 51900 by default.

## Identities and keys

Every device has a **device id** (16 random bytes, public) and a **device key**
(32 random bytes, secret). Both are created by `minivpn-admin add`. They are stored in
the server's registry and in the device's config file.

```
auth_key     = HKDF-SHA256(ikm = device_key, info = "minivpn v2 handshake auth")
session keys = HKDF-SHA256(salt = device_key, ikm = X25519(eph_priv, peer_eph_pub),
                           info = "minivpn v2 session keys" || device_id || client_pub || server_pub || session_id)
             -> key_c2s (32) || key_s2c (32)
```

An attacker needs **both** a device key and an ephemeral private key to read any
session. Ephemeral keys are wiped right after the handshake, which gives forward secrecy.

## Handshake (one round trip)

```
HELLO   client -> server   92 bytes
  0  type = 1
  1  version = 2
  2  reserved (2)
  4  device_id (16)
 20  client ephemeral X25519 public key (32)
 52  unix time, seconds (8)
 60  HMAC-SHA256(auth_key, bytes 0..59) (32)

WELCOME server -> client   84 bytes
  0  type = 2
  1  version = 2
  2  tunnel MTU (2)
  4  session_id (4)
  8  server ephemeral X25519 public key (32)
 40  client tunnel IP (4)
 44  netmask (4)
 48  server tunnel IP (4)
 52  HMAC-SHA256(auth_key, HELLO.mac || bytes 0..51) (32)
```

Server rules:
- It looks up `device_id`. An unknown or disabled device, or a bad MAC, gets **no reply**,
  so nothing is revealed to scanners. Rejections are logged, rate-limited.
- The timestamp must be within ±60 s of the server's clock. That limits HELLO replays.
- A HELLO carrying the same ephemeral key as the device's current session is a
  retransmission or a replay. The server re-sends the cached WELCOME and never creates
  a second session.
- A device holds one session. A new HELLO from the same device (a rekey or reconnect)
  replaces the old one and keeps its traffic counters.

The WELCOME MAC covers the HELLO's MAC, so a WELCOME is only accepted as the answer
to the exact HELLO the client sent.

## Data packets

```
  0  type: 3 DATA | 4 KEEPALIVE | 5 DISCONNECT
  1  reserved (3)
  4  session_id (4)
  8  counter (8)
 16  ChaCha20-Poly1305 ciphertext (n)
16+n tag (16)

AAD = bytes 0..15 (header, authenticated but not encrypted)
nonce = 0x00000000 || counter
```

- Each direction has its own key, so a nonce never repeats with the same key.
- **Anti-replay:** a 1024-entry sliding window. Counters already seen, or 1024 or more
  below the highest, are dropped. The window only advances after the tag verifies.
- **Anti-spoofing:** the server drops DATA whose inner IPv4 source isn't the
  device's assigned address.
- **Roaming:** the server updates a session's UDP endpoint whenever an authenticated
  packet arrives from a new address.
- Overhead is 32 bytes, plus 28 for UDP/IPv4. The default MTU of 1400 fits a 1500-byte path.

## Timers

| What | Value |
|---|---|
| Keepalive after idle | 10 s (both sides) |
| Client: server considered dead | 30 s without receiving |
| Server: session expires | 60 s without receiving |
| HELLO retransmit | 1, 2, 4, 8, 8… s, fresh ephemeral key after 45 s |
| Rekey | every 300 s (client `rekey`) |

## Local control API

Unix stream socket, `/run/minivpn/control.sock` by default, mode 0600. Only uid 0 and
the daemon's own uid may connect (checked with `SO_PEERCRED`). The client sends one
line and gets one JSON reply:

| Command | Reply |
|---|---|
| `status` | server info, license, `sessions[]` with endpoint, counters, idle time |
| `reload` | re-reads the registry and license; disconnects revoked or changed devices |
| `kick <device_id hex>` | disconnects one device |

## License files

```
customer = Acme Corp
edition = business
max_devices = 25
issued = 2026-10-04
expires = 2027-10-04
license_id = LIC-9e7875763e59bc27
signature = <128 hex: Ed25519 over the canonical text below>
```

The canonical text is `"minivpn-license-v1\n"` followed by `key=value\n` for customer,
edition, max_devices, issued, expires and license_id, in that order. Whitespace and
comments in the file don't matter. Any change to a value breaks the signature. The
verification key is compiled into the `minivpn` binary.
