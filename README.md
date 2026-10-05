# minivpn

**A self-hosted team VPN with a web dashboard.** Connect laptops, servers and offices
into one private network on your own server. Onboard a device in one command, and
cut it off in under a second when someone leaves.

- 🔐 **Per-device keys.** Every device has its own identity and fixed address, and can be revoked instantly.
- 🖥️ **Web dashboard.** See who's online, where they connect from and live throughput. Add, disable or revoke devices, with an audit log.
- ⚡ **Fast and modern.** X25519 + ChaCha20-Poly1305 with forward secrecy and automatic rekeying. About 680 Mbit/s on a laptop.
- 🧳 **Resilient.** Auto-reconnect, roaming between networks, keepalives through NAT, optional full-tunnel mode.
- 📦 **Easy to run.** One `.deb`, hardened systemd services, an unprivileged daemon, a config-file workflow.
- 💼 **Editions.** Community is free for 5 devices. Business licenses are signed files that work offline.

```
$ sudo minivpn-admin add alice-laptop -o alice.conf
added alice-laptop (10.8.0.2); config written to alice.conf
server reloaded (3 device(s) active)

$ sudo minivpn-admin list
NAME                   TUNNEL IP       STATUS    ONLINE   CONNECTED FROM           RECEIVED       SENT
alice-laptop           10.8.0.2        active    yes      49.36.112.7:55120          1.7 GB   394.9 MB
build-server           10.8.0.4        active    yes      34.93.10.4:51900          11.8 GB     8.5 GB
carol-phone            10.8.0.5        active    -        -                              -          -

3 of 25 licensed devices active (business edition)
```

---

## Try it in 2 minutes (Linux or WSL2)

```bash
sudo apt install build-essential libssl-dev python3
make
sudo ./scripts/demo.sh
```

The demo starts a server, two employee devices and the dashboard, each device in its
own network namespace. Open **http://localhost:8090** (user `admin`, password
`demo-password`). On WSL2 this works from your Windows browser too. Click **Disable**
on a device and watch its traffic stop.

## Install for real

```bash
make deb                                         # build/minivpn_2.0.0_amd64.deb
sudo apt install ./build/minivpn_2.0.0_amd64.deb
sudo minivpn-admin init --endpoint vpn.yourcompany.com
sudo minivpn-admin add laptop -o laptop.conf
sudo systemctl enable --now minivpn-server minivpn-admin
```

On each Linux device:

```bash
sudo install -m 600 laptop.conf /etc/minivpn/clients/laptop.conf
sudo systemctl enable --now minivpn-client@laptop
```

The full walkthrough covers firewall, dashboard over TLS, backups and troubleshooting:
**[docs/ADMIN-GUIDE.md](docs/ADMIN-GUIDE.md)**.

---

## Architecture

```
  device (laptop)                                     server
 +-----------------------+                +-------------------------------------------+
 | apps -> tun0 10.8.0.2 |   UDP 51900    | minivpn server (unprivileged after start) |
 | minivpn client        |===============>|  - device registry  /etc/minivpn/devices  |
 |  encrypt / decrypt    |  ChaCha20-     |  - license check    /etc/minivpn/license  |
 +-----------------------+  Poly1305      |  - tun0 10.8.0.1 <-> kernel routing / NAT |
                                          |  - control socket  /run/minivpn/control   |
                                          +---------------------^---------------------+
                                                                |  status / reload / kick
                                          +---------------------+---------------------+
                                          | minivpn-admin (CLI + web dashboard :8090) |
                                          +-------------------------------------------+
```

| Component | Language | Role |
|---|---|---|
| `minivpn` (`src/`) | C, OpenSSL | Data plane: TUN device, encryption, sessions, routing, control socket |
| `minivpn-admin` (`admin/`) | Python 3, stdlib only | Management plane: device registry, configs, licenses, dashboard |
| `license-tool` (`tools/`) | C | **Vendor only**: signs license files. Never shipped |
| `packaging/` | systemd, dpkg | Hardened services and the `.deb` installer |

| Source file | Role |
|---|---|
| `src/server.c` | Session table, handshake, forwarding, reload and revocation, status JSON |
| `src/client.c` | Handshake state machine, reconnect, rekey, routes, full tunnel |
| `src/proto.c`, `src/channel.c`, `src/replay.c` | Wire format, key schedule, AEAD channel, anti-replay |
| `src/devices.c`, `src/license.c`, `src/config.c` | Registry, signed licenses, config files |
| `src/tun.c`, `src/sys.c`, `src/control.c` | TUN and routing ioctls, epoll/signalfd/timerfd, privilege drop, Unix-socket API |

The protocol, byte by byte: **[docs/PROTOCOL.md](docs/PROTOCOL.md)**.

## Testing

| Command | Coverage |
|---|---|
| `make test` | **119 C checks.** Crypto against RFC 4231/5869/7748/8032 vectors, AEAD tampering, replay window, handshake binding, license verification, registry parsing. **13 Python tests.** Admin operations, limits, password hashing, dashboard auth, CSRF, origin checks, lockout |
| `sudo make integration` | **53 end-to-end checks** across 4 network namespaces: provisioning; wrong-key and unknown-device rejection; encrypted wire (no plaintext seen); 8 MiB transfer verified by SHA-256; MTU; kick, disable, enable and revoke taking effect live; rekey keeping counters; Community limit enforced by admin **and** server; forged license refused; Business license applied without restart; dashboard against the live server; restart and reconnect; full-tunnel routing |
| `make sanitize` | Rebuild with AddressSanitizer + UBSan, then run the suites above |

## Operating-systems and networking concepts

This started as an OS + Computer Networks project. The product is built on these concepts:

**Operating systems.** Virtual network devices (`/dev/net/tun`, `TUNSETIFF`). Kernel
configuration through `ioctl` (addresses, MTU, routing table). The `/proc` and `/sys`
interfaces. One-thread I/O multiplexing with `epoll`, where signals (`signalfd`) and
timers (`timerfd`) are just file descriptors. Non-blocking I/O with fair batching.
Privilege separation (`setuid` to an unprivileged user after setup). Unix-domain-socket
IPC with peer-credential checks (`SO_PEERCRED`). File locking (`flock`) and atomic
updates (write, `fsync`, `rename`). Resource cleanup tied to fd lifetime. Process
isolation with network namespaces. systemd sandboxing.

**Computer networks.** IP-in-UDP encapsulation and tunnelling. IPv4 header parsing.
Longest-prefix routing (the `0/1 + 128/1` full-tunnel trick with a pinned host route).
Subnetting and static address assignment. MTU and fragmentation. NAT and forwarding.
Reliability over UDP (retransmission with backoff, keepalives, dead-peer detection).
NAT traversal and roaming. Authenticated key exchange, AEAD, replay windows,
anti-spoofing and forward secrecy. Plus an HTTP application layer with cookies, CSRF
protection and TLS.

## Editions

| | Community | Business |
|---|---|---|
| Devices | up to 5 | as licensed |
| All features | ✓ | ✓ |
| License | free | signed license file, per device per year |

If a license expires, the VPN doesn't go down. It falls back to Community limits and
the dashboard says why. Vendors: see **[docs/SELLING.md](docs/SELLING.md)** for
issuing licenses (keep that file and `vendor/` private).

## Limitations

Linux clients only for now (Windows/macOS planned). IPv4 inside the tunnel. A single
dashboard admin account. Not yet independently audited. See
[docs/SELLING.md](docs/SELLING.md#honest-limitations-to-fix-before-selling-to-large-customers).
