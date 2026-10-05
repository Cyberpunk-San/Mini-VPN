# minivpn administrator guide

This guide is for the person running a minivpn server for a team.

## 1. Install the server

You need a Linux server (Ubuntu 22.04+ or Debian 12+) with a public IP address and
UDP port 51900 open.

```bash
sudo apt install ./minivpn_2.0.0_amd64.deb
sudo minivpn-admin init --endpoint vpn.yourcompany.com     # or the server's public IP
sudo systemctl enable --now minivpn-server minivpn-admin
```

`init` writes `/etc/minivpn/server.conf` and asks for a dashboard password. The
server starts as root to create its network interface, then switches to the
unprivileged `minivpn` user.

**Firewall:** allow `UDP 51900` inbound, for example `sudo ufw allow 51900/udp`.
On cloud hosts, also open it in the provider's security group.

## 2. Add devices

Every laptop, desktop, server or office router is a **device** with its own key and
a fixed tunnel address.

```bash
sudo minivpn-admin add alice-laptop -o alice-laptop.conf
```

Send `alice-laptop.conf` to the device owner over a secure channel, such as a password
manager share or an encrypted message. Don't use plain email. Anyone holding the file
can connect as that device.

Alternatively, use the dashboard: **Add device**, then **Download**.

## 3. Connect a device (Linux)

```bash
sudo apt install ./minivpn_2.0.0_amd64.deb
sudo install -m 600 alice-laptop.conf /etc/minivpn/clients/alice-laptop.conf
sudo systemctl enable --now minivpn-client@alice-laptop
```

The device can now reach the server at `10.8.0.1` and other devices at their `10.8.0.x`
addresses. Optional lines in the device's config:

```
route = 192.168.1.0/24       # reach the office LAN behind the server
redirect_gateway = yes       # send all internet traffic through the VPN
```

For `redirect_gateway`, the server must forward and NAT traffic:
`sudo /usr/share/minivpn/server-nat.sh up`.

## 4. The dashboard

The dashboard listens on `127.0.0.1:8090` only. Reach it with an SSH tunnel:

```bash
ssh -L 8090:127.0.0.1:8090 you@vpn.yourcompany.com
# then open http://localhost:8090
```

To expose it directly, serve it over TLS with `sudo systemctl edit minivpn-admin`:

```ini
[Service]
ExecStart=
ExecStart=/usr/sbin/minivpn-admin web --listen 0.0.0.0:8443 --tls-cert /etc/ssl/vpn.crt --tls-key /etc/ssl/vpn.key
```

The dashboard shows who is online, where they connect from, live throughput and
traffic totals. From it you can add, disable, re-enable, disconnect and revoke devices,
install a license, and read the activity log.

**Security built in:**
- Passwords are hashed with PBKDF2-SHA256.
- Sessions use HttpOnly, SameSite=Strict cookies and expire after 30 minutes idle.
- Every change requires a CSRF token, and cross-origin requests are refused.
- Sign-in locks out for 5 minutes after 5 failed attempts.
- A strict Content-Security-Policy is applied, and the dashboard can't be framed.

Change the password with `sudo minivpn-admin passwd`.

## 5. Day-to-day operations

| Task | Command |
|---|---|
| Who is online? | `sudo minivpn-admin list` |
| Server and license summary | `sudo minivpn-admin status` |
| Lost laptop: block it now | `sudo minivpn-admin disable alice-laptop` |
| Unblock it | `sudo minivpn-admin enable alice-laptop` |
| Employee left: remove for good | `sudo minivpn-admin revoke alice-laptop` |
| Re-send a config | `sudo minivpn-admin show alice-laptop` |
| Force a reconnect | `sudo minivpn-admin kick alice-laptop` |
| Who changed what? | `sudo minivpn-admin audit` |
| Server logs | `journalctl -u minivpn-server -f` |

Disable and revoke take effect **immediately**. The device is disconnected within a
second and its key stops working.

## 6. Editions and licenses

| | Community | Business |
|---|---|---|
| Devices | 5 | as licensed (e.g. 25, 100, 500) |
| Dashboard, revocation, audit log | ✓ | ✓ |
| Price | free | per-device annual license |

Install a license file:

```bash
sudo minivpn-admin license install acme.license
```

Or paste it in the dashboard under **License**, then **Install license**. It takes effect
without a restart. If a license expires, the VPN keeps working under Community limits:
the first 5 devices stay connected, and the dashboard and `status` explain why the
others can't.

## 7. Backups

Back up `/etc/minivpn/`. It holds `server.conf`, `devices` (all device keys),
`license.key`, `admin.conf` and `audit.log`. Restoring it on a new server and
pointing your DNS name there brings every device back without reissuing configs.

## 8. Troubleshooting

| Symptom | Check |
|---|---|
| Device log says "no answer from the server yet" | UDP 51900 open? Is `endpoint` correct? Is the device still active (`minivpn-admin list`)? |
| Server log: "rejected handshake ... wrong device key" | The device has an old config. Send it a fresh one with `minivpn-admin show NAME` |
| Server log: "timestamp off by Ns" | The device's clock is wrong. Enable NTP |
| Dashboard: "Server offline" | `systemctl status minivpn-server`, `journalctl -u minivpn-server` |
| Some devices can't connect, dashboard warns about the license | More active devices than licensed. Disable some or upgrade |
| Large downloads stall | Path MTU below 1428 bytes. Set `mtu = 1280` in server.conf and restart |
