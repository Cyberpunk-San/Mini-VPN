# minivpn: Two-Client (Kali 1 & Kali 2) Live Presentation Guide

This guide documents the exact steps for running and presenting **minivpn** with:
- **Server:** WSL2 (Ubuntu on Windows)
- **Client 1 (Sender):** Kali Linux 1 (`10.8.0.2`)
- **Client 2 (Receiver):** Kali Linux 2 (`10.8.0.3`)
- **Web Dashboard:** Windows Browser (`http://localhost:8090`)

---

## 🖥️ Screen & Terminal Architecture

```
┌──────────────────────────────────────┐     ┌────────────────────────────────────────────────────────┐
│ KALI LINUX 1 (The Sender)            │     │ KALI LINUX 2 (The Receiver)                            │
│                                      │     │                                                        │
│ [Terminal 1 - Background VPN]        │     │ [Terminal 1 - Background VPN]                          │
│ sudo ./minivpn client --config ...   │     │ sudo ./minivpn client --config ...                     │
│                                      │     │                                                        │
│ [Terminal 2 - One-Click Sender]      │     │ [Terminal 2 - One-Click Receiver]                      │
│ sudo ./scripts/demo-secret-send.sh   │     │ sudo ./scripts/demo-secret-recv.sh                     │
│ (Sniffs wire + sends secret file)    │     │ (Listens on VPN + shows decrypted file + SHA-256)      │
└──────────────────────────────────────┘     └────────────────────────────────────────────────────────┘
                                 ▲                         ▲
                                 │                         │
                                 └───► [WSL Server (Windows)] ◄───┘
                                       Dashboard on http://localhost:8090
```

---

## PART 1: Preparation (Start Services & VPN)

### 1. In WSL Terminal (Windows)
Ensure both client devices are registered and configs are generated:
```bash
# Start server and dashboard services
sudo systemctl start minivpn-server minivpn-admin

# Generate config for Kali 1 (if not already done)
sudo minivpn-admin add kali-laptop -o /mnt/c/Users/Dell/minivpn/kali.conf

# Generate config for Kali 2
sudo minivpn-admin add kali-laptop-2 -o /mnt/c/Users/Dell/minivpn/kali2.conf
```
*(Copy `kali.conf` to Kali 1, and `kali2.conf` to Kali 2).*

### 2. On Windows (Browser)
Open **http://localhost:8090**
- **Username:** `admin`
- **Password:** `minivpn-admin123`
*(Keep this tab open so your teacher can see the live web dashboard).*

### 3. In Kali 1 (Terminal 1)
Start the VPN connection:
```bash
cd Mini-VPN
sudo ./minivpn client --config kali.conf
```
*(Leave running in background — assigned `10.8.0.2` on `tun0`).*

### 4. In Kali 2 (Terminal 1)
Start the VPN connection:
```bash
cd Mini-VPN
sudo ./minivpn client --config kali2.conf
```
*(Leave running in background — assigned `10.8.0.3` on `tun0`).*

---

## PART 2: 🎯 The Live Presentation (Run `recv` and `send.sh`)

Instead of typing long commands in front of your teacher, open **Terminal 2** on both machines and run our automated scripts:

---

### Step 1: On Kali 2 (Terminal 2 - Run Receiver)

```bash
cd Mini-VPN
sudo ./scripts/demo-secret-recv.sh
```

> **What appears on Kali 2 screen:**
> ```text
> ==========================================================
>           MINIVPN SECRET FILE RECEIVER                    
> ==========================================================
>   [+] VPN Tunnel Active: 10.8.0.3
>   [+] Listening on port: 9999
>   [+] Waiting for incoming encrypted transmission...
> ==========================================================
> ```
> *(It is now waiting for the secret transmission over the VPN).*

---

### Step 2: On Kali 1 (Terminal 2 - Run Sender & Sniffer)

Send the secret file across the tunnel to Kali 2 (`10.8.0.3`):
```bash
cd Mini-VPN
sudo ./scripts/demo-secret-send.sh 10.8.0.3
```

---

### Step 3: What Your Teacher Sees on the Screens!

#### 1. On Kali 1 (The Sender & Wire Sniffer Output):
The script automatically:
- Starts a live packet sniffer on the outside network adapter (`eth0`).
- Encrypts and transmits the secret file through the VPN tunnel (`10.8.0.3:9999`).
- Dumps the captured wire packets on screen:
  ```text
  ==========================================================
                LIVE WIRE SNIFFING ANALYSIS                 
  ==========================================================
  --- [1] WHAT HACKERS / ISP / ROUTER SAW ON THE WIRE: ---
  0x0000:  4500 0054 b5a2 4000 4011 3a2c ac1e b78d
  0x0010:  7f4a b219 90e1 33c4 e810 5a2d 81fe 4209
  ...
  [✓] ZERO-KNOWLEDGE PROOF: Plaintext search ('eagle', 'DEADBEEF') returned 0 matches.
  [✓] Wire inspection shows ONLY ChaCha20-Poly1305 encrypted ciphertext.
  [✓] Only devices with private X25519 keys inside the VPN can decrypt this file.
  ==========================================================
  ```

#### 2. On Kali 2 (The Receiver Output):
At the exact same moment, Kali 2 receives and validates the file:
```text
==========================================================
  >>> TRANSMISSION RECEIVED SUCCESSFULLY! <<<
==========================================================
  From VPN Peer:  10.8.0.2:49922
  Payload Size:   79 bytes
  SHA-256 Hash:   424e4e152464d9a7ba241964a26deb42bb9659...
----------------------------------------------------------
  [DECRYPTED FILE CONTENT]:
CONFIDENTIAL VPN TEST: The eagle flies at midnight. Secret key: 0xDEADBEEFCAFE
----------------------------------------------------------
  Saved to: received_secret.txt
==========================================================
```

#### 3. On Windows (Web Dashboard `http://localhost:8090`):
- Both `kali-laptop` and `kali-laptop-2` show with **green ONLINE dots**.
- Bandwidth meters and live throughput spike as the file is transmitted.
- Click **Disable** on `kali-laptop-2` in the UI to demonstrate that traffic is cut off in under 1 second!

---

## PART 3: Optional Manual Commands (If Teacher Requests)

If the teacher asks to see individual raw commands instead of scripts:

### On Kali 2:
- **Terminal 2 (Wire Sniffer):** `sudo tcpdump -ni eth0 udp port 51900 -A`
- **Terminal 3 (Receiver):** `nc -lvnp 9999`

### On Kali 1:
- **Terminal 2 (Sender):** `echo "SECRET" | nc -w 1 10.8.0.3 9999`

---

## PART 4: Quick Reference Command Summary

| Action | Where to Run | Command |
| :--- | :--- | :--- |
| **Start Server** | WSL (Windows) | `sudo systemctl start minivpn-server minivpn-admin` |
| **Connect Client 1** | Kali 1 (Terminal 1) | `sudo ./minivpn client --config kali.conf` |
| **Connect Client 2** | Kali 2 (Terminal 1) | `sudo ./minivpn client --config kali2.conf` |
| **Run Receiver Script** | Kali 2 (Terminal 2) | `sudo ./scripts/demo-secret-recv.sh` |
| **Run Sender Script** | Kali 1 (Terminal 2) | `sudo ./scripts/demo-secret-send.sh 10.8.0.3` |
| **View Dashboard** | Windows Browser | `http://localhost:8090` |
