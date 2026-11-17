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
│ [Terminal 2 - The Sender]            │     │ [Terminal 2 - 🕵️ HACKER / SNIFFER WINDOW]             │
│ Sends the secret file over VPN       │     │ Sniffs eth0 (physical wire). Sees ONLY ciphertext.     │
│ to 10.8.0.3                          │     │ ------------------------------------------------------ │
│                                      │     │ [Terminal 3 - 📥 TARGET APPLICATION]                   │
│                                      │     │ Listens on tun0 (VPN). Receives the decrypted file!   │
└──────────────────────────────────────┘     └────────────────────────────────────────────────────────┘
                                 ▲                         ▲
                                 │                         │
                                 └───► [WSL Server (Windows)] ◄───┘
                                       Dashboard on http://localhost:8090
```

---

## PART 1: One-Time Preparation (Before Calling Teacher)

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

## PART 2: The Live Presentation (Side-by-Side Proof)

Open **two more terminal tabs** on **Kali 2**:

---

### Step 1: On Kali 2, Open the "Hacker / Sniffer" Window (Terminal 2)

Run standard `tcpdump` sniffing the physical wire interface (`eth0`) on UDP port 51900:
```bash
sudo tcpdump -ni eth0 udp port 51900 -A
```
> **What to say to your teacher:**
> *"Professor, this terminal represents an eavesdropper, malicious router, or ISP sniffing my physical network cable. The `-A` flag forces tcpdump to print all packets in readable plain text."*

---

### Step 2: On Kali 2, Open the "Receiver Application" Window (Terminal 3)

Place this terminal side-by-side with Terminal 2:
```bash
nc -lvnp 9999
```
> **What to say to your teacher:**
> *"This terminal is our internal private service listening on the encrypted VPN address 10.8.0.3."*

---

### Step 3: On Kali 1, Send the Secret File (Terminal 2)

Switch to Kali 1 and fire a secret file directly to Kali 2 (`10.8.0.3`):
```bash
echo "TOP SECRET ASSIGNMENT: Exam grade is A+ (Token: 0x99FF)" | nc -w 1 10.8.0.3 9999
```

---

## PART 3: The Proof (What to Show the Teacher)

Look at the two side-by-side terminals on **Kali 2**:

1. **Terminal 2 (The Hacker Sniffer on `eth0`):**
   - Shows raw packet activity flying across the wire.
   - Because `-A` is enabled, it attempts to print text, but outputs **only scrambled binary symbols**:
     ```text
     ..@.~..r...3..$).x..A......|...W...=...^.7f.4a.b2.19
     ```
   - **The secret text is 100% invisible.**

2. **Terminal 3 (The Private Receiver on `tun0`):**
   - At the exact same second, Terminal 3 prints:
     ```text
     TOP SECRET ASSIGNMENT: Exam grade is A+ (Token: 0x99FF)
     ```
   - **Explain to your teacher:**
     *"This proves end-to-end ChaCha20-Poly1305 encryption. The outside network sees only high-entropy encrypted ciphertext. Only the authorized VPN endpoint with the matching X25519 key could decrypt the data."*

3. **The Plaintext Grep Challenge:**
   In Terminal 2 on Kali 2, run:
   ```bash
   sudo tcpdump -ni eth0 udp port 51900 -A | grep -i "TOP SECRET"
   ```
   Send the message again from Kali 1.
   👉 **Nothing prints.** `grep` returns **0 matches**, conclusively proving zero plaintext leakage on the wire.

4. **Show the Web Dashboard (Windows):**
   Switch to your Windows browser at **http://localhost:8090**:
   - Both **`kali-laptop`** and **`kali-laptop-2`** show as **ONLINE** (green dots).
   - Show the live **RX/TX bandwidth meters** and connection uptime.
   - Click **Disable** on `kali-laptop-2` in the web UI.
   - Try sending a ping from Kali 1: `ping -c 2 10.8.0.3`.
   - **It instantly fails/drops packets!**
   - Click **Enable** on the dashboard, and the connection resumes instantly.

---

## PART 4: Quick Reference Command Summary

| Action | Machine | Command |
| :--- | :--- | :--- |
| **Start Server** | WSL (Windows) | `sudo systemctl start minivpn-server minivpn-admin` |
| **Connect Client 1** | Kali 1 | `sudo ./minivpn client --config kali.conf` |
| **Connect Client 2** | Kali 2 | `sudo ./minivpn client --config kali2.conf` |
| **Hacker Sniffer** | Kali 2 (Terminal 2) | `sudo tcpdump -ni eth0 udp port 51900 -A` |
| **Receiver App** | Kali 2 (Terminal 3) | `nc -lvnp 9999` |
| **Sender App** | Kali 1 (Terminal 2) | `echo "SECRET" \| nc -w 1 10.8.0.3 9999` |
| **Dashboard** | Windows Browser | `http://localhost:8090` |
