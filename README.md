# Information Security — Practical Assignment 2
## DNS Cache Poisoning (Complete Extended Lab)

### Overview

DNS Cache Poisoning (also known as DNS Spoofing) is a form of cyber-attack where corrupted DNS data is introduced into a DNS resolver's cache, causing the resolver to return an incorrect IP address for a domain. As a result, traffic intended for a legitimate website is redirected to a malicious server controlled by the attacker.

This assignment demonstrates:
1. **The Attack** — Poisoning a vulnerable DNS caching server to redirect a target domain to an attacker-controlled IP natively via a multi-threaded flood script.
2. **The Impact** — Serving a fake phishing page (IIT Jammu Portal mock-up) to the victim.
3. **The Defense** — How modern DNS hardening mechanisms (Source Port Randomization, CSPRNG TxID, TSIG validation) completely prevent this attack.

---

## Lab Architecture

All components run inside an isolated Docker virtual network (`10.0.0.0/24`) to prevent any impact on real systems.

| Container      | IP          | Role                                                      |
|----------------|-------------|-----------------------------------------------------------|
| `upstream_dns` | `10.0.0.5`  | Authoritative server — signs responses with HMAC-SHA256   |
| `dns`          | `10.0.0.2`  | **Vulnerable** resolver — fixed port 22222, TxID 10000–50 |
| `dns_hardened` | `10.0.0.6`  | **Hardened** resolver — random port, CSPRNG, TSIG, ratelimit |
| `victim`       | `10.0.0.3`  | Client host configured to use the vulnerable resolver     |
| `victim2`      | `10.0.0.7`  | Client host configured to use the hardened resolver       |
| `attacker`     | `10.0.0.4`  | Runs the multi-threaded attack script & phishing website  |
| `monitor`      | `10.0.0.8`  | Hosts the Live Dashboard GUI → `http://localhost:8080`    |

### Why is the Demo DNS Vulnerable?
- **Fixed Transaction ID Range:** The DNS resolver uses a predictable TxID range (10000–10050), making it trivial for the attacker to guess the correct ID.
- **Fixed Source Port:** Port `22222` is always used, removing one layer of randomness the attacker needs to guess.
- **No Signature Validation:** Any response matching the TxID is blindly cached.

### Hardened Resolver Defenses (The Fix)
| Defense | Implementation | Effect on Attack |
|---------|---------------|-----------------|
| Random ephemeral port | `sock.bind(("",0))` — OS-assigned | Attacker must guess 1 of ~28,000 ports |
| CSPRNG TxID | `secrets.randbelow(65536)` | 65,536 IDs instead of just 51 |
| Combined entropy | 28,000 × 65,536 | **~1.85 billion combinations required** |
| TSIG validation | HMAC-SHA256 shared with upstream | Forged responses fail even with correct TxID+port |
| Source-IP check | `assert addr[0] == UPSTREAM_IP` | Off-path IP spoofing is rejected immediately |
| Rate limiting | 20 q/s per client | Slows attacker's ability to force cache-misses |

---

## Project Structure

```text
submission_assignment_2/
├── README.md                 ← This documentation
├── Presentation_Content.md   ← Slide outlines for Viva/Defense 
├── dns-cache-poisoning-demo/
│   ├── attacker/             ← Threaded attacker (attack.py) & Phishing Page (index.html)
│   ├── dns/                  ← Vulnerable resolver (port 22222)
│   ├── dns_hardened/         | Hardened resolver (Random Ports + TSIG)
│   ├── upstream_dns/         ← Simulated Authoritative DNS (Signs TSIG)
│   ├── monitor/              ← Flask backend & Dashboard HTML GUI
│   ├── victim/               ← Client systems
│   └── docker-compose.yml    ← Network orchestration
```

---

## Quick Start & Demo Walkthrough

### Prerequisites
- Docker + Docker Compose installed with sudo access.

### Step 1: Start the Lab & Dashboard
```bash
cd dns-cache-poisoning-demo
sudo docker compose up -d --build
```
> **Open your browser to `http://localhost:8080` to view the Live DNS Monitor Dashboard.**

### Step 2: Attack the Vulnerable Resolver
Enter the attacker container and launch the multi-threaded script:
```bash
sudo docker exec -it attacker bash
python3 attack.py sprightly-torrone-5f4946.netlify.app 10.0.0.4
```
**Watch the live dashboard:**
- You will see `attack_detected` events flooding the `dns_vulnerable` log.
- Wait until it successfully guesses the ID and shows a red `⚠ POISONED` flag.

### Step 3: Visual Proof on the Victim
Switch to the victim machine (which uses the vulnerable DNS):
```bash
sudo docker exec -it victim bash
dig sprightly-torrone-5f4946.netlify.app      # → It resolves to 10.0.0.4 (attacker!)
curl http://sprightly-torrone-5f4946.netlify.app   
```
**Result:** The phishing page is displayed natively! It contains a blinking red banner stating: *"VISUAL PROOF: DNS CACHE POISONING ATTACK SUCCESSFUL"*.

### Step 4: Attack the Hardened Resolver (Proof of Immunity)
From the attacker container, attempt to poison the hardened server directly:
```bash
python3 attack.py sprightly-torrone-5f4946.netlify.app 10.0.0.4 --target hardened --duration 20
```
**Watch the live dashboard:**
- You will see `blocked` events piling up (`wrong_source_ip`, `invalid_tsig`, `txid_mismatch`).
- The hardened cache panel stays perfectly clean.

### Step 5: Side-by-Side Comparison
```bash
python3 attack.py sprightly-torrone-5f4946.netlify.app 10.0.0.4 --target both --threads 6
```
The script will output a comparison at the end proving the entropy/signatures blocked the attack:
```text
  ✓ POISONED   VULNERABLE DNS  (port 22222, TxID 10000-10050)
  ✗ BLOCKED    HARDENED DNS    (random port, CSPRNG TxID, TSIG)
```

Confirm that the second victim (`victim2`), which relies on the hardened server, remains safe:
```bash
sudo docker exec -it victim2 dig sprightly-torrone-5f4946.netlify.app
```
*(It resolves to the real upstream IP, untampered.)*

---

*This demo was conducted entirely within an isolated Docker network (`10.0.0.0/24`) and does not affect any real-world infrastructure.*
