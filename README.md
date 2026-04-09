# Information Security — Practical Assignment 2

## Aim
To showcase a demo of a network attack (DNS Cache Poisoning) and a defensive strategy/method to mitigate it.

---

## Lab Architecture

This demo uses a highly reliable and isolated Docker environment to ensure the attack works consistently for the presentation.

| Container        | IP Address  | Role                                                   |
|------------------|-------------|--------------------------------------------------------|
| `dns`            | `10.0.0.2`  | **Vulnerable** DNS resolver (Python-based)             |
| `victim`         | `10.0.0.3`  | Victim host - configured to use the `dns` container    |
| `attacker`       | `10.0.0.4`  | Attacker - hosts phishing page & sends spoofed packets |
| `upstream_dns`   | `10.0.0.5`  | Simulated Authoritative server (Always returns 1.2.3.4)|

---

## The Attack: DNS Cache Poisoning

The goal is to redirect the domain **`sprightly-torrone-5f4946.netlify.app`** from its real IP to the attacker's IP (`10.0.0.4`).

### How to Run the Demo:

1. **Step 1: Fresh Start** (Host Terminal)
   ```bash
   sudo docker compose down && sudo docker compose up -d
   ```

2. **Step 2: Attack Launch** (Attacker Terminal)
   ```bash
   sudo docker exec -it attacker bash
   # 1. Start Phishing Web Server in background
   python3 -m http.server 80 &
   # 2. Poison the DNS cache
   python3 attack.py sprightly-torrone-5f4946.netlify.app 10.0.0.4
   ```

3. **Step 3: Verification** (Victim Terminal)
   ```bash
   sudo docker exec -it victim bash
   # Check the poisoned DNS record
   dig sprightly-torrone-5f4946.netlify.app
   ```
   **Expected Result:** The `ANSWER SECTION` will show `10.0.0.4` instead of the original IP.

---

## Visual Proof of Compromise

To differentiate between the original website and the attacker's spoofed version, we have modified the attacker's `index.html`:

- **Compromised Site:** Displays a large, **Red Blinking Banner** at the top:
  `VISUAL PROOF: DNS CACHE POISONING ATTACK SUCCESSFUL`
- **Original Reference:** The version in the root directory (`/Submission_assignment_2/index.html`) is the clean version without this banner.

**Fetch Proof (Victim Terminal):**
```bash
curl http://sprightly-torrone-5f4946.netlify.app
```
Wait for the response—The top of the output will show the **COMPROMISED** banner!

---

## Defense Strategy

The Demo highlights that the attack is only possible when:
1. **Source Port is fixed** (making it predictable).
2. **Transaction IDs are in a small range** (brute-forceable).
3. **DNSSEC is missing.**

### Mitigation in Real Systems:
In modern BIND9/ISP servers, we mitigate this by:
- **Source Port Randomisation:** Changing the query port for every request.
- **DNSSEC:** Cryptographically signing DNS records so spoofed ones are rejected.

---

*This demo was conducted in an isolated lab environment for ethical education purposes.*

---

## Overview

DNS Cache Poisoning (also known as DNS Spoofing) is a form of cyber-attack where corrupted DNS data is introduced into a DNS resolver's cache, causing the resolver to return an incorrect IP address for a domain. As a result, traffic intended for a legitimate website is redirected to a malicious server controlled by the attacker.

This assignment demonstrates:
1. **The Attack** — Poisoning a vulnerable DNS caching server to redirect a target domain to an attacker-controlled IP.
2. **The Impact** — Serving a fake phishing page (spoofed IIT Jammu Login Portal) to the victim.
3. **The Defense** — How modern DNS hardening mechanisms (DNSSEC, Source Port Randomization) completely prevent this attack.

---

## Lab Architecture

All components run inside an isolated Docker virtual network (`10.0.0.0/24`) to prevent any impact on real systems.

| Container        | IP Address  | Role                                                   |
|------------------|-------------|--------------------------------------------------------|
| `dns`            | `10.0.0.2`  | Vulnerable caching DNS resolver (fixed TxID range)     |
| `victim`         | `10.0.0.3`  | Victim host — uses the vulnerable DNS server           |
| `attacker`       | `10.0.0.4`  | Attacker host — runs the poisoning script & fake web server |
| `upstream_dns`   | `10.0.0.5`  | Simulated authoritative DNS server (always returns `1.2.3.4`) |

### Why is the Demo DNS Vulnerable?
- **Fixed Transaction ID Range:** The DNS resolver uses a predictable TxID range (10000–10050), making it trivial for the attacker to guess the correct ID.
- **Fixed Source Port:** Port `22222` is always used, removing one layer of randomness the attacker needs to guess.

---

## Project Structure

```
submission_assignment_2/
├── README.md              ← This file
├── dns_spoof.c            ← Custom C-based raw socket DNS spoofing tool
├── index.html             ← Fake phishing page (IIT Jammu portal mock-up)
├── docker-compose.yml     ← Isolated lab environment config
└── dns-cache-poisoning-demo/
    ├── attacker/
    │   ├── attack.py      ← Python-based DNS poisoning attack script (Scapy)
    │   └── Dockerfile
    ├── dns/               ← Vulnerable DNS caching server implementation
    ├── upstream_dns/      ← Simulated authoritative DNS server
    └── victim/            ← Victim container
```

---

## How to Run the Demo

### Prerequisites
- Docker + Docker Compose installed
- Sudo access

### Step 1: Start the Lab Environment
```bash
cd dns-cache-poisoning-demo
sudo docker compose up -d --build
```

### Step 2: Launch the Attack (Attacker Container)
```bash
sudo docker exec -it attacker bash

# Start the fake phishing web server
python3 -m http.server 80 &

# Launch the DNS Cache Poisoning attack
python3 attack.py sprightly-torrone-5f4946.netlify.app 10.0.0.4
```

### Step 3: Verify the Attack (Victim Container)
```bash
sudo docker exec -it victim bash

# Check poisoned DNS record
dig sprightly-torrone-5f4946.netlify.app
# Expected: ANSWER SECTION shows 10.0.0.4 (attacker's IP, NOT the real IP)

# Fetch content from the poisoned URL
curl http://sprightly-torrone-5f4946.netlify.app
# Expected: Attacker's fake IIT Jammu phishing HTML page is returned
```

---

## Attack Results (Proof of Concept)

### Before Attack (Normal DNS)
```
sprightly-torrone-5f4946.netlify.app. IN A    52.74.6.109  ← Real Netlify IP
```

### After Attack (Poisoned DNS Cache)
```
sprightly-torrone-5f4946.netlify.app. 3600 IN A  10.0.0.4  ← Attacker's IP!
```

The victim's HTTP request is now silently redirected to the attacker's machine, which serves a convincing fake login page designed to steal credentials.

---

## Phishing Page Impact (`index.html`)

The attacker hosts a fake "IIT Jammu Student Portal" login page (`index.html`) which:
- Visually mimics the real university portal.
- Displays an **"DNS CACHE POISONING ATTACK SUCCESSFUL"** banner automatically.
- Captures login credentials on form submit (for demo purposes).

---

## Defense Strategy

Modern DNS servers are protected against cache poisoning by:

| Defense Mechanism        | How it Helps                                                                 | Status in Demo |
|--------------------------|------------------------------------------------------------------------------|----------------|
| **Source Port Randomisation** | Attacker must now guess *both* TxID (16-bit) AND source port (16-bit) = `2^32` combinations | Disabled (for demo) |
| **Randomised Transaction IDs** | Without a predictable range, brute-force TxID guessing becomes unfeasible | ❌ Fixed range (for demo) |
| **DNSSEC**               | All DNS records are cryptographically signed; spoofed records fail signature verification | Disabled (for demo) |
| **DNS Cookies (RFC 7873)**| Client-server cookie exchange prevents off-path injection                   | ❌ Disabled (for demo) |

### How to Enable Defenses (BIND9 Secure Config)
The `dns_server_secure` directory contains a hardened BIND9 configuration with:
- Source port randomisation enabled (default BIND behaviour)
- DNSSEC validation enabled (`dnssec-validation auto;`)
- DNS Cookies enabled

With these defenses active, the same attack produces `SERVFAIL` — the cache poisoning is completely blocked.

---

## Key Takeaways

1. **DNS Cache Poisoning** exploits the trust a caching resolver places in responses — if the TxID matches, the record is accepted.
2. **The attack is a race condition** — the attacker must send a spoofed response before the legitimate authoritative server does.
3. **Modern DNS implementations** are not vulnerable to this attack due to source port randomisation and DNSSEC.
4. **This demo** is conducted entirely within an isolated Docker network and does not affect any real-world infrastructure.

---

*Demonstrated in an isolated lab environment for educational purposes only.*
