# DNS Cache Poisoning: Vulnerabilities & Mitigations
**Information Security Assignment 2**
*(Author: Dhruv)*

---

## Slide 1: Title Slide
**Title:** Understanding & Mitigating DNS Cache Poisoning
**Subtitle:** A Practical Demonstration of the Kaminsky Bug and Modern Defenses
**Presenter:** Dhruv
**Course:** Information Security (Assignment 2)

---

## Slide 2: Introduction to DNS & The Vulnerability
**What is DNS Cache Poisoning?**
* **Concept:** Tricking a DNS resolver into caching a fake IP address for a legitimate domain.
* **Impact:** Redirects all subsequent user traffic for that domain to an attacker-controlled server (Phishing, Malware, DoS).
* **Root Cause (The Kaminsky Bug):** Early DNS implementations lacked sufficient randomness in their query parameters, making responses predictable and spoofable.

**Visual Idea:** A diagram showing a user requesting "example.com" and being redirected to a malicious "6.6.6.6" server.

---

## Slide 3: Lab Architecture & Environment Setup
**Our Docker-based Simulation:**
* **`victim` (10.0.0.3):** The innocent client making the DNS query.
* **`upstream_dns` (10.0.0.5):** The authoritative name server.
* **`attacker` (10.0.0.4):** The malicious container attempting to inject fake records.
* **`dns` (10.0.0.2):** The *Vulnerable* DNS Resolver.
* **`dns_hardened` (10.0.0.6):** The *Hardened* DNS Resolver (Modern configuration).

**Visual Idea:** A network topology diagram mapping out these 5 Docker containers and their IP addresses.

---

## Slide 4: Anatomy of the Vulnerable Server
**Why does the vulnerable server (`10.0.0.2`) fail?**
* **Hardcoded Source Port:** It binds strictly to port `22222` for all outgoing queries to the upstream server.
* **Weak Transaction IDs:** Uses a severely limited range of Transaction IDs (`10000` to `10050` = only 50 possible values).
* **Attacker Advantage:** The attacker knows the exact port (`22222`) and only needs a maximum of 50 guesses to match the correct ID. 

**Visual Idea:** Snippet of `server.py` showing `qid_to_request = randint(10000, 10050)` and `sock.bind(('10.0.0.2', 22222))`.

---

## Slide 5: Executing the Attack (The Kaminsky Method)
**Attack Step-by-Step (`attack.py`):**
1. **Trigger Cache Miss:** Send a legitimate query to the vulnerable resolver to force it to ask the upstream server.
2. **Race Condition:** Before the real upstream server replies, flood the resolver with fake responses.
3. **Spoofing:** Fake the Source IP (pretend to be `10.0.0.5`) and target Destination Port `22222`.
4. **Brute Force ID:** Loop through all 50 possible IDs and inject the malicious IP (`6.6.6.6`).

**Visual Idea:** A screenshot of the terminal triggering the `attack.py` script, followed by the victim attempting to `dig example.com` and receiving the poisoned result.

---

## Slide 6: Implementing the Hardened Server
**Fixing the Flaws (`server_hardened.py` on `10.0.0.6`):**
* **Source Port Randomization:** Binding socket to port `0`, forcing the OS kernel to assign a random ephemeral port (typically between `32768–60999`).
* **Full TX-ID Entropy:** Utilizing Cryptographically Secure Pseudo-Random Numbers (CSPRNG) for the full 16-bit Transaction ID space (`0–65535`).
* **Strict Validation:** Ensuring both the TX-ID and the Upstream Source IP match exactly before caching.

**Visual Idea:** Snippet of `server_hardened.py` showing `secrets.randbelow(65536)` and `sock.bind(('', 0))`.

---

## Slide 7: Analyzing the Attacker's Challenge
**Vulnerable vs. Hardened (The Math):**
* **Vulnerable Server Entropy:** 
  * 1 Port × 50 IDs = **50 total packets needed.** (Instant Poisoning)
* **Hardened Server Entropy:** 
  * ~28,232 Ports × 65,536 IDs = **~1.85 Billion combinations.**
* **The Reality Check:** An attacker must send 1.85 billion packets in the ~5-10 millisecond window before the legitimate upstream server replies. This is practically impossible on modern networks.

**Visual Idea:** A comparison table highlighting "50 Guesses" vs "~1.85 Billion Guesses".

---

## Slide 8: The "Flooding" / Distributed Attack Theory
**What if we used a Botnet to guess all 1.85 billion combinations?**
* **Bandwidth Limits:** Sending 1.85 billion spoofed UDP packets would equal ~185GB of data. Accomplishing this in 5 milliseconds requires a ~37,000 Gbps connection.
* **Self-Defeating DDoS:** This volume of traffic acts as a volumetric Denial of Service attack. It would crash the resolver before the cache is ever poisoned.
* **ISP Filtering (BCP38):** Modern internet infrastructure drops packets with spoofed source IPs originating from outside their defined subnets.

**Visual Idea:** An illustration of a massive packet flood hitting the resolver and causing a bottleneck (DoS).

---

## Slide 9: Why Scanning Open Ports Fails
**A Common Misconception:**
* "Can't the attacker just scan the DNS server for its open ports using Nmap?"
* **Answer: No.** 
* The resolver's *receiving* port (Port 53) is public. However, the *ephemeral source port* is only opened for milliseconds during an active query and is immediately closed afterward. By the time a scanner identifies it, the attack window has already expired.

**Visual Idea:** A timeline graphic showing: Outbound Query -> Port Opens -> Milliseconds pass -> Reply Received -> Port Closes.

---

## Slide 10: Conclusion & The Ultimate Defense
**Summary of Findings:**
* Source Port Randomization effectively neutralized the Kaminsky attack by relying on statistical improbability ("Entropy Tricks").
* However, entropy is not cryptographically secure. 

**The Ultimate Solution:**
* **DNSSEC (DNS Security Extensions):** Adds cryptographic digital signatures to DNS records. Even if an attacker perfectly guesses the Port and TX-ID, the resolver will reject the poisoned response because it lacks the valid cryptographic signature from the true domain owner.

**Visual Idea:** A padlock icon over a DNS record representing DNSSEC.
