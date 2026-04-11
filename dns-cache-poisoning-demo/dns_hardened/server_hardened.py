#!/usr/bin/env python3
"""
dns_hardened/server.py — Hardened DNS Caching Resolver

Defenses applied (mirroring real-world BIND9 / Unbound hardening):

  1. RANDOM EPHEMERAL SOURCE PORT — a fresh OS-assigned port is opened for
     every single upstream query. The attacker must now guess *which* of
     ~28 000 ports was used in addition to the TxID.

  2. CSPRNG TRANSACTION ID — secrets.randbelow(65536) gives the full 16-bit
     TxID space. Combined with port randomisation the search space is
     ~28 000 × 65 536 ≈ 1.85 billion combinations.

  3. TSIG-LIKE HMAC VALIDATION — the upstream server embeds an
     HMAC-SHA256 signature in an additional TXT record (_tsig.<qname>).
     We validate this signature before caching. A spoofed response that
     lacks or forges this record is silently dropped.

  4. STRICT SOURCE-IP CHECK — responses not originating from 10.0.0.5
     are rejected before any further processing.

  5. RATE LIMITING — clients are limited to 20 queries/second to slow
     any attempt to trigger repeated cache misses.

All blocked attempts and legitimate responses are reported to the
monitor dashboard.
"""

import socket
import threading
import secrets
import hmac
import hashlib
import time
import json
import os
from collections import defaultdict
from dnslib import DNSRecord, RR, QTYPE, A, TXT
from dnslib.dns import DNSError

# ── Config ────────────────────────────────────────────────────────────────────
MY_IP         = "10.0.0.6"
UPSTREAM_IP   = "10.0.0.5"
UPSTREAM_PORT = 53
MONITOR_IP    = "10.0.0.8"
MONITOR_PORT  = 9999
DNS_SECRET    = os.environ.get("DNS_SECRET", "shared_tsig_secret_2024")
RATE_LIMIT    = 20   # max queries per second per client IP

# ── Shared state ──────────────────────────────────────────────────────────────
cache      : dict = {}
state_lock  = threading.Lock()

rate_counts : dict = defaultdict(list)   # ip -> [timestamps]
rate_lock   = threading.Lock()

# ── Helpers ───────────────────────────────────────────────────────────────────

def emit(event_type: str, data: dict):
    try:
        payload = json.dumps({
            "type":   event_type,
            "time":   time.time(),
            "source": "dns_hardened",
            **data,
        }).encode()
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(payload, (MONITOR_IP, MONITOR_PORT))
        s.close()
    except Exception:
        pass


def make_txid() -> int:
    """DEFENSE 2 — cryptographically secure, full 16-bit range."""
    return secrets.randbelow(65536)


def verify_tsig(qname: str, ip: str, ttl: int, provided_sig: str) -> bool:
    """DEFENSE 3 — verify the HMAC-SHA256 signature from upstream."""
    msg = f"{qname}:{ip}:{ttl}".encode()
    expected = hmac.new(DNS_SECRET.encode(), msg, hashlib.sha256).hexdigest()
    try:
        return hmac.compare_digest(expected, provided_sig)
    except Exception:
        return False


def is_rate_limited(client_ip: str) -> bool:
    """DEFENSE 5 — sliding-window rate limiter."""
    now = time.time()
    with rate_lock:
        ts = rate_counts[client_ip]
        # Drop timestamps older than 1 second
        rate_counts[client_ip] = [t for t in ts if now - t < 1.0]
        if len(rate_counts[client_ip]) >= RATE_LIMIT:
            return True
        rate_counts[client_ip].append(now)
    return False


def cache_get(domain: str):
    with state_lock:
        if domain in cache:
            ip, exp = cache[domain]
            if time.time() < exp:
                return ip
            del cache[domain]
    return None


def cache_set(domain: str, ip: str, ttl: int = 3600):
    with state_lock:
        cache[domain] = (ip, time.time() + ttl)
    emit("cache_updated", {"domain": domain, "ip": ip, "ttl": ttl})
    print(f"[hardened] CACHED  {domain} -> {ip}  (TTL {ttl}s)")


# ── Client-facing socket (port 53) ────────────────────────────────────────────
client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
client_sock.bind(("0.0.0.0", 53))


# ── Per-query upstream handling ───────────────────────────────────────────────

def query_upstream(domain: str, txid: int, client_addr: tuple, orig_data: bytes):
    """
    Opens a brand-new, ephemeral UDP socket for this query (DEFENSE 1).
    The OS assigns a random source port — closed as soon as the response
    (or timeout) arrives.
    """
    up_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    up_sock.bind(("", 0))                        # OS picks random port
    src_port = up_sock.getsockname()[1]
    up_sock.settimeout(2.0)

    fwd = DNSRecord.question(domain)
    fwd.header.id = txid
    up_sock.sendto(fwd.pack(), (UPSTREAM_IP, UPSTREAM_PORT))
    print(f"[hardened] FORWARDED {domain}  TxID={txid}  SrcPort={src_port}")

    try:
        resp_data, resp_addr = up_sock.recvfrom(4096)
        process_response(resp_data, resp_addr, txid, domain, client_addr, orig_data)
    except socket.timeout:
        print(f"[hardened] TIMEOUT waiting for {domain}  TxID={txid}")
        emit("timeout", {"domain": domain, "txid": txid})
    finally:
        up_sock.close()


def process_response(
    data: bytes,
    addr: tuple,
    expected_txid: int,
    queried_domain: str,
    client_addr: tuple,
    orig_data: bytes,
):
    # ── DEFENSE 4: strict source-IP check ─────────────────────────────────────
    if addr[0] != UPSTREAM_IP:
        print(f"[hardened] BLOCKED — wrong source IP {addr[0]} (expected {UPSTREAM_IP})")
        emit("blocked", {
            "reason":  "wrong_source_ip",
            "from":    addr[0],
            "domain":  queried_domain,
            "txid":    expected_txid,
        })
        return

    try:
        resp = DNSRecord.parse(data)
    except DNSError:
        print(f"[hardened] BLOCKED — malformed DNS packet")
        emit("blocked", {"reason": "malformed_packet", "domain": queried_domain})
        return

    # ── TxID match ─────────────────────────────────────────────────────────────
    if resp.header.id != expected_txid:
        print(f"[hardened] BLOCKED — TxID mismatch (got {resp.header.id}, expected {expected_txid})")
        emit("blocked", {"reason": "txid_mismatch", "domain": queried_domain})
        return

    if not resp.rr:
        return

    rr     = resp.rr[0]
    ip     = str(rr.rdata)
    ttl    = rr.ttl
    domain = str(rr.rname)

    # ── DEFENSE 3: TSIG-like HMAC validation ───────────────────────────────────
    tsig_sig = None
    for ar in resp.ar:
        name = str(ar.rname)
        if name.startswith("_tsig."):
            try:
                # dnslib returns TXT rdata as list of byte strings
                tsig_sig = ar.rdata.data[0].decode()
            except Exception:
                pass
            break

    if tsig_sig is None:
        print(f"[hardened] BLOCKED — no TSIG record for {domain}")
        emit("blocked", {"reason": "missing_tsig", "domain": domain, "ip": ip})
        return

    if not verify_tsig(domain, ip, ttl, tsig_sig):
        print(f"[hardened] BLOCKED — invalid TSIG signature for {domain} -> {ip}")
        emit("blocked", {
            "reason":     "invalid_tsig",
            "domain":     domain,
            "claimed_ip": ip,
            "txid":       expected_txid,
        })
        return

    # ── All checks passed ──────────────────────────────────────────────────────
    print(f"[hardened] VALIDATED  {domain} -> {ip}  TSIG OK")
    cache_set(domain, ip, ttl)
    emit("legitimate_response", {"domain": domain, "ip": ip})

    orig_req = DNSRecord.parse(orig_data)
    reply    = orig_req.reply()
    reply.add_answer(RR(orig_req.q.qname, QTYPE.A, rdata=A(ip), ttl=ttl))
    client_sock.sendto(reply.pack(), client_addr)


# ── Client listener ───────────────────────────────────────────────────────────

def handle_client(data: bytes, addr: tuple):
    # ── DEFENSE 5: rate limiting ───────────────────────────────────────────────
    if is_rate_limited(addr[0]):
        emit("rate_limited", {"client": addr[0]})
        return

    try:
        req    = DNSRecord.parse(data)
        domain = str(req.q.qname)

        emit("query", {"domain": domain, "client": addr[0]})

        # Cache hit?
        ip = cache_get(domain)
        if ip:
            reply = req.reply()
            reply.add_answer(RR(req.q.qname, QTYPE.A, rdata=A(ip), ttl=3600))
            client_sock.sendto(reply.pack(), addr)
            emit("cache_hit", {"domain": domain, "ip": ip})
            print(f"[hardened] CACHE HIT  {domain} -> {ip}")
            return

        # Fresh query → upstream with random port + CSPRNG TxID
        txid = make_txid()
        threading.Thread(
            target=query_upstream,
            args=(domain, txid, addr, data),
            daemon=True,
        ).start()

    except DNSError as e:
        print(f"[hardened] Malformed client packet: {e}")
    except Exception as e:
        print(f"[hardened] handle_client error: {e}")


def listen_clients():
    print("=" * 60)
    print("[dns_hardened] Starting up")
    print(f"  Client port    : 53")
    print(f"  Upstream ports : random ephemeral (OS-assigned)  ← DEFENSE 1")
    print(f"  TxID space     : 0–65535 (CSPRNG)               ← DEFENSE 2")
    print(f"  TSIG validation: ON  (HMAC-SHA256)               ← DEFENSE 3")
    print(f"  Source-IP check: ON  (must be {UPSTREAM_IP})        ← DEFENSE 4")
    print(f"  Rate limit     : {RATE_LIMIT} q/s per client            ← DEFENSE 5")
    print("=" * 60)

    while True:
        data, addr = client_sock.recvfrom(4096)
        threading.Thread(target=handle_client, args=(data, addr), daemon=True).start()


if __name__ == "__main__":
    listen_clients()
