#!/usr/bin/env python3
"""
dns/server.py — Vulnerable DNS Caching Resolver

Intentional weaknesses (for demonstration):
  1. Fixed source port 22222 for ALL upstream queries — attacker knows where to aim.
  2. TxID drawn from randint(10000, 10050) — only 51 possible values, trivially brute-forced.
  3. No signature validation — accepts any response that matches the TxID, even spoofed ones.
  4. No source-IP check on upstream responses.

The monitor receives live events via UDP so the dashboard can show cache state and attack activity.
"""

import socket
import threading
import random
import time
import json
from dnslib import DNSRecord, RR, QTYPE, A
from dnslib.dns import DNSError

# ── Config ────────────────────────────────────────────────────────────────────
MY_IP         = "10.0.0.2"
UPSTREAM_IP   = "10.0.0.5"
UPSTREAM_PORT = 53
FIXED_SRC_PORT = 22222     # VULNERABILITY 1 — fixed port, known to attacker
TXID_MIN      = 10000      # VULNERABILITY 2 — tiny TxID range
TXID_MAX      = 10050
MONITOR_IP    = "10.0.0.8"
MONITOR_PORT  = 9999

# ── Shared State ──────────────────────────────────────────────────────────────
cache   : dict = {}          # domain -> (ip, expires_at)
pending : dict = {}          # txid  -> {"client_addr", "orig_data", "event"}
state_lock = threading.Lock()


# ── Helpers ───────────────────────────────────────────────────────────────────

def emit(event_type: str, data: dict):
    try:
        payload = json.dumps({
            "type":   event_type,
            "time":   time.time(),
            "source": "dns_vulnerable",
            **data,
        }).encode()
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(payload, (MONITOR_IP, MONITOR_PORT))
        s.close()
    except Exception:
        pass


def get_txid() -> int:
    """VULNERABLE: only 51 possible values."""
    return random.randint(TXID_MIN, TXID_MAX)


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
    print(f"[dns] CACHED  {domain} -> {ip}  (TTL {ttl}s)")


# ── Sockets ───────────────────────────────────────────────────────────────────

# Client-facing: listens on port 53
client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
client_sock.bind(("0.0.0.0", 53))

# Upstream-facing: FIXED port 22222 (the vulnerability)
upstream_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
upstream_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
upstream_sock.bind((MY_IP, FIXED_SRC_PORT))


# ── Client query handler ──────────────────────────────────────────────────────

def handle_client(data: bytes, addr: tuple):
    try:
        req    = DNSRecord.parse(data)
        domain = str(req.q.qname)

        emit("query", {"domain": domain, "client": addr[0]})

        # ── Cache hit ──────────────────────────────────────────────────────────
        ip = cache_get(domain)
        if ip:
            reply = req.reply()
            reply.add_answer(RR(req.q.qname, QTYPE.A, rdata=A(ip), ttl=3600))
            client_sock.sendto(reply.pack(), addr)
            emit("cache_hit", {"domain": domain, "ip": ip, "client": addr[0]})
            print(f"[dns] CACHE HIT  {domain} -> {ip}")
            return

        # ── Forward to upstream ────────────────────────────────────────────────
        txid = get_txid()
        fwd  = DNSRecord.question(domain)
        fwd.header.id = txid

        ev = threading.Event()
        with state_lock:
            # If the same TxID is already in-flight, the new query wins
            pending[txid] = {"client_addr": addr, "orig_data": data, "event": ev}

        upstream_sock.sendto(fwd.pack(), (UPSTREAM_IP, UPSTREAM_PORT))
        print(f"[dns] FORWARDED {domain}  TxID={txid}  SrcPort={FIXED_SRC_PORT}")

        # Wait up to 2s for an upstream (or spoofed) response
        ev.wait(timeout=2.0)

    except DNSError as e:
        print(f"[dns] Malformed client packet: {e}")
    except Exception as e:
        print(f"[dns] handle_client error: {e}")


# ── Upstream response listener ────────────────────────────────────────────────

def listen_upstream():
    """
    Receives whatever arrives on the fixed port 22222.
    No source-IP validation — accepts spoofed packets equally.
    """
    while True:
        try:
            data, addr = upstream_sock.recvfrom(4096)

            try:
                resp = DNSRecord.parse(data)
            except DNSError:
                # Malformed packet — common during flood
                continue

            txid = resp.header.id

            with state_lock:
                entry = pending.get(txid)

            if entry is None:
                # No pending query for this TxID — discard
                continue

            client_addr = entry["client_addr"]
            orig_data   = entry["orig_data"]
            ev          = entry["event"]

            if not resp.rr:
                ev.set()
                continue

            rr     = resp.rr[0]
            ip     = str(rr.rdata)
            ttl    = rr.ttl
            domain = str(rr.rname)

            # ── No validation — just accept it! (the core vulnerability) ───────
            if addr[0] != UPSTREAM_IP:
                # This was a spoofed packet — but we accept it anyway
                print(f"[dns] ⚠  SPOOFED response accepted!  from={addr[0]}  TxID={txid}  ip={ip}")
                emit("attack_detected", {
                    "domain":   domain,
                    "fake_ip":  ip,
                    "from":     addr[0],
                    "txid":     txid,
                })
                emit("poisoned", {"domain": domain, "fake_ip": ip, "txid": txid})
            else:
                emit("legitimate_response", {"domain": domain, "ip": ip})

            cache_set(domain, ip, ttl)

            # Return answer to client
            orig_req = DNSRecord.parse(orig_data)
            reply    = orig_req.reply()
            reply.add_answer(RR(orig_req.q.qname, QTYPE.A, rdata=A(ip), ttl=ttl))
            client_sock.sendto(reply.pack(), client_addr)

            # Signal client handler to stop waiting
            with state_lock:
                pending.pop(txid, None)
            ev.set()

        except Exception as e:
            print(f"[dns] listen_upstream error: {e}")


# ── Client listener ───────────────────────────────────────────────────────────

def listen_clients():
    while True:
        data, addr = client_sock.recvfrom(4096)
        threading.Thread(target=handle_client, args=(data, addr), daemon=True).start()


# ── Entry ─────────────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("[dns_vulnerable] Starting up")
    print(f"  Client port  : 53")
    print(f"  Upstream port: {FIXED_SRC_PORT}  ← FIXED (vulnerability 1)")
    print(f"  TxID range   : {TXID_MIN}–{TXID_MAX}  ← {TXID_MAX-TXID_MIN+1} values (vulnerability 2)")
    print(f"  Validation   : NONE  ← accepts any matching TxID (vulnerability 3)")
    print("=" * 60)

    threading.Thread(target=listen_upstream, daemon=True).start()
    listen_clients()


if __name__ == "__main__":
    main()
