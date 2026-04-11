#!/usr/bin/env python3
"""
upstream_dns/server.py — Simulated Authoritative DNS Server

Always returns 1.2.3.4 for any A query.
Signs every response with HMAC-SHA256 (TSIG-like) so that the hardened
resolver can cryptographically verify the response came from us.

TSIG record format (simplified):
  Additional record: _tsig.<qname> TXT "<hex_signature>"
  where signature = HMAC-SHA256(secret, "<qname>:<ip>:<ttl>")
"""

import socket
import threading
import hmac
import hashlib
import json
import time
import os
from dnslib import DNSRecord, RR, QTYPE, A, TXT
from dnslib.dns import DNSError

# ── Config ────────────────────────────────────────────────────────────────────
MY_IP        = "10.0.0.5"
REAL_IP      = "1.2.3.4"
DNS_PORT     = 53
RECORD_TTL   = 3600
MONITOR_IP   = "10.0.0.8"
MONITOR_PORT = 9999
DNS_SECRET   = os.environ.get("DNS_SECRET", "shared_tsig_secret_2024")


# ── Helpers ───────────────────────────────────────────────────────────────────

def emit(event_type: str, data: dict):
    """Send a JSON event to the monitor dashboard (fire-and-forget UDP)."""
    try:
        payload = json.dumps({
            "type":   event_type,
            "time":   time.time(),
            "source": "upstream_dns",
            **data,
        }).encode()
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(payload, (MONITOR_IP, MONITOR_PORT))
        s.close()
    except Exception:
        pass


def sign_record(qname: str, ip: str, ttl: int) -> str:
    """
    Compute HMAC-SHA256(secret, "<qname>:<ip>:<ttl>") and return as hex string.
    This is what the hardened resolver will verify before caching.
    """
    msg = f"{qname}:{ip}:{ttl}".encode()
    return hmac.new(DNS_SECRET.encode(), msg, hashlib.sha256).hexdigest()


# ── Query handler ─────────────────────────────────────────────────────────────

def handle(data: bytes, addr: tuple, srv_sock: socket.socket):
    try:
        req = DNSRecord.parse(data)
        qname = str(req.q.qname)
        qtype = QTYPE[req.q.qtype]

        reply = req.reply()

        if req.q.qtype == QTYPE.A:
            # A record answer
            reply.add_answer(
                RR(req.q.qname, QTYPE.A, rdata=A(REAL_IP), ttl=RECORD_TTL)
            )
            # TSIG-like signature in an additional TXT record
            sig    = sign_record(qname, REAL_IP, RECORD_TTL)
            tsig_name = "_tsig.{}".format(qname)
            reply.add_ar(
                RR(tsig_name, QTYPE.TXT, rdata=TXT(sig.encode()), ttl=30)
            )
            print(f"[upstream] {qname} -> {REAL_IP}  sig={sig[:12]}...")

        emit("upstream_response", {
            "domain":  qname,
            "qtype":   qtype,
            "ip":      REAL_IP,
            "client":  addr[0],
        })

        srv_sock.sendto(reply.pack(), addr)

    except DNSError as e:
        print(f"[upstream] Malformed query from {addr}: {e}")
    except Exception as e:
        print(f"[upstream] Unexpected error: {e}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", DNS_PORT))
    print(f"[upstream_dns] Listening on 0.0.0.0:{DNS_PORT}")
    print(f"[upstream_dns] Real IP: {REAL_IP} | TSIG signing: ON | Secret: {DNS_SECRET[:8]}...")

    while True:
        data, addr = sock.recvfrom(4096)
        threading.Thread(target=handle, args=(data, addr, sock), daemon=True).start()


if __name__ == "__main__":
    main()
