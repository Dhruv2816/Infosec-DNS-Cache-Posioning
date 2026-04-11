#!/usr/bin/env python3
"""
monitor/monitor.py — Live Dashboard Backend

Receives UDP JSON events from dns (10.0.0.2) and dns_hardened (10.0.0.6)
on port 9999, then exposes them via a polling REST API consumed by the
browser dashboard at http://localhost:8080.

Event types emitted by the DNS servers
──────────────────────────────────────
  query               — client made a DNS request
  cache_hit           — served from cache
  cache_updated       — new record stored in cache
  legitimate_response — upstream response passed all checks
  attack_detected     — spoofed packet arrived at vulnerable resolver
  poisoned            — vulnerable resolver cached the fake IP
  blocked             — hardened resolver rejected a suspicious response
  rate_limited        — client hit the rate limit on hardened resolver
  upstream_response   — upstream authoritative server replied
  timeout             — upstream request timed out
"""

import json
import socket
import threading
import time
from collections import deque, defaultdict
from flask import Flask, jsonify, render_template

# ── Config ────────────────────────────────────────────────────────────────────
UDP_PORT    = 9999
HTTP_PORT   = 8080
MAX_EVENTS  = 500

# ── Shared state ──────────────────────────────────────────────────────────────
events      = deque(maxlen=MAX_EVENTS)
state_lock  = threading.Lock()

cache_state = {
    "dns_vulnerable": {},   # domain -> ip
    "dns_hardened":   {},
}

counters = {
    "dns_vulnerable": defaultdict(int),
    "dns_hardened":   defaultdict(int),
    "upstream_dns":   defaultdict(int),
}

attack_log   = deque(maxlen=100)  # high-priority events only
blocked_log  = deque(maxlen=100)

# ── Colour map for event types ────────────────────────────────────────────────
COLORS = {
    "query":               "#94A3B8",
    "cache_hit":           "#22C55E",
    "cache_updated":       "#00D4FF",
    "legitimate_response": "#22C55E",
    "upstream_response":   "#A855F7",
    "attack_detected":     "#FF4444",
    "poisoned":            "#FF0000",
    "blocked":             "#F59E0B",
    "rate_limited":        "#F97316",
    "timeout":             "#64748B",
}

ICON = {
    "query":               "→",
    "cache_hit":           "✓",
    "cache_updated":       "📥",
    "legitimate_response": "✓",
    "upstream_response":   "↑",
    "attack_detected":     "⚠",
    "poisoned":            "☠",
    "blocked":             "🛡",
    "rate_limited":        "⏱",
    "timeout":             "⌛",
}


# ── UDP listener ──────────────────────────────────────────────────────────────

def udp_listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", UDP_PORT))
    print(f"[monitor] UDP listener ready on :{UDP_PORT}")

    while True:
        try:
            raw, _ = sock.recvfrom(8192)
            event  = json.loads(raw.decode())
        except Exception:
            continue

        etype  = event.get("type", "unknown")
        source = event.get("source", "unknown")
        ts     = event.get("time", time.time())

        event["color"] = COLORS.get(etype, "#FFFFFF")
        event["icon"]  = ICON.get(etype, "•")
        event["ts"]    = time.strftime("%H:%M:%S", time.localtime(ts))

        with state_lock:
            events.appendleft(event)

            # Update per-source counters
            if source in counters:
                counters[source][etype] += 1

            # Update cache snapshots
            if etype == "cache_updated":
                domain = event.get("domain", "")
                ip     = event.get("ip", "")
                if source == "dns_vulnerable" and domain:
                    cache_state["dns_vulnerable"][domain] = ip
                elif source == "dns_hardened" and domain:
                    cache_state["dns_hardened"][domain] = ip

            # Separate high-priority logs
            if etype in ("attack_detected", "poisoned"):
                attack_log.appendleft(event)
            elif etype == "blocked":
                blocked_log.appendleft(event)


# ── Flask app ─────────────────────────────────────────────────────────────────

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/events")
def get_events():
    with state_lock:
        return jsonify(list(events)[:150])


@app.route("/api/stats")
def get_stats():
    with state_lock:
        return jsonify({
            "counters":   {k: dict(v) for k, v in counters.items()},
            "cache":      cache_state,
            "attacks":    list(attack_log)[:20],
            "blocked":    list(blocked_log)[:20],
        })


# ── Entry ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    threading.Thread(target=udp_listener, daemon=True).start()
    print(f"[monitor] Dashboard on http://0.0.0.0:{HTTP_PORT}")
    app.run(host="0.0.0.0", port=HTTP_PORT, debug=False, threaded=True)
