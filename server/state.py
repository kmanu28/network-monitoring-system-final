"""
state.py  –  In-memory shared state for the monitoring server.

All mutable state lives here so every server module can import a single
authoritative copy.  A single threading.Lock protects all mutations.
"""

import threading
import time
from collections import defaultdict
from typing import Dict, Any

# ── Lock ──────────────────────────────────────────────────────────────────────
lock = threading.Lock()

# ── Node registry ─────────────────────────────────────────────────────────────
# nodes[node_id] = {
#     "ip":         str,
#     "last_seen":  float (epoch),
#     "status":     "UP" | "DOWN",
#     "last_event": str,
#     "last_seq":   int,
#     "loss_count": int,
# }
nodes: Dict[str, Dict[str, Any]] = {}

# ── Sequence-number tracking (packet-loss detection) ─────────────────────────
# last_seq[node_id] = last accepted sequence number
last_seq: Dict[str, int] = defaultdict(lambda: -1)

# ── Event counters ────────────────────────────────────────────────────────────
event_counts: Dict[str, int] = defaultdict(int)

# ── Per-second throughput ring buffer (last 60 seconds) ──────────────────────
# throughput[epoch_second] = count of events received in that second
throughput: Dict[int, int] = defaultdict(int)

# ── Performance metrics (updated by perf_collector thread) ───────────────────
perf: Dict[str, Any] = {
    "events_per_sec":   0.0,
    "avg_rtt_ms":       0.0,
    "p99_rtt_ms":       0.0,
    "packet_loss_pct":  0.0,
    "active_nodes":     0,
    "total_events":     0,
    "updated_at":       0.0,
}

# ── Helpers ───────────────────────────────────────────────────────────────────

def touch_node(node_id: str, ip: str, seq: int, event: str) -> bool:
    """
    Update node state and return True if a sequence-number gap is detected
    (indicating at least one dropped packet).
    """
    now = time.time()
    loss = False
    with lock:
        prev = last_seq[node_id]
        if prev >= 0 and seq != prev + 1:
            nodes.setdefault(node_id, {})["loss_count"] = \
                nodes.get(node_id, {}).get("loss_count", 0) + abs(seq - prev - 1)
            loss = True
        last_seq[node_id] = seq

        nodes[node_id] = {
            "ip":         ip,
            "last_seen":  now,
            "status":     "UP",
            "last_event": event,
            "last_seq":   seq,
            "loss_count": nodes.get(node_id, {}).get("loss_count", 0),
        }

        event_counts[event] += 1
        throughput[int(now)] += 1

    return loss


def get_active_nodes() -> list:
    """Return nodes seen in the last NODE_TIMEOUT seconds."""
    from config import NODE_TIMEOUT
    cutoff = time.time() - NODE_TIMEOUT
    with lock:
        return [
            {"id": nid, **info}
            for nid, info in nodes.items()
            if info.get("last_seen", 0) >= cutoff
        ]


def get_throughput_last_n_seconds(n: int = 10) -> float:
    """Return average events/second over the last n seconds."""
    now = int(time.time())
    with lock:
        counts = [throughput.get(now - i, 0) for i in range(1, n + 1)]
    return round(sum(counts) / n, 2)
