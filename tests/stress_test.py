"""
stress_test.py  –  Performance & Stress Test for the Network Monitoring System

What this script measures
=========================
  PHASE 1 – Baseline (1 client, 20 packets, no artificial load)
    • Measures unloaded per-packet RTT
    • Establishes "before" latency distribution

  PHASE 2 – Concurrent-client stress (N clients × M packets each)
    • Spawns N threads, each acting as an independent node
    • All threads send simultaneously (simulates real concurrency)
    • Measures:
        – per-packet RTT (avg, P50, P95, P99, max)
        – ACK success rate
        – effective throughput (packets/s as seen by clients)
        – packet-loss rate (ACK timeouts / retransmissions)

  PHASE 3 – Burst test (all clients fire at once, no sleep between packets)
    • Shows how the server behaves under a packet storm

  Summary report is printed to stdout and saved to stress_report.txt

Usage
-----
  # Start the server first:
  #   cd server && python udp_server.py
  
  python tests/stress_test.py --clients 10 --packets 50
  python tests/stress_test.py --clients 50 --packets 100 --burst
"""

import argparse
import os
import socket
import statistics
import sys
import threading
import time
import uuid

from cryptography.fernet import Fernet

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "server"))
import config

# ── Config ────────────────────────────────────────────────────────────────────
SERVER_IP = "127.0.0.1"
CIPHER     = Fernet(config.FERNET_KEY)
ACK_TIMEOUT = config.ACK_TIMEOUT


# ── Low-level send/receive ────────────────────────────────────────────────────

def make_socket() -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(ACK_TIMEOUT)
    return s


def send_one(sock: socket.socket, node_id: str, seq: int,
             event: str = "HEARTBEAT",
             metric: str = "status",
             value: str  = "stress") -> dict:
    """
    Send one encrypted datagram, wait for ACK.
    Returns a result dict.
    """
    ts      = int(time.time())
    payload = f"{node_id}|{seq}|{ts}|{event}|{metric}|{value}"
    enc     = CIPHER.encrypt(payload.encode())

    t_send  = time.perf_counter()
    sock.sendto(enc, (SERVER_IP, config.UDP_PORT))

    retries = 0
    acked   = False
    rtt_ms  = None

    for attempt in range(config.MAX_RETRIES + 1):
        try:
            ack, _ = sock.recvfrom(256)
            t_ack  = time.perf_counter()
            parts  = ack.decode().split("|")
            if (len(parts) == 4
                    and parts[0] == "ACK"
                    and parts[1] == node_id
                    and int(parts[2]) == seq):
                rtt_ms = (t_ack - t_send) * 1000
                acked  = True
                break
        except socket.timeout:
            retries += 1
            if attempt < config.MAX_RETRIES:
                sock.sendto(enc, (SERVER_IP, config.UDP_PORT))

    return {
        "seq":     seq,
        "acked":   acked,
        "rtt_ms":  rtt_ms,
        "retries": retries,
    }


# ── Per-client worker ─────────────────────────────────────────────────────────

def client_worker(node_id: str, n_packets: int, results: list,
                  start_barrier: threading.Barrier,
                  burst: bool = False) -> None:
    """
    Simulate one client node sending n_packets telemetry events.
    Uses start_barrier so all clients begin simultaneously.
    """
    sock = make_socket()
    start_barrier.wait()  # synchronised start

    local_results = []
    for seq in range(1, n_packets + 1):
        r = send_one(sock, node_id, seq)
        local_results.append(r)
        if not burst:
            time.sleep(0.05)   # 50 ms inter-packet gap in non-burst mode

    sock.close()
    results.extend(local_results)


# ── Statistics helper ─────────────────────────────────────────────────────────

def compute_stats(results: list) -> dict:
    rtts   = [r["rtt_ms"] for r in results if r["acked"] and r["rtt_ms"] is not None]
    total  = len(results)
    acked  = sum(1 for r in results if r["acked"])
    lost   = total - acked
    retx   = sum(r["retries"] for r in results)

    def pct(lst, p):
        if not lst:
            return 0.0
        lst_s = sorted(lst)
        idx   = max(0, int(len(lst_s) * p / 100) - 1)
        return lst_s[idx]

    return {
        "total_packets":  total,
        "acked":          acked,
        "lost":           lost,
        "loss_pct":       round(lost / max(total, 1) * 100, 2),
        "retransmissions": retx,
        "avg_rtt_ms":     round(statistics.mean(rtts), 3)    if rtts else 0,
        "median_rtt_ms":  round(statistics.median(rtts), 3)  if rtts else 0,
        "p95_rtt_ms":     round(pct(rtts, 95), 3),
        "p99_rtt_ms":     round(pct(rtts, 99), 3),
        "max_rtt_ms":     round(max(rtts), 3)                if rtts else 0,
        "stdev_rtt_ms":   round(statistics.stdev(rtts), 3)   if len(rtts) > 1 else 0,
    }


def print_stats(label: str, stats: dict, elapsed: float,
                n_clients: int = 1) -> str:
    total_pkts = stats["total_packets"]
    throughput = round(total_pkts / max(elapsed, 0.001), 1)
    lines = [
        "",
        f"  +- {label} {'-' * max(0, 48 - len(label))}+",
        f"  |  Clients            : {n_clients}",
        f"  |  Total packets      : {total_pkts}",
        f"  |  ACKed              : {stats['acked']}",
        f"  |  Lost               : {stats['lost']}  ({stats['loss_pct']} %)",
        f"  |  Retransmissions    : {stats['retransmissions']}",
        f"  |  Elapsed            : {elapsed:.2f} s",
        f"  |  Throughput         : {throughput} pkt/s",
        f"  |  Avg RTT            : {stats['avg_rtt_ms']} ms",
        f"  |  Median RTT         : {stats['median_rtt_ms']} ms",
        f"  |  P95 RTT            : {stats['p95_rtt_ms']} ms",
        f"  |  P99 RTT            : {stats['p99_rtt_ms']} ms",
        f"  |  Max RTT            : {stats['max_rtt_ms']} ms",
        f"  |  Stdev RTT          : {stats['stdev_rtt_ms']} ms",
        f"  +--------------------------------------------------+",
    ]
    block = "\n".join(lines)
    print(block)
    return block


# ── Run a test phase ──────────────────────────────────────────────────────────

def run_phase(label: str, n_clients: int, n_packets: int,
              burst: bool = False) -> tuple[dict, float]:
    print(f"\n[PHASE] {label}")
    print(f"        clients={n_clients}  packets_per_client={n_packets}"
          f"  burst={burst}")

    all_results: list = []
    threads: list[threading.Thread] = []
    barrier = threading.Barrier(n_clients + 1)  # +1 for this thread

    for i in range(n_clients):
        node_id = f"stress-{uuid.uuid4().hex[:6]}"
        t = threading.Thread(
            target=client_worker,
            args=(node_id, n_packets, all_results, barrier, burst),
            daemon=True,
        )
        threads.append(t)
        t.start()

    t_start = time.perf_counter()
    barrier.wait()  # release all clients simultaneously

    for t in threads:
        t.join(timeout=120)

    elapsed = time.perf_counter() - t_start
    return compute_stats(all_results), elapsed


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="NMS Stress Test & Performance Benchmark"
    )
    parser.add_argument("--clients",  type=int, default=10,
                        help="Number of concurrent client threads (default 10)")
    parser.add_argument("--packets",  type=int, default=50,
                        help="Packets per client (default 50)")
    parser.add_argument("--burst",    action="store_true",
                        help="No inter-packet sleep – maximum send rate")
    parser.add_argument("--out",      default="stress_report.txt",
                        help="Output file for the report (default stress_report.txt)")
    args = parser.parse_args()

    report_lines = []
    report_lines.append("=" * 60)
    report_lines.append("  NMS Performance & Stress Test Report")
    report_lines.append(f"  Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    report_lines.append("=" * 60)

    # ── Phase 1: Baseline (1 client, 20 packets) ──────────────────────────────
    stats1, elapsed1 = run_phase(
        "Baseline – 1 client, 20 packets (no load)", 1, 20, burst=False
    )
    block = print_stats("Baseline (before load)", stats1, elapsed1, n_clients=1)
    report_lines.append(block)

    # ── Phase 2: Multi-client stress ─────────────────────────────────────────
    stats2, elapsed2 = run_phase(
        f"Stress – {args.clients} clients × {args.packets} packets",
        args.clients, args.packets, burst=False,
    )
    block = print_stats(
        f"Stress ({args.clients} clients)", stats2, elapsed2, n_clients=args.clients
    )
    report_lines.append(block)

    # ── Phase 3: Burst ────────────────────────────────────────────────────────
    if args.burst:
        stats3, elapsed3 = run_phase(
            f"Burst – {args.clients} clients, no inter-packet sleep",
            args.clients, args.packets, burst=True,
        )
        block = print_stats(
            f"Burst ({args.clients} clients)", stats3, elapsed3, n_clients=args.clients
        )
        report_lines.append(block)

    # ── Delta summary ─────────────────────────────────────────────────────────
    delta_avg = stats2["avg_rtt_ms"] - stats1["avg_rtt_ms"]
    delta_p99 = stats2["p99_rtt_ms"] - stats1["p99_rtt_ms"]
    summary = (
        f"\n  +- Before vs After Summary {'-'*30}+\n"
        f"  |  Avg RTT  baseline  : {stats1['avg_rtt_ms']} ms\n"
        f"  |  Avg RTT  stress    : {stats2['avg_rtt_ms']} ms   "
        f"(Delta {delta_avg:+.3f} ms)\n"
        f"  |  P99 RTT  baseline  : {stats1['p99_rtt_ms']} ms\n"
        f"  |  P99 RTT  stress    : {stats2['p99_rtt_ms']} ms   "
        f"(Delta {delta_p99:+.3f} ms)\n"
        f"  |  Loss     baseline  : {stats1['loss_pct']} %\n"
        f"  |  Loss     stress    : {stats2['loss_pct']} %\n"
        f"  +----------------------------------------------------+"
    )
    print(summary)
    report_lines.append(summary)

    # ── Write report ─────────────────────────────────────────────────────────
    report_path = os.path.join(os.path.dirname(__file__), args.out)
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(report_lines))
    print(f"\n[INFO ] Report saved to {report_path}")


if __name__ == "__main__":
    main()