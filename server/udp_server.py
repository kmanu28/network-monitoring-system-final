"""
udp_server.py  –  Network Monitoring System – Server Entry Point

Architecture
============
  Thread 1  : udp_receiver     – recvfrom loop; decrypts, validates, stores
  Thread 2  : tcp_control      – TLS-wrapped TCP listener for control messages
                                  (registration, RTT-ACK records, key exchange)
  Thread 3  : node_watchdog    – marks nodes DOWN when heartbeat times out
  Thread 4  : perf_collector   – samples throughput/RTT every second and writes
                                  a perf snapshot to the DB every 10 s
  Main      : keeps threads alive; prints status line every 5 s

Protocol (UDP telemetry)
========================
  Client  →  Server :  <fernet-encrypted>( node|seq|ts|event|metric|value )
  Server  →  Client :  ACK|<node>|<seq>|<server_ts_ms>

  The server_ts_ms lets the client compute one-way delay (with clock skew
  caveat) and round-trip time.

Reliability
===========
  Each datagram carries a monotonically increasing sequence number.
  The server detects gaps (dropped / reordered packets) and updates the
  packet-loss counter in state.py.  The ACK includes the server receive
  timestamp so the client can measure per-packet RTT and report back via
  the TLS control channel.
"""

import socket
import threading
import time
import traceback

from cryptography.fernet import Fernet, InvalidToken

import config
import state
import database

# ── Sockets ───────────────────────────────────────────────────────────────────
_udp_sock: socket.socket | None = None


def _build_udp_socket() -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # Increase receive buffer to absorb burst traffic during stress tests
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    s.bind((config.HOST, config.UDP_PORT))
    return s


# ── UDP receiver ──────────────────────────────────────────────────────────────
cipher = Fernet(config.FERNET_KEY)


def _process_udp_packet(data: bytes, addr: tuple, sock: socket.socket) -> None:
    """Decrypt, parse, persist, ACK one UDP datagram."""
    try:
        plaintext = cipher.decrypt(data).decode("utf-8")
    except InvalidToken:
        print(f"[WARN ] Invalid Fernet token from {addr}")
        return
    except Exception as exc:
        print(f"[WARN ] Decrypt error from {addr}: {exc}")
        return

    parts = plaintext.split("|")
    if len(parts) != 6:
        print(f"[WARN ] Malformed packet from {addr}: {plaintext!r}")
        return

    node, seq_s, ts_s, event, metric, value = parts
    try:
        seq = int(seq_s)
        ts  = int(ts_s)
    except ValueError:
        print(f"[WARN ] Non-integer seq/ts from {node}")
        return

    # Update shared state (also detects packet loss)
    loss = state.touch_node(node, addr[0], seq, event)
    if loss:
        print(f"[LOSS ] Gap detected for {node}  (expected {state.last_seq[node]-1}, got {seq})")

    # Persist to database
    severity = config.EVENT_TYPES.get(event, "UNKNOWN")
    database.insert_event(node, ts, event, metric, value, severity)

    # Send ACK: ACK|<node>|<seq>|<server_recv_ms>
    server_ts_ms = int(time.time() * 1000)
    ack_payload  = f"{config.ACK_PREFIX}|{node}|{seq}|{server_ts_ms}".encode()
    try:
        sock.sendto(ack_payload, addr)
    except OSError as exc:
        print(f"[WARN ] ACK send failed to {addr}: {exc}")

    print(f"[RECV ] {node:<18}  seq={seq:<6}  {event:<30}  {metric}={value}")


def udp_receiver(sock: socket.socket) -> None:
    """Main receive loop – runs in its own thread."""
    print(f"[UDP  ] Listening on {config.HOST}:{config.UDP_PORT}")
    while True:
        try:
            data, addr = sock.recvfrom(8192)
            # Dispatch to a thread so a slow DB write never blocks the next recv
            threading.Thread(
                target=_process_udp_packet,
                args=(data, addr, sock),
                daemon=True,
            ).start()
        except OSError:
            break
        except Exception as exc:
            print(f"[ERROR] UDP receiver: {exc}")
            traceback.print_exc()


# ── Node watchdog ─────────────────────────────────────────────────────────────

def node_watchdog() -> None:
    """Periodically marks nodes DOWN if their heartbeat has timed out."""
    print("[WTCH ] Node watchdog started")
    while True:
        time.sleep(config.HEARTBEAT_INTERVAL)
        cutoff = time.time() - config.NODE_TIMEOUT
        with state.lock:
            for nid, info in state.nodes.items():
                if info.get("last_seen", 0) < cutoff and info.get("status") != "DOWN":
                    state.nodes[nid]["status"] = "DOWN"
                    severity = config.EVENT_TYPES["NODE_DOWN"]
                    database.insert_event(
                        nid, int(time.time()),
                        "NODE_DOWN", "status", "timeout", severity,
                    )
                    print(f"[WTCH ] Node {nid} marked DOWN (timeout)")


# ── Performance collector ─────────────────────────────────────────────────────

def perf_collector() -> None:
    """
    Samples throughput every second; writes a DB snapshot every 10 s.
    Updates state.perf so the dashboard can read live metrics.
    """
    print("[PERF ] Performance collector started")
    snapshot_interval = 10
    last_snapshot     = time.time()

    while True:
        time.sleep(1)
        now = time.time()

        eps      = state.get_throughput_last_n_seconds(5)
        rtt_info = database.get_rtt_stats(since_ts=now - 60)
        active   = len(state.get_active_nodes())
        total    = database.get_total_event_count()

        # Packet-loss %
        total_expected = sum(state.last_seq.values())  # rough proxy
        total_lost     = sum(
            n.get("loss_count", 0) for n in state.nodes.values()
        )
        loss_pct = round(
            (total_lost / max(total_expected, 1)) * 100, 2
        )

        with state.lock:
            state.perf.update({
                "events_per_sec":  eps,
                "avg_rtt_ms":      rtt_info["avg"],
                "p99_rtt_ms":      rtt_info["p99"],
                "packet_loss_pct": loss_pct,
                "active_nodes":    active,
                "total_events":    total,
                "updated_at":      now,
            })

        if now - last_snapshot >= snapshot_interval:
            database.insert_perf_snapshot(
                active, eps,
                rtt_info["avg"], rtt_info["p99"],
                loss_pct, total,
            )
            last_snapshot = now


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    print("-" * 60)
    print("  Network Monitoring System - Server")
    print(f"  UDP telemetry : {config.HOST}:{config.UDP_PORT}")
    print("-" * 60)

    global _udp_sock
    _udp_sock = _build_udp_socket()

    # Start background threads
    threads = [
        threading.Thread(target=udp_receiver,    args=(_udp_sock,), daemon=True, name="udp-recv"),
        threading.Thread(target=node_watchdog,   daemon=True, name="watchdog"),
        threading.Thread(target=perf_collector,  daemon=True, name="perf"),
    ]

    for t in threads:
        t.start()

    # Main thread: status heartbeat
    try:
        while True:
            time.sleep(5)
            p = state.perf
            print(
                f"[STAT ] nodes={p['active_nodes']}  "
                f"eps={p['events_per_sec']:.1f}  "
                f"avg_rtt={p['avg_rtt_ms']:.1f}ms  "
                f"loss={p['packet_loss_pct']:.2f}%  "
                f"total={p['total_events']}"
            )
    except KeyboardInterrupt:
        print("\n[INFO ] Server shutting down.")
        if _udp_sock:
            _udp_sock.close()


if __name__ == "__main__":
    main()
