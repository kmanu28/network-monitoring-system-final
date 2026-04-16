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
import ssl
import threading
import time
import traceback
import os

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


def _build_tls_context() -> ssl.SSLContext:
    """
    Mutual TLS context: server presents its certificate; client must
    present a certificate signed by our CA.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(config.SERVER_CERT, config.SERVER_KEY)
    ctx.load_verify_locations(config.CA_CERT)
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


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


# ── TLS control channel ───────────────────────────────────────────────────────

def _handle_control_client(conn: ssl.SSLSocket, addr: tuple) -> None:
    """
    Handle one TLS control connection.

    Messages (newline-delimited JSON-like plain text for simplicity):
      REGISTER|<node_id>         → server replies OK|<node_id>
      RTT_RECORD|<node>|<seq>|<sent_ms>|<ack_ms>|<retries>
                                 → server persists ACK log, replies OK
      PING                       → server replies PONG|<server_ts_ms>
    """
    print(f"[TLS  ] Control connection from {addr}")
    try:
        conn.settimeout(30)
        raw = conn.recv(4096).decode("utf-8").strip()
        parts = raw.split("|")
        cmd   = parts[0] if parts else ""

        if cmd == "REGISTER" and len(parts) >= 2:
            node_id = parts[1]
            print(f"[TLS  ] REGISTER  node={node_id}")
            conn.sendall(f"OK|{node_id}\n".encode())

        elif cmd == "RTT_RECORD" and len(parts) >= 6:
            node, seq_s, sent_ms_s, ack_ms_s, retries_s = (
                parts[1], parts[2], parts[3], parts[4], parts[5]
            )
            sent_ts = float(sent_ms_s) / 1000.0
            ack_ts  = float(ack_ms_s)  / 1000.0
            retries = int(retries_s)
            database.insert_ack_log(node, int(seq_s), sent_ts, ack_ts, retries)
            conn.sendall(b"OK\n")

        elif cmd == "PING":
            ts = int(time.time() * 1000)
            conn.sendall(f"PONG|{ts}\n".encode())

        else:
            conn.sendall(b"ERR|unknown_command\n")

    except ssl.SSLError as exc:
        print(f"[WARN ] TLS error from {addr}: {exc}")
    except Exception as exc:
        print(f"[ERROR] Control handler: {exc}")
    finally:
        conn.close()


def tcp_control_server(ctx: ssl.SSLContext) -> None:
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    raw.bind((config.HOST, config.TCP_PORT))
    raw.listen(64)
    print(f"[TLS  ] Control server on {config.HOST}:{config.TCP_PORT}  (mTLS)")
    while True:
        try:
            client, addr = raw.accept()
            tls_conn = ctx.wrap_socket(client, server_side=True)
            threading.Thread(
                target=_handle_control_client,
                args=(tls_conn, addr),
                daemon=True,
            ).start()
        except Exception as exc:
            print(f"[ERROR] TLS accept: {exc}")


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

def _get_local_ips():
    try:
        import subprocess
        output = subprocess.check_output("ipconfig", shell=True).decode()
        ips = []
        import re
        for match in re.finditer(r"IPv4 Address[ .]*:[ ]*([\d.]+)", output):
            ips.append(match.group(1))
        return ips
    except Exception:
        return []


def main() -> None:
    print("-" * 60)
    print("  Network Monitoring System - Server")
    print(f"  UDP telemetry : {config.HOST}:{config.UDP_PORT}")
    print(f"  TCP port (TLS): {config.TCP_PORT}")
    
    local_ips = _get_local_ips()
    if local_ips:
        print("  Local IP addresses discovered:")
        for ip in local_ips:
            print(f"    - {ip}")
        print("  Use one of these in the client: python client.py --server <IP>")
    print("-" * 60)

    global _udp_sock
    _udp_sock = _build_udp_socket()

    # Start background threads
    threads = [
        threading.Thread(target=udp_receiver,    args=(_udp_sock,), daemon=True, name="udp-recv"),
        threading.Thread(target=node_watchdog,   daemon=True, name="watchdog"),
        threading.Thread(target=perf_collector,  daemon=True, name="perf"),
    ]

    # TLS certificates check
    if not os.path.exists(config.SERVER_CERT) or not os.path.exists(config.SERVER_KEY):
        print("[ERROR] TLS certificates not found.")
        print("        Run:  python scripts/setup_certs.py")
        # Don't abort, just warn, maybe the user wants UDP-only (though unlikely)
        # But according to README, it's required.
    else:
        try:
            tls_ctx = _build_tls_context()
            threads.append(
                threading.Thread(
                    target=tcp_control_server, args=(tls_ctx,),
                    daemon=True, name="tls-ctrl",
                )
            )
        except Exception as exc:
            print(f"[ERROR] Failed to initialize TLS: {exc}")

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
