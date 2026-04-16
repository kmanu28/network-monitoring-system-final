"""
client.py  –  Network Monitoring System – Agent Node

Dual-channel design
===================
  UDP (port 9000) : telemetry / metrics  (Fernet-encrypted datagrams)
  TCP (port 9001) : TLS control channel  (registration + RTT reporting)

Metrics reported every cycle
=============================
  HEARTBEAT            – always sent; carries uptime
  CPU_USAGE            – actual CPU % (always reported, WARNING if > threshold)
  MEMORY_USAGE         – actual RAM % (always reported, WARNING if > threshold)
  NETWORK_LATENCY      – TCP probe RTT to 8.8.8.8:53 in ms (always reported)
  DISK_USAGE           – disk % on primary drive (always reported)
  BANDWIDTH_USAGE      – bytes sent+recv per second (network I/O rate)
  TCP_CONNECTIONS      – number of ESTABLISHED TCP connections
  PACKET_LOSS          – % loss from dropped ACKs this session
  NETWORK_JITTER       – variance in successive latency readings (ms)

Alert events (sent only when threshold crossed, with cooldown)
==============================================================
  CPU_THRESHOLD_EXCEEDED
  MEMORY_THRESHOLD_EXCEEDED
  LATENCY_HIGH
  NETWORK_FAILURE
  DISK_USAGE_HIGH
  BANDWIDTH_SPIKE
"""

import os
import socket
import ssl
import sys
import threading
import time
import uuid
from collections import deque

import psutil
from cryptography.fernet import Fernet

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "server"))
import config

# ── Identity & startup time ───────────────────────────────────────────────────
NODE_ID    = f"node-{uuid.uuid4().hex[:8]}"
START_TIME = time.time()

# ── Encryption ────────────────────────────────────────────────────────────────
cipher = Fernet(config.FERNET_KEY)

# ── Sequence counter ──────────────────────────────────────────────────────────
_seq_lock = threading.Lock()
_seq      = 0

def next_seq():
    global _seq
    with _seq_lock:
        _seq += 1
        return _seq

# ── UDP socket ────────────────────────────────────────────────────────────────
_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
_udp.settimeout(config.ACK_TIMEOUT)

# ── RTT & loss tracking ───────────────────────────────────────────────────────
_rtt_buffer   = deque(maxlen=500)
_rtt_lock     = threading.Lock()
_sent_total   = 0
_dropped_total = 0
_drop_lock    = threading.Lock()

# ── Jitter (last 10 latency samples) ─────────────────────────────────────────
_latency_history = deque(maxlen=10)

# ── Bandwidth baseline ────────────────────────────────────────────────────────
_last_net_io   = psutil.net_io_counters()
_last_net_time = time.time()

# ── Cooldown tracker ─────────────────────────────────────────────────────────
_last_sent = {}

def _should_alert(event, cooldown=None):
    cd  = cooldown if cooldown is not None else config.COOLDOWN_SECONDS
    now = time.time()
    if event not in _last_sent or now - _last_sent[event] > cd:
        _last_sent[event] = now
        return True
    return False


# ── Core send with ACK + retransmit ──────────────────────────────────────────

def send_event(event, metric, value):
    global _sent_total, _dropped_total
    seq       = next_seq()
    ts        = int(time.time())
    payload   = f"{NODE_ID}|{seq}|{ts}|{event}|{metric}|{value}"
    encrypted = cipher.encrypt(payload.encode())

    sent_ms = time.time() * 1000
    retries = 0
    acked   = False

    with _drop_lock:
        _sent_total += 1

    for attempt in range(config.MAX_RETRIES + 1):
        if attempt > 0:
            retries += 1
            print(f"[RETRY] seq={seq}  attempt={attempt}/{config.MAX_RETRIES}")

        _udp.sendto(encrypted, (config.SERVER_IP, config.UDP_PORT))

        try:
            ack_data, _ = _udp.recvfrom(256)
            ack_ms      = time.time() * 1000
            parts       = ack_data.decode("utf-8").split("|")
            if (len(parts) == 4
                    and parts[0] == config.ACK_PREFIX
                    and parts[1] == NODE_ID
                    and int(parts[2]) == seq):
                rtt_ms = ack_ms - sent_ms
                print(f"[ACK  ] seq={seq:<5}  {event:<30}  {metric}={value}  RTT={rtt_ms:.1f}ms")
                with _rtt_lock:
                    _rtt_buffer.append((seq, sent_ms, ack_ms, retries))
                acked = True
                break
        except socket.timeout:
            pass

    if not acked:
        print(f"[DROP ] seq={seq}  {event}  unacknowledged after {config.MAX_RETRIES} retries")
        with _drop_lock:
            _dropped_total += 1

    return acked


# ── TLS control channel ───────────────────────────────────────────────────────

def _build_tls_ctx():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname  = False  # Disable hostname check for remote IP
    ctx.verify_mode     = ssl.CERT_REQUIRED
    ctx.load_verify_locations(config.CA_CERT)
    ctx.load_cert_chain(config.CLIENT_CERT, config.CLIENT_KEY)
    return ctx

def _tls_send(msg):
    try:
        ctx = _build_tls_ctx()
        raw = socket.create_connection((config.SERVER_IP, config.TCP_PORT), timeout=5)
        with ctx.wrap_socket(raw, server_hostname=config.SERVER_IP) as tls:
            tls.sendall(msg.encode())
            return tls.recv(256).decode().strip()
    except Exception as exc:
        print(f"[TLS  ] {exc}")
        return None

def _register_node():
    if not os.path.exists(config.CLIENT_CERT):
        print("[TLS  ] No client cert – skipping registration.")
        return
    reply = _tls_send(f"REGISTER|{NODE_ID}")
    print(f"[TLS  ] Registration: {reply}")

def _flush_rtt_records():
    if not os.path.exists(config.CLIENT_CERT):
        return
    while True:
        time.sleep(15)
        with _rtt_lock:
            if not _rtt_buffer:
                continue
            records = list(_rtt_buffer)
            _rtt_buffer.clear()
        for seq, sent_ms, ack_ms, retries in records:
            _tls_send(f"RTT_RECORD|{NODE_ID}|{seq}|{sent_ms:.0f}|{ack_ms:.0f}|{retries}")
        print(f"[TLS  ] Flushed {len(records)} RTT records")


# ── Metric collectors ─────────────────────────────────────────────────────────

def collect_heartbeat():
    uptime = int(time.time() - START_TIME)
    send_event("HEARTBEAT", "uptime_s", uptime)


def collect_cpu():
    cpu = psutil.cpu_percent(interval=0.3)
    send_event("CPU_USAGE", "cpu_pct", round(cpu, 1))
    if cpu > config.CPU_THRESHOLD and _should_alert("CPU_THRESHOLD_EXCEEDED"):
        send_event("CPU_THRESHOLD_EXCEEDED", "cpu_pct", round(cpu, 1))


def collect_memory():
    mem = round(psutil.virtual_memory().percent, 1)
    send_event("MEMORY_USAGE", "mem_pct", mem)
    if mem > config.MEMORY_THRESHOLD and _should_alert("MEMORY_THRESHOLD_EXCEEDED"):
        send_event("MEMORY_THRESHOLD_EXCEEDED", "mem_pct", mem)


def collect_latency():
    """TCP probe to 8.8.8.8:53 – no root/ICMP needed, works on Windows."""
    try:
        t0 = time.perf_counter()
        s  = socket.create_connection(("8.8.8.8", 53), timeout=3)
        s.close()
        latency_ms = round((time.perf_counter() - t0) * 1000, 2)
    except OSError:
        latency_ms = None

    if latency_ms is None:
        if _should_alert("NETWORK_FAILURE"):
            send_event("NETWORK_FAILURE", "latency_ms", 0)
        return

    # Jitter = spread of last 10 readings
    _latency_history.append(latency_ms)
    if len(_latency_history) >= 2:
        jitter = round(max(_latency_history) - min(_latency_history), 2)
        send_event("NETWORK_JITTER", "jitter_ms", jitter)

    send_event("NETWORK_LATENCY", "latency_ms", latency_ms)

    if latency_ms > config.LATENCY_THRESHOLD * 1000 and _should_alert("LATENCY_HIGH"):
        send_event("LATENCY_HIGH", "latency_ms", latency_ms)


def collect_disk():
    try:
        path  = "C:\\" if os.name == "nt" else "/"
        usage = round(psutil.disk_usage(path).percent, 1)
    except Exception:
        return
    send_event("DISK_USAGE", "disk_pct", usage)
    if usage > 90 and _should_alert("DISK_USAGE_HIGH"):
        send_event("DISK_USAGE_HIGH", "disk_pct", usage)


def collect_bandwidth():
    global _last_net_io, _last_net_time
    now     = time.time()
    curr    = psutil.net_io_counters()
    elapsed = now - _last_net_time
    if elapsed <= 0:
        return
    total_bps = round(
        (curr.bytes_sent - _last_net_io.bytes_sent +
         curr.bytes_recv - _last_net_io.bytes_recv) / elapsed
    )
    _last_net_io   = curr
    _last_net_time = now
    send_event("BANDWIDTH_USAGE", "bps", total_bps)
    if total_bps > 10_000_000 and _should_alert("BANDWIDTH_SPIKE"):
        send_event("BANDWIDTH_SPIKE", "bps", total_bps)


def collect_tcp_connections():
    try:
        conns = len([c for c in psutil.net_connections(kind="tcp")
                     if c.status == "ESTABLISHED"])
        send_event("TCP_CONNECTIONS", "conn_count", conns)
    except (psutil.AccessDenied, NotImplementedError):
        pass


def collect_packet_loss():
    with _drop_lock:
        sent    = _sent_total
        dropped = _dropped_total
    if sent == 0:
        return
    loss_pct = round((dropped / sent) * 100, 2)
    send_event("PACKET_LOSS", "loss_pct", loss_pct)


# ── Main loop ─────────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print(f"  NMS Agent  –  {NODE_ID}")
    print(f"  Server  {config.SERVER_IP}  UDP:{config.UDP_PORT}  TLS:{config.TCP_PORT}")
    print("=" * 60)

    _register_node()
    threading.Thread(target=_flush_rtt_records, daemon=True).start()

    cycle = 0
    try:
        while True:
            cycle += 1
            print(f"\n-- Cycle {cycle} ---------------------------------------")
            collect_heartbeat()
            collect_cpu()
            collect_memory()
            collect_latency()
            collect_disk()
            collect_bandwidth()
            collect_tcp_connections()
            collect_packet_loss()
            time.sleep(config.HEARTBEAT_INTERVAL)
    except KeyboardInterrupt:
        print("\n[INFO ] Agent stopped.")
    finally:
        _udp.close()


if __name__ == "__main__":
    main()
