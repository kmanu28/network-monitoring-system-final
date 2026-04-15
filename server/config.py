"""
config.py  –  Central configuration for the Network Monitoring System.
"""

import os

# ── Network ───────────────────────────────────────────────────────────────────
HOST     = "0.0.0.0"
UDP_PORT = 9000
TCP_PORT = 9001
WEB_PORT = 5000

# ── Fernet key ────────────────────────────────────────────────────────────────
# Loaded from env var NMS_FERNET_KEY, or certs/fernet.key file.
# If neither exists, a key is auto-generated and saved to certs/fernet.key on first run.
_KEY_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                         "certs", "fernet.key")
if os.environ.get("NMS_FERNET_KEY"):
    FERNET_KEY = os.environ["NMS_FERNET_KEY"].encode()
elif os.path.exists(_KEY_FILE):
    with open(_KEY_FILE, "rb") as _f:
        FERNET_KEY = _f.read().strip()
else:
    from cryptography.fernet import Fernet as _F
    FERNET_KEY = _F.generate_key()
    os.makedirs(os.path.dirname(_KEY_FILE), exist_ok=True)
    with open(_KEY_FILE, "wb") as _f:
        _f.write(FERNET_KEY)
    print(f"[CONFIG] New Fernet key saved to {_KEY_FILE}")

# ── TLS certificates ──────────────────────────────────────────────────────────
BASE_DIR    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CERT_DIR    = os.path.join(BASE_DIR, "certs")
SERVER_CERT = os.path.join(CERT_DIR, "server.crt")
SERVER_KEY  = os.path.join(CERT_DIR, "server.key")
CA_CERT     = os.path.join(CERT_DIR, "ca.crt")
CLIENT_CERT = os.path.join(CERT_DIR, "client.crt")
CLIENT_KEY  = os.path.join(CERT_DIR, "client.key")

# ── ACK / reliability ─────────────────────────────────────────────────────────
ACK_TIMEOUT = 2.0
MAX_RETRIES = 3
ACK_PREFIX  = "ACK"

# ── Heartbeat / watchdog ─────────────────────────────────────────────────────
HEARTBEAT_INTERVAL = 5
NODE_TIMEOUT       = 30

# ── Alert thresholds ─────────────────────────────────────────────────────────
CPU_THRESHOLD     = 75.0    # %
MEMORY_THRESHOLD  = 80.0    # %
LATENCY_THRESHOLD = 0.100   # seconds (100 ms)  – note: client uses ms directly
COOLDOWN_SECONDS  = 15

# ── Event severity map ────────────────────────────────────────────────────────
EVENT_TYPES = {
    # Always-reported metrics
    "HEARTBEAT":                 "INFO",
    "CPU_USAGE":                 "INFO",
    "MEMORY_USAGE":              "INFO",
    "NETWORK_LATENCY":           "INFO",
    "NETWORK_JITTER":            "INFO",
    "DISK_USAGE":                "INFO",
    "BANDWIDTH_USAGE":           "INFO",
    "TCP_CONNECTIONS":           "INFO",
    "PACKET_LOSS":               "INFO",
    # Alert events
    "NODE_REGISTERED":           "INFO",
    "NODE_DOWN":                 "CRITICAL",
    "CPU_THRESHOLD_EXCEEDED":    "WARNING",
    "MEMORY_THRESHOLD_EXCEEDED": "WARNING",
    "LATENCY_HIGH":              "WARNING",
    "NETWORK_FAILURE":           "CRITICAL",
    "DISK_USAGE_HIGH":           "WARNING",
    "BANDWIDTH_SPIKE":           "WARNING",
    "PACKET_LOSS_DETECTED":      "WARNING",
}

# ── Database ──────────────────────────────────────────────────────────────────
DB_NAME = "events.db"
