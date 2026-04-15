"""
app.py  –  Network Monitoring System – Web Dashboard
All metrics are read from the shared SQLite database so this process
works correctly independently of the server process.
"""

import os
import sys
import time

from flask import Flask, jsonify, render_template, request

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "server")))
import database
from config import WEB_PORT, NODE_TIMEOUT

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/events")
def api_events():
    node_filter  = request.args.get("node",  "")
    event_filter = request.args.get("event", "")
    limit        = min(int(request.args.get("limit", 100)), 500)
    return jsonify(database.get_events(limit, node_filter, event_filter))


@app.route("/api/nodes")
def api_nodes():
    """Derive active nodes directly from the events DB."""
    cutoff = int(time.time()) - NODE_TIMEOUT
    rows = database.get_db().execute("""
        SELECT node,
               MAX(timestamp)  AS last_seen,
               MAX(event)      AS last_event
        FROM   events
        WHERE  timestamp >= ?
        GROUP  BY node
        ORDER  BY last_seen DESC
    """, (cutoff,)).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/perf")
def api_perf():
    """Compute live perf metrics entirely from the DB."""
    now    = int(time.time())
    since5 = now - 5
    since60 = now - 60

    # Events per second (last 5 s)
    eps_row = database.get_db().execute(
        "SELECT COUNT(*) FROM events WHERE timestamp >= ?", (since5,)
    ).fetchone()
    eps = round((eps_row[0] or 0) / 5, 2)

    # Active nodes (seen in last NODE_TIMEOUT seconds)
    nodes_row = database.get_db().execute(
        "SELECT COUNT(DISTINCT node) FROM events WHERE timestamp >= ?",
        (now - NODE_TIMEOUT,)
    ).fetchone()
    active_nodes = nodes_row[0] or 0

    # Total events
    total_row = database.get_db().execute("SELECT COUNT(*) FROM events").fetchone()
    total = total_row[0] or 0

    # RTT stats from ack_log (last 60 s)
    rtt = database.get_rtt_stats(since_ts=time.time() - 60)

    # Packet loss from latest PACKET_LOSS events per node
    loss_rows = database.get_db().execute("""
        SELECT AVG(CAST(value AS REAL))
        FROM   events
        WHERE  event = 'PACKET_LOSS'
        AND    timestamp >= ?
    """, (since60,)).fetchone()
    loss_pct = round(loss_rows[0] or 0, 2)

    return jsonify({
        "active_nodes":    active_nodes,
        "events_per_sec":  eps,
        "avg_rtt_ms":      rtt["avg"],
        "p99_rtt_ms":      rtt["p99"],
        "packet_loss_pct": loss_pct,
        "total_events":    total,
    })


@app.route("/api/perf/history")
def api_perf_history():
    rows = database.get_perf_history(limit=60)
    rows.reverse()
    return jsonify(rows)


@app.route("/api/rtt")
def api_rtt():
    since = float(request.args.get("since", time.time() - 300))
    return jsonify(database.get_rtt_stats(since_ts=since))


if __name__ == "__main__":
    print(f"[WEB  ] Dashboard starting on http://0.0.0.0:{WEB_PORT}")
    app.run(host="0.0.0.0", port=WEB_PORT, debug=False, threaded=True)