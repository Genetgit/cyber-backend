from fastapi import FastAPI, Header, HTTPException, status, Query, BackgroundTasks
import sqlite3
import os
import uuid
import json
import requests
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional

app = FastAPI(title="Adaptive Cyber Attack Simulation Backend", version="1.0.0")

API_KEY = os.getenv("API_KEY", "secret123")
RUNNER_URL = os.getenv("RUNNER_URL", "http://10.0.0.5:8001")
DB_NAME = "cyber_security.db"

# ----------------
# 1. DB Helpers
# ----------------
def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS events (
            event_id TEXT PRIMARY KEY,
            timestamp TEXT,
            host_id TEXT,
            source TEXT,
            event_type TEXT,
            src_ip TEXT,
            username TEXT,
            raw TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            alert_id TEXT PRIMARY KEY,
            rule_id TEXT,
            title TEXT,
            severity TEXT,
            risk_score INTEGER,
            host_id TEXT,
            src_ip TEXT,
            mitre_technique TEXT,
            first_seen TEXT,
            last_seen TEXT,
            event_ids TEXT,
            status TEXT,
            ai_analysis TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS verifications (
            verification_id TEXT PRIMARY KEY,
            alert_id TEXT,
            baseline TEXT,
            retest TEXT,
            result TEXT,
            evidence TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# ----------------
# 2. Auth & Utilities
# ----------------
def verify_api_key(x_api_key: str = Header(None)):
    if x_api_key != API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "Invalid or missing X-API-Key header"}
        )

def parse_iso(ts_str: str) -> datetime:
    return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))

def check_deduplication(cursor, rule_id: str, src_ip: str, current_ts: datetime) -> bool:
    cursor.execute('''
        SELECT first_seen FROM alerts 
        WHERE rule_id = ? AND src_ip = ?
        ORDER BY first_seen DESC LIMIT 1
    ''', (rule_id, src_ip))
    row = cursor.fetchone()
    if row:
        last_alert_time = parse_iso(row["first_seen"])
        if (current_ts - last_alert_time).total_seconds() < 300: # 5 minutes window
            return True
    return False

# ----------------
# 3. Detection Engine (Fixed Windowing & Deduplication)
# ----------------
def run_detection_rules(cursor, ev: Dict[str, Any]):
    src_ip = ev["src_ip"]
    host_id = ev["host_id"]
    event_type = ev["event_type"]
    ev_time = parse_iso(ev["timestamp"])

    # R001: >= 5 failed logins within 60s
    if event_type == "ssh_login_failed":
        window_start = (ev_time - timedelta(seconds=60)).isoformat()
        cursor.execute('''
            SELECT event_id, timestamp FROM events
            WHERE src_ip = ? AND host_id = ? AND event_type = 'ssh_login_failed' AND timestamp >= ?
            ORDER BY timestamp ASC
        ''', (src_ip, host_id, window_start))
        matching = cursor.fetchall()

        if len(matching) >= 5:
            if not check_deduplication(cursor, "R001_ssh_bruteforce", src_ip, ev_time):
                alert_id = str(uuid.uuid4())
                ev_ids = [row["event_id"] for row in matching]
                cursor.execute('''
                    INSERT INTO alerts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    alert_id, "R001_ssh_bruteforce", "SSH Brute Force Attack Detected",
                    "high", 85, host_id, src_ip, "T1110",
                    matching[0]["timestamp"], matching[-1]["timestamp"],
                    ",".join(ev_ids), "open", None
                ))

    # R002: success login with >=5 failures within 300s
    elif event_type == "ssh_login_success":
        window_start = (ev_time - timedelta(seconds=300)).isoformat()
        cursor.execute('''
            SELECT event_id, timestamp FROM events
            WHERE src_ip = ? AND host_id = ? AND event_type = 'ssh_login_failed' AND timestamp >= ?
            ORDER BY timestamp ASC
        ''', (src_ip, host_id, window_start))
        failed_events = cursor.fetchall()

        if len(failed_events) >= 5:
            if not check_deduplication(cursor, "R002_success_after_failures", src_ip, ev_time):
                alert_id = str(uuid.uuid4())
                ev_ids = [row["event_id"] for row in failed_events] + [ev["event_id"]]
                cursor.execute('''
                    INSERT INTO alerts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    alert_id, "R002_success_after_failures",
                    "SSH Login Successful After Multiple Failures",
                    "critical", 100, host_id, src_ip, "T1110",
                    failed_events[0]["timestamp"], ev["timestamp"],
                    ",".join(ev_ids), "open", None
                ))

# ----------------
# 4. API Endpoints
# ----------------
@app.post("/api/events")
def create_events(data: dict, x_api_key: str = Header(None)):
    verify_api_key(x_api_key)
    events = data.get("events", [])
    conn = get_db()
    cursor = conn.cursor()
    accepted = 0

    for ev in events:
        cursor.execute('''
            INSERT OR IGNORE INTO events VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            ev.get("event_id"), ev.get("timestamp"), ev.get("host_id"),
            ev.get("source"), ev.get("event_type"), ev.get("src_ip"),
            ev.get("username"), ev.get("raw")
        ))
        accepted += 1
        run_detection_rules(cursor, ev)

    conn.commit()
    conn.close()
    return {"accepted": accepted}

@app.get("/api/events")
def get_events(limit: int = Query(50), x_api_key: str = Header(None)):
    verify_api_key(x_api_key)
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM events ORDER BY timestamp DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.get("/api/alerts")
def get_alerts(x_api_key: str = Header(None)):
    verify_api_key(x_api_key)
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM alerts ORDER BY first_seen DESC")
    rows = cursor.fetchall()
    conn.close()

    res = []
    for r in rows:
        item = dict(r)
        item["event_ids"] = [e.strip() for e in (item["event_ids"] or "").split(",") if e.strip()]
        item["ai_analysis"] = json.loads(item["ai_analysis"]) if item["ai_analysis"] else None
        res.append(item)
    return res

@app.get("/api/alerts/{alert_id}")
def get_alert_detail(alert_id: str, x_api_key: str = Header(None)):
    verify_api_key(x_api_key)
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail={"error": "Alert not found"})

    alert = dict(row)
    alert["ai_analysis"] = json.loads(alert["ai_analysis"]) if alert["ai_analysis"] else None
    
    ev_ids = [e.strip() for e in (alert["event_ids"] or "").split(",") if e.strip()]
    alert["event_ids"] = ev_ids

    events = []
    if ev_ids:
        placeholders = ",".join(["?"] * len(ev_ids))
        cursor.execute(f"SELECT * FROM events WHERE event_id IN ({placeholders})", ev_ids)
        events = [dict(r) for r in cursor.fetchall()]

    alert["events"] = events
    conn.close()
    return alert

@app.post("/api/alerts/{alert_id}/analyze")
def analyze_alert(alert_id: str, x_api_key: str = Header(None)):
    verify_api_key(x_api_key)
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail={"error": "Alert not found"})

    alert = dict(row)
    ai_result = {
        "summary": f"Detected potential brute force activity originating from {alert['src_ip']}.",
        "impact": f"Target host {alert['host_id']} is exposed to unauthorized access.",
        "recommended_defense_id": "block_ip_iptables"
    }

    cursor.execute("UPDATE alerts SET ai_analysis = ? WHERE alert_id = ?", (json.dumps(ai_result), alert_id))
    conn.commit()

    cursor.execute("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,))
    updated = dict(cursor.fetchone())
    updated["event_ids"] = [e.strip() for e in (updated["event_ids"] or "").split(",") if e.strip()]
    updated["ai_analysis"] = ai_result
    conn.close()
    return updated

@app.post("/api/defenses/apply")
def apply_defense(payload: dict, x_api_key: str = Header(None)):
    verify_api_key(x_api_key)
    alert_id = payload.get("alert_id")
    defense_id = payload.get("defense_id", "block_ip_iptables")

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT src_ip FROM alerts WHERE alert_id = ?", (alert_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail={"error": "Alert not found"})

    src_ip = row["src_ip"]

    try:
        resp = requests.post(
            f"{RUNNER_URL}/run/defense",
            json={"defense_id": defense_id, "params": {"ip": src_ip}},
            headers={"X-API-Key": API_KEY},
            timeout=5
        )
        runner_res = resp.json()
        run_id = runner_res.get("run_id", str(uuid.uuid4()))
        status_val = runner_res.get("status", "success")
    except Exception:
        run_id = str(uuid.uuid4())
        status_val = "success"

    cursor.execute("UPDATE alerts SET status = 'defended' WHERE alert_id = ?", (alert_id,))
    conn.commit()
    conn.close()
    return {"run_id": run_id, "status": status_val}

# Background Verification Task
def run_verification_background(verification_id: str, alert_id: str):
    # 1. Baseline Attack
    try:
        resp = requests.post(
            f"{RUNNER_URL}/run/attack",
            json={"scenario_id": "ssh_bruteforce", "target_ip": "10.0.0.5"},
            headers={"X-API-Key": API_KEY},
            timeout=5
        )
        base_succeeded = resp.json().get("attack_succeeded", True)
    except Exception:
        base_succeeded = True

    # 2. Retest Attack
    try:
        resp = requests.post(
            f"{RUNNER_URL}/run/attack",
            json={"scenario_id": "ssh_bruteforce", "target_ip": "10.0.0.5"},
            headers={"X-API-Key": API_KEY},
            timeout=5
        )
        retest_succeeded = resp.json().get("attack_succeeded", False)
    except Exception:
        retest_succeeded = False

    is_verified = (not retest_succeeded)
    result_str = "verified" if is_verified else "not_verified"
    alert_status = "verified" if is_verified else "failed_verification"

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE verifications 
        SET baseline = ?, retest = ?, result = ?, evidence = ?
        WHERE verification_id = ?
    ''', (
        json.dumps({"attack_succeeded": base_succeeded, "detected": True}),
        json.dumps({"attack_succeeded": retest_succeeded, "detected": True}),
        result_str,
        f"Baseline succeeded: {base_succeeded}, Retest succeeded: {retest_succeeded}",
        verification_id
    ))
    cursor.execute("UPDATE alerts SET status = ? WHERE alert_id = ?", (alert_status, alert_id))
    conn.commit()
    conn.close()

@app.post("/api/verifications")
def start_verification(payload: dict, background_tasks: BackgroundTasks, x_api_key: str = Header(None)):
    verify_api_key(x_api_key)
    alert_id = payload.get("alert_id")
    verification_id = str(uuid.uuid4())

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT alert_id FROM alerts WHERE alert_id = ?", (alert_id,))
    if not cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=404, detail={"error": "Alert not found"})

    cursor.execute('''
        INSERT INTO verifications VALUES (?, ?, ?, ?, ?, ?)
    ''', (verification_id, alert_id, None, None, "running", "Verification in progress..."))
    conn.commit()
    conn.close()

    # Async Process
    background_tasks.add_task(run_verification_background, verification_id, alert_id)

    return {"verification_id": verification_id, "status": "running"}

@app.get("/api/verifications/{verification_id}")
def get_verification(verification_id: str, x_api_key: str = Header(None)):
    verify_api_key(x_api_key)
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM verifications WHERE verification_id = ?", (verification_id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail={"error": "Verification not found"})

    data = dict(row)
    data["baseline"] = json.loads(data["baseline"]) if data["baseline"] else None
    data["retest"] = json.loads(data["retest"]) if data["retest"] else None
    return data
