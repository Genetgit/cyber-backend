from fastapi import FastAPI, Header, HTTPException, status
from pydantic import BaseModel
import sqlite3
import os

app = FastAPI(title="Adaptive Cyber Attack Simulation Backend")

API_KEY = os.getenv("API_KEY", "secret123")
DB_NAME = "cyber_security.db"

# 1. Database ማዘጋጀት (Table መፍጠር)
def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    # Events የሚቀመጡበት Table
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
    conn.commit()
    conn.close()

# Application ሲነሳ ዳታቤዙ እንዲዘጋጅ ጥሪ ማድረግ
init_db()

# 2. Authentication መፈተሻ
def verify_api_key(x_api_key: str = Header(None)):
    if x_api_key != API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "Invalid or missing X-API-Key header"}
        )

@app.get("/")
def home():
    return {"message": "Backend API is running with SQLite Database!"}

# 3. Events ማስቀመጫ Endpoint
@app.post("/api/events")
def create_events(data: dict, x_api_key: str = Header(None)):
    verify_api_key(x_api_key)
    events = data.get("events", [])
    
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    accepted_count = 0
    for ev in events:
        cursor.execute('''
            INSERT OR IGNORE INTO events 
            (event_id, timestamp, host_id, source, event_type, src_ip, username, raw)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            ev.get("event_id"),
            ev.get("timestamp"),
            ev.get("host_id"),
            ev.get("source"),
            ev.get("event_type"),
            ev.get("src_ip"),
            ev.get("username"),
            ev.get("raw")
        ))
        accepted_count += 1
        
    conn.commit()
    conn.close()
    
    return {"accepted": accepted_count}

# 4. Events ማሳያ Endpoint
@app.get("/api/events")
def get_events(limit: int = 50, x_api_key: str = Header(None)):
    verify_api_key(x_api_key)
    
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM events ORDER BY timestamp DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    
    result = [dict(row) for row in rows]
    conn.close()
    
    return result
