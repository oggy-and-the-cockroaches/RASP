"""Unprotected local baseline for comparing the Sentinel demo.

This app intentionally has no Sentinel dependency or runtime hook. It contains
only fake local data and the same login/search training exercises.
"""
from pathlib import Path
import sqlite3

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

app = FastAPI(title="Northstar Knowledge — unprotected baseline", version="0.1.0")
LAB_DATABASE = Path(__file__).with_name("vuln-lab.sqlite3")

def initialise_lab_database():
    with sqlite3.connect(LAB_DATABASE) as db:
        db.execute("CREATE TABLE IF NOT EXISTS documents (id INTEGER PRIMARY KEY, title TEXT, body TEXT)")
        db.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)")
        if not db.execute("SELECT 1 FROM documents LIMIT 1").fetchone():
            db.executemany("INSERT INTO documents(title, body) VALUES (?, ?)", [
                ("Public status", "All local demo systems nominal."),
                ("Engineering notes", "Local proof-of-concept checklist."),
                ("Internal demo record", "Fake record for local SQL injection exercise."),
            ])
        if not db.execute("SELECT 1 FROM users LIMIT 1").fetchone():
            db.executemany("INSERT INTO users(username, password, role) VALUES (?, ?, ?)", [
                ("alex", "welcome123", "analyst"),
                ("admin", "demo-admin-password", "administrator"),
            ])

initialise_lab_database()

@app.get("/api/login")
def local_demo_login(username: str = "", password: str = ""):
    """INTENTIONALLY VULNERABLE local training endpoint: SQL concatenation."""
    sql = f"SELECT username, role FROM users WHERE username = '{username}' AND password = '{password}'"
    try:
        with sqlite3.connect(LAB_DATABASE) as db:
            user = db.execute(sql).fetchone()
        if user:
            return {"authenticated": True, "user": user[0], "role": user[1], "demo_only": True}
        return {"authenticated": False, "message": "Invalid username or password.", "demo_only": True}
    except sqlite3.DatabaseError as exc:
        return {"authenticated": False, "message": "Invalid username or password.", "sql_error": str(exc), "demo_only": True}

@app.get("/search", response_class=HTMLResponse)
def normal_search_results(query: str = ""):
    """INTENTIONALLY VULNERABLE local training endpoint: raw reflected HTML."""
    with sqlite3.connect(LAB_DATABASE) as db:
        rows = db.execute("SELECT title, body FROM documents WHERE title LIKE ?", (f"%{query}%",)).fetchall()
    results = "".join(f"<article><b>{title}</b><p>{body}</p></article>" for title, body in rows) or "<p>No documents found.</p>"
    return f"""<!doctype html><html><head><style>body{{font:14px system-ui;padding:13px;color:#172234}}article{{border-bottom:1px solid #d8dee8;padding:8px 0}}p{{margin:4px 0;color:#516176}}</style></head>
    <body><div>Search results for: <strong>{query}</strong></div>{results}</body></html>"""

@app.get("/", response_class=HTMLResponse)
def portal():
    return Path(__file__).with_name("dashboard.html").read_text(encoding="utf-8")
