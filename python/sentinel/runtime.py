import contextvars
import json
import logging
from urllib.parse import urlparse
from uuid import uuid4

from .engine import NativeEngine
from .events import EventType, SecurityEvent
from .policy import load_policy

_request_id = contextvars.ContextVar("sentinel_request_id", default="")
_runtime = None
_original_request = None
log = logging.getLogger("sentinel.security")

class SentinelBlocked(RuntimeError):
    def __init__(self, policy, reason, destination):
        self.policy, self.reason, self.destination = policy, reason, destination
        super().__init__(f"Sentinel blocked outbound request: {reason}")

class SensitiveValue(str):
    """Explicit marker; string-compatible so supported HTTP clients can send it."""
    pass

def secret(value, resource="SECRET"):
    return SensitiveValue(str(value))

def _contains_secret(value):
    if isinstance(value, SensitiveValue): return True
    if isinstance(value, dict): return any(_contains_secret(v) for v in value.values())
    if isinstance(value, (tuple, list)): return any(_contains_secret(v) for v in value)
    return False

def _destination(url):
    host = (urlparse(url).hostname or "").lower()
    # Explicitly local hosts form the MVP trusted set for deterministic tests/demo.
    return "TRUSTED" if host in {"localhost", "127.0.0.1", "::1"} else "UNTRUSTED"

def _patched_request(session, method, url, **kwargs):
    sensitive = _contains_secret(kwargs.get("data")) or _contains_secret(kwargs.get("json"))
    event = SecurityEvent(EventType.NETWORK_SEND, request_id=_request_id.get(), destination=_destination(url),
                          data_classification="SECRET" if sensitive else "PUBLIC", operation_id=str(uuid4()))
    decision, reason = _runtime.engine.evaluate(event)
    if decision == "BLOCK":
        record = {"event": "SECURITY_VIOLATION", "policy": _runtime.policy.name,
                  "event_type": event.event_type.value, "data": event.data_classification,
                  "destination": event.destination, "decision": "BLOCKED", "reason": reason}
        log.warning(json.dumps(record, sort_keys=True))
        raise SentinelBlocked(_runtime.policy.name, reason, event.destination)
    return _original_request(session, method, url, **kwargs)

class _Runtime:
    def __init__(self, policy):
        self.policy = policy
        self.engine = NativeEngine(policy)

def protect(app, policy):
    """Install the supported pre-operation hook for requests.Session.request."""
    global _runtime, _original_request
    _runtime = _Runtime(load_policy(policy))
    import requests
    if _original_request is None:
        _original_request = requests.sessions.Session.request
        requests.sessions.Session.request = _patched_request

    @app.middleware("http")
    async def sentinel_request_context(request, call_next):
        token = _request_id.set(request.headers.get("x-request-id", str(uuid4())))
        try: return await call_next(request)
        finally: _request_id.reset(token)

    @app.exception_handler(SentinelBlocked)
    async def sentinel_blocked_handler(request, exc):
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=403, content={"error": "security_operation_blocked", "reason": exc.reason, "policy": exc.policy})
    return _runtime
