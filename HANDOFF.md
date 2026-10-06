# Sentinel RASP handoff

## Current working state

- Prototype supports FastAPI + `requests` interception and SQLite query interception.
- C++ core decisions: `SECRET_EXFILTRATION` and `SQL_INJECTION_ATTEMPT`.
- Protected app: `examples/vulnerable-fastapi`, run on port 8000.
- Baseline with no Sentinel import: `examples/non-vuln-fastapi`, run on port 8001.
- All data and demos are local/fake. The dashboard is served at `/`.

## Run

```powershell
uvicorn app:app --app-dir examples/vulnerable-fastapi --port 8000
uvicorn app:app --app-dir examples/non-vuln-fastapi --port 8001
```

Restart Uvicorn after native/runtime changes. The current bridge uses the
versioned native artifact `sentinel_core_v2.dll` so it does not conflict with
the old DLL a running Uvicorn process may hold open.

## Judge comparison

Protected SQL injection input:

```text
username: admin' -- 
password: anything
```

At port 8000 it returns 403 with `SQL_INJECTION_ATTEMPT`, records a `DB_QUERY`
event in `examples/vulnerable-fastapi/security-events.json`, and aborts before
SQLite execution. At port 8001 the same fake query signs in as the seeded fake
admin user.

The protected dashboard also demonstrates secret exfiltration blocking through
its Security audit section. It intercepts a marked secret outbound `requests`
call before network I/O.

## Tests

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

Latest result: `8 passed`.

## Important limitation

XSS remains intentionally demonstrable in both local apps. Sentinel currently
enforces only `NETWORK_SEND` secret-exfiltration and unsafe `sqlite3` `DB_QUERY`
patterns; it does not yet enforce HTML rendering/XSS policies.
