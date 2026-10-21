# Session Hijacking Detection & Prevention System

> **Cryptography and Security — College Microproject**  
> Educational prototype demonstrating a controlled session-hijacking scenario and a working defense mechanism.

---

## Overview

Web applications use session identifiers to recognize authenticated users across HTTP requests. If an attacker obtains a valid session token, they may impersonate the legitimate user without knowing the password — a **session hijacking** (replay) attack.

This project:

1. Creates a legitimate authenticated session for a demo user.
2. Runs a controlled simulation where an attacker replays only the session identifier (without the required proof credential).
3. Detects the suspicious request using server-side validation logic.
4. Rejects the request, revokes the session, and records security events.
5. Verifies that subsequent access using the revoked session is also rejected.

---

## Features

| Feature | Description |
|---------|-------------|
| Argon2id password hashing | OWASP-recommended, with proper parameters |
| 256-bit random session IDs | `secrets.token_hex(32)` — cryptographically secure |
| HMAC-SHA256 proof tokens | Second credential bound to session ID + user ID + timestamp |
| Server-side session store | SQLite with WAL mode — revocation is atomic |
| Dual-token validation | Session ID alone is insufficient for access |
| Replay detection | Missing proof token → suspicious → reject + revoke |
| Thread-safe revocation | `WHERE revoked=0` guard prevents concurrent bypass |
| Security event log | Events stored with fingerprints, no raw secrets |
| Controlled simulator | Real HTTP requests, localhost only, no external targets |
| Polished lab UI | Dark cybersecurity theme, 4-stage guided demo |
| 22 automated tests | Auth, session, detection, simulator, concurrency |

---

## Technology Stack

- **Backend:** Python 3.13 + Flask 3.0
- **Password hashing:** argon2-cffi (Argon2id)
- **Database:** SQLite (WAL journal mode)
- **HTTP client (simulator):** requests
- **Testing:** pytest 8.3.2 + pytest-flask
- **Frontend:** Vanilla HTML + CSS + JavaScript (no frameworks)

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Browser / Test Client                        │
└────────────┬────────────────────────────────┬───────────────────┘
             │ /api/*                         │ /demo/*
             ▼                                ▼
┌────────────────────┐            ┌────────────────────────┐
│    API Routes      │            │    Demo Routes          │
│  (auth, session,   │            │  (stage1–4 orchestrate) │
│   protected res,   │            │                         │
│   security log)    │            │  Replay Simulator ──────┼──► /api/protected-resource
└────┬────────┬──────┘            └────────────────────────┘
     │        │
     ▼        ▼
┌─────────┐ ┌─────────────────┐   ┌──────────────────┐
│  Auth   │ │ Session Manager │   │ Detection Engine  │
│ Module  │ │ create/validate │──►│ evaluate_request  │
│ Argon2id│ │ revoke/expire   │   │ fire on missing   │
└────┬────┘ └────────┬────────┘   │ proof token       │
     │               │            └──────────┬─────────┘
     ▼               ▼                       │
┌────────────────────────────────────────────▼──────────────────┐
│                      SQLite Database                            │
│  users  │  sessions (sid, proof_token, revoked)  │  sec_events │
└────────────────────────────────────────────────────────────────┘
                                     │
                                     ▼
                           ┌──────────────────┐
                           │  Security Logger  │
                           │  (sanitized, no   │
                           │   raw secrets)    │
                           └──────────────────┘
```

### Request Validation Flow

```
Request arrives with cookies
         │
         ▼
  session_id present? ──No──► 401 (no session)
         │Yes
         ▼
  Session found in DB? ──No──► 401 (unknown session)
         │Yes
         ▼
  Session revoked? ──Yes──► 401 + log REVOKED_SESSION_ACCESS
         │No
         ▼
  Session expired? ──Yes──► 401 (expired)
         │No
         ▼
  Recompute HMAC proof
  Compare with stored proof (constant-time)
         │
    Match? ──No──► DETECTION TRIGGERED
         │          → log DETECTION_TRIGGERED
         │          → revoke session
         │          → return 401
         │Yes
         ▼
    200 ACCESS GRANTED
```

---

## Prerequisites

- Python 3.11 or later
- pip

All required packages are standard PyPI packages:

```
Flask==3.0.3
argon2-cffi==23.1.0
requests==2.32.3
pytest==8.3.2
pytest-flask==1.3.0
Werkzeug==3.0.4
```

---

## Installation

```bash
# Clone or unzip the project
cd session-hijack-detection

# Install dependencies
pip install -r requirements.txt
```

---

## Running the Application

```bash
python run.py
```

Output:
```
============================================================
  Session Hijacking Detection & Prevention System
  Running at: http://127.0.0.1:5000
  Demo user:  alice / Demo@1234
============================================================
```

Open **http://127.0.0.1:5000** in your browser.

When the host provides a `PORT` environment variable (for example, Render), the internal replay simulator uses that port; local runs default to port 5000.

The repository's `gunicorn.conf.py` enables threaded workers. This is required for the demo's internal HTTP replay request: a single synchronous worker would block Stage 2 while waiting for the replay request that it must itself serve.

---

## Running Tests

```bash
python -m pytest tests/ -v
```

Expected output:
```
23 passed
```

Test coverage:
- T01–T04: Authentication (valid/invalid/empty credentials)
- T05–T11: Session management (uniqueness, regeneration, fixation, expiry, admin bypass)
- T12–T18: Detection, prevention, revocation, concurrency, log safety, reset
- T19–T20: Simulator safety (external URL rejection)
- Demo integration: replay detection, session revocation, final outcome logging, and Stage 4 rejection

---

## Demonstration Instructions (3–5 minutes)

### Part 1 — Introduce the threat
Explain: an attacker who obtains a session cookie can impersonate a logged-in user.

### Part 2 — Show normal behavior
1. Open http://127.0.0.1:5000/demo
2. Click **"Create Legitimate Session"**
3. Observe: session created, two cookies set (`sid` + `sproof`)
4. Click **"Access Protected Resource"** → HTTP 200, document returned

### Part 3 — Trigger the attack
5. Click **"Execute Replay Attack"**
6. Observe: the attacker sends ONLY the `sid` cookie — no proof token
7. Server returns **HTTP 401**

### Part 4 — Show the defense
8. Observe the detection pipeline animate:
   - Replay received → Validated → Suspicious detected → Rejected → Revoked → Logged
9. Check the **Security Event Timeline** — `DETECTION_TRIGGERED` and `SESSION_REVOKED` events appear

### Part 5 — Verify prevention
10. Click **"Verify Post-Revocation Rejection"**
11. Original session credentials (both cookies) are sent — server returns **HTTP 401**
12. Final result: **PASS**

### Part 6 — Reset
13. Click **"Reset & Run Again"** for a repeatable demo

---

## Expected HTTP Responses

| Request | Expected Status |
|---------|----------------|
| Login with valid credentials | 200 |
| Login with wrong password | 401 |
| Access protected resource (authenticated) | 200 |
| Replay with session ID only (no proof) | 401 |
| Access with revoked session | 401 |
| Logout | 200 |

---

## Security Design

### What is detected
Requests that present a valid session ID but an absent or incorrect proof token.

This simulates an attacker who obtained only the session identifier (e.g., from a non-TLS log, predictable token, or partial credential theft).

### What is NOT detected
- An attacker who steals **both** the `sid` and `sproof` cookies can still impersonate the user.
- This system does not use IP address or User-Agent as detection signals — they change during legitimate browsing.
- This is an educational prototype, not a production security system.

### Proof token design
```
proof_token = HMAC-SHA256(SESSION_PROOF_KEY, session_id + ":" + user_id + ":" + created_at)
```

The proof is not simply the session ID — it binds the session to the user identity and creation time. Without the server's `SESSION_PROOF_KEY`, it cannot be forged.

### Revocation
Sessions are revoked using an atomic SQL `UPDATE WHERE revoked=0`. Concurrent replay attempts cannot race past this guard — all return 401.

---

## File Structure

```
session-hijack-detection/
├── app/
│   ├── __init__.py          # Flask app factory
│   ├── auth.py              # Argon2id-based authentication
│   ├── session_manager.py   # Session create/validate/revoke/expire
│   ├── detection.py         # Detection engine
│   ├── simulator.py         # Controlled replay simulator (localhost only)
│   ├── logger.py            # Sanitized security event logger
│   ├── models.py            # SQLite schema + password hashing
│   ├── routes/
│   │   ├── api.py           # Login, logout, protected resource, events
│   │   ├── demo.py          # Stage 1–4 demo orchestration
│   │   └── main.py          # Landing and demo pages
│   └── templates/
│       ├── base.html
│       ├── index.html
│       └── demo.html
├── static/
│   ├── css/style.css        # Cybersecurity lab dark theme
│   └── js/demo.js           # 4-stage demo controller
├── tests/
│   ├── conftest.py
│   ├── test_auth.py
│   ├── test_detection.py
│   ├── test_session.py
│   └── test_simulator.py
├── config.py
├── run.py
└── requirements.txt
```

---

## Limitations and Ethical Use

1. **Local only.** The simulator sends HTTP requests only to `127.0.0.1`. No external websites or users are targeted.
2. **Partial scenario.** Detecting a missing proof token is one specific scenario. A sophisticated attacker with both cookies is not detected by this mechanism alone.
3. **Not production-ready.** Flask's development server, HTTP (not HTTPS), and single-file SQLite are appropriate for demonstration only.
4. **Do not modify** the simulator to target external hosts.
5. **Do not deploy** this application publicly.

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| Port 5000 already in use | `python run.py --port 5001` |
| `ModuleNotFoundError` | `pip install -r requirements.txt` |
| Tests fail with `OperationalError` | Ensure you are using the latest code; `init_db` creates the schema |
| Demo shows FAIL | Run stages in order (1 → 2 → 3 → 4); click Reset before re-running |
| Server not responding in Stage 2 | The simulator connects to 127.0.0.1:5000; ensure the server port matches |
