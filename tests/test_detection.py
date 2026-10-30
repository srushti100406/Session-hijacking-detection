"""
tests/test_detection.py — Tests for detection, prevention, and revocation.

Test IDs
--------
T12 — Session-ID-only replay is detected (suspicious=True, 401 returned).
T13 — Replay request is rejected (HTTP 401).
T14 — Suspicious session is revoked.
T15 — Original credentials cannot reuse revoked session.
T16 — Logs contain detection evidence without raw secrets.
T17 — Concurrent requests do not bypass revocation.
T18 — Resetting the demo does not disable security.
"""
import threading
import pytest


def _login_and_get_cookies(client):
    """Login and return (sid, sproof) tuple from response cookies."""
    resp = client.post("/api/login", json={"username": "alice", "password": "Demo@1234"})
    assert resp.status_code == 200
    # Extract from response cookie headers
    cookies = {}
    for header in resp.headers.getlist("Set-Cookie"):
        name, _, rest = header.partition("=")
        value, _, _ = rest.partition(";")
        cookies[name.strip()] = value.strip()
    return cookies.get("sid"), cookies.get("sproof")


# ---------------------------------------------------------------------------
# T12 — Replay detected
# ---------------------------------------------------------------------------

def test_T12_session_id_only_replay_detected(client):
    """
    Request with session ID but NO proof token must trigger suspicious detection.
    """
    sid, _ = _login_and_get_cookies(client)
    assert sid, "Login must set sid cookie"

    # New client context — send ONLY the session ID
    with client.application.test_client() as tc:
        tc.set_cookie("sid", sid)
        resp = tc.get("/api/protected-resource")
        assert resp.status_code == 401
        data = resp.get_json()
        assert data["success"] is False
        assert data.get("detection") == "SUSPICIOUS_REPLAY_DETECTED"


# ---------------------------------------------------------------------------
# T13 — Replay request rejected (HTTP 401)
# ---------------------------------------------------------------------------

def test_T13_replay_rejected_with_401(client):
    """The replay response must be HTTP 401."""
    sid, _ = _login_and_get_cookies(client)

    with client.application.test_client() as tc:
        tc.set_cookie("sid", sid)
        resp = tc.get("/api/protected-resource")
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# T14 — Session revoked after detection
# ---------------------------------------------------------------------------

def test_T14_session_revoked_after_detection(client, db_path):
    """After the replay triggers detection, the session must be revoked in the DB."""
    from app.session_manager import get_session_status

    sid, _ = _login_and_get_cookies(client)

    with client.application.test_client() as tc:
        tc.set_cookie("sid", sid)
        tc.get("/api/protected-resource")  # triggers detection + revocation

    status = get_session_status(db_path, sid)
    assert status is not None
    assert status["revoked"] is True
    assert "replay" in (status.get("revoke_reason") or "")


# ---------------------------------------------------------------------------
# T15 — Revoked session rejected even with both cookies
# ---------------------------------------------------------------------------

def test_T15_revoked_session_rejected(client):
    """After revocation, original full credentials must still be rejected."""
    sid, sproof = _login_and_get_cookies(client)

    # Trigger replay/revocation with a separate client context
    with client.application.test_client() as tc:
        tc.set_cookie("sid", sid)
        tc.get("/api/protected-resource")  # triggers revocation

    # Now try with both original cookies from another clean client
    with client.application.test_client() as tc2:
        tc2.set_cookie("sid", sid)
        tc2.set_cookie("sproof", sproof)
        resp = tc2.get("/api/protected-resource")
        assert resp.status_code == 401
        data = resp.get_json()
        assert data["success"] is False


# ---------------------------------------------------------------------------
# T16 — Security logs contain evidence without raw secrets
# ---------------------------------------------------------------------------

def test_T16_security_logs_safe(client):
    """
    Security event log must contain detection evidence.
    Raw session IDs, proof tokens, and passwords must NOT appear.
    """
    sid, sproof = _login_and_get_cookies(client)

    with client.application.test_client() as tc:
        tc.set_cookie("sid", sid)
        tc.get("/api/protected-resource")  # detection triggered

    resp = client.get("/api/security-events")
    assert resp.status_code == 200
    events = resp.get_json()["events"]

    # Must have at least one detection or revocation event
    event_types = [e["event_type"] for e in events]
    assert any(t in event_types for t in [
        "DETECTION_TRIGGERED", "SESSION_REVOKED", "REVOKED_SESSION_ACCESS"
    ]), f"Expected detection event in: {event_types}"

    # Raw session ID and proof token must NOT appear in any log field
    import json
    log_text = json.dumps(events)
    assert sid not in log_text, "Raw session ID must not appear in logs"
    assert sproof not in log_text, "Raw proof token must not appear in logs"
    assert "Demo@1234" not in log_text, "Password must not appear in logs"

    # Fingerprint must appear instead
    assert "fp:" in log_text


# ---------------------------------------------------------------------------
# T17 — Concurrent requests do not bypass revocation
# ---------------------------------------------------------------------------

def test_T17_concurrent_requests_revocation(client):
    """
    Concurrent replays must all return 401. Since the detection fires on
    any request missing the proof token, even a concurrent first hit is 401.
    """
    sid, _ = _login_and_get_cookies(client)

    results = []
    lock = threading.Lock()

    def replay():
        with client.application.test_client() as tc:
            tc.set_cookie("sid", sid)
            r = tc.get("/api/protected-resource")
            with lock:
                results.append(r.status_code)

    threads = [threading.Thread(target=replay) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # All must be 401 (the suspicious replay is always denied)
    assert all(code == 401 for code in results), (
        f"All concurrent replays must return 401. Got: {results}"
    )


# ---------------------------------------------------------------------------
# T18 — Demo reset does not disable security
# ---------------------------------------------------------------------------

def test_T18_reset_does_not_disable_security(client):
    """
    After resetting the demo, the protected endpoint must still require
    valid credentials.
    """
    login = client.post(
        "/demo/stage1-login",
        json={"username": "alice", "password": "Demo@1234"},
    )
    assert login.status_code == 200
    test_session_id = login.get_json()["test_session_id"]
    reset = client.post(
        "/demo/reset",
        json={"test_session_id": test_session_id},
    )
    assert reset.status_code == 200
    assert reset.get_json()["session_revoked"] is True

    resp = client.get("/api/protected-resource")
    assert resp.status_code == 401
    data = resp.get_json()
    assert data["success"] is False
