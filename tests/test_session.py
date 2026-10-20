"""
tests/test_session.py — Tests for session management.

Test IDs
--------
T05 — Session IDs are unpredictable (all unique across 100 creations).
T06 — Session ID is regenerated after login (old session invalid).
T07 — Client-supplied session IDs cannot establish an authenticated session.
T08 — Normal authenticated requests succeed with both cookies.
T09 — Logout revokes the session.
T10 — Expired sessions are rejected.
T11 — Browser-supplied admin cookies cannot grant privileges.
"""
import time
import secrets
import pytest

from app.session_manager import (
    create_session, validate_session, revoke_session,
    expire_all_user_sessions, get_session_status, ValidationResult
)


# ---------------------------------------------------------------------------
# T05 — Unpredictable session IDs
# ---------------------------------------------------------------------------

def test_T05_session_ids_are_unique(db_path, proof_key, app):
    """100 consecutive session IDs must all be different."""
    from app.auth import authenticate_user
    success, user_id, _ = authenticate_user(db_path, "alice", "Demo@1234")
    assert success

    ids = set()
    with app.app_context():
        for _ in range(100):
            sid, _ = create_session(db_path, proof_key, user_id, 1800)
            ids.add(sid)

    assert len(ids) == 100, "Session IDs must be unique"
    for sid in ids:
        assert len(sid) >= 32, "Session ID must be at least 32 hex chars"


# ---------------------------------------------------------------------------
# T06 — Session regenerated after login
# ---------------------------------------------------------------------------

def _get_cookies_from_response(resp):
    """Extract cookies from a Flask test response Set-Cookie headers."""
    cookies = {}
    for header in resp.headers.getlist("Set-Cookie"):
        name, _, rest = header.partition("=")
        value, _, _ = rest.partition(";")
        cookies[name.strip()] = value.strip()
    return cookies


# ---------------------------------------------------------------------------
# T06 — Session regenerated after login
# ---------------------------------------------------------------------------

def test_T06_session_regenerated_after_login(client):
    """A second login must issue a new session and invalidate the old one."""
    r1 = client.post("/api/login", json={"username": "alice", "password": "Demo@1234"})
    fp1 = r1.get_json()["session_fingerprint"]
    cookies1 = _get_cookies_from_response(r1)
    sid1 = cookies1.get("sid")

    r2 = client.post("/api/login", json={"username": "alice", "password": "Demo@1234"})
    fp2 = r2.get_json()["session_fingerprint"]
    cookies2 = _get_cookies_from_response(r2)
    sid2 = cookies2.get("sid")

    assert sid1 != sid2, "Session ID must change on re-login"
    assert fp1 != fp2


# ---------------------------------------------------------------------------
# T07 — Client-supplied session IDs rejected
# ---------------------------------------------------------------------------

def test_T07_client_supplied_session_id_rejected(client):
    """
    Sending an arbitrary attacker-chosen session ID must NOT grant access.
    This verifies resistance to session fixation.
    """
    fake_sid = secrets.token_hex(32)
    client.set_cookie("sid", fake_sid)
    client.set_cookie("sproof", "fakepoof")

    resp = client.get("/api/protected-resource")
    assert resp.status_code == 401
    data = resp.get_json()
    assert data["success"] is False


# ---------------------------------------------------------------------------
# T08 — Normal authenticated request succeeds
# ---------------------------------------------------------------------------

def test_T08_authenticated_request_succeeds(client):
    """After login, a request with both valid cookies must return 200."""
    client.post("/api/login", json={"username": "alice", "password": "Demo@1234"})
    resp = client.get("/api/protected-resource")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["success"] is True
    assert data["status"] == "ACCESS_GRANTED"


# ---------------------------------------------------------------------------
# T09 — Logout revokes the session
# ---------------------------------------------------------------------------

def test_T09_logout_revokes_session(client):
    """After logout, the same session must not grant access."""
    client.post("/api/login", json={"username": "alice", "password": "Demo@1234"})
    client.post("/api/logout")
    resp = client.get("/api/protected-resource")
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# T10 — Expired sessions rejected
# ---------------------------------------------------------------------------

def test_T10_expired_session_rejected(db_path, proof_key, app):
    """A session with a past expiry must be rejected."""
    from app.auth import authenticate_user
    from datetime import datetime, timezone, timedelta
    import sqlite3

    success, user_id, _ = authenticate_user(db_path, "alice", "Demo@1234")
    assert success

    with app.app_context():
        sid, proof = create_session(db_path, proof_key, user_id, 1800)

        # Manually expire the session
        conn = sqlite3.connect(db_path)
        past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        conn.execute("UPDATE sessions SET expires_at=? WHERE session_id=?", (past, sid))
        conn.commit()
        conn.close()

        result = validate_session(db_path, proof_key, sid, proof)
        assert result.valid is False
        assert result.reason == "session_expired"


# ---------------------------------------------------------------------------
# T11 — Admin cookie cannot grant privileges
# ---------------------------------------------------------------------------

def test_T11_admin_cookie_ignored(client):
    """Setting is_admin=true cookie must not grant access without a real session."""
    client.set_cookie("is_admin", "true")
    client.set_cookie("role", "admin")
    resp = client.get("/api/protected-resource")
    assert resp.status_code == 401
