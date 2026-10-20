"""
tests/test_auth.py — Tests for authentication module.

Test IDs
--------
T01 — Valid login succeeds.
T02 — Invalid password fails.
T03 — Unknown username fails.
T04 — Empty credentials fail.
"""
import pytest
from app.auth import authenticate_user
from app.models import init_db


# ---------------------------------------------------------------------------
# T01 — Valid login
# ---------------------------------------------------------------------------

def test_T01_valid_login_succeeds(db_path, proof_key):
    """Valid demo credentials must authenticate successfully."""
    success, user_id, role = authenticate_user(db_path, "alice", "Demo@1234")
    assert success is True
    assert user_id is not None
    assert role == "user"


# ---------------------------------------------------------------------------
# T02 — Invalid password
# ---------------------------------------------------------------------------

def test_T02_wrong_password_fails(db_path):
    """Wrong password must not authenticate."""
    success, user_id, role = authenticate_user(db_path, "alice", "wrongpassword")
    assert success is False
    assert user_id is None
    assert role is None


# ---------------------------------------------------------------------------
# T03 — Unknown username
# ---------------------------------------------------------------------------

def test_T03_unknown_username_fails(db_path):
    """Non-existent username must not authenticate."""
    success, user_id, role = authenticate_user(db_path, "hacker", "Demo@1234")
    assert success is False
    assert user_id is None


# ---------------------------------------------------------------------------
# T04 — Empty credentials
# ---------------------------------------------------------------------------

def test_T04_empty_credentials_fail(db_path):
    """Empty username and password must not authenticate."""
    success, _, _ = authenticate_user(db_path, "", "")
    assert success is False


# ---------------------------------------------------------------------------
# API-level login tests
# ---------------------------------------------------------------------------

def test_login_api_success(client):
    """POST /api/login with valid credentials returns 200 and sets cookies."""
    resp = client.post("/api/login", json={"username": "alice", "password": "Demo@1234"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["success"] is True
    assert "session_fingerprint" in data
    # Both cookies must be set (check all Set-Cookie headers)
    set_cookie_headers = "\n".join(resp.headers.getlist("Set-Cookie"))
    assert "sid" in set_cookie_headers
    assert "sproof" in set_cookie_headers


def test_login_api_failure(client):
    """POST /api/login with wrong password returns 401."""
    resp = client.post("/api/login", json={"username": "alice", "password": "bad"})
    assert resp.status_code == 401
    data = resp.get_json()
    assert data["success"] is False
