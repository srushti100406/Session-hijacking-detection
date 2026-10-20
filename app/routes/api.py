"""
app/routes/api.py — Core API endpoints for authentication, session management,
the protected resource, and security event log.

All endpoints return JSON. Session cookies are set/cleared here.
"""
import hashlib
from datetime import datetime, timezone
from flask import (
    Blueprint, request, jsonify, current_app, make_response, g
)

from app.auth import authenticate_user, get_user_by_id
from app.session_manager import (
    create_session, validate_session, revoke_session,
    expire_all_user_sessions, get_session_status,
)
from app.models import session_fingerprint as _fp
from app.detection import evaluate_request
from app import logger as sec_log
from app.models import get_db

api_bp = Blueprint("api", __name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _db_path():
    return current_app.config["DATABASE_PATH"]


def _proof_key():
    return current_app.config["SESSION_PROOF_KEY"]


def _lifetime():
    return current_app.config["SESSION_LIFETIME_SECONDS"]


def _get_cookies():
    """Extract sid and sproof cookies from the current request."""
    return request.cookies.get("sid"), request.cookies.get("sproof")


def _set_session_cookies(response, session_id: str, proof_token: str):
    """Attach sid and sproof cookies to a response."""
    samesite = current_app.config.get("SESSION_COOKIE_SAMESITE", "Lax")
    secure = current_app.config.get("SESSION_COOKIE_SECURE", False)
    httponly = current_app.config.get("SESSION_COOKIE_HTTPONLY", True)
    max_age = current_app.config.get("SESSION_LIFETIME_SECONDS", 1800)

    response.set_cookie(
        "sid", session_id,
        httponly=httponly, samesite=samesite, secure=secure, max_age=max_age
    )
    response.set_cookie(
        "sproof", proof_token,
        httponly=httponly, samesite=samesite, secure=secure, max_age=max_age
    )


def _clear_session_cookies(response):
    """Expire sid and sproof cookies."""
    response.set_cookie("sid", "", expires=0, max_age=0)
    response.set_cookie("sproof", "", expires=0, max_age=0)


def _client_ip():
    return request.remote_addr or "unknown"


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------

@api_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()[:64]
    password = str(data.get("password", ""))[:128]

    db = _db_path()
    conn = get_db(db)

    success, user_id, role = authenticate_user(db, username, password)

    if not success:
        sec_log.record_event(
            conn,
            "LOGIN_FAILURE",
            username=username,
            reason="Invalid credentials",
            action_taken="login_denied",
            outcome="failure",
            ip_address=_client_ip(),
        )
        conn.close()
        return jsonify({"success": False, "error": "Invalid username or password"}), 401

    # Invalidate any existing sessions for this user before creating a new one
    expire_all_user_sessions(db, user_id)

    # Create new session (regenerated after login — prevents session fixation)
    session_id, proof_token = create_session(db, _proof_key(), user_id, _lifetime())

    sec_log.record_event(
        conn,
        "LOGIN_SUCCESS",
        user_id=user_id,
        username=username,
        session_fingerprint=_fp(session_id),
        reason="Credentials validated",
        action_taken="session_created",
        outcome="success",
        ip_address=_client_ip(),
    )
    sec_log.record_event(
        conn,
        "SESSION_CREATED",
        user_id=user_id,
        username=username,
        session_fingerprint=_fp(session_id),
        reason="New session after authentication",
        action_taken="session_issued",
        outcome="success",
        ip_address=_client_ip(),
    )
    conn.close()

    resp = make_response(jsonify({
        "success": True,
        "username": username,
        "role": role,
        "session_fingerprint": _fp(session_id),
        "message": "Authenticated successfully. Session created.",
    }))
    _set_session_cookies(resp, session_id, proof_token)
    return resp


# ---------------------------------------------------------------------------
# Logout
# ---------------------------------------------------------------------------

@api_bp.route("/logout", methods=["POST"])
def logout():
    session_id, _ = _get_cookies()
    db = _db_path()
    conn = get_db(db)

    if session_id:
        # Retrieve user info before revoking
        status = get_session_status(db, session_id)
        user_id = status["user_id"] if status else None
        fp = _fp(session_id) if session_id else None

        revoked = expire_all_user_sessions(db, user_id) if user_id else 0
        sec_log.record_event(
            conn,
            "LOGOUT",
            user_id=user_id,
            session_fingerprint=fp,
            reason="User initiated logout",
            action_taken=f"revoked_{revoked}_sessions",
            outcome="success",
            ip_address=_client_ip(),
        )

    conn.close()
    resp = make_response(jsonify({"success": True, "message": "Logged out."}))
    _clear_session_cookies(resp)
    return resp


# ---------------------------------------------------------------------------
# Protected resource
# ---------------------------------------------------------------------------

@api_bp.route("/protected-resource", methods=["GET"])
def protected_resource():
    """
    The protected resource that the legitimate user accesses and
    the attacker tries to replay into.
    """
    session_id, proof_token = _get_cookies()
    db = _db_path()

    validation = validate_session(db, _proof_key(), session_id, proof_token)
    decision = evaluate_request(db, validation, _client_ip())

    if decision.allow:
        user = get_user_by_id(db, validation.user_id)
        return jsonify({
            "success": True,
            "status": "ACCESS_GRANTED",
            "message": f"Welcome, {user['username']}! You have access to the protected resource.",
            "resource_data": {
                "document": "CONFIDENTIAL — Cryptography Lab Report Q4",
                "classification": "Internal",
                "accessed_at": datetime.now(timezone.utc).isoformat(),
                "accessed_by": user["username"],
            },
            "session_fingerprint": decision.fingerprint,
            "http_status": 200,
        }), 200

    # --- SUSPICIOUS REPLAY DETECTED ---
    if decision.suspicious:
        # Revoke the session (we have the session_id)
        if session_id:
            revoke_session(db, session_id, reason="suspected_replay_attack")
            # Log revocation
            conn = get_db(db)
            sec_log.record_event(
                conn,
                "SESSION_REVOKED",
                session_fingerprint=_fp(session_id),
                user_id=validation.user_id,
                username=validation.username,
                reason="Session revoked after replay attempt detected",
                action_taken="session_revoked",
                outcome="revoked",
                ip_address=_client_ip(),
            )
            conn.close()

        resp = make_response(jsonify({
            "success": False,
            "status": "ACCESS_DENIED",
            "detection": "SUSPICIOUS_REPLAY_DETECTED",
            "reason": "Session ID presented without valid proof token — suspected replay attack.",
            "action": "Request rejected. Session revoked.",
            "session_fingerprint": decision.fingerprint,
            "http_status": 401,
        }))
        _clear_session_cookies(resp)
        return resp, 401

    # Other invalid cases
    status_messages = {
        "session_revoked": "Session has been revoked. Access denied.",
        "session_expired": "Session has expired. Please log in again.",
        "session_not_found": "Session not found.",
        "no_session_id": "No session. Please authenticate first.",
    }
    msg = status_messages.get(validation.reason, "Access denied.")

    return jsonify({
        "success": False,
        "status": "ACCESS_DENIED",
        "reason": validation.reason,
        "message": msg,
        "session_fingerprint": decision.fingerprint,
        "http_status": 401,
    }), 401


# ---------------------------------------------------------------------------
# Session status endpoint
# ---------------------------------------------------------------------------

@api_bp.route("/session-status", methods=["GET"])
def session_status():
    session_id, _ = _get_cookies()
    if not session_id:
        return jsonify({"has_session": False}), 200

    status = get_session_status(_db_path(), session_id)
    if not status:
        return jsonify({"has_session": False}), 200

    return jsonify({"has_session": True, **status}), 200


# ---------------------------------------------------------------------------
# Security event log (server-side protected — requires active session)
# ---------------------------------------------------------------------------

@api_bp.route("/security-events", methods=["GET"])
def security_events():
    db = _db_path()
    conn = get_db(db)
    try:
        events = sec_log.get_recent_events(conn, limit=100)
    finally:
        conn.close()
    return jsonify({"events": events}), 200
