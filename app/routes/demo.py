"""
app/routes/demo.py — Demo orchestration endpoints.

These endpoints coordinate the four-stage guided demonstration.
They are the bridge between the frontend demo UI and the backend
security logic + simulator.

The simulator runs local HTTP requests — it does NOT manipulate
the browser's cookies or attack external services.
"""
import threading
from flask import Blueprint, request, jsonify, current_app

from app.session_manager import (
    create_session, validate_session, revoke_session,
    expire_all_user_sessions, get_session_status,
)
from app.models import session_fingerprint as _fp
from app.auth import authenticate_user
from app.simulator import run_replay_attack, run_legitimate_request
from app import logger as sec_log
from app.models import get_db
from app.detection import evaluate_request

demo_bp = Blueprint("demo", __name__)

# Thread-local demo state (persisted per demo run, keyed by session)
_demo_state_lock = threading.Lock()
_demo_sessions: dict = {}   # fingerprint -> {session_id, proof_token, stages}


def _db():
    return current_app.config["DATABASE_PATH"]

def _pk():
    return current_app.config["SESSION_PROOF_KEY"]

def _lt():
    return current_app.config["SESSION_LIFETIME_SECONDS"]

def _port():
    return current_app.config.get("SIMULATOR_PORT", 5000)


# ---------------------------------------------------------------------------
# Stage 1 — Create legitimate session
# ---------------------------------------------------------------------------

@demo_bp.route("/stage1-login", methods=["POST"])
def stage1_login():
    """Authenticate the demo user and create a legitimate session."""
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "alice")).strip()[:64]
    password = str(data.get("password", "Demo@1234"))[:128]

    db = _db()
    conn = get_db(db)

    success, user_id, role = authenticate_user(db, username, password)
    if not success:
        sec_log.record_event(conn, "LOGIN_FAILURE", username=username,
                             reason="Demo login: invalid credentials",
                             action_taken="denied", outcome="failure",
                             ip_address=request.remote_addr)
        conn.close()
        return jsonify({"success": False, "error": "Invalid credentials"}), 401

    # Revoke any previous sessions for this user
    expire_all_user_sessions(db, user_id)

    session_id, proof_token = create_session(db, _pk(), user_id, _lt())
    fp = _fp(session_id)

    sec_log.record_event(conn, "LOGIN_SUCCESS", user_id=user_id,
                         username=username, session_fingerprint=fp,
                         reason="Demo Stage 1: legitimate authentication",
                         action_taken="session_created", outcome="success",
                         ip_address=request.remote_addr)
    sec_log.record_event(conn, "SESSION_CREATED", user_id=user_id,
                         username=username, session_fingerprint=fp,
                         reason="Demo Stage 1: new session issued",
                         action_taken="session_issued", outcome="success",
                         ip_address=request.remote_addr)
    conn.close()

    # Store session info for later demo stages (keyed by fingerprint)
    with _demo_state_lock:
        _demo_sessions[fp] = {
            "session_id": session_id,
            "proof_token": proof_token,
            "username": username,
            "user_id": user_id,
            "stages": {
                "stage1_complete": True,
                "stage2_complete": False,
                "stage3_complete": False,
                "stage4_complete": False,
            },
            "results": {}
        }

    return jsonify({
        "success": True,
        "stage": 1,
        "username": username,
        "role": role,
        "session_fingerprint": fp,
        "session_status": "ACTIVE",
        "auth_status": "AUTHENTICATED",
        "explanation": (
            "A legitimate session has been created. The server generated a "
            "cryptographically random session ID and a separate HMAC-based "
            "proof token. Both are required to access protected resources. "
            "The session ID alone is NOT sufficient."
        ),
    }), 200


# ---------------------------------------------------------------------------
# Stage 2 — Attacker replay (controlled simulation)
# ---------------------------------------------------------------------------

@demo_bp.route("/stage2-replay", methods=["POST"])
def stage2_replay():
    """
    Run the controlled replay attack.

    The simulator sends ONLY the session_id cookie (no proof_token).
    This is a real HTTP request to the local /api/protected-resource endpoint.
    """
    data = request.get_json(silent=True) or {}
    fp = str(data.get("session_fingerprint", "")).strip()

    with _demo_state_lock:
        state = _demo_sessions.get(fp)

    if not state:
        return jsonify({"success": False, "error": "No demo session found. Run Stage 1 first."}), 400

    if state["stages"].get("stage3_complete"):
        return jsonify({"success": False, "error": "Session already revoked. Reset the demo."}), 400

    base_url = f"http://127.0.0.1:{_port()}"
    session_id = state["session_id"]

    result = run_replay_attack(base_url, session_id)
    status = get_session_status(_db(), session_id)
    server_response = result.get("response_json") or {}
    detected = (
        result.get("status_code") == 401
        and server_response.get("success") is False
        and server_response.get("status") == "ACCESS_DENIED"
        and server_response.get("detection") == "SUSPICIOUS_REPLAY_DETECTED"
        and bool(
            status
            and status["revoked"]
            and status["revoke_reason"] == "suspected_replay_attack"
        )
    )
    session_revoked = bool(status and status["revoked"])

    if detected:
        outcome = "detected"
        action_taken = "replay_rejected_session_revoked"
    elif result.get("status_code") is None:
        outcome = "failure"
        action_taken = "simulator_request_failed"
    elif result.get("status_code") == 200:
        outcome = "failure"
        action_taken = "replay_access_granted"
    else:
        outcome = "failure"
        action_taken = "unexpected_server_response"

    conn = get_db(_db())
    sec_log.record_event(conn, "REPLAY_ATTEMPT",
                         user_id=state["user_id"],
                         username=state["username"],
                         session_fingerprint=fp,
                         reason="Demo Stage 2: attacker replaying stolen session ID without proof token",
                         action_taken=action_taken,
                         outcome=outcome,
                         ip_address=request.remote_addr)
    conn.close()

    with _demo_state_lock:
        if fp in _demo_sessions:
            _demo_sessions[fp]["stages"]["stage2_complete"] = result.get("status_code") is not None
            stored = dict(result)
            stored["server_response_code"] = result.get("status_code")
            stored["detected"] = detected
            stored["session_revoked"] = session_revoked
            _demo_sessions[fp]["results"]["stage2"] = stored

    return jsonify({
        "success": True,
        "stage": 2,
        "attack_type": result["attack_type"],
        "cookies_sent": result["cookies_sent"],
        "server_response_code": result["status_code"],
        "server_response": server_response,
        "detected": detected,
        "session_revoked": session_revoked,
        "description": result["description"],
        "explanation": (
            "The attacker sent ONLY the session ID cookie — no proof token. "
            "The server evaluated this against its actual validation logic. "
            "A missing proof token is the detection signal in this scenario."
        ),
    }), 200


# ---------------------------------------------------------------------------
# Stage 3 — Confirm detection and revocation status
# ---------------------------------------------------------------------------

@demo_bp.route("/stage3-detection", methods=["POST"])
def stage3_detection():
    """Confirm that detection fired and session is revoked."""
    data = request.get_json(silent=True) or {}
    fp = str(data.get("session_fingerprint", "")).strip()

    with _demo_state_lock:
        state = _demo_sessions.get(fp)

    if not state:
        return jsonify({"success": False, "error": "No demo session found."}), 400

    db = _db()
    session_id = state["session_id"]
    status = get_session_status(db, session_id)

    session_revoked = bool(status and status["revoked"])
    stage2_result = state.get("results", {}).get("stage2", {})
    replay_detected = bool(stage2_result.get("detected"))

    with _demo_state_lock:
        if fp in _demo_sessions:
            _demo_sessions[fp]["stages"]["stage3_complete"] = True
            _demo_sessions[fp]["results"]["stage3"] = {
                "session_revoked": session_revoked,
                "revoke_reason": status.get("revoke_reason") if status else None,
            }

    return jsonify({
        "success": True,
        "stage": 3,
        "session_fingerprint": fp,
        "detection_status": "DETECTED" if replay_detected else "NOT_DETECTED",
        "session_revoked": session_revoked,
        "revoke_reason": status.get("revoke_reason") if status else None,
        "explanation": (
            "The missing proof token was detected and the session was revoked."
            if replay_detected and session_revoked else
            "The replay detection and session revocation were not both verified."
        ),
    }), 200


# ---------------------------------------------------------------------------
# Stage 4 — Post-revocation verification
# ---------------------------------------------------------------------------

@demo_bp.route("/stage4-verify", methods=["POST"])
def stage4_verify():
    """
    Attempt to use the original (now revoked) session credentials.
    Confirms that revocation is enforced even with both cookies.
    """
    data = request.get_json(silent=True) or {}
    fp = str(data.get("session_fingerprint", "")).strip()

    with _demo_state_lock:
        state = _demo_sessions.get(fp)

    if not state:
        return jsonify({"success": False, "error": "No demo session found."}), 400

    base_url = f"http://127.0.0.1:{_port()}"
    session_id = state["session_id"]
    proof_token = state["proof_token"]

    status = get_session_status(_db(), session_id)

    # Attempt access with the full original credentials (both cookies)
    result = run_legitimate_request(base_url, session_id, proof_token)
    server_response = result.get("response_json") or {}

    stage4_passed = (
        bool(status and status["revoked"])
        and status["revoke_reason"] == "suspected_replay_attack"
        and result.get("status_code") == 401
        and server_response.get("success") is False
        and server_response.get("status") == "ACCESS_DENIED"
        and server_response.get("reason") == "session_revoked"
    )

    conn = get_db(_db())
    sec_log.record_event(conn, "REVOKED_SESSION_ACCESS",
                         user_id=state["user_id"],
                         username=state["username"],
                         session_fingerprint=fp,
                         reason="Demo Stage 4: post-revocation verification attempt",
                         action_taken="access_denied_after_revocation" if stage4_passed else "revocation_verification_failed",
                         outcome="blocked" if stage4_passed else "failure",
                         ip_address=request.remote_addr)
    conn.close()

    s = state["stages"]
    stage2_result = state.get("results", {}).get("stage2", {})
    replay_detected = bool(stage2_result.get("detected"))
    stage3_result = state.get("results", {}).get("stage3", {})
    stage3_revoked = bool(stage3_result.get("session_revoked"))
    all_passed = (
        s.get("stage1_complete")
        and replay_detected
        and stage3_revoked
        and stage4_passed
    )
    conclusion = (
        "The replay was detected, rejected, and revoked; a subsequent request "
        "with the original credentials was rejected specifically because the "
        "session had been revoked. This applies to the controlled demonstration "
        "scenario — not every possible form of session hijacking."
        if all_passed else
        "The demonstration did not pass all checks. The replay detection, "
        "session revocation, or post-revocation access denial was not verified."
    )

    with _demo_state_lock:
        if fp in _demo_sessions:
            _demo_sessions[fp]["stages"]["stage4_complete"] = True
            _demo_sessions[fp]["results"]["stage4"] = result

    return jsonify({
        "success": True,
        "stage": 4,
        "session_fingerprint": fp,
        "post_revocation_response_code": result["status_code"],
        "post_revocation_access_denied": stage4_passed,
        "session_revoked_before_attempt": bool(status and status["revoked"]),
        "post_revocation_reason": server_response.get("reason"),
        "demo_summary": {
            "stage1_legitimate_login": s.get("stage1_complete", False),
            "stage2_replay_detected": replay_detected,
            "stage3_session_revoked": stage3_revoked,
            "stage4_revocation_enforced": stage4_passed,
            "overall_result": "PASS" if all_passed else "FAIL",
        },
        "conclusion": conclusion,
    }), 200


# ---------------------------------------------------------------------------
# Reset demo
# ---------------------------------------------------------------------------

@demo_bp.route("/reset", methods=["POST"])
def reset_demo():
    """
    Reset the demo state.
    Revokes any active demo sessions and clears in-memory state.
    Does NOT disable any security mechanism.
    """
    db = _db()
    conn = get_db(db)

    with _demo_state_lock:
        for fp, state in list(_demo_sessions.items()):
            try:
                expire_all_user_sessions(db, state["user_id"])
            except Exception:
                pass
        _demo_sessions.clear()

    sec_log.record_event(conn, "DEMO_RESET",
                         reason="Demo reset requested",
                         action_taken="all_demo_sessions_revoked",
                         outcome="success",
                         ip_address=request.remote_addr)
    conn.close()

    return jsonify({
        "success": True,
        "message": "Demo reset. All demo sessions revoked. Security mechanisms remain active.",
    }), 200
