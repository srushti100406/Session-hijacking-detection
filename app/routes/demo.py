"""Database-backed endpoints for the controlled session replay demonstration."""
from flask import Blueprint, current_app, jsonify, make_response, request

from app import logger as sec_log
from app.auth import authenticate_user
from app.models import get_db, session_fingerprint as _fp
from app.session_manager import (
    create_test_session,
    get_session_status,
    revoke_session,
)
from app.simulator import run_legitimate_request, run_replay_attack

demo_bp = Blueprint("demo", __name__)


def _db():
    return current_app.config["DATABASE_PATH"]


def _proof_key():
    return current_app.config["SESSION_PROOF_KEY"]


def _lt():
    return current_app.config["SESSION_LIFETIME_SECONDS"]


def _test_session(session_id):
    """Load a session only when its database record explicitly marks it test-only."""
    conn = get_db(_db())
    try:
        row = conn.execute(
            """SELECT s.session_id, s.user_id, s.proof_token, s.revoked,
                      s.revoke_reason, u.username
               FROM sessions s
               JOIN users u ON u.id = s.user_id
               WHERE s.session_id = ? AND s.is_test_session = 1""",
            (session_id,),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def _has_replay_detection(session_fingerprint):
    conn = get_db(_db())
    try:
        return conn.execute(
            """SELECT 1 FROM security_events
               WHERE event_type = 'DETECTION_TRIGGERED'
                 AND outcome = 'detected'
                 AND session_fingerprint = ?
               LIMIT 1""",
            (session_fingerprint,),
        ).fetchone() is not None
    finally:
        conn.close()


def _has_legitimate_access(session_fingerprint):
    conn = get_db(_db())
    try:
        return conn.execute(
            """SELECT 1 FROM security_events
               WHERE event_type = 'TEST_SESSION_ACCESS_GRANTED'
                 AND outcome = 'success'
                 AND session_fingerprint = ?
               LIMIT 1""",
            (session_fingerprint,),
        ).fetchone() is not None
    finally:
        conn.close()


def _test_session_id(data):
    session_id = data.get("test_session_id")
    if not isinstance(session_id, str) or not session_id or len(session_id) > 128:
        return None
    return session_id


def _request_data():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


@demo_bp.route("/stage1-login", methods=["POST"])
def stage1_login():
    """Authenticate and create a database-marked test session for the demo."""
    data = _request_data()
    username = str(data.get("username", "")).strip()[:64]
    password = str(data.get("password", ""))[:128]
    db = _db()
    conn = get_db(db)

    success, user_id, role = authenticate_user(db, username, password)
    if not success:
        sec_log.record_event(
            conn,
            "LOGIN_FAILURE",
            username=username,
            reason="Demo login: invalid credentials",
            action_taken="denied",
            outcome="failure",
            ip_address=request.remote_addr,
        )
        conn.close()
        return jsonify({"success": False, "error": "Invalid credentials"}), 401

    session_id, proof_token = create_test_session(db, _proof_key(), user_id, _lt())
    fingerprint = _fp(session_id)
    sec_log.record_event(
        conn,
        "LOGIN_SUCCESS",
        user_id=user_id,
        username=username,
        session_fingerprint=fingerprint,
        reason="Demo Stage 1: legitimate authentication",
        action_taken="test_session_created",
        outcome="success",
        ip_address=request.remote_addr,
    )
    sec_log.record_event(
        conn,
        "SESSION_CREATED",
        user_id=user_id,
        username=username,
        session_fingerprint=fingerprint,
        reason="Demo Stage 1: new test session issued",
        action_taken="test_session_issued",
        outcome="success",
        ip_address=request.remote_addr,
    )
    conn.close()

    response = make_response(
        jsonify(
            {
                "success": True,
                "stage": 1,
                "username": username,
                "role": role,
                "session_fingerprint": fingerprint,
                "test_session_id": session_id,
                "session_status": "ACTIVE",
                "auth_status": "AUTHENTICATED",
                "explanation": (
                    "A test-only session was created after normal credential "
                    "validation. Its identifier can be copied to the demo "
                    "attacker flow; the separate proof credential is not shared."
                ),
            }
        )
    )
    response.set_cookie(
        "sid",
        session_id,
        httponly=current_app.config.get("SESSION_COOKIE_HTTPONLY", True),
        samesite=current_app.config.get("SESSION_COOKIE_SAMESITE", "Lax"),
        secure=current_app.config.get("SESSION_COOKIE_SECURE", False),
        max_age=_lt(),
    )
    response.set_cookie(
        "sproof",
        proof_token,
        httponly=current_app.config.get("SESSION_COOKIE_HTTPONLY", True),
        samesite=current_app.config.get("SESSION_COOKIE_SAMESITE", "Lax"),
        secure=current_app.config.get("SESSION_COOKIE_SECURE", False),
        max_age=_lt(),
    )
    return response, 200


@demo_bp.route("/stage2-replay", methods=["POST"])
def stage2_replay():
    """Replay only a copied test-session ID, without sending its proof cookie."""
    data = _request_data()
    session_id = _test_session_id(data)
    if session_id is None:
        return jsonify(
            {"success": False, "error": "A test session ID is required."}
        ), 400

    test_session = _test_session(session_id)
    if test_session is None:
        return jsonify(
            {"success": False, "error": "This identifier is not a demo test session."}
        ), 404
    if test_session["revoked"]:
        return jsonify(
            {"success": False, "error": "The demo test session is already revoked."}
        ), 409

    fingerprint = _fp(session_id)
    if not _has_legitimate_access(fingerprint):
        return jsonify(
            {
                "success": False,
                "error": "The legitimate test session must access the protected resource first.",
            }
        ), 409

    base_url = current_app.config.get("SIMULATOR_BASE_URL") or (
        f"http://127.0.0.1:{current_app.config.get('SIMULATOR_PORT', 5000)}"
    )
    allowed_origin = current_app.config.get("SIMULATOR_ALLOWED_ORIGIN") or base_url
    result = run_replay_attack(base_url, session_id, allowed_origin=allowed_origin)
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

    conn = get_db(_db())
    try:
        sec_log.record_event(
            conn,
            "REPLAY_ATTEMPT",
            user_id=test_session["user_id"],
            username=test_session["username"],
            session_fingerprint=_fp(session_id),
            reason="Demo Stage 2: test session ID sent without proof token",
            action_taken=(
                "replay_rejected_session_revoked"
                if detected
                else "replay_verification_failed"
            ),
            outcome="detected" if detected else "failure",
            ip_address=request.remote_addr,
        )
    finally:
        conn.close()

    response_body = {
        "success": detected,
        "stage": 2,
        "attack_type": result.get("attack_type"),
        "cookies_sent": result.get("cookies_sent", []),
        "server_response_code": result.get("status_code"),
        "server_response": server_response,
        "detected": detected,
        "session_revoked": bool(status and status["revoked"]),
        "session_fingerprint": _fp(session_id),
        "description": result.get("description"),
        "explanation": (
            "The backend protected-resource endpoint evaluated a real HTTP "
            "request containing sid only; it did not receive the proof cookie."
        ),
    }
    return jsonify(response_body), 200 if detected else 502


@demo_bp.route("/stage3-detection", methods=["POST"])
def stage3_detection():
    """Confirm replay detection and revocation from persisted backend records."""
    data = _request_data()
    session_id = _test_session_id(data)
    if session_id is None:
        return jsonify(
            {"success": False, "error": "A test session ID is required."}
        ), 400

    test_session = _test_session(session_id)
    if test_session is None:
        return jsonify(
            {"success": False, "error": "This identifier is not a demo test session."}
        ), 404

    status = get_session_status(_db(), session_id)
    replay_detected = _has_replay_detection(_fp(session_id))
    session_revoked = bool(status and status["revoked"])
    confirmed = replay_detected and session_revoked
    return jsonify(
        {
            "success": confirmed,
            "stage": 3,
            "session_fingerprint": _fp(session_id),
            "detection_status": "DETECTED" if replay_detected else "NOT_DETECTED",
            "session_revoked": session_revoked,
            "revoke_reason": status.get("revoke_reason") if status else None,
            "explanation": (
                "The backend recorded the missing-proof detection and confirmed "
                "that this test session was revoked."
                if confirmed
                else "Backend records do not confirm both replay detection and revocation."
            ),
        }
    ), 200 if confirmed else 409


@demo_bp.route("/stage4-verify", methods=["POST"])
def stage4_verify():
    """Send both original test credentials and confirm revoked-session denial."""
    data = _request_data()
    session_id = _test_session_id(data)
    if session_id is None:
        return jsonify(
            {"success": False, "error": "A test session ID is required."}
        ), 400

    test_session = _test_session(session_id)
    if test_session is None:
        return jsonify(
            {"success": False, "error": "This identifier is not a demo test session."}
        ), 404

    status = get_session_status(_db(), session_id)
    replay_detected = _has_replay_detection(_fp(session_id))
    legitimate_access = _has_legitimate_access(_fp(session_id))
    session_revoked_before_attempt = bool(status and status["revoked"])
    if not legitimate_access or not replay_detected or not session_revoked_before_attempt:
        return jsonify(
            {
                "success": False,
                "error": "Replay detection and revocation must be confirmed first.",
            }
        ), 409

    base_url = current_app.config.get("SIMULATOR_BASE_URL") or (
        f"http://127.0.0.1:{current_app.config.get('SIMULATOR_PORT', 5000)}"
    )
    allowed_origin = current_app.config.get("SIMULATOR_ALLOWED_ORIGIN") or base_url
    result = run_legitimate_request(
        base_url,
        session_id,
        test_session["proof_token"],
        allowed_origin=allowed_origin,
    )
    server_response = result.get("response_json") or {}
    stage4_passed = (
        legitimate_access
        and replay_detected
        and session_revoked_before_attempt
        and result.get("status_code") == 401
        and server_response.get("success") is False
        and server_response.get("status") == "ACCESS_DENIED"
        and server_response.get("reason") == "session_revoked"
    )

    conn = get_db(_db())
    try:
        sec_log.record_event(
            conn,
            "REVOKED_SESSION_ACCESS",
            user_id=test_session["user_id"],
            username=test_session["username"],
            session_fingerprint=_fp(session_id),
            reason="Demo Stage 4: post-revocation test-session verification",
            action_taken=(
                "access_denied_after_revocation"
                if stage4_passed
                else "revocation_verification_failed"
            ),
            outcome="blocked" if stage4_passed else "failure",
            ip_address=request.remote_addr,
        )
    finally:
        conn.close()

    conclusion = (
        "The replay was detected and rejected, the test session was revoked, "
        "and a later request with both original credentials was rejected. "
        "This applies only to the demonstrated replay scenario."
        if stage4_passed
        else "The backend did not confirm post-revocation rejection."
    )
    response_body = {
        "success": stage4_passed,
        "stage": 4,
        "session_fingerprint": _fp(session_id),
        "post_revocation_response_code": result.get("status_code"),
        "post_revocation_response": server_response,
        "post_revocation_access_denied": stage4_passed,
        "session_revoked_before_attempt": session_revoked_before_attempt,
        "post_revocation_reason": server_response.get("reason"),
        "demo_summary": {
            "stage1_legitimate_access": legitimate_access,
            "stage2_replay_detected": replay_detected,
            "stage3_session_revoked": session_revoked_before_attempt,
            "stage4_revocation_enforced": stage4_passed,
            "overall_result": "PASS" if stage4_passed else "FAIL",
        },
        "conclusion": conclusion,
    }
    return jsonify(response_body), 200 if stage4_passed else 502


@demo_bp.route("/reset", methods=["POST"])
def reset_demo():
    """Revoke one supplied test session; never revoke a user's other sessions."""
    data = _request_data()
    session_id = _test_session_id(data)
    if session_id is None:
        return jsonify(
            {"success": False, "error": "A test session ID is required."}
        ), 400

    test_session = _test_session(session_id)
    if test_session is None:
        return jsonify(
            {"success": False, "error": "This identifier is not a demo test session."}
        ), 404

    revoked = revoke_session(_db(), session_id, reason="demo_reset")
    conn = get_db(_db())
    try:
        sec_log.record_event(
            conn,
            "DEMO_RESET",
            user_id=test_session["user_id"],
            username=test_session["username"],
            session_fingerprint=_fp(session_id),
            reason="Demo test session reset",
            action_taken="test_session_revoked" if revoked else "already_revoked",
            outcome="success",
            ip_address=request.remote_addr,
        )
    finally:
        conn.close()

    return jsonify(
        {
            "success": True,
            "session_revoked": True,
            "message": "Demo test session revoked. Security mechanisms remain active.",
        }
    ), 200
