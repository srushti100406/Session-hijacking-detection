"""Integration tests for the database-backed, two-client demo workflow."""
import json
from pathlib import Path
import runpy
import threading

from werkzeug.serving import make_server

from app.models import get_db, init_db
from app.session_manager import get_session_status


def _cookie_values(response):
    cookies = {}
    for header in response.headers.getlist("Set-Cookie"):
        name, _, value = header.partition("=")
        cookies[name] = value.partition(";")[0]
    return cookies


def test_gunicorn_configuration_allows_nested_simulator_request():
    config_path = Path(__file__).resolve().parents[1] / "gunicorn.conf.py"
    config = runpy.run_path(str(config_path))

    assert config["worker_class"] == "gthread"
    assert config["threads"] >= 2


def test_two_clients_detect_replay_revoke_and_reject_afterwards(app, client):
    server = make_server("127.0.0.1", 0, app, threaded=True)
    app.config["SIMULATOR_PORT"] = server.server_port
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    try:
        # Laptop A authenticates and accesses the protected resource normally.
        login = client.post(
            "/demo/stage1-login",
            json={"username": "alice", "password": "Demo@1234"},
        )
        assert login.status_code == 200
        login_data = login.get_json()
        session_id = login_data["test_session_id"]
        fingerprint = login_data["session_fingerprint"]
        cookies = _cookie_values(login)
        assert cookies["sid"] == session_id
        assert cookies["sproof"]
        assert "proof_token" not in login_data
        assert "password" not in login_data

        conn = get_db(app.config["DATABASE_PATH"])
        try:
            row = conn.execute(
                "SELECT is_test_session FROM sessions WHERE session_id = ?",
                (session_id,),
            ).fetchone()
        finally:
            conn.close()
        assert row["is_test_session"] == 1

        with app.test_client() as premature_attacker:
            premature_replay = premature_attacker.post(
                "/demo/stage2-replay",
                json={"test_session_id": session_id},
            )
        assert premature_replay.status_code == 409
        assert get_session_status(app.config["DATABASE_PATH"], session_id)["revoked"] is False

        legitimate = client.get("/api/protected-resource")
        assert legitimate.status_code == 200
        assert legitimate.get_json()["status"] == "ACCESS_GRANTED"

        # Laptop B has a different HTTP client and sends only the copied test ID.
        with app.test_client() as attacker:
            replay = attacker.post(
                "/demo/stage2-replay",
                json={"test_session_id": session_id},
            )
            replay_data = replay.get_json()
            assert replay.status_code == 200
            assert replay_data["success"] is True
            assert replay_data["server_response_code"] == 401
            assert replay_data["server_response"]["success"] is False
            assert replay_data["server_response"]["status"] == "ACCESS_DENIED"
            assert replay_data["server_response"]["detection"] == "SUSPICIOUS_REPLAY_DETECTED"
            assert replay_data["detected"] is True
            assert replay_data["session_revoked"] is True
            assert replay_data["cookies_sent"] == [
                "sid (session identifier — NO proof token)"
            ]

            status = get_session_status(app.config["DATABASE_PATH"], session_id)
            assert status["revoked"] is True
            assert status["revoke_reason"] == "suspected_replay_attack"

            stage3 = attacker.post(
                "/demo/stage3-detection",
                json={"test_session_id": session_id},
            )
            assert stage3.status_code == 200
            assert stage3.get_json()["success"] is True
            assert stage3.get_json()["detection_status"] == "DETECTED"
            assert stage3.get_json()["session_revoked"] is True

            stage4 = attacker.post(
                "/demo/stage4-verify",
                json={"test_session_id": session_id},
            )
            stage4_data = stage4.get_json()
            assert stage4.status_code == 200
            assert stage4_data["success"] is True
            assert stage4_data["post_revocation_response_code"] == 401
            assert stage4_data["post_revocation_response"]["reason"] == "session_revoked"
            assert stage4_data["post_revocation_access_denied"] is True
            assert stage4_data["demo_summary"]["stage1_legitimate_access"] is True
            assert stage4_data["demo_summary"]["overall_result"] == "PASS"

            # A separate client presenting the original pair is also rejected.
            with app.test_client() as original_credentials:
                original_credentials.set_cookie("sid", session_id)
                original_credentials.set_cookie("sproof", cookies["sproof"])
                after_revocation = original_credentials.get("/api/protected-resource")
                assert after_revocation.status_code == 401
                assert after_revocation.get_json()["reason"] == "session_revoked"

        # The Laptop A dashboard can retrieve the same real revoked state and event.
        laptop_status = client.get("/api/session-status")
        assert laptop_status.status_code == 200
        laptop_status_data = laptop_status.get_json()
        assert laptop_status_data["has_session"] is True
        assert laptop_status_data["revoked"] is True
        assert laptop_status_data["revoke_reason"] == "suspected_replay_attack"
        laptop_events = client.get("/api/security-events").get_json()["events"]
        laptop_detection = next(
            event for event in laptop_events
            if event["event_type"] == "DETECTION_TRIGGERED"
            and event["session_fingerprint"] == fingerprint
        )
        assert laptop_detection["outcome"] == "detected"
        assert laptop_detection["timestamp"]

        conn = get_db(app.config["DATABASE_PATH"])
        try:
            replay_event = conn.execute(
                """SELECT outcome, action_taken FROM security_events
                   WHERE event_type='REPLAY_ATTEMPT' AND session_fingerprint=?
                   ORDER BY id DESC LIMIT 1""",
                (fingerprint,),
            ).fetchone()
            detection_event = conn.execute(
                """SELECT 1 FROM security_events
                   WHERE event_type='DETECTION_TRIGGERED' AND session_fingerprint=?
                     AND outcome='detected' LIMIT 1""",
                (fingerprint,),
            ).fetchone()
            legitimate_event = conn.execute(
                """SELECT 1 FROM security_events
                   WHERE event_type='TEST_SESSION_ACCESS_GRANTED'
                     AND session_fingerprint=? AND outcome='success' LIMIT 1""",
                (fingerprint,),
            ).fetchone()
            demo_events = conn.execute(
                "SELECT * FROM security_events WHERE session_fingerprint = ?",
                (fingerprint,),
            ).fetchall()
        finally:
            conn.close()
        assert replay_event["outcome"] == "detected"
        assert replay_event["action_taken"] == "replay_rejected_session_revoked"
        assert detection_event is not None
        assert legitimate_event is not None
        event_text = json.dumps([dict(event) for event in demo_events])
        assert session_id not in event_text
        assert cookies["sproof"] not in event_text
        assert "Demo@1234" not in event_text
    finally:
        server.shutdown()
        server_thread.join(timeout=5)


def test_demo_frontend_copies_legitimate_session_state(app, client):
    script = Path(__file__).resolve().parents[1] / "static" / "js" / "demo.js"
    source = script.read_text(encoding="utf-8")

    assert "const sessionId = state.testSessionId;" in source
    assert 'el("attackerSessionId").value = "";' in source
    assert 'const sessionId = el("attackerSessionId").value.trim();' in source


def test_demo_replay_rejects_non_test_session_without_revoking_it(app, client):
    server = make_server("127.0.0.1", 0, app, threaded=True)
    app.config["SIMULATOR_PORT"] = server.server_port
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    try:
        login = client.post(
            "/api/login",
            json={"username": "alice", "password": "Demo@1234"},
        )
        assert login.status_code == 200
        session_id = _cookie_values(login)["sid"]

        with app.test_client() as attacker:
            replay = attacker.post(
                "/demo/stage2-replay",
                json={"test_session_id": session_id},
            )
        assert replay.status_code == 404
        assert replay.get_json()["success"] is False
        assert get_session_status(app.config["DATABASE_PATH"], session_id)["revoked"] is False
        assert client.get("/api/protected-resource").status_code == 200
    finally:
        server.shutdown()
        server_thread.join(timeout=5)


def test_existing_database_migrates_test_session_marker(tmp_path):
    import sqlite3

    database_path = tmp_path / "existing.db"
    conn = sqlite3.connect(database_path)
    conn.execute(
        """CREATE TABLE users (
               id INTEGER PRIMARY KEY,
               username TEXT NOT NULL UNIQUE,
               password_hash TEXT NOT NULL,
               role TEXT NOT NULL,
               created_at TEXT NOT NULL
           )"""
    )
    conn.execute(
        "INSERT INTO users VALUES (1, 'alice', 'existing-hash', 'user', 'now')"
    )
    conn.execute(
        """CREATE TABLE sessions (
               session_id TEXT PRIMARY KEY,
               user_id INTEGER NOT NULL,
               proof_token TEXT NOT NULL,
               created_at TEXT NOT NULL,
               expires_at TEXT NOT NULL,
               revoked INTEGER NOT NULL DEFAULT 0,
               revoke_reason TEXT,
               revoked_at TEXT
           )"""
    )
    conn.close()

    init_db(str(database_path))

    conn = get_db(str(database_path))
    try:
        columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(sessions)")
        }
        assert "is_test_session" in columns
        assert conn.execute(
            "SELECT is_test_session FROM sessions"
        ).fetchall() == []
    finally:
        conn.close()
