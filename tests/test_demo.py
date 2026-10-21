"""Integration tests for the four-stage demo workflow."""
from pathlib import Path
import runpy
import threading

from werkzeug.serving import make_server

from app.models import get_db


def test_gunicorn_configuration_allows_nested_simulator_request():
    config_path = Path(__file__).resolve().parents[1] / "gunicorn.conf.py"
    config = runpy.run_path(str(config_path))

    assert config["worker_class"] == "gthread"
    assert config["threads"] >= 2


def test_demo_replay_revocation_and_stage4_verification(app, client):
    server = make_server("127.0.0.1", 0, app, threaded=True)
    app.config["SIMULATOR_PORT"] = server.server_port
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    try:
        login = client.post("/demo/stage1-login", json={"username": "alice", "password": "Demo@1234"})
        assert login.status_code == 200
        fingerprint = login.get_json()["session_fingerprint"]

        replay = client.post("/demo/stage2-replay", json={"session_fingerprint": fingerprint})
        replay_data = replay.get_json()
        assert replay.status_code == 200
        assert replay_data["server_response_code"] == 401
        assert replay_data["server_response"]["success"] is False
        assert replay_data["server_response"]["status"] == "ACCESS_DENIED"
        assert replay_data["server_response"]["detection"] == "SUSPICIOUS_REPLAY_DETECTED"
        assert replay_data["detected"] is True
        assert replay_data["session_revoked"] is True

        conn = get_db(app.config["DATABASE_PATH"])
        try:
            replay_event = conn.execute(
                """SELECT outcome, action_taken FROM security_events
                   WHERE event_type='REPLAY_ATTEMPT' AND session_fingerprint=?
                   ORDER BY id DESC LIMIT 1""",
                (fingerprint,),
            ).fetchone()
        finally:
            conn.close()
        assert replay_event["outcome"] == "detected"
        assert replay_event["action_taken"] == "replay_rejected_session_revoked"

        stage3 = client.post("/demo/stage3-detection", json={"session_fingerprint": fingerprint})
        assert stage3.status_code == 200
        assert stage3.get_json()["detection_status"] == "DETECTED"
        assert stage3.get_json()["session_revoked"] is True

        stage4 = client.post("/demo/stage4-verify", json={"session_fingerprint": fingerprint})
        stage4_data = stage4.get_json()
        assert stage4.status_code == 200
        assert stage4_data["post_revocation_response_code"] == 401
        assert stage4_data["post_revocation_reason"] == "session_revoked"
        assert stage4_data["session_revoked_before_attempt"] is True
        assert stage4_data["post_revocation_access_denied"] is True
        assert stage4_data["demo_summary"]["overall_result"] == "PASS"
    finally:
        server.shutdown()
        server_thread.join(timeout=5)
