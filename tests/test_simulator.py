"""
tests/test_simulator.py — Tests for the local replay simulator safety.

Test IDs
--------
T19 — Simulator rejects external URLs.
T20 — Simulator accepts localhost.
"""
import pytest
from app.simulator import run_replay_attack, _assert_local


# ---------------------------------------------------------------------------
# T19 — Simulator rejects external URLs
# ---------------------------------------------------------------------------

def test_T19_simulator_rejects_external_url():
    """Simulator must raise ValueError for any non-localhost target."""
    with pytest.raises(ValueError, match="not allowed"):
        _assert_local("http://example.com/api/protected-resource")

    with pytest.raises(ValueError, match="not allowed"):
        _assert_local("http://192.168.1.1/api/protected-resource")

    with pytest.raises(ValueError, match="not allowed"):
        _assert_local("https://evil.com/steal")


# ---------------------------------------------------------------------------
# T20 — Simulator accepts localhost
# ---------------------------------------------------------------------------

def test_T20_simulator_accepts_localhost():
    """Simulator must NOT raise for 127.0.0.1 or localhost."""
    # Should not raise
    _assert_local("http://127.0.0.1:5000/api/protected-resource")
    _assert_local("http://localhost:5000/api/protected-resource")


def test_approved_https_origin_is_accepted():
    origin = "https://session-hijacking-detection.onrender.com"
    _assert_local(origin, allowed_origin=origin)
    _assert_local(origin + "/", allowed_origin=origin)


@pytest.mark.parametrize(
    "target",
    [
        "https://example.com",
        "http://session-hijacking-detection.onrender.com",
        "https://session-hijacking-detection.onrender.com:8443",
        "https://session-hijacking-detection.onrender.com.evil.example",
    ],
)
def test_unapproved_https_origin_is_rejected(target):
    origin = "https://session-hijacking-detection.onrender.com"
    with pytest.raises(ValueError, match="not allowed"):
        _assert_local(target, allowed_origin=origin)
