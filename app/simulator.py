"""
app/simulator.py — Controlled replay simulator.

Performs the simulated session-hijacking attack as REAL HTTP requests
against the local application. This is the ONLY component that issues
requests to the protected resource; it is strictly limited to localhost.

Safety restrictions
-------------------
- The target URL must be on 127.0.0.1 (the SIMULATOR_ALLOWED_HOST).
- No real browser cookies are extracted or manipulated.
- No external websites are targeted.
- The 'session_id' given to the attacker is the legitimate one, but
  no proof_token is included (simulating partial credential theft).
"""
import re
import requests as http
from urllib.parse import urlparse
from typing import Optional

# The ONLY allowed host for simulator requests
_ALLOWED_HOST = "127.0.0.1"
_PROTECTED_PATH = "/api/protected-resource"


def _assert_local(url: str) -> None:
    """Raise ValueError if the URL does not target the allowed local host."""
    parsed = urlparse(url)
    host = parsed.hostname or ""
    if host not in (_ALLOWED_HOST, "localhost"):
        raise ValueError(
            f"Simulator target '{host}' is not allowed. "
            f"Only '{_ALLOWED_HOST}' (localhost) is permitted."
        )


def run_replay_attack(
    base_url: str,
    stolen_session_id: str,
) -> dict:
    """
    Execute the controlled replay attack.

    The attacker has the session_id cookie but NOT the proof_token cookie.
    This simulates a scenario where only the session identifier was stolen
    (e.g., via a server log exposure, predictable token, or partial
    network interception in a non-TLS environment).

    Parameters
    ----------
    base_url : str
        Must be http://127.0.0.1:<port>
    stolen_session_id : str
        The session ID obtained by the simulated attacker.

    Returns
    -------
    dict with keys: status_code, response_json, attack_type, description
    """
    _assert_local(base_url)

    target_url = base_url.rstrip("/") + _PROTECTED_PATH

    # Attacker sends ONLY the session ID cookie — no proof token
    cookies = {"sid": stolen_session_id}

    try:
        resp = http.get(
            target_url,
            cookies=cookies,
            timeout=5,
            allow_redirects=False,
            headers={
                "User-Agent": "SimulatedAttacker/1.0",
                "X-Simulated-Attack": "session-replay",
            },
        )
        return {
            "status_code": resp.status_code,
            "response_json": _safe_json(resp),
            "attack_type": "session_id_replay_without_proof",
            "description": (
                "Attacker replayed the session ID cookie without the required "
                "proof token. Server evaluated the request against actual "
                "session-validation logic."
            ),
            "cookies_sent": ["sid (session identifier — NO proof token)"],
            "success": False,   # Attack should always fail if defence works
        }
    except http.exceptions.RequestException as exc:
        return {
            "status_code": None,
            "response_json": {"error": str(exc)},
            "attack_type": "session_id_replay_without_proof",
            "description": "HTTP request failed — server may not be running.",
            "cookies_sent": ["sid"],
            "success": False,
        }


def run_legitimate_request(
    base_url: str,
    session_id: str,
    proof_token: str,
) -> dict:
    """
    Perform an authenticated request as the legitimate user (both cookies).

    Used to verify that the session works BEFORE and that it is rejected
    AFTER revocation.
    """
    _assert_local(base_url)

    target_url = base_url.rstrip("/") + _PROTECTED_PATH
    cookies = {"sid": session_id, "sproof": proof_token}

    try:
        resp = http.get(target_url, cookies=cookies, timeout=5, allow_redirects=False)
        return {
            "status_code": resp.status_code,
            "response_json": _safe_json(resp),
            "description": "Legitimate user request with both session ID and proof token.",
            "cookies_sent": ["sid (session identifier)", "sproof (proof token — MASKED)"],
        }
    except http.exceptions.RequestException as exc:
        return {
            "status_code": None,
            "response_json": {"error": str(exc)},
            "description": "HTTP request failed.",
            "cookies_sent": [],
        }


def _safe_json(response) -> dict:
    """Parse JSON response safely; return an error dict on failure."""
    try:
        return response.json()
    except Exception:
        return {"raw": response.text[:200]}
