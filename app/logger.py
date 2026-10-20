"""
app/logger.py — Security event logger.

Records security-relevant events to the database and (optionally) stdout.
Never logs raw session tokens, proof credentials, or passwords.
User-controlled data is sanitised before storage to prevent log injection.
"""
import re
import logging
from datetime import datetime, timezone
from typing import Optional

_LOG = logging.getLogger("security")


def _sanitise(value: Optional[str]) -> Optional[str]:
    """Strip control characters and newlines to prevent log injection."""
    if value is None:
        return None
    cleaned = re.sub(r"[\x00-\x1f\x7f]", " ", str(value))
    return cleaned[:512]   # Cap length to limit DoS via huge strings


def record_event(
    conn,
    event_type: str,
    *,
    user_id: Optional[int] = None,
    username: Optional[str] = None,
    session_fingerprint: Optional[str] = None,
    reason: Optional[str] = None,
    action_taken: Optional[str] = None,
    outcome: Optional[str] = None,
    ip_address: Optional[str] = None,
    extra_info: Optional[str] = None,
) -> int:
    """
    Insert a security event row and return its row ID.

    Parameters
    ----------
    conn : sqlite3.Connection
    event_type : str
        One of: LOGIN_SUCCESS, LOGIN_FAILURE, SESSION_CREATED,
        REPLAY_ATTEMPT, DETECTION_TRIGGERED, REQUEST_REJECTED,
        SESSION_REVOKED, REVOKED_SESSION_ACCESS, LOGOUT,
        SESSION_EXPIRED, DEMO_RESET.
    """
    now = datetime.now(timezone.utc).isoformat()

    # Sanitise user-supplied fields
    safe_username = _sanitise(username)
    safe_reason = _sanitise(reason)
    safe_action = _sanitise(action_taken)
    safe_outcome = _sanitise(outcome)
    safe_ip = _sanitise(ip_address)
    safe_extra = _sanitise(extra_info)
    safe_fingerprint = _sanitise(session_fingerprint)

    cursor = conn.execute(
        """INSERT INTO security_events
           (timestamp, event_type, user_id, username, session_fingerprint,
            reason, action_taken, outcome, ip_address, extra_info)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            now, event_type, user_id, safe_username, safe_fingerprint,
            safe_reason, safe_action, safe_outcome, safe_ip, safe_extra,
        ),
    )
    conn.commit()

    _LOG.info(
        "[%s] event=%s user=%s fingerprint=%s reason=%s outcome=%s",
        now, event_type, safe_username, safe_fingerprint, safe_reason, safe_outcome,
    )

    return cursor.lastrowid


def get_recent_events(conn, limit: int = 50) -> list[dict]:
    """Return the most recent security events as a list of dicts (safe for JSON)."""
    rows = conn.execute(
        """SELECT id, timestamp, event_type, username, session_fingerprint,
                  reason, action_taken, outcome, ip_address, extra_info
           FROM security_events
           ORDER BY id DESC
           LIMIT ?""",
        (limit,),
    ).fetchall()
    return [dict(r) for r in rows]
