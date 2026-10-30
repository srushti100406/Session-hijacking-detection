"""
app/session_manager.py — Session creation, validation, revocation, and expiry.

Design
------
Every authenticated session uses TWO server-side credentials:

  1. session_id  — a 32-byte cryptographically random identifier stored in
                   the 'sid' cookie. It locates the session record in the DB.

  2. proof_token — an HMAC-SHA256 value stored in the 'sproof' cookie.
                   It is computed as:
                       HMAC-SHA256(SESSION_PROOF_KEY,
                                   session_id + ":" + str(user_id) + ":" + created_at)
                   The server recomputes this on every request and compares it
                   to the stored value using a constant-time comparison.

Attack simulation
-----------------
The controlled demo gives the attacker only the session_id (the 'sid' cookie).
A request that presents a valid session_id but a missing or incorrect
proof_token is treated as a SUSPICIOUS REPLAY ATTEMPT and triggers detection.

Limitation (documented)
-----------------------
If an attacker steals BOTH cookies, this mechanism cannot detect the replay.
This is acknowledged in the UI and README. Additional controls such as
per-request CSRF tokens, TLS-bound tokens, or device fingerprinting are
outside the scope of this educational prototype.

Thread safety
-------------
Each request opens its own DB connection. The WAL journal mode and atomic
SQL UPDATE WHERE clauses ensure that revocation is consistent even under
concurrent requests.
"""
import hmac
import hashlib
import secrets
from datetime import datetime, timezone, timedelta
from typing import Optional, Tuple

from app.models import get_db, session_fingerprint as _fp


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _compute_proof(proof_key: str, session_id: str, user_id: int, created_at: str) -> str:
    """
    Derive the proof token using HMAC-SHA256.
    The proof is NOT simply the session ID — it binds the session ID to the
    user identity and creation time, so it cannot be forged without the key.
    """
    message = f"{session_id}:{user_id}:{created_at}".encode()
    return hmac.new(proof_key.encode(), message, hashlib.sha256).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_dt(iso: str) -> datetime:
    return datetime.fromisoformat(iso)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def _create_session(
    db_path: str,
    proof_key: str,
    user_id: int,
    lifetime_seconds: int,
    is_test_session: bool,
) -> Tuple[str, str]:
    """
    Create a new server-side session for the given user.

    Returns
    -------
    (session_id, proof_token)
        Both values must be set as separate cookies by the caller.
        The proof_token is stored in the DB; it is also returned so the
        caller can set the sproof cookie.
    """
    session_id = secrets.token_hex(32)    # 256-bit random identifier
    created_at = _now()
    expires_at = (
        datetime.now(timezone.utc) + timedelta(seconds=lifetime_seconds)
    ).isoformat()
    proof_token = _compute_proof(proof_key, session_id, user_id, created_at)

    conn = get_db(db_path)
    try:
        conn.execute(
            """INSERT INTO sessions
               (session_id, user_id, proof_token, created_at, expires_at, revoked,
                is_test_session)
               VALUES (?, ?, ?, ?, ?, 0, ?)""",
            (
                session_id,
                user_id,
                proof_token,
                created_at,
                expires_at,
                int(is_test_session),
            ),
        )
        conn.commit()
    finally:
        conn.close()

    return session_id, proof_token


def create_session(
    db_path: str,
    proof_key: str,
    user_id: int,
    lifetime_seconds: int,
) -> Tuple[str, str]:
    """Create a regular authenticated session."""
    return _create_session(db_path, proof_key, user_id, lifetime_seconds, False)


def create_test_session(
    db_path: str,
    proof_key: str,
    user_id: int,
    lifetime_seconds: int,
) -> Tuple[str, str]:
    """Create a session eligible for the controlled demo replay flow."""
    return _create_session(db_path, proof_key, user_id, lifetime_seconds, True)


class ValidationResult:
    """Structured result returned by validate_session()."""

    def __init__(
        self,
        valid: bool,
        user_id: Optional[int] = None,
        username: Optional[str] = None,
        reason: Optional[str] = None,
        suspicious: bool = False,
        fingerprint: Optional[str] = None,
        is_test_session: bool = False,
    ):
        self.valid = valid
        self.user_id = user_id
        self.username = username
        self.reason = reason
        self.suspicious = suspicious
        self.fingerprint = fingerprint
        self.is_test_session = is_test_session

    def __repr__(self):
        return (
            f"ValidationResult(valid={self.valid}, suspicious={self.suspicious}, "
            f"reason={self.reason!r}, user={self.username!r})"
        )


def validate_session(
    db_path: str,
    proof_key: str,
    session_id: Optional[str],
    proof_token: Optional[str],
) -> ValidationResult:
    """
    Validate a session request.

    Decision tree
    -------------
    1. If session_id is absent → INVALID (no session).
    2. Look up session record → INVALID if not found.
    3. If revoked → INVALID (revoked session access).
    4. If expired → INVALID.
    5. Recompute expected proof; compare with provided proof_token:
       - Token absent or mismatched → SUSPICIOUS replay attempt.
       - Token matches → VALID.
    """
    if not session_id:
        return ValidationResult(valid=False, reason="no_session_id")

    conn = get_db(db_path)
    try:
        row = conn.execute(
            """SELECT s.session_id, s.user_id, s.proof_token, s.created_at,
                      s.expires_at, s.revoked, s.is_test_session, u.username
               FROM sessions s
               JOIN users u ON u.id = s.user_id
               WHERE s.session_id = ?""",
            (session_id,),
        ).fetchone()
    finally:
        conn.close()

    if row is None:
        return ValidationResult(valid=False, reason="session_not_found")

    fp = _fp(session_id)

    if row["revoked"]:
        return ValidationResult(
            valid=False,
            reason="session_revoked",
            fingerprint=fp,
            user_id=row["user_id"],
            username=row["username"],
        )

    now = datetime.now(timezone.utc)
    expires_at = _parse_dt(row["expires_at"])
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if now > expires_at:
        return ValidationResult(
            valid=False,
            reason="session_expired",
            fingerprint=fp,
            user_id=row["user_id"],
            username=row["username"],
        )

    # Recompute expected proof
    expected_proof = _compute_proof(
        proof_key, session_id, row["user_id"], row["created_at"]
    )

    if not proof_token or not hmac.compare_digest(proof_token, expected_proof):
        # Suspicious: session ID present but proof missing or wrong
        return ValidationResult(
            valid=False,
            suspicious=True,
            reason="proof_token_invalid_or_missing",
            fingerprint=fp,
            user_id=row["user_id"],
            username=row["username"],
        )

    return ValidationResult(
        valid=True,
        user_id=row["user_id"],
        username=row["username"],
        fingerprint=fp,
        is_test_session=bool(row["is_test_session"]),
    )


def revoke_session(
    db_path: str,
    session_id: str,
    reason: str,
) -> bool:
    """
    Atomically revoke a session.

    Uses a WHERE revoked=0 guard so a session cannot be un-revoked by a
    concurrent race condition. Returns True if the row was actually updated.
    """
    conn = get_db(db_path)
    try:
        cursor = conn.execute(
            """UPDATE sessions
               SET revoked=1, revoke_reason=?, revoked_at=?
               WHERE session_id=? AND revoked=0""",
            (reason, _now(), session_id),
        )
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()


def expire_all_user_sessions(db_path: str, user_id: int) -> int:
    """
    Revoke all active sessions for a user (e.g., on logout).
    Returns the number of sessions revoked.
    """
    conn = get_db(db_path)
    try:
        cursor = conn.execute(
            """UPDATE sessions
               SET revoked=1, revoke_reason='logout', revoked_at=?
               WHERE user_id=? AND revoked=0""",
            (_now(), user_id),
        )
        conn.commit()
        return cursor.rowcount
    finally:
        conn.close()


def get_session_status(db_path: str, session_id: str) -> Optional[dict]:
    """Return session metadata for display (no tokens exposed)."""
    conn = get_db(db_path)
    try:
        row = conn.execute(
            """SELECT session_id, user_id, created_at, expires_at,
                      revoked, revoke_reason, revoked_at
               FROM sessions WHERE session_id=?""",
            (session_id,),
        ).fetchone()
    finally:
        conn.close()

    if row is None:
        return None

    return {
        "fingerprint": _fp(row["session_id"]),
        "user_id": row["user_id"],
        "created_at": row["created_at"],
        "expires_at": row["expires_at"],
        "revoked": bool(row["revoked"]),
        "revoke_reason": row["revoke_reason"],
        "revoked_at": row["revoked_at"],
    }
