"""
app/auth.py — Authentication module.

Handles credential validation and login / logout flows.
"""
from typing import Optional, Tuple

from app.models import get_db, verify_password


def authenticate_user(
    db_path: str,
    username: str,
    password: str,
) -> Tuple[bool, Optional[int], Optional[str]]:
    """
    Validate username + password.

    Returns
    -------
    (success, user_id, role)
        success : bool
        user_id : int or None
        role    : str or None
    """
    if not username or not password:
        return False, None, None

    conn = get_db(db_path)
    try:
        row = conn.execute(
            "SELECT id, password_hash, role FROM users WHERE username = ?",
            (username,),
        ).fetchone()
    finally:
        conn.close()

    if row is None:
        # Perform a dummy hash to prevent username-enumeration via timing
        verify_password(password, "$argon2id$v=19$m=65536,t=2,p=2$dummysaltdummysa$dummyhashvalue00000000000000000000000000000")
        return False, None, None

    if verify_password(password, row["password_hash"]):
        return True, row["id"], row["role"]

    return False, None, None


def get_user_by_id(db_path: str, user_id: int) -> Optional[dict]:
    """Return safe user metadata (no password hash)."""
    conn = get_db(db_path)
    try:
        row = conn.execute(
            "SELECT id, username, role, created_at FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
    finally:
        conn.close()

    if row is None:
        return None
    return dict(row)
