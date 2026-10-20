"""
app/models.py — Database models and schema management.

Provides SQLite-backed storage for demo users and security events.
Uses argon2id for password hashing (OWASP recommended).
"""
import sqlite3
import hashlib
import time
from datetime import datetime, timezone
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

# Global password hasher — argon2id with OWASP-recommended parameters
_ph = PasswordHasher(
    time_cost=2,        # iterations
    memory_cost=65536,  # 64 MB
    parallelism=2,
    hash_len=32,
    salt_len=16,
)


def get_db(db_path: str) -> sqlite3.Connection:
    """Return a SQLite connection with row_factory set for dict-like access."""
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")   # Better concurrency
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db(db_path: str) -> None:
    """Create tables and seed the demo user if they do not already exist."""
    conn = get_db(db_path)
    try:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                username    TEXT    NOT NULL UNIQUE,
                password_hash TEXT  NOT NULL,
                role        TEXT    NOT NULL DEFAULT 'user',
                created_at  TEXT    NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sessions (
                session_id      TEXT PRIMARY KEY,
                user_id         INTEGER NOT NULL,
                proof_token     TEXT    NOT NULL,
                created_at      TEXT    NOT NULL,
                expires_at      TEXT    NOT NULL,
                revoked         INTEGER NOT NULL DEFAULT 0,
                revoke_reason   TEXT,
                revoked_at      TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS security_events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT    NOT NULL,
                event_type  TEXT    NOT NULL,
                user_id     INTEGER,
                username    TEXT,
                session_fingerprint TEXT,
                reason      TEXT,
                action_taken TEXT,
                outcome     TEXT,
                ip_address  TEXT,
                extra_info  TEXT
            );
        """)

        # Seed demo user (password: Demo@1234)
        existing = conn.execute(
            "SELECT id FROM users WHERE username = ?", ("alice",)
        ).fetchone()
        if not existing:
            pw_hash = _ph.hash("Demo@1234")
            conn.execute(
                """INSERT INTO users (username, password_hash, role, created_at)
                   VALUES (?, ?, ?, ?)""",
                ("alice", pw_hash, "user", _now()),
            )
            conn.commit()
    finally:
        conn.close()


def verify_password(plain: str, hashed: str) -> bool:
    """Verify a plaintext password against an argon2id hash. Returns True on match."""
    try:
        _ph.verify(hashed, plain)
        return True
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def hash_password(plain: str) -> str:
    """Hash a plaintext password using argon2id."""
    return _ph.hash(plain)


def session_fingerprint(session_id: str) -> str:
    """
    Return a short, non-reversible fingerprint of the session ID for safe display/logging.
    Never logs the raw session ID.
    """
    digest = hashlib.sha256(session_id.encode()).hexdigest()
    return f"fp:{digest[:12]}"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
