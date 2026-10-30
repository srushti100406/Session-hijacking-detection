"""
config.py — Application configuration for Session Hijacking Detection & Prevention System.
"""
import os
import secrets


class Config:
    # Flask secret key for server-side session signing
    SECRET_KEY = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

    # Session proof HMAC key — separate from Flask secret key
    SESSION_PROOF_KEY = os.environ.get("SESSION_PROOF_KEY") or secrets.token_hex(32)

    # SQLite database path
    DATABASE_PATH = os.environ.get(
        "DATABASE_PATH",
        os.path.join(os.path.dirname(__file__), "session_hijack_demo.db"),
    )

    # Session lifetime in seconds (30 minutes for demo)
    SESSION_LIFETIME_SECONDS = 1800

    # Cookie settings
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.environ.get(
        "SESSION_COOKIE_SECURE", "false"
    ).lower() in {"1", "true", "yes"}

    # Simulator target configuration. Localhost is the development default.
    SIMULATOR_PORT = int(os.environ.get("PORT", 5000))
    SIMULATOR_BASE_URL = os.environ.get(
        "SIMULATOR_BASE_URL",
        f"http://127.0.0.1:{SIMULATOR_PORT}",
    )
    SIMULATOR_ALLOWED_ORIGIN = os.environ.get(
        "SIMULATOR_ALLOWED_ORIGIN",
        SIMULATOR_BASE_URL,
    )

    # Log level
    LOG_LEVEL = "INFO"


class TestingConfig(Config):
    TESTING = True
    DATABASE_PATH = ":memory:"
    SIMULATOR_BASE_URL = None
    SIMULATOR_ALLOWED_ORIGIN = None
    # Use a fixed key for reproducible tests
    SECRET_KEY = "test-secret-key-not-for-production"
    SESSION_PROOF_KEY = "test-proof-key-not-for-production"
    SESSION_LIFETIME_SECONDS = 60
    WTF_CSRF_ENABLED = False
