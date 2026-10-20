"""
tests/conftest.py — Shared pytest fixtures.
"""
import os
import tempfile
import pytest
from app import create_app
from config import TestingConfig
from app.models import init_db


@pytest.fixture(scope="function")
def app():
    """
    Fresh Flask app instance with a temporary file-based SQLite DB for each test.

    We use a temporary file (not :memory:) because each call to get_db()
    opens a new connection, and SQLite :memory: databases are not shared
    across separate connections.
    """
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(db_fd)

    class FunctionTestingConfig(TestingConfig):
        DATABASE_PATH = db_path

    application = create_app(FunctionTestingConfig)
    application.config["TESTING"] = True
    application.config["SIMULATOR_PORT"] = 5000

    # init_db is called inside create_app; no need to call again
    yield application

    # Cleanup
    try:
        os.unlink(db_path)
    except OSError:
        pass


@pytest.fixture(scope="function")
def client(app):
    """Test client attached to the fresh app."""
    return app.test_client()


@pytest.fixture(scope="function")
def db_path(app):
    return app.config["DATABASE_PATH"]


@pytest.fixture(scope="function")
def proof_key(app):
    return app.config["SESSION_PROOF_KEY"]
