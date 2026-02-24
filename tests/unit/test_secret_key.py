import os
import pytest
from backend.app import app

def test_secret_key_is_set():
    """Test that SECRET_KEY is set in the application configuration."""
    # SECRET_KEY is set during app initialization in backend/app.py
    secret_key = app.config.get("SECRET_KEY")
    assert secret_key is not None, "SECRET_KEY should be set in app.config"
    assert secret_key != "", "SECRET_KEY should not be an empty string"

def test_secret_key_value():
    """Test that SECRET_KEY matches the environment variable if set, or uses default."""
    expected_key = os.environ.get("SECRET_KEY", "dev-secret-key")
    assert app.config["SECRET_KEY"] == expected_key
