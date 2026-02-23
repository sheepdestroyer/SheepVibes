from unittest.mock import patch

import pytest
from sqlalchemy.exc import IntegrityError

from backend.app import app, db
from backend.models import Tab


@pytest.fixture(autouse=True)
def disable_csrf():
    """Disable CSRF protection for these tests."""
    original_value = app.config.get("WTF_CSRF_ENABLED")
    app.config["WTF_CSRF_ENABLED"] = False
    yield
    if original_value is not None:
        app.config["WTF_CSRF_ENABLED"] = original_value
    else:
        app.config.pop("WTF_CSRF_ENABLED", None)


def test_create_tab_success(client):
    """Test successful creation of a new tab."""
    response = client.post("/api/tabs", json={"name": "New Tab"})
    assert response.status_code == 201
    data = response.get_json()
    assert data["name"] == "New Tab"
    assert "id" in data

    # Verify in DB
    tab = Tab.query.filter_by(name="New Tab").first()
    assert tab is not None
    assert tab.name == "New Tab"


def test_create_tab_duplicate_name(client):
    """Test creating a tab with a duplicate name (application-level check)."""
    # Create first tab
    client.post("/api/tabs", json={"name": "Duplicate Tab"})

    # Try to create second tab with same name
    response = client.post("/api/tabs", json={"name": "Duplicate Tab"})
    assert response.status_code == 409
    assert "already exists" in response.get_json()["error"]


def test_create_tab_race_condition_integrity_error(client):
    """
    Test handling of IntegrityError during tab creation to simulate a race condition.
    Mock db.session.commit to raise IntegrityError after the initial check passes.
    """
    tab_name = "Race Condition Tab"

    # We need to ensure the initial check (Tab.query.filter_by...) passes (returns None),
    # so we don't create the tab beforehand.

    # Mock db.session.commit to raise IntegrityError
    # The IntegrityError constructor requires arguments, usually (statement, params, orig)
    # But for testing the except block, just the type or a basic instance is often enough.
    # However, SQLAlchemy's IntegrityError requires arguments in __init__.
    # A simpler way is to use a MagicMock that raises the exception class if possible,
    # or instantiate it with dummy values.

    # Using a side_effect with an instance of IntegrityError
    fake_integrity_error = IntegrityError("INSERT...", {}, "orig")

    with patch(
        "backend.blueprints.tabs.db.session.commit", side_effect=fake_integrity_error
    ) as mock_commit:
        # Also verify rollback is called
        with patch("backend.blueprints.tabs.db.session.rollback") as mock_rollback:
            response = client.post("/api/tabs", json={"name": tab_name})

            assert response.status_code == 409
            assert "already exists" in response.get_json()["error"]

            # Verify commit was attempted
            mock_commit.assert_called_once()

            # Verify rollback was called
            mock_rollback.assert_called_once()
