from unittest.mock import patch

import pytest
from sqlalchemy.exc import IntegrityError

from backend.app import app
from backend.models import Tab


@pytest.fixture(autouse=True)
def disable_csrf(monkeypatch):
    """Disable CSRF protection for these tests."""
    monkeypatch.setitem(app.config, "WTF_CSRF_ENABLED", False)


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
    # Create first tab and verify it succeeds
    setup_response = client.post("/api/tabs", json={"name": "Duplicate Tab"})
    assert setup_response.status_code == 201, (
        "Setup failed: could not create initial tab")

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
    fake_integrity_error = IntegrityError(
        "INSERT...", {}, Exception("UNIQUE constraint failed: tabs.name"))

    with (
            patch(
                "backend.blueprints.tabs.db.session.commit",
                side_effect=fake_integrity_error,
            ) as mock_commit,
            patch("backend.blueprints.tabs.db.session.rollback") as
            mock_rollback,
    ):
        response = client.post("/api/tabs", json={"name": tab_name})

        assert response.status_code == 409
        assert "already exists" in response.get_json()["error"]

        mock_commit.assert_called_once()
        mock_rollback.assert_called_once()
