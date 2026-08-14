import pytest
from unittest.mock import MagicMock, patch

from backend.app import db
from backend.feed_service import _process_fetch_result
from backend.models import Feed, Tab


def test_process_fetch_result_prevents_detached_instance_error_on_rollback(client):
    """
    Verify that _process_fetch_result returns tab_id successfully and does not
    raise DetachedInstanceError when process_feed_entries raises an exception
    and triggers a db.session.rollback().
    """
    tab = Tab(name="Test Tab Rollback", order=1)
    db.session.add(tab)
    db.session.commit()

    feed = Feed(name="Test Feed", url="http://example.com/rss", tab_id=tab.id)
    db.session.add(feed)
    db.session.commit()

    tab_id = tab.id
    parsed_feed = MagicMock()
    parsed_feed.entries = ["entry1"]

    with patch("backend.feed_service.process_feed_entries", side_effect=Exception("DB Processing Error")):
        success, new_items, returned_tab_id = _process_fetch_result(feed, parsed_feed)

    assert success is False
    assert new_items == 0
    assert returned_tab_id == tab_id


def test_delete_tab_invalidates_tab_feeds_cache(client):
    """
    Verify that deleting a tab calls invalidate_tab_feeds_cache(tab_id, invalidate_tabs=False).
    """
    tab = Tab(name="Tab to Delete", order=1)
    db.session.add(tab)
    db.session.commit()
    tab_id = tab.id

    with patch("backend.blueprints.tabs.invalidate_tab_feeds_cache") as mock_invalidate_tab_feeds, \
         patch("backend.blueprints.tabs.invalidate_tabs_cache") as mock_invalidate_tabs:
        response = client.delete(f"/api/tabs/{tab_id}")

    assert response.status_code == 200
    mock_invalidate_tab_feeds.assert_called_once_with(tab_id, user_id=1, invalidate_tabs=False)
    mock_invalidate_tabs.assert_called_once()


def test_create_and_process_feed_returns_accurate_unread_count(client, mock_dns):
    """
    Verify that creating a feed with new items returns the actual unread count
    in the JSON response instead of hardcoded 0.
    """
    tab = Tab(name="Tab for Feed Creation", order=1)
    db.session.add(tab)
    db.session.commit()

    parsed_feed_mock = MagicMock()

    with patch("backend.blueprints.feeds._get_feed_metadata", return_value=("New Feed Name", "http://example.com", parsed_feed_mock)), \
         patch("backend.blueprints.feeds.process_feed_entries", return_value=5):
        
        response = client.post(
            "/api/feeds",
            json={
                "url": "http://example.com/rss",
                "tab_id": tab.id
            }
        )

    assert response.status_code == 201
    data = response.get_json()
    assert data["unread_count"] == 5
