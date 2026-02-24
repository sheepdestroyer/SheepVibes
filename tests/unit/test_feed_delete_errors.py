from unittest.mock import patch

from backend.app import app
from backend.models import Feed, Tab, db


def test_delete_feed_exception(client):
    """Test that delete_feed handles exceptions during deletion gracefully."""
    # 1. Setup: Create a Tab and a Feed in a single transaction
    with app.app_context():
        tab = Tab(name="Test Tab")
        feed = Feed(name="Test Feed", url="http://example.com/feed", tab=tab)
        db.session.add(feed)
        db.session.commit()
        feed_id = feed.id

    # 2. Mock db.session.commit to raise an exception
    # We patch the commit method on the session object used by the feeds blueprint.
    with patch(
            "backend.blueprints.feeds.db.session.commit",
            side_effect=Exception("Database error"),
    ):
        # Spy on rollback using wraps to preserve real behavior while
        # allowing call-count assertions.
        with patch(
                "backend.blueprints.feeds.db.session.rollback",
                wraps=db.session.rollback,
        ) as mock_rollback:
            # 3. Call DELETE /api/feeds/<feed_id>
            response = client.delete(f"/api/feeds/{feed_id}")

            # 4. Assert response
            assert response.status_code == 500
            assert (response.json["error"] ==
                    "An internal error occurred while deleting the feed.")

            # 5. Verify rollback and database state
            mock_rollback.assert_called_once()
            feed_after_delete = db.session.get(Feed, feed_id)
            assert feed_after_delete is not None, (
                "Feed should not be deleted on commit failure.")
