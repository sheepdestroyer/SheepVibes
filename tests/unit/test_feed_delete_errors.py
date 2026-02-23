from unittest.mock import patch
from backend.models import Feed, Tab, db
from backend.app import app

def test_delete_feed_exception(client):
    """Test that delete_feed handles exceptions during deletion gracefully."""
    # 1. Setup: Create a Tab and a Feed
    with app.app_context():
        tab = Tab(name="Test Tab")
        db.session.add(tab)
        db.session.commit()

        feed = Feed(name="Test Feed", url="http://example.com/feed", tab_id=tab.id)
        db.session.add(feed)
        db.session.commit()
        feed_id = feed.id

    # 2. Mock db.session.commit to raise an exception
    # We patch the commit method on the session object used by the feeds blueprint.
    with patch('backend.blueprints.feeds.db.session.commit', side_effect=Exception("Database error")):
        # We also want to verify rollback is called.
        with patch('backend.blueprints.feeds.db.session.rollback') as mock_rollback:
            # 3. Call DELETE /api/feeds/<feed_id>
            response = client.delete(f'/api/feeds/{feed_id}')

            # 4. Assert response
            assert response.status_code == 500
            assert response.json['error'] == "An internal error occurred while deleting the feed."

            # 5. Verify rollback was called
            mock_rollback.assert_called_once()
