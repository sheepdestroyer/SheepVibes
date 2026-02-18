import os
import unittest
from unittest.mock import patch, MagicMock

# Set testing environment before import to prevent scheduler start
os.environ['TESTING'] = 'true'

from backend.app import app, db
from backend.models import Feed, Tab

class TestFeedStoredXSS(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        self.client = app.test_client()
        self.app_context = app.app_context()
        self.app_context.push()
        db.create_all()

        # Create a default tab
        self.tab = Tab(name="Default", order=0)
        db.session.add(self.tab)
        db.session.commit()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    @patch('backend.blueprints.feeds.fetch_feed')
    def test_add_feed_with_javascript_scheme(self, mock_fetch_feed):
        # mock fetch_feed to return None, as it would for invalid scheme
        mock_fetch_feed.return_value = None

        payload = {
            "url": "javascript:alert(1)",
            "tab_id": self.tab.id
        }

        response = self.client.post('/api/feeds', json=payload)

        # Assert that the request was rejected
        self.assertEqual(response.status_code, 400)
        self.assertIn("Invalid feed URL scheme", response.get_json()['error'])

        # Verify no feed was created
        feeds = Feed.query.all()
        self.assertEqual(len(feeds), 0)

    @patch('backend.blueprints.feeds.fetch_feed')
    def test_update_feed_with_javascript_scheme(self, mock_fetch_feed):
        # Create a valid feed first
        feed = Feed(name="Valid", url="http://example.com", tab_id=self.tab.id)
        db.session.add(feed)
        db.session.commit()

        mock_fetch_feed.return_value = None

        payload = {
            "url": "javascript:alert(1)"
        }

        response = self.client.put(f'/api/feeds/{feed.id}', json=payload)

        # Assert that the request was rejected
        self.assertEqual(response.status_code, 400)
        self.assertIn("Invalid feed URL scheme", response.get_json()['error'])

        # Verify feed was not updated
        updated_feed = db.session.get(Feed, feed.id)
        self.assertEqual(updated_feed.url, "http://example.com")
