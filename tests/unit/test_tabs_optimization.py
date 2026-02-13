import os
import unittest
from sqlalchemy import event
from backend.app import app, db
from backend.models import Tab, Feed, FeedItem

class TestTabsOptimization(unittest.TestCase):
    def setUp(self):
        # Ensure TESTING is set
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        app.config['CACHE_TYPE'] = 'SimpleCache'

        self.client = app.test_client()
        self.app_context = app.app_context()
        self.app_context.push()
        db.create_all()

        # Create data: 5 tabs, 2 feeds each, 3 items each
        for i in range(5):
            tab = Tab(name=f"Tab {i}", order=i)
            db.session.add(tab)
            db.session.flush() # get ID

            feed = Feed(tab_id=tab.id, name=f"Feed {i}", url=f"http://example.com/{i}")
            db.session.add(feed)
            db.session.flush()

            for j in range(3):
                item = FeedItem(feed_id=feed.id, title=f"Item {j}", link=f"http://example.com/{i}/{j}", is_read=False)
                db.session.add(item)

        db.session.commit()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_get_tabs_query_count(self):
        """
        Verify that fetching tabs performs a constant number of queries
        regardless of the number of tabs (N+1 prevention).
        """
        query_count = 0

        def before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
            nonlocal query_count
            query_count += 1

        event.listen(db.engine, "before_cursor_execute", before_cursor_execute)

        response = self.client.get('/api/tabs')
        self.assertEqual(response.status_code, 200)

        # Expected: 1 query for tabs + 1 query for unread counts = 2 queries total.
        # We allow a small margin for potential future changes (e.g. auth checks),
        # but anything >= 5 (number of tabs) would indicate N+1.
        self.assertLess(query_count, 4, f"Too many queries executed: {query_count}. N+1 optimization might be broken.")

        # Also verify the data is correct
        data = response.get_json()
        self.assertEqual(len(data), 5)
        for tab in data:
            # Each tab has 1 feed with 3 unread items
            self.assertEqual(tab['unread_count'], 3)

if __name__ == '__main__':
    unittest.main()
