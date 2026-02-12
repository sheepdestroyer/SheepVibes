import os
import sys
import unittest
from backend.app import app, db
from backend.models import Tab, Feed, FeedItem
from sqlalchemy import event

class TestTabOptimization(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.app = app
        self.client = self.app.test_client()
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()

        # Create test data
        for i in range(5):
            tab = Tab(name=f"Tab {i}", order=i)
            db.session.add(tab)
            db.session.flush()

            feed = Feed(tab_id=tab.id, name=f"Feed {i}", url=f"http://example.com/{i}")
            db.session.add(feed)
            db.session.flush()

            for j in range(3):
                item = FeedItem(feed_id=feed.id, title=f"Item {j}", link=f"http://example.com/{i}/{j}")
                db.session.add(item)

        db.session.commit()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_get_tabs_query_count(self):
        # Count queries executed during get_tabs
        query_count = 0

        def before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
            nonlocal query_count
            query_count += 1
            # print(f"Query: {statement}")

        event.listen(db.engine, "before_cursor_execute", before_cursor_execute)

        response = self.client.get('/api/tabs')
        self.assertEqual(response.status_code, 200)

        print(f"Total queries: {query_count}")

        # Verify optimization: Should be 2 queries (1 for tabs, 1 for counts)
        self.assertEqual(query_count, 2, "Expected exactly 2 queries for get_tabs")

        event.remove(db.engine, "before_cursor_execute", before_cursor_execute)

if __name__ == '__main__':
    unittest.main()
