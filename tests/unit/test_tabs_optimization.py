from sqlalchemy import event

from backend.app import db
from backend.models import Feed, FeedItem, Tab


def test_get_tabs_query_count_constant(client):
    """
    Verify that get_tabs endpoint executes a constant number of queries
    regardless of the number of tabs (optimizing N+1 problem).
    """

    # Helper to create tabs
    def create_tabs(start_index, count):
        for i in range(start_index, start_index + count):
            tab = Tab(name=f"Tab {i}", order=i)
            db.session.add(tab)
            db.session.flush()

            feed = Feed(tab_id=tab.id,
                        name=f"Feed {i}",
                        url=f"http://example.com/{i}")
            db.session.add(feed)
            db.session.flush()

            item = FeedItem(
                feed_id=feed.id,
                title=f"Item {i}",
                link=f"http://example.com/{i}/item",
                guid=f"guid-{i}",
            )
            db.session.add(item)
        db.session.commit()

    # Helper to count queries
    def get_query_count():
        query_count = [0]

        def before_cursor_execute(conn, cursor, statement, parameters, context,
                                  executemany):
            query_count[0] += 1

        event.listen(db.engine, "before_cursor_execute", before_cursor_execute)
        try:
            response = client.get("/api/tabs")
            assert response.status_code == 200
        finally:
            event.remove(db.engine, "before_cursor_execute",
                         before_cursor_execute)
        return query_count[0]

    # Phase 1: 1 Tab
    create_tabs(0, 1)
    count_1 = get_query_count()

    # Phase 2: 5 Tabs (Total 6)
    create_tabs(1, 5)
    count_n = get_query_count()

    print(f"Queries for 1 tab: {count_1}")
    print(f"Queries for 6 tabs: {count_n}")

    # Assert constant queries
    # It should be exactly the same, but <= is safe for optimization check
    assert count_n <= count_1, f"Query count increased from {count_1} to {count_n}!"
    assert count_n <= 2, f"Expected <= 2 queries, got {count_n}"
