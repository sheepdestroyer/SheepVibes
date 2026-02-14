from sqlalchemy import event
from backend.app import db
from backend.models import Tab, Feed, FeedItem

def test_get_tabs_query_count(client):
    """
    Verify that get_tabs endpoint executes a constant number of queries
    regardless of the number of tabs (optimizing N+1 problem).
    """
    # Create N tabs
    num_tabs = 5
    for i in range(num_tabs):
        tab = Tab(name=f"Tab {i}", order=i)
        db.session.add(tab)
        db.session.flush() # flush to get ID

        # Add a feed to each tab
        feed = Feed(tab_id=tab.id, name=f"Feed {i}", url=f"http://example.com/{i}")
        db.session.add(feed)
        db.session.flush()

        # Add an item to each feed
        item = FeedItem(feed_id=feed.id, title=f"Item {i}", link=f"http://example.com/{i}/item", guid=f"guid-{i}")
        db.session.add(item)

    db.session.commit()

    # Count queries
    query_count = [0] # use list to allow modification in closure

    # Define listener
    def before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
        query_count[0] += 1

    event.listen(db.engine, "before_cursor_execute", before_cursor_execute)

    try:
        # Call the endpoint
        response = client.get("/api/tabs")
        assert response.status_code == 200

        print(f"Number of queries for {num_tabs} tabs: {query_count[0]}")

        # Expected: 2 queries (one for tabs, one for counts)
        # N+1 would be 6 queries

        # Assert optimization
        assert query_count[0] <= 2, f"Expected <= 2 queries, but got {query_count[0]}"

    finally:
        # Remove listener to avoid affecting other tests
        event.remove(db.engine, "before_cursor_execute", before_cursor_execute)
