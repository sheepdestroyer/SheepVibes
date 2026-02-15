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
            # Use relationship assignment
            feed = Feed(name=f"Feed {i}",
                        url=f"http://example.com/{i}",
                        tab=tab)
            item = FeedItem(
                title=f"Item {i}",
                link=f"http://example.com/{i}/item",
                guid=f"guid-{i}",
                feed=feed,
            )
            db.session.add(tab)
            db.session.add(feed)
            db.session.add(item)
        db.session.commit()

    # Helper to count queries
    def get_query_count():
        from backend.extensions import cache

        cache.clear()

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
    # It should be exactly the same
    assert count_n == count_1, f"Query count changed from {count_1} to {count_n}!"
    assert count_n <= 2, f"Expected <= 2 queries, got {count_n}"


def test_tab_to_dict_optimization(client):
    """
    Verify Tab.to_dict respects the unread_count override and does not issue
    an extra unread-count query when the override is provided.
    """
    # client fixture ensures app context and db structure

    # Build a tab with a related feed and item
    tab = Tab(name="Tab for to_dict", order=100)
    feed = Feed(name="Feed 1", url="http://example.com/feed-1", tab=tab)
    item = FeedItem(title="Item 1",
                    link="http://example.com/item-1",
                    feed=feed,
                    guid="guid-to-dict")

    db.session.add(tab)
    db.session.add(feed)
    db.session.add(item)
    db.session.commit()

    # Ensure tab attributes are loaded so access in to_dict doesn't trigger a refresh query
    # resulting from expire_on_commit=True (default)
    db.session.refresh(tab)

    # Count SQL queries executed during to_dict with an unread_count override
    query_count = [0]

    def before_cursor_execute(conn, cursor, statement, parameters, context,
                              executemany):
        query_count[0] += 1

    event.listen(db.engine, "before_cursor_execute", before_cursor_execute)
    try:
        result = tab.to_dict(unread_count=123)
    finally:
        event.remove(db.engine, "before_cursor_execute", before_cursor_execute)

    # The override should be passed through to the serialized dict
    assert result["unread_count"] == 123

    # to_dict should not need to hit the DB just to compute unread_count.
    # It accesses self.id, self.name, self.order which are already loaded.
    assert query_count[0] == 0


def test_tab_to_dict_db_lookup_uses_single_aggregate_query(client):
    """
    When no unread_count override is supplied, Tab.to_dict should issue a single
    aggregate query to compute the unread count.
    """
    tab = Tab(name="Tab for DB lookup", order=10)
    feed = Feed(name="Feed for DB lookup",
                url="http://example.com/db",
                tab=tab)
    unread_item = FeedItem(title="Unread",
                           link="http://example.com/u",
                           feed=feed,
                           is_read=False,
                           guid="guid-u")
    read_item = FeedItem(title="Read",
                         link="http://example.com/r",
                         feed=feed,
                         is_read=True,
                         guid="guid-r")

    db.session.add(tab)
    db.session.add(feed)
    db.session.add(unread_item)
    db.session.add(read_item)
    db.session.commit()

    db.session.refresh(tab)

    query_count = [0]

    def before_cursor_execute(conn, cursor, statement, parameters, context,
                              executemany):
        query_count[0] += 1

    event.listen(db.engine, "before_cursor_execute", before_cursor_execute)
    try:
        result = tab.to_dict()
    finally:
        event.remove(db.engine, "before_cursor_execute", before_cursor_execute)

    assert result["unread_count"] == 1
    assert query_count[
        0] == 1, f"Expected a single unread aggregate query, got {query_count[0]}"


def test_tab_to_dict_db_lookup_with_no_unread_items_returns_zero(client):
    """
    When a tab has no unread items, Tab.to_dict without an override should
    return unread_count == 0 and still use at most a single aggregate query.
    """
    tab = Tab(name="Tab with no unread", order=20)
    feed = Feed(name="Feed with no unread",
                url="http://example.com/zero",
                tab=tab)
    read_item_1 = FeedItem(title="Read 1",
                           link="http://example.com/r1",
                           feed=feed,
                           is_read=True,
                           guid="guid-r1")
    read_item_2 = FeedItem(title="Read 2",
                           link="http://example.com/r2",
                           feed=feed,
                           is_read=True,
                           guid="guid-r2")

    db.session.add(tab)
    db.session.add(feed)
    db.session.add(read_item_1)
    db.session.add(read_item_2)
    db.session.commit()

    db.session.refresh(tab)

    query_count = [0]

    def before_cursor_execute(conn, cursor, statement, parameters, context,
                              executemany):
        query_count[0] += 1

    event.listen(db.engine, "before_cursor_execute", before_cursor_execute)
    try:
        result = tab.to_dict()
    finally:
        event.remove(db.engine, "before_cursor_execute", before_cursor_execute)

    assert result["unread_count"] == 0
    assert query_count[
        0] <= 1, f"Expected at most one unread aggregate query, got {query_count[0]}"
