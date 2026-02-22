from contextlib import contextmanager

from sqlalchemy import event

from backend.app import db
from backend.models import Feed, FeedItem, Subscription, Tab, User, UserItemState


@contextmanager
def count_queries():
    """Context manager to count SQL queries executed within the block."""
    query_count = [0]

    def before_cursor_execute(
        conn, cursor, statement, parameters, context, executemany
    ):
        query_count[0] += 1

    event.listen(db.engine, "before_cursor_execute", before_cursor_execute)
    try:
        yield query_count
    finally:
        event.remove(db.engine, "before_cursor_execute", before_cursor_execute)


def test_get_tabs_query_count_constant(client):
    """Verify that get_tabs executes a constant number of queries."""
    user = User.query.first()
    user_id = user.id

    def create_tabs(start_index, count):
        for i in range(start_index, start_index + count):
            tab = Tab(user_id=user_id, name=f"Tab {i}", order=i)
            db.session.add(tab)
            db.session.flush()
            feed = Feed(name=f"Feed {i}", url=f"http://example.com/{i}")
            db.session.add(feed)
            db.session.flush()
            sub = Subscription(user_id=user_id, tab_id=tab.id, feed_id=feed.id)
            db.session.add(sub)
            item = FeedItem(
                title=f"Item {i}",
                link=f"http://example.com/{i}/item",
                guid=f"guid-{i}",
                feed_id=feed.id,
            )
            db.session.add(item)
        db.session.commit()

    def get_query_count():
        from backend.extensions import cache

        cache.clear()
        with count_queries() as qc:
            response = client.get("/api/tabs")
            assert response.status_code == 200
        return qc[0]

    create_tabs(0, 1)
    count_1 = get_query_count()
    create_tabs(1, 5)
    count_n = get_query_count()

    assert count_n == count_1
    assert count_n <= 3


def test_tab_to_dict_optimization(client):
    """Verify Tab.to_dict respects the unread_count override."""
    user = User.query.first()
    tab = Tab(user_id=user.id, name="Tab for to_dict", order=100)
    db.session.add(tab)
    db.session.flush()
    feed = Feed(name="Feed 1", url="http://example.com/feed-1")
    db.session.add(feed)
    db.session.flush()
    sub = Subscription(user_id=user.id, tab_id=tab.id, feed_id=feed.id)
    db.session.add(sub)
    item = FeedItem(
        title="Item 1",
        link="http://example.com/item-1",
        feed_id=feed.id,
        guid="guid-to-dict",
    )
    db.session.add(item)
    db.session.commit()

    db.session.refresh(tab)
    with count_queries() as qc:
        result = tab.to_dict(unread_count=123)

    assert result["unread_count"] == 123
    assert qc[0] == 0


def test_tab_to_dict_db_lookup_uses_single_aggregate_query(client):
    """Verify Tab.to_dict unread count calculation."""
    user = User.query.first()
    tab = Tab(user_id=user.id, name="Tab for DB lookup", order=10)
    db.session.add(tab)
    db.session.flush()
    feed = Feed(name="Feed for DB lookup", url="http://example.com/db")
    db.session.add(feed)
    db.session.flush()
    sub = Subscription(user_id=user.id, tab_id=tab.id, feed_id=feed.id)
    db.session.add(sub)

    unread_item = FeedItem(
        title="Unread", link="http://example.com/u", feed_id=feed.id, guid="guid-u"
    )
    db.session.add(unread_item)
    db.session.flush()

    read_item = FeedItem(
        title="Read", link="http://example.com/r", feed_id=feed.id, guid="guid-r"
    )
    db.session.add(read_item)
    db.session.flush()

    state = UserItemState(user_id=user.id, item_id=read_item.id, is_read=True)
    db.session.add(state)
    db.session.commit()

    db.session.refresh(tab)
    with count_queries() as qc:
        result = tab.to_dict()

    assert result["unread_count"] == 1
    assert qc[0] == 1
