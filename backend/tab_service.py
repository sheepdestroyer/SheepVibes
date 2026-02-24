import logging

from sqlalchemy import func, select

from .constants import DEFAULT_FEED_ITEMS_LIMIT
from .extensions import db
from .models import Feed, FeedItem

logger = logging.getLogger(__name__)


def get_tab_feeds_with_items(tab_id: int,
                             limit: int = DEFAULT_FEED_ITEMS_LIMIT
                             ) -> list[dict]:
    """
    Returns a list of feeds for a tab, including recent items for each feed.
    This is highly optimized to prevent the N+1 query problem.

    Args:
        tab_id (int): The ID of the tab to fetch feeds for.
        limit (int): The maximum number of items to fetch per feed.

    Returns:
        list[dict]: A list of feed dictionaries, each containing a list of item dictionaries.
    """
    # Query 1: Get all feeds for the given tab.
    feeds = Feed.query.filter_by(tab_id=tab_id).all()
    if not feeds:
        return []

    feed_ids = [feed.id for feed in feeds]

    # Query 2: Get unread counts for all feeds in this tab to avoid N+1 queries.
    unread_counts_query = (db.session.query(
        FeedItem.feed_id, func.count(FeedItem.id)).filter(
            FeedItem.feed_id.in_(feed_ids),
            FeedItem.is_read.is_(False)).group_by(FeedItem.feed_id))
    unread_counts = dict(unread_counts_query.all())

    # Query 3: Get the top N items for ALL those feeds in a single, efficient query.
    # Use a window function to rank items within each feed.
    ranked_items_subq = (select(
        FeedItem,
        func.row_number().over(
            partition_by=FeedItem.feed_id,
            order_by=[
                FeedItem.published_time.desc().nullslast(),
                FeedItem.fetched_time.desc(),
            ],
        ).label("rank"),
    ).filter(FeedItem.feed_id.in_(feed_ids)).subquery())

    # Select from the subquery to filter by the rank.
    top_items_query = select(ranked_items_subq).filter(
        ranked_items_subq.c.rank <= limit)

    top_items_results = db.session.execute(top_items_query).all()

    # Group the fetched items by feed_id for efficient lookup.
    items_by_feed = {}
    for item_row in top_items_results:
        # Directly serialize the row to a dict, avoiding ORM object creation.
        item_dict = {
            "id": item_row.id,
            "feed_id": item_row.feed_id,
            "title": item_row.title,
            "link": item_row.link,
            "published_time":
            FeedItem.to_iso_z_string(item_row.published_time),
            "fetched_time": FeedItem.to_iso_z_string(item_row.fetched_time),
            "is_read": item_row.is_read,
            "guid": item_row.guid,
        }

        feed_id = item_row.feed_id
        if feed_id not in items_by_feed:
            items_by_feed[feed_id] = []
        items_by_feed[feed_id].append(item_dict)

    # Build the final response, combining feeds with their items.
    response_data = []
    for feed in feeds:
        # Pass the pre-calculated unread count to avoid N+1 queries
        feed_dict = feed.to_dict(unread_count=unread_counts.get(feed.id, 0))
        feed_dict["items"] = items_by_feed.get(feed.id, [])
        response_data.append(feed_dict)

    return response_data
