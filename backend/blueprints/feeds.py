import datetime
import json
import logging

from flask import Blueprint, jsonify, request

from ..cache_utils import invalidate_tab_feeds_cache, invalidate_tabs_cache
from ..constants import (
    DEFAULT_FEED_ITEMS_LIMIT,
    DEFAULT_PAGINATION_LIMIT,
    MAX_PAGINATION_LIMIT,
)
from ..extensions import cache, db
from ..feed_service import (
    fetch_and_update_feed,
    fetch_feed,
    process_feed_entries,
    update_all_feeds,
)
from ..models import Feed, FeedItem, Tab
from ..sse import announcer

logger = logging.getLogger(__name__)

feeds_bp = Blueprint("feeds", __name__, url_prefix="/api/feeds")
items_bp = Blueprint("items", __name__, url_prefix="/api/items")


@feeds_bp.route("", methods=["POST"])
def add_feed():
    """Adds a new feed to a specified tab (or the default tab)."""
    data = request.get_json()
    # Validate input
    if not data or "url" not in data or not data["url"].strip():
        return jsonify({"error": "Missing feed URL"}), 400

    feed_url = data["url"].strip()
    tab_id = data.get("tab_id")  # Optional tab ID

    # Determine target tab ID
    if not tab_id:
        # Find the first tab by order if no ID provided
        default_tab = Tab.query.order_by(Tab.order).first()
        if not default_tab:
            # Cannot add feed if no tabs exist
            return jsonify({"error": "Cannot add feed: No default tab found"}), 400
        tab_id = default_tab.id
    else:
        # Verify the provided tab_id exists
        tab = db.session.get(Tab, tab_id)
        if not tab:
            return jsonify({"error": f"Tab with id {tab_id} not found"}), 404

    # Check if feed URL already exists in the database
    existing_feed = Feed.query.filter_by(url=feed_url).first()
    if existing_feed:
        return (
            jsonify({"error": f"Feed with URL {feed_url} already exists"}),
            409,
        )  # Conflict

    # Attempt to fetch the feed to get its title
    parsed_feed = fetch_feed(feed_url)
    if not parsed_feed or not parsed_feed.feed:
        # If fetch fails initially, use the URL as the name
        feed_name = feed_url
        site_link = None  # No website link if fetch failed
        logger.warning(
            f"Could not fetch title for {feed_url}, using URL as name.")
    else:
        feed_name = parsed_feed.feed.get(
            "title", feed_url
        )  # Use URL as fallback if title missing
        site_link = parsed_feed.feed.get("link")  # Get the website link

    try:
        # Create and save the new feed
        new_feed = Feed(
            tab_id=tab_id,
            name=feed_name,
            url=feed_url,
            site_link=site_link,
            # last_updated_time defaults to now
        )
        db.session.add(new_feed)
        db.session.commit()  # Commit to get the new_feed.id

        # Trigger initial fetch and processing of items for the new feed
        num_new_items = 0
        if parsed_feed:
            try:
                num_new_items = process_feed_entries(new_feed, parsed_feed)
                logger.info(
                    f"Processed initial {num_new_items} items for feed {new_feed.id}"
                )
            except Exception as proc_e:
                # Log error during initial processing but don't fail the add operation
                logger.error(
                    f"Error processing initial items for feed {new_feed.id}: {proc_e}",
                    exc_info=True,
                )

        if num_new_items > 0:
            invalidate_tab_feeds_cache(tab_id)
        else:
            invalidate_tabs_cache()  # At least invalidate for unread count change potential

        logger.info(
            f"Added new feed '{new_feed.name}' with id {new_feed.id} to tab {tab_id}."
        )
        return jsonify(new_feed.to_dict()), 201  # Created

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error adding feed {feed_url}: {str(e)}", exc_info=True)
        return jsonify({"error": f"Error adding feed {feed_url}: {str(e)}"}), 500


@feeds_bp.route("/<int:feed_id>", methods=["DELETE"])
def delete_feed(feed_id):
    """Deletes a feed and its associated items.

    Args:
        feed_id (int): The ID of the feed to delete.

    Returns:
        A tuple containing a JSON response and the HTTP status code.
    """
    # Find feed or return 404
    feed = db.get_or_404(Feed, feed_id)
    try:
        tab_id = feed.tab_id
        feed_name = feed.name
        # Associated items are deleted due to cascade settings
        db.session.delete(feed)
        db.session.commit()
        invalidate_tab_feeds_cache(tab_id)
        logger.info(f"Deleted feed '{feed_name}' with id {feed_id}.")
        # OK
        return jsonify({"message": f"Feed {feed_id} deleted successfully"}), 200
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting feed {feed_id}: {str(e)}", exc_info=True)
        return jsonify({"error": f"Error deleting feed {feed_id}: {str(e)}"}), 500


@feeds_bp.route("/<int:feed_id>", methods=["PUT"])
def update_feed_url(feed_id):
    """Updates a feed's URL and name.

    Args:
        feed_id (int): The ID of the feed to update.

    Returns:
        A tuple containing a JSON response and the HTTP status code.
    """
    # Find feed or return 404
    feed = db.get_or_404(Feed, feed_id)

    data = request.get_json()
    # Validate input
    if (
        not data
        or "url" not in data
        or not (isinstance(data["url"], str) and data["url"].strip())
    ):
        return jsonify({"error": "Missing or invalid feed URL"}), 400

    new_url = data["url"].strip()

    # Check if the new URL is already used by another feed
    existing_feed = Feed.query.filter(
        Feed.id != feed_id, Feed.url == new_url).first()
    if existing_feed:
        return (
            jsonify({"error": f"Feed with URL {new_url} already exists"}),
            409,
        )  # Conflict

    try:
        # Attempt to fetch the feed to get its title
        parsed_feed = fetch_feed(new_url)
        if not parsed_feed or not parsed_feed.feed:
            # If fetch fails, use the URL as the name
            new_name = new_url
            new_site_link = None
            logger.warning(
                f"Could not fetch title for {new_url}, using URL as name.")
        else:
            new_name = parsed_feed.feed.get(
                "title", new_url
            )  # Use URL as fallback if title missing
            new_site_link = parsed_feed.feed.get(
                "link")  # Get the website link

        # Update the feed
        original_url = feed.url
        feed.url = new_url
        feed.name = new_name
        feed.site_link = new_site_link
        feed.last_updated_time = datetime.datetime.now(datetime.timezone.utc)

        db.session.commit()

        # Invalidate cache for the feed's tab, as feed properties (name, url) have changed.
        invalidate_tab_feeds_cache(feed.tab_id)
        logger.info(
            f"Cache invalidated for tab {feed.tab_id} after updating feed {feed.id}."
        )

        # Trigger update to fetch new items using the already fetched feed data
        try:
            if parsed_feed:
                # Reuse the already fetched and parsed feed data to process entries,
                # avoiding a redundant network call.
                process_feed_entries(feed, parsed_feed)
        except Exception as update_e:
            # Log error during update but don't fail the operation
            logger.error(
                f"Error updating feed {feed.id} after URL change: {update_e}",
                exc_info=True,
            )

        logger.info(
            f"Updated feed {feed_id} from '{original_url}' to '{new_url}'.")

        # Return full feed data including items for frontend to update widget
        feed_data = feed.to_dict()
        # Include only recent feed items in the response (limit to DEFAULT_FEED_ITEMS_LIMIT)
        feed_data["items"] = [
            item.to_dict()
            for item in feed.items.order_by(
                FeedItem.published_time.desc().nullslast(), FeedItem.fetched_time.desc()
            ).limit(DEFAULT_FEED_ITEMS_LIMIT)
        ]
        return jsonify(feed_data), 200  # OK

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating feed {feed_id}: {str(e)}", exc_info=True)
        return jsonify({"error": f"Error updating feed {feed_id}: {str(e)}"}), 500


@feeds_bp.route("/update-all", methods=["POST"])
def api_update_all_feeds():
    """Triggers an update for all feeds in the system.

    Returns:
        A tuple containing a JSON response and the HTTP status code.
    """
    logger.info("Received request to update all feeds.")
    try:
        processed_count, new_items_count = update_all_feeds()
        logger.info(
            f"All feeds update process completed. Processed: {processed_count}, New Items: {new_items_count}"
        )
        if new_items_count > 0:
            cache.clear()
            logger.info(
                "Cache cleared after manual 'update-all' found new items.")
        # Announce the update to listening clients
        event_data = {"feeds_processed": processed_count,
                      "new_items": new_items_count}
        msg = f"data: {json.dumps(event_data)}\n\n"
        announcer.announce(msg=msg)
        return (
            jsonify(
                {
                    "message": "All feeds updated successfully.",
                    "feeds_processed": processed_count,
                    "new_items": new_items_count,
                }
            ),
            200,
        )
    except Exception as e:
        logger.error(
            f"Error during /api/feeds/update-all: {str(e)}", exc_info=True)
        # Consistent error response with other parts of the API
        return jsonify({"error": f"Error during /api/feeds/update-all: {str(e)}"}), 500


@feeds_bp.route("/<int:feed_id>/update", methods=["POST"])
def update_feed(feed_id):
    """Manually triggers an update check for a specific feed."""
    feed = db.get_or_404(Feed, feed_id)
    try:
        success, new_items = fetch_and_update_feed(feed.id)
        if success and new_items > 0:
            invalidate_tab_feeds_cache(feed.tab_id)
            logger.info(
                f"Cache invalidated for tab {feed.tab_id} after manual update of feed {feed.id}."
            )

        return jsonify(feed.to_dict())
    except Exception as e:
        logger.error(
            f"Error during manual update for feed {feed.id}: {e}", exc_info=True
        )
        return jsonify({"error": f"Error during manual update for feed {feed.id}: {e}"}), 500


@feeds_bp.route("/<int:feed_id>/items", methods=["GET"])
def get_feed_items(feed_id):
    """Returns a paginated list of items for a specific feed."""
    # Ensure the feed exists, or return a 404 error
    db.get_or_404(Feed, feed_id)

    # Get offset and limit from the request's query string, with default values
    try:
        offset = int(request.args.get("offset", 0))
        limit = int(request.args.get("limit", DEFAULT_PAGINATION_LIMIT))
    except (ValueError, TypeError):
        return (
            jsonify(
                {"error": "Offset and limit parameters must be valid integers."}),
            400,
        )

    # Validate and cap pagination parameters
    if offset < 0:
        return jsonify({"error": "Offset cannot be negative."}), 400
    if limit <= 0:
        return jsonify({"error": "Limit must be positive."}), 400
    limit = min(limit, MAX_PAGINATION_LIMIT)

    # Query the database for the items, ordered by date
    items = (
        FeedItem.query.filter_by(feed_id=feed_id)
        .order_by(
            FeedItem.published_time.desc().nullslast(), FeedItem.fetched_time.desc()
        )
        .offset(offset)
        .limit(limit)
        .all()
    )

    # Return the items as a JSON response
    return jsonify([item.to_dict() for item in items])


@items_bp.route("/<int:item_id>/read", methods=["POST"])
def mark_item_read(item_id):
    """Marks a specific feed item as read.

    Args:
        item_id (int): The ID of the feed item to mark as read.

    Returns:
        A tuple containing a JSON response and the HTTP status code.
    """
    # Find item or return 404
    item = db.session.get(FeedItem, item_id)
    if not item:
        return jsonify({"error": "Feed item not found"}), 404

    # If already read, return success without changing anything
    if item.is_read:
        return jsonify({"message": "Item already marked as read"}), 200  # OK

    try:
        tab_id = item.feed.tab_id
        item.is_read = True
        db.session.commit()
        invalidate_tab_feeds_cache(tab_id)
        logger.info(f"Marked item {item_id} as read.")
        # OK
        return jsonify({"message": f"Item {item_id} marked as read"}), 200
    except Exception as e:
        db.session.rollback()
        logger.error(
            f"Error marking item {item_id} as read: {str(e)}", exc_info=True)
        # Let 500 handler manage response (or return specific error)
        return jsonify({"error": f"Error marking item {item_id} as read: {e}"}), 500
