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
from ..extensions import db
from ..feed_service import (
    fetch_and_update_feed,
    fetch_feed,
    is_valid_feed_url,
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

    # Prevent Stored XSS: Validate URL scheme (must be http/https)
    if not is_valid_feed_url(feed_url):
        return (
            jsonify({"error": "Invalid feed URL. Scheme must be http or https."}),
            400,
        )

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
            "Could not fetch title for %s, using URL as name.",
            feed_url,
        )
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
                    "Processed initial %s items for feed %s",
                    num_new_items,
                    new_feed.id,
                )
            except Exception as proc_e:
                # Log error during initial processing but don't fail the add operation
                logger.error(
                    "Error processing initial items for feed %s: %s",
                    new_feed.id,
                    proc_e,
                    exc_info=True,
                )

        if num_new_items > 0:
            invalidate_tab_feeds_cache(tab_id)
        else:
            invalidate_tabs_cache()  # At least invalidate for unread count change potential

        logger.info(
            "Added new feed '%s' with id %s to tab %s.",
            new_feed.name,
            new_feed.id,
            tab_id,
        )
        return jsonify(new_feed.to_dict()), 201  # Created

    except Exception as e:
        db.session.rollback()
        logger.error(
            "Error adding feed %s: %s",
            feed_url,
            str(e),
            exc_info=True,
        )
        return (
            jsonify({"error": "An internal error occurred while adding the feed."}),
            500,
        )


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
        logger.info(
            "Deleted feed '%s' with id %s.",
            feed_name,
            feed_id,
        )
        # OK
        return jsonify({"message": f"Feed {feed_id} deleted successfully"}), 200
    except Exception as e:
        db.session.rollback()
        logger.error(
            "Error deleting feed %s: %s",
            feed_id,
            str(e),
            exc_info=True,
        )
        return (
            jsonify(
                {"error": "An internal error occurred while deleting the feed."}),
            500,
        )


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

    # Prevent Stored XSS: Validate URL scheme (must be http/https)
    if not is_valid_feed_url(new_url):
        return (
            jsonify({"error": "Invalid feed URL. Scheme must be http or https."}),
            400,
        )

    # Check if the new URL is already used by another feed
    existing_feed = Feed.query.filter(
        Feed.id != feed_id, Feed.url == new_url).first()
    if existing_feed:
        return (
            jsonify({"error": f"Feed with URL {new_url} already exists"}),
            409,
        )  # Conflict

    custom_name = data.get("name", "").strip()

    try:
        # Attempt to fetch the feed to get its title (and verify accessibility/SSRF)
        parsed_feed = fetch_feed(new_url)

        if custom_name:
            new_name = custom_name
            new_site_link = (
                parsed_feed.feed.get("link")
                if parsed_feed and parsed_feed.feed
                else None
            )
        elif not parsed_feed or not parsed_feed.feed:
            # If fetch fails and no custom name provided, use the URL as the name
            new_name = new_url
            new_site_link = None
            logger.warning(
                "Could not fetch title for %s and no custom name provided, using URL as name.",
                new_url,
            )
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
            "Cache invalidated for tab %s after updating feed %s.",
            feed.tab_id,
            feed.id,
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
                "Error updating feed %s after URL change: %s",
                feed.id,
                update_e,
                exc_info=True,
            )

        logger.info(
            "Updated feed %s from '%s' to '%s'.",
            feed_id,
            original_url,
            new_url,
        )

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
        logger.error("Error updating feed %s: %s", feed_id, e, exc_info=True)
        return (
            jsonify(
                {"error": "An internal error occurred while updating the feed."}),
            500,
        )


@feeds_bp.route("/update-all", methods=["POST"])
def api_update_all_feeds():
    """Triggers an update for all feeds in the system.

    Returns:
        A tuple containing a JSON response and the HTTP status code.
    """
    logger.info("Received request to update all feeds.")
    try:
        processed_count, new_items_count, affected_tab_ids = update_all_feeds()
        logger.info(
            "All feeds update process completed. Processed: %s, New Items: %s",
            processed_count,
            new_items_count,
        )
        if new_items_count > 0 and affected_tab_ids:
            for tab_id in affected_tab_ids:
                invalidate_tab_feeds_cache(tab_id, invalidate_tabs=False)
            invalidate_tabs_cache()
            logger.info(
                "Granular cache invalidation completed for affected tabs: %s",
                affected_tab_ids,
            )
        # Announce the update to listening clients
        event_data = {
            "feeds_processed": processed_count,
            "new_items": new_items_count,
            "affected_tab_ids": (
                sorted(list(affected_tab_ids)) if affected_tab_ids else []
            ),
        }
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
        logger.error("Error during /api/feeds/update-all: %s",
                     e, exc_info=True)
        # Consistent error response with other parts of the API
        return (
            jsonify(
                {"error": "An internal error occurred while updating all feeds."}),
            500,
        )


@feeds_bp.route("/<int:feed_id>/update", methods=["POST"])
def update_feed(feed_id):
    """Manually triggers an update check for a specific feed."""
    feed = db.get_or_404(Feed, feed_id)
    try:
        success, new_items, _ = fetch_and_update_feed(feed.id)
        if success and new_items > 0:
            invalidate_tab_feeds_cache(feed.tab_id)
            logger.info(
                "Cache invalidated for tab %s after manual update of feed %s.",
                feed.tab_id,
                feed.id,
            )

        return jsonify(feed.to_dict())
    except Exception as e:
        logger.error(
            "Error during manual update for feed %s: %s",
            feed.id,
            e,
            exc_info=True,
        )
        return (
            jsonify(
                {
                    "error": f"An internal error occurred while manually updating feed {feed_id}."
                }
            ),
            500,
        )


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
        logger.info("Marked item %s as read.", item_id)
        # OK
        return jsonify({"message": f"Item {item_id} marked as read"}), 200
    except Exception as e:
        db.session.rollback()
        logger.error(
            "Error marking item %s as read: %s", item_id, str(e), exc_info=True
        )
        # Let 500 handler manage response (or return specific error)
        return (
            jsonify(
                {"error": "An internal error occurred while marking the item as read."}
            ),
            500,
        )
