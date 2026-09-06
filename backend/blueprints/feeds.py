"""Blueprint for managing feeds and feed items in SheepVibes."""

import datetime
import html
import json
import logging
import re

from flask import Blueprint, jsonify, request

from ..auth import get_current_user, login_required
from ..cache_utils import invalidate_tab_feeds_cache, invalidate_tabs_cache
from ..constants import (
    DEFAULT_FEED_ITEMS_LIMIT,
    DEFAULT_PAGINATION_LIMIT,
    MAX_PAGINATION_LIMIT,
)
from ..extensions import db
from ..feed_name_utils import derive_canonical_feed_name
from ..feed_service import (
    is_valid_feed_url,
    fetch_and_update_feed,
    fetch_feed,
    process_feed_entries,
    update_all_feeds,
    validate_link_structure,
)
from ..models import Feed, FeedItem, Tab
from ..sse import announcer

logger = logging.getLogger(__name__)

feeds_bp = Blueprint("feeds", __name__, url_prefix="/api/feeds")
items_bp = Blueprint("items", __name__, url_prefix="/api/items")


def _get_unread_count(feed_id):
    """Helper to fetch unread count for a single feed."""
    return (
        db.session.query(db.func.count(FeedItem.id))
        .filter(FeedItem.feed_id == feed_id, FeedItem.is_read.is_(False))
        .scalar()
        or 0
    )


def _resolve_tab_id(tab_id, user_id):
    """Resolves the tab ID, finding the default tab for the user if none is provided.

    Returns:
        tuple: (resolved_tab_id, error_response)
    """
    if not tab_id:
        default_tab = (
            Tab.query.filter_by(user_id=user_id)
            .order_by(Tab.order)
            .first()
        )
        if not default_tab:
            return None, (
                jsonify({"error": "Cannot add feed: No default tab found"}),
                400,
            )
        return default_tab.id, None

    tab = Tab.query.filter_by(id=tab_id, user_id=user_id).first()
    if not tab:
        return None, (jsonify({"error": f"Tab with id {tab_id} not found"}), 404)

    return tab_id, None


def _get_feed_metadata(feed_url):
    """Attempts to fetch the feed to get its title and link.

    Returns:
        tuple: (feed_name, site_link, parsed_feed)
    """
    parsed_feed = fetch_feed(feed_url)
    if not parsed_feed or not parsed_feed.feed:
        logger.warning(
            "Could not fetch title for %s, using URL as name.",
            feed_url,
        )
        return feed_url, None, parsed_feed

    raw_title = parsed_feed.feed.get("title", feed_url)
    site_link = parsed_feed.feed.get("link")
    valid_site_link = validate_link_structure(site_link)
    feed_name = (
        derive_canonical_feed_name(
            raw_title,
            site_url=valid_site_link,
            feed_url=feed_url,
        )
        or raw_title
        or feed_url
    )

    return feed_name, valid_site_link, parsed_feed


def _create_and_process_feed(tab_id, feed_url, feed_name, site_link, parsed_feed, user_id):
    """Creates a new feed in the database and processes its initial items."""
    try:
        new_feed = Feed(
            tab_id=tab_id,
            name=feed_name,
            url=feed_url,
            site_link=site_link,
        )
        db.session.add(new_feed)
        db.session.commit()

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
                logger.error(
                    "Error processing initial items for feed %s: %s",
                    new_feed.id,
                    proc_e,
                    exc_info=True,
                )

        if num_new_items > 0:
            invalidate_tab_feeds_cache(tab_id, user_id=user_id)
        else:
            invalidate_tabs_cache(user_id=user_id)

        logger.info(
            "Added new feed '%s' with id %s to tab %s for user %s.",
            new_feed.name,
            new_feed.id,
            tab_id,
            user_id,
        )
        return jsonify(new_feed.to_dict(unread_count=num_new_items if num_new_items > 0 else 0)), 201

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


@feeds_bp.route("", methods=["POST"])
@login_required
def add_feed():
    """Adds a new feed to a specified tab owned by the user."""
    user = get_current_user()
    data = request.get_json()
    if not data or "url" not in data or not str(data["url"]).strip():
        return jsonify({"error": "Missing feed URL"}), 400

    feed_url = str(data["url"]).strip()

    if not is_valid_feed_url(feed_url):
        return jsonify({"error": "Invalid feed URL scheme"}), 400

    existing_feed = (
        Feed.query.join(Tab)
        .filter(Tab.user_id == user.id, Feed.url == feed_url)
        .first()
    )
    if existing_feed:
        return jsonify({"error": f"Feed with URL {feed_url} already exists"}), 409

    tab_id, error_response = _resolve_tab_id(data.get("tab_id"), user_id=user.id)
    if error_response:
        return error_response

    feed_name, site_link, parsed_feed = _get_feed_metadata(feed_url)

    return _create_and_process_feed(tab_id, feed_url, feed_name, site_link, parsed_feed, user_id=user.id)


@feeds_bp.route("/<int:feed_id>", methods=["DELETE"])
@login_required
def delete_feed(feed_id):
    """Deletes a feed owned by the authenticated user."""
    user = get_current_user()
    feed = (
        Feed.query.join(Tab)
        .filter(Feed.id == feed_id, Tab.user_id == user.id)
        .first()
    )
    if not feed:
        return jsonify({"error": "Feed not found"}), 404

    try:
        tab_id = feed.tab_id
        feed_name = feed.name
        db.session.delete(feed)
        db.session.commit()
        invalidate_tab_feeds_cache(tab_id, user_id=user.id)
        logger.info(
            "Deleted feed '%s' with id %s for user %s.",
            feed_name,
            feed_id,
            user.id,
        )
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
            jsonify({"error": "An internal error occurred while deleting the feed."}),
            500,
        )


def sanitize_feed_name(name: str | None) -> str:
    """Validates and sanitizes a custom feed name.

    Strips control characters, unescapes HTML entities, normalizes whitespace,
    and caps the length to 200 characters to match the Feed.name database column.
    """
    if not name or not isinstance(name, str):
        return ""
    cleaned = html.unescape(name.strip())
    cleaned = re.sub(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]", "", cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned[:200]


def _determine_feed_metadata(new_url, custom_name, parsed_feed):
    """Determines the appropriate name and site link for a feed."""
    sanitized_custom = sanitize_feed_name(custom_name) if custom_name else ""
    if sanitized_custom:
        new_name = sanitized_custom
        new_site_link = (
            validate_link_structure(parsed_feed.feed.get("link"))
            if parsed_feed and parsed_feed.feed
            else None
        )
    elif not parsed_feed or not parsed_feed.feed:
        new_name = new_url
        new_site_link = None
        logger.warning(
            "Could not fetch title for %s and no custom name provided, using URL as name.",
            new_url,
        )
    else:
        raw_title = parsed_feed.feed.get("title", new_url)
        new_site_link = validate_link_structure(parsed_feed.feed.get("link"))
        new_name = (
            derive_canonical_feed_name(
                raw_title,
                site_url=new_site_link,
                feed_url=new_url,
            )
            or raw_title
            or new_url
        )

    return new_name, new_site_link


def _apply_feed_updates(feed, new_url, custom_name, user_id):
    """Applies URL and metadata updates to a feed, handles cache and item processing."""
    original_url = feed.url
    url_changed = (new_url != original_url)
    sanitized_name = sanitize_feed_name(custom_name) if custom_name is not None else None

    if not url_changed:
        # Avoid unnecessary network refetches when URL remains the same
        if sanitized_name:
            feed.name = sanitized_name
            feed.last_updated_time = datetime.datetime.now(datetime.timezone.utc)
            db.session.commit()
            invalidate_tab_feeds_cache(feed.tab_id, user_id=user_id)
            logger.info(
                "Updated feed %s name to '%s' without URL refetch for user %s.",
                feed.id,
                sanitized_name,
                user_id,
            )
            return

        if custom_name is not None and not sanitized_name:
            # Custom name explicitly passed as empty/whitespace: re-derive from feed
            parsed_feed = fetch_feed(feed.url)
            if parsed_feed and parsed_feed.feed:
                derived_name, new_site_link = _determine_feed_metadata(
                    feed.url, None, parsed_feed
                )
                feed.name = derived_name or feed.name
                if new_site_link:
                    feed.site_link = new_site_link
            # If fetch failed, preserve existing feed.name
            feed.last_updated_time = datetime.datetime.now(datetime.timezone.utc)
            db.session.commit()
            invalidate_tab_feeds_cache(feed.tab_id, user_id=user_id)
            logger.info(
                "Re-derived feed %s name '%s' from feed for user %s.",
                feed.id,
                feed.name,
                user_id,
            )
            return

        # Neither URL nor name changed; nothing to update
        return

    # URL has changed: fetch new feed and process entries
    parsed_feed = fetch_feed(new_url)
    new_name, new_site_link = _determine_feed_metadata(
        new_url, sanitized_name, parsed_feed
    )

    feed.url = new_url
    feed.name = new_name
    feed.site_link = new_site_link
    feed.last_updated_time = datetime.datetime.now(datetime.timezone.utc)

    db.session.commit()
    invalidate_tab_feeds_cache(feed.tab_id, user_id=user_id)
    logger.info(
        "Cache invalidated for user %s tab %s after updating feed %s.",
        user_id,
        feed.tab_id,
        feed.id,
    )

    try:
        if parsed_feed:
            process_feed_entries(feed, parsed_feed)
    except Exception as update_e:
        logger.error(
            "Error updating feed %s after URL change: %s",
            feed.id,
            update_e,
            exc_info=True,
        )

    logger.info(
        "Updated feed %s from '%s' to '%s' for user %s.",
        feed.id,
        original_url,
        new_url,
        user_id,
    )


def _validate_feed_update_payload(data, current_feed, user_id):
    """Validates the payload for updating a feed URL and name.

    Returns:
        tuple: (new_url, custom_name, error_response)
    """
    if (
        not data
        or not isinstance(data, dict)
        or ("url" not in data and "name" not in data)
    ):
        return None, None, (jsonify({"error": "Missing or invalid feed URL"}), 400)

    if "url" in data and (not isinstance(data["url"], str) or not data["url"].strip()):
        return None, None, (jsonify({"error": "Missing or invalid feed URL"}), 400)

    new_url = data["url"].strip() if "url" in data else current_feed.url

    if not is_valid_feed_url(new_url):
        return None, None, (jsonify({"error": "Invalid feed URL scheme"}), 400)

    existing_feed = (
        Feed.query.join(Tab)
        .filter(Tab.user_id == user_id, Feed.id != current_feed.id, Feed.url == new_url)
        .first()
    )
    if existing_feed:
        return None, None, (
            jsonify({"error": f"Feed with URL {new_url} already exists"}),
            409,
        )

    if "name" in data and data["name"] is not None:
        if not isinstance(data["name"], str):
            return None, None, (jsonify({"error": "Invalid feed name: must be a string"}), 400)
        if len(data["name"].strip()) > 200:
            return None, None, (
                jsonify({"error": "Invalid feed name: exceeds maximum length of 200 characters"}),
                400,
            )

    custom_name = data.get("name") if "name" in data else None
    return new_url, custom_name, None


@feeds_bp.route("/<int:feed_id>", methods=["PUT"])
@login_required
def update_feed_url(feed_id):
    """Updates a feed's URL and name for the authenticated user."""
    user = get_current_user()
    feed = (
        Feed.query.join(Tab)
        .filter(Feed.id == feed_id, Tab.user_id == user.id)
        .first()
    )
    if not feed:
        return jsonify({"error": "Feed not found"}), 404

    data = request.get_json()
    new_url, custom_name, error_response = _validate_feed_update_payload(data, feed, user.id)
    if error_response:
        return error_response

    try:
        _apply_feed_updates(feed, new_url, custom_name, user_id=user.id)
        unread_count = _get_unread_count(feed.id)
        feed_data = feed.to_dict(unread_count=unread_count)
        feed_data["items"] = [
            item.to_dict()
            for item in feed.items.order_by(
                FeedItem.published_time.desc().nullslast(), FeedItem.fetched_time.desc()
            ).limit(DEFAULT_FEED_ITEMS_LIMIT)
        ]
        return jsonify(feed_data), 200

    except Exception as e:
        db.session.rollback()
        logger.error("Error updating feed %s: %s", feed_id, e, exc_info=True)
        return (
            jsonify({"error": "An internal error occurred while updating the feed."}),
            500,
        )


@feeds_bp.route("/update-all", methods=["POST"])
@login_required
def api_update_all_feeds():
    """Triggers an update for all feeds in the system."""
    logger.info("Received request to update all feeds.")
    try:
        processed_count, new_items_count, affected_tab_ids = update_all_feeds()
        logger.info(
            "All feeds update process completed. Processed: %s, New Items: %s",
            processed_count,
            new_items_count,
        )
        if affected_tab_ids:
            # Look up tab user_ids for accurate cache invalidation
            affected_tabs = Tab.query.filter(Tab.id.in_(affected_tab_ids)).all()
            user_ids_to_invalidate = set()
            for tab in affected_tabs:
                invalidate_tab_feeds_cache(tab.id, user_id=tab.user_id, invalidate_tabs=False)
                if tab.user_id:
                    user_ids_to_invalidate.add(tab.user_id)
            for uid in user_ids_to_invalidate:
                invalidate_tabs_cache(user_id=uid)
            logger.info(
                "Granular cache invalidation completed for affected tabs: %s",
                affected_tab_ids,
            )
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
        logger.error("Error during /api/feeds/update-all: %s", e, exc_info=True)
        return (
            jsonify({"error": "An internal error occurred while updating all feeds."}),
            500,
        )


@feeds_bp.route("/<int:feed_id>/update", methods=["POST"])
@login_required
def update_feed(feed_id):
    """Manually triggers an update check for a specific feed owned by the user."""
    user = get_current_user()
    feed = (
        Feed.query.join(Tab)
        .filter(Feed.id == feed_id, Tab.user_id == user.id)
        .first()
    )
    if not feed:
        return jsonify({"error": "Feed not found"}), 404

    try:
        old_name = feed.name
        old_site_link = feed.site_link
        success, new_items, _ = fetch_and_update_feed(feed.id)
        if success and (
            new_items > 0
            or feed.name != old_name
            or feed.site_link != old_site_link
        ):
            invalidate_tab_feeds_cache(feed.tab_id, user_id=user.id)
            logger.info(
                "Cache invalidated for user %s tab %s after manual update of feed %s.",
                user.id,
                feed.tab_id,
                feed.id,
            )

        unread_count = _get_unread_count(feed.id)
        return jsonify(feed.to_dict(unread_count=unread_count))
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
@login_required
def get_feed_items(feed_id):
    """Returns a paginated list of items for a specific feed owned by the user."""
    user = get_current_user()
    feed = (
        Feed.query.join(Tab)
        .filter(Feed.id == feed_id, Tab.user_id == user.id)
        .first()
    )
    if not feed:
        return jsonify({"error": "Feed not found"}), 404

    try:
        offset = int(request.args.get("offset", 0))
        limit = int(request.args.get("limit", DEFAULT_PAGINATION_LIMIT))
    except (ValueError, TypeError):
        return (
            jsonify({"error": "Offset and limit parameters must be valid integers."}),
            400,
        )

    if offset < 0:
        return jsonify({"error": "Offset cannot be negative."}), 400
    if limit <= 0:
        return jsonify({"error": "Limit must be positive."}), 400
    limit = min(limit, MAX_PAGINATION_LIMIT)

    items = (
        FeedItem.query.filter_by(feed_id=feed_id)
        .order_by(
            FeedItem.published_time.desc().nullslast(), FeedItem.fetched_time.desc()
        )
        .offset(offset)
        .limit(limit)
        .all()
    )

    return jsonify([item.to_dict() for item in items])


@items_bp.route("/<int:item_id>/read", methods=["POST"])
@login_required
def mark_item_read(item_id):
    """Marks a specific feed item as read for the owning user."""
    user = get_current_user()
    item = (
        FeedItem.query.join(Feed).join(Tab)
        .filter(FeedItem.id == item_id, Tab.user_id == user.id)
        .first()
    )
    if not item:
        return jsonify({"error": "Feed item not found"}), 404

    if item.is_read:
        return jsonify({"message": "Item already marked as read"}), 200

    try:
        tab_id = item.feed.tab_id
        item.is_read = True
        db.session.commit()
        invalidate_tab_feeds_cache(tab_id, user_id=user.id)
        logger.info("Marked item %s as read for user %s.", item_id, user.id)
        return jsonify({"message": f"Item {item_id} marked as read"}), 200
    except Exception as e:
        db.session.rollback()
        logger.error(
            "Error marking item %s as read: %s", item_id, str(e), exc_info=True
        )
        return (
            jsonify(
                {"error": "An internal error occurred while marking the item as read."}
            ),
            500,
        )
