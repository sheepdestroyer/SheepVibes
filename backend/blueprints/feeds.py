import datetime
import json
import logging

from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required

from ..cache_utils import invalidate_tab_feeds_cache
from ..constants import (
    DEFAULT_FEED_ITEMS_LIMIT,
    DEFAULT_PAGINATION_LIMIT,
    MAX_PAGINATION_LIMIT,
)
from ..extensions import db
from ..feed_service import (
    fetch_and_update_feed,
    fetch_feed,
    process_feed_entries,
)
from ..models import Feed, FeedItem, Subscription, Tab, UserItemState

logger = logging.getLogger(__name__)

feeds_bp = Blueprint("feeds", __name__, url_prefix="/api/feeds")
items_bp = Blueprint("items", __name__, url_prefix="/api/items")


@feeds_bp.route("", methods=["POST"])
@login_required
def add_feed():
    """Adds a new subscription to a specified tab for the current user."""
    data = request.get_json()
    if not data or "url" not in data or not data["url"].strip():
        return jsonify({"error": "Missing feed URL"}), 400

    feed_url = data["url"].strip()
    tab_id = data.get("tab_id")

    if not tab_id:
        default_tab = (
            Tab.query.filter_by(user_id=current_user.id).order_by(
                Tab.order).first()
        )
        if not default_tab:
            return jsonify({"error": "Cannot add feed: No tabs found"}), 400
        tab_id = default_tab.id
    else:
        tab = (
            db.session.query(Tab).filter_by(
                id=tab_id, user_id=current_user.id).first()
        )
        if not tab:
            return jsonify({"error": f"Tab with id {tab_id} not found"}), 404

    # Get or create global Feed
    new_feed_created = False
    existing_feed = Feed.query.filter_by(url=feed_url).first()

    if existing_feed:
        feed = existing_feed
        # Check if user already has this feed subscribed
        existing_sub = Subscription.query.filter_by(
            user_id=current_user.id, feed_id=feed.id
        ).first()
        if existing_sub:
            return jsonify({"error": f"You are already subscribed to {feed_url}"}), 409
    else:
        # Attempt to fetch the feed
        parsed_feed = fetch_feed(feed_url)
        feed_name = feed_url
        site_link = None
        if parsed_feed and parsed_feed.feed:
            feed_name = parsed_feed.feed.get("title", feed_url)
            site_link = parsed_feed.feed.get("link")

        feed = Feed(name=feed_name, url=feed_url, site_link=site_link)
        db.session.add(feed)
        db.session.flush()  # Get feed.id
        new_feed_created = True

    try:
        new_sub = Subscription(user_id=current_user.id,
                               tab_id=tab_id, feed_id=feed.id)
        db.session.add(new_sub)
        db.session.commit()

        if new_feed_created and parsed_feed:
            process_feed_entries(feed, parsed_feed)

        invalidate_tab_feeds_cache(tab_id)
        return jsonify(new_sub.to_dict()), 201

    except Exception as e:
        db.session.rollback()
        logger.error("Error adding feed %s: %s",
                     feed_url, str(e), exc_info=True)
        return (
            jsonify({"error": "An internal error occurred while adding the feed."}),
            500,
        )


@feeds_bp.route("/<int:sub_id>", methods=["DELETE"])
@login_required
def delete_feed(sub_id):
    """Deletes a subscription for the current user."""
    sub = (
        db.session.query(Subscription)
        .filter_by(id=sub_id, user_id=current_user.id)
        .first_or_404()
    )
    tab_id = sub.tab_id
    try:
        db.session.delete(sub)
        db.session.commit()
        invalidate_tab_feeds_cache(tab_id)
        return jsonify({"message": f"Subscription {sub_id} deleted successfully"}), 200
    except Exception as e:
        db.session.rollback()
        logger.error(
            "Error deleting subscription %s: %s", sub_id, str(e), exc_info=True
        )
        return (
            jsonify(
                {"error": "An internal error occurred while deleting the feed."}),
            500,
        )


@feeds_bp.route("/<int:sub_id>", methods=["PUT"])
@login_required
def update_feed_url(sub_id):
    """Updates a subscription's custom name or URL (global)."""
    sub = (
        db.session.query(Subscription)
        .filter_by(id=sub_id, user_id=current_user.id)
        .first_or_404()
    )
    data = request.get_json()

    # In this multi-user model, users usually shouldn't change the GLOBAL URL
    # unless we want them to. Let's assume URL change means switching subscription
    # to another feed (or creating it).

    new_url = data.get("url", "").strip()
    custom_name = data.get("name", "").strip()

    if new_url and new_url != sub.feed.url:
        # Logic to change feed URL for this subscription
        # Similar to add_feed: find/create global feed and update sub.feed_id
        existing_feed = Feed.query.filter_by(url=new_url).first()
        if existing_feed:
            sub.feed_id = existing_feed.id
        else:
            parsed_feed = fetch_feed(new_url)
            feed_name = new_url
            site_link = None
            if parsed_feed and parsed_feed.feed:
                feed_name = parsed_feed.feed.get("title", new_url)
                site_link = parsed_feed.feed.get("link")

            new_global_feed = Feed(
                name=feed_name, url=new_url, site_link=site_link)
            db.session.add(new_global_feed)
            db.session.flush()
            sub.feed_id = new_global_feed.id
            if parsed_feed:
                process_feed_entries(new_global_feed, parsed_feed)

    if custom_name:
        sub.custom_name = custom_name

    try:
        db.session.commit()
        invalidate_tab_feeds_cache(sub.tab_id)

        # Return subscription data including items
        sub_dict = sub.to_dict()
        items = (
            sub.feed.items.order_by(FeedItem.published_time.desc().nullslast())
            .limit(DEFAULT_FEED_ITEMS_LIMIT)
            .all()
        )
        # Get is_read statuses
        item_ids = [it.id for it in items]
        item_states = {
            s.item_id: s.is_read
            for s in UserItemState.query.filter(
                UserItemState.user_id == current_user.id,
                UserItemState.item_id.in_(item_ids),
            ).all()
        }

        sub_dict["items"] = [
            it.to_dict(is_read=item_states.get(it.id, False)) for it in items
        ]
        return jsonify(sub_dict), 200

    except Exception as e:
        db.session.rollback()
        logger.error("Error updating subscription %s: %s",
                     sub_id, e, exc_info=True)
        return (
            jsonify(
                {"error": "An internal error occurred while updating the feed."}),
            500,
        )


@feeds_bp.route("/update-all", methods=["POST"])
@login_required
def api_update_all_feeds():
    """Triggers an update for all feeds in the system (global)."""
    # Still global, but maybe restricted to admins?
    # Or just let any user trigger a global refresh?
    # For SheepVibes, let's keep it open or restricted to logged-in users.
    try:
        # Call the existing update_all_feeds service
        from ..feed_service import update_all_feeds

        processed_count, new_items_count, _ = update_all_feeds()

        # SSE handles broadcasting
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
        return (
            jsonify(
                {"error": "An internal error occurred while updating all feeds."}),
            500,
        )


@feeds_bp.route("/<int:sub_id>/update", methods=["POST"])
@login_required
def update_feed(sub_id):
    """Manually triggers an update check for a specific feed via subscription."""
    sub = (
        db.session.query(Subscription)
        .filter_by(id=sub_id, user_id=current_user.id)
        .first_or_404()
    )
    try:
        success, new_items, _ = fetch_and_update_feed(sub.feed_id)
        if success and new_items > 0:
            invalidate_tab_feeds_cache(sub.tab_id)
        return jsonify(sub.to_dict())
    except Exception as e:
        logger.error(
            "Error during manual update for subscription %s: %s",
            sub_id,
            e,
            exc_info=True,
        )
        return (jsonify({"error": "An internal error occurred"}), 500)


@feeds_bp.route("/<int:sub_id>/items", methods=["GET"])
@login_required
def get_feed_items(sub_id):
    """Returns a paginated list of items for a specific subscription."""
    sub = (
        db.session.query(Subscription)
        .filter_by(id=sub_id, user_id=current_user.id)
        .first_or_404()
    )

    try:
        offset = int(request.args.get("offset", 0))
        limit = int(request.args.get("limit", DEFAULT_PAGINATION_LIMIT))
    except (ValueError, TypeError):
        return (
            jsonify(
                {"error": "Offset and limit parameters must be valid integers."}),
            400,
        )

    offset = max(0, offset)
    limit = max(1, min(limit, MAX_PAGINATION_LIMIT))

    items = (
        FeedItem.query.filter_by(feed_id=sub.feed_id)
        .order_by(
            FeedItem.published_time.desc().nullslast(), FeedItem.fetched_time.desc()
        )
        .offset(offset)
        .limit(limit)
        .all()
    )

    # Get is_read statuses
    item_ids = [it.id for it in items]
    item_states = {
        s.item_id: s.is_read
        for s in UserItemState.query.filter(
            UserItemState.user_id == current_user.id,
            UserItemState.item_id.in_(item_ids),
        ).all()
    }

    return jsonify([it.to_dict(is_read=item_states.get(it.id, False)) for it in items])


@items_bp.route("/<int:item_id>/read", methods=["POST"])
@login_required
def mark_item_read(item_id):
    """Marks a specific feed item as read for the current user."""
    item = db.session.get(FeedItem, item_id)
    if not item:
        return jsonify({"error": "Feed item not found"}), 404

    # Check if item state already exists
    state = UserItemState.query.filter_by(
        user_id=current_user.id, item_id=item_id
    ).first()
    if state and state.is_read:
        return jsonify({"message": "Item already marked as read"}), 200

    try:
        if not state:
            state = UserItemState(
                user_id=current_user.id, item_id=item_id, is_read=True
            )
            db.session.add(state)
        else:
            state.is_read = True

        db.session.commit()

        # Invalidate caches for all tabs where this feed is subscribed by this user
        subs = Subscription.query.filter_by(
            user_id=current_user.id, feed_id=item.feed_id
        ).all()
        for sub in subs:
            invalidate_tab_feeds_cache(sub.tab_id)

        return jsonify({"message": f"Item {item_id} marked as read"}), 200
    except Exception as e:
        db.session.rollback()
        logger.error(
            "Error marking item %s as read: %s", item_id, str(e), exc_info=True
        )
        return (jsonify({"error": "An internal error occurred"}), 500)
