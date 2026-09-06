"""Blueprint for managing tabs in SheepVibes."""

import logging

from flask import Blueprint, jsonify, request
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from ..auth import get_current_user, login_required
from ..cache_utils import (
    invalidate_tab_feeds_cache,
    invalidate_tabs_cache,
    make_tab_feeds_cache_key,
    make_tabs_cache_key,
)
from ..constants import DEFAULT_FEED_ITEMS_LIMIT, MAX_PAGINATION_LIMIT
from ..extensions import cache, db
from ..models import Feed, FeedItem, Tab

logger = logging.getLogger(__name__)


def _validate_tab_name(data, user_id, exclude_tab_id=None, is_rename=False):
    """Validates tab name input and checks for duplicates for the specific user.

    Returns:
        tuple: (tab_name, error_response) where error_response is None if valid
    """
    error_prefix = "new " if is_rename else ""
    if not data or "name" not in data or not str(data["name"]).strip():
        return None, (
            jsonify({"error": f"Missing or empty {error_prefix}tab name"}),
            400,
        )

    tab_name = str(data["name"]).strip()

    query = Tab.query.filter(Tab.user_id == user_id, Tab.name == tab_name)
    if exclude_tab_id is not None:
        query = query.filter(Tab.id != exclude_tab_id)

    if query.first():
        msg = (
            f'Tab name "{tab_name}" is already in use'
            if is_rename
            else f'Tab with name "{tab_name}" already exists'
        )
        return None, (jsonify({"error": msg}), 409)

    return tab_name, None


def _get_unread_counts(feed_ids):
    """Calculates unread counts for given feed IDs."""
    if not feed_ids:
        return {}
    unread_counts_query = (
        db.session.query(FeedItem.feed_id, func.count(FeedItem.id))
        .filter(FeedItem.feed_id.in_(feed_ids), FeedItem.is_read.is_(False))
        .group_by(FeedItem.feed_id)
    )
    return dict(unread_counts_query.all())


def _get_top_items_for_feeds(feed_ids, limit):
    """Fetches the top items for given feed IDs up to the limit."""
    if not feed_ids:
        return {}
    ranked_items_subq = (
        select(
            FeedItem,
            func.row_number()
            .over(
                partition_by=FeedItem.feed_id,
                order_by=[
                    FeedItem.published_time.desc().nullslast(),
                    FeedItem.fetched_time.desc(),
                ],
            )
            .label("rank"),
        )
        .filter(FeedItem.feed_id.in_(feed_ids))
        .subquery()
    )

    top_items_query = select(ranked_items_subq).filter(
        ranked_items_subq.c.rank <= limit
    )

    top_items_results = db.session.execute(top_items_query).all()

    items_by_feed = {}
    for item_row in top_items_results:
        item_dict = {
            "id": item_row.id,
            "feed_id": item_row.feed_id,
            "title": item_row.title,
            "link": item_row.link,
            "comments_url": item_row.comments_url,
            "published_time": FeedItem.to_iso_z_string(item_row.published_time),
            "fetched_time": FeedItem.to_iso_z_string(item_row.fetched_time),
            "is_read": item_row.is_read,
            "guid": item_row.guid,
        }
        feed_id = item_row.feed_id
        if feed_id not in items_by_feed:
            items_by_feed[feed_id] = []
        items_by_feed[feed_id].append(item_dict)

    return items_by_feed


tabs_bp = Blueprint("tabs", __name__, url_prefix="/api/tabs")


@tabs_bp.route("", methods=["GET"])
@login_required
@cache.cached(make_cache_key=make_tabs_cache_key)
def get_tabs():
    """Returns a list of all tabs for the authenticated user, ordered by 'order'.

    Returns:
        A JSON response containing a list of tab objects.
    """
    user = get_current_user()
    tabs = Tab.query.filter_by(user_id=user.id).order_by(Tab.order).all()

    tab_ids = [tab.id for tab in tabs]
    if not tab_ids:
        return jsonify([])

    # Pre-calculate unread counts for all tabs in a single query to avoid N+1
    unread_counts_query = (
        db.session.query(Feed.tab_id, func.count(FeedItem.id))
        .join(FeedItem, Feed.id == FeedItem.feed_id)
        .filter(Feed.tab_id.in_(tab_ids), FeedItem.is_read.is_(False))
        .group_by(Feed.tab_id)
    )
    unread_counts = dict(unread_counts_query.all())

    return jsonify(
        [tab.to_dict(unread_count=unread_counts.get(tab.id, 0)) for tab in tabs]
    )


@tabs_bp.route("", methods=["POST"])
@login_required
def create_tab():
    """Creates a new tab for the authenticated user.

    Returns:
        A tuple containing a JSON response and the HTTP status code.
    """
    user = get_current_user()
    data = request.get_json()
    tab_name, error_response = _validate_tab_name(data, user_id=user.id)
    if error_response:
        return error_response

    # Determine the order for the new tab (append to the end for this user)
    max_order = (
        db.session.query(db.func.max(Tab.order))
        .filter(Tab.user_id == user.id)
        .scalar()
    )
    new_order = (max_order or -1) + 1

    try:
        new_tab = Tab(user_id=user.id, name=tab_name, order=new_order)
        db.session.add(new_tab)
        db.session.commit()
        invalidate_tabs_cache(user.id)
        logger.info(
            "Created new tab '%s' with id %s for user %s.",
            new_tab.name,
            new_tab.id,
            user.id,
        )
        return jsonify(new_tab.to_dict(unread_count=0)), 201  # Created
    except IntegrityError:
        db.session.rollback()
        logger.warning(
            "Attempted to create a tab with duplicate name '%s' for user %s",
            tab_name,
            user.id,
        )
        return jsonify({"error": f'Tab with name "{tab_name}" already exists'}), 409
    except Exception as e:
        db.session.rollback()
        logger.error("Error creating tab '%s': %s", tab_name, e, exc_info=True)
        return (
            jsonify({"error": "An internal error occurred while creating the tab."}),
            500,
        )


@tabs_bp.route("/<int:tab_id>", methods=["PUT"])
@login_required
def rename_tab(tab_id):
    """Renames an existing tab owned by the authenticated user.

    Args:
        tab_id (int): The ID of the tab to rename.

    Returns:
        A tuple containing a JSON response and the HTTP status code.
    """
    user = get_current_user()
    tab = Tab.query.filter_by(id=tab_id, user_id=user.id).first()
    if not tab:
        return jsonify({"error": "Tab not found"}), 404

    data = request.get_json()
    new_name, error_response = _validate_tab_name(
        data, user_id=user.id, exclude_tab_id=tab_id, is_rename=True
    )
    if error_response:
        return error_response

    try:
        original_name = tab.name
        tab.name = new_name
        db.session.commit()
        invalidate_tabs_cache(user.id)
        logger.info(
            "Renamed tab %s from '%s' to '%s' for user %s.",
            tab_id,
            original_name,
            new_name,
            user.id,
        )
        unread_count = (
            db.session.query(db.func.count(FeedItem.id))
            .join(Feed)
            .filter(Feed.tab_id == tab.id, FeedItem.is_read.is_(False))
            .scalar()
            or 0
        )
        return jsonify(tab.to_dict(unread_count=unread_count)), 200  # OK
    except IntegrityError:
        db.session.rollback()
        logger.warning(
            "Failed to rename tab %s to '%s' due to duplicate name.",
            tab_id,
            new_name,
        )
        return jsonify({"error": f'Tab name "{new_name}" is already in use'}), 409
    except Exception as e:
        db.session.rollback()
        logger.error(
            "Error renaming tab %s to '%s': %s",
            tab_id,
            new_name,
            str(e),
            exc_info=True,
        )
        return (
            jsonify({"error": "An internal error occurred while renaming the tab."}),
            500,
        )


@tabs_bp.route("/<int:tab_id>", methods=["DELETE"])
@login_required
def delete_tab(tab_id):
    """Deletes a tab and its associated feeds/items for the authenticated user."""
    user = get_current_user()
    tab = Tab.query.filter_by(id=tab_id, user_id=user.id).first()
    if not tab:
        return jsonify({"error": "Tab not found"}), 404

    try:
        tab_name = tab.name
        invalidate_tab_feeds_cache(tab_id, user_id=user.id, invalidate_tabs=False)
        db.session.delete(tab)
        db.session.commit()
        invalidate_tabs_cache(user.id)
        logger.info(
            "Deleted tab '%s' with id %s for user %s.",
            tab_name,
            tab_id,
            user.id,
        )
        return jsonify({"message": f"Tab {tab_id} deleted successfully"}), 200
    except Exception as e:
        db.session.rollback()
        logger.error("Error deleting tab %s: %s", tab_id, e, exc_info=True)
        return (
            jsonify({"error": "An internal error occurred while deleting the tab."}),
            500,
        )


@tabs_bp.route("/<int:tab_id>/feeds", methods=["GET"])
@login_required
@cache.cached(make_cache_key=make_tab_feeds_cache_key)
def get_feeds_for_tab(tab_id):
    """Returns feeds for a tab owned by the user, including recent items."""
    user = get_current_user()
    tab = Tab.query.filter_by(id=tab_id, user_id=user.id).first()
    if not tab:
        return jsonify({"error": "Tab not found"}), 404

    limit = request.args.get("limit", DEFAULT_FEED_ITEMS_LIMIT, type=int)
    limit = max(0, min(limit, MAX_PAGINATION_LIMIT))

    feeds = (
        Feed.query.filter_by(tab_id=tab_id)
        .order_by(Feed.order.asc(), Feed.id.asc())
        .all()
    )
    if not feeds:
        return jsonify([])

    feed_ids = [feed.id for feed in feeds]
    unread_counts = _get_unread_counts(feed_ids)
    items_by_feed = _get_top_items_for_feeds(feed_ids, limit)

    response_data = []
    for feed in feeds:
        feed_dict = feed.to_dict(unread_count=unread_counts.get(feed.id, 0))
        feed_dict["items"] = items_by_feed.get(feed.id, [])
        response_data.append(feed_dict)

    return jsonify(response_data)


def _validate_reorder_payload(data, tab_feed_map):
    """Validates the reorder request payload against feeds present in the tab."""
    if not data or "feed_ids" not in data or not isinstance(data["feed_ids"], list):
        return None, ("Missing or invalid feed_ids list", 400)

    feed_ids = data["feed_ids"]
    if not feed_ids:
        return feed_ids, None

    if not all(isinstance(fid, int) for fid in feed_ids):
        return None, ("All feed IDs must be integers", 400)

    if len(feed_ids) != len(set(feed_ids)):
        return None, ("Duplicate feed IDs provided", 400)

    for fid in feed_ids:
        if fid not in tab_feed_map:
            return None, (f"Feed {fid} not found in this tab", 400)

    return feed_ids, None


def _apply_feed_order(feed_ids, tab_feed_map):
    """Applies new order indices to feeds in the tab."""
    for index, fid in enumerate(feed_ids):
        tab_feed_map[fid].order = index

    unmentioned_order = len(feed_ids)
    for fid, feed in tab_feed_map.items():
        if fid not in feed_ids:
            feed.order = unmentioned_order
            unmentioned_order += 1


@tabs_bp.route("/<int:tab_id>/feeds/reorder", methods=["PUT"])
@login_required
def reorder_feeds(tab_id):
    """Updates the display order of feeds within a tab owned by the user.

    Expects JSON payload: {"feed_ids": [id1, id2, ...]}
    """
    user = get_current_user()
    tab = Tab.query.filter_by(id=tab_id, user_id=user.id).first()
    if not tab:
        return jsonify({"error": "Tab not found"}), 404

    tab_feeds = Feed.query.filter_by(tab_id=tab.id).all()
    tab_feed_map = {feed.id: feed for feed in tab_feeds}

    feed_ids, error = _validate_reorder_payload(request.get_json(), tab_feed_map)
    if error:
        return jsonify({"error": error[0]}), error[1]

    if not feed_ids:
        return jsonify({"message": "No feeds to reorder", "feed_ids": []}), 200

    _apply_feed_order(feed_ids, tab_feed_map)

    try:
        db.session.commit()
        invalidate_tab_feeds_cache(tab.id, user_id=user.id)
        logger.info(
            "Reordered %d feeds in tab %s for user %s.",
            len(feed_ids),
            tab.id,
            user.id,
        )
        return jsonify({"message": "Feeds reordered successfully", "feed_ids": feed_ids}), 200
    except Exception as e:
        db.session.rollback()
        logger.error("Error reordering feeds in tab %s: %s", tab.id, e, exc_info=True)
        return (
            jsonify({"error": "An internal error occurred while reordering feeds."}),
            500,
        )
