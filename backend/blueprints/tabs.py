import logging

from flask import Blueprint, jsonify, request
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from ..cache_utils import (
    invalidate_tabs_cache,
    make_tab_feeds_cache_key,
    make_tabs_cache_key,
)
from ..constants import DEFAULT_FEED_ITEMS_LIMIT, MAX_PAGINATION_LIMIT
from ..extensions import cache, db
from ..models import Feed, FeedItem, Tab

logger = logging.getLogger(__name__)

tabs_bp = Blueprint("tabs", __name__, url_prefix="/api/tabs")


@tabs_bp.route("", methods=["GET"])
@cache.cached(make_cache_key=make_tabs_cache_key)
def get_tabs():
    """Returns a list of all tabs, ordered by their 'order' field.

    Returns:
        A JSON response containing a list of tab objects.
    """
    tabs = Tab.query.order_by(Tab.order).all()

    tab_ids = [tab.id for tab in tabs]
    if not tab_ids:
        return jsonify([])

    # Pre-calculate unread counts for all tabs in a single query to avoid N+1
    unread_counts_query = (db.session.query(Feed.tab_id, func.count(
        FeedItem.id)).join(FeedItem, Feed.id == FeedItem.feed_id).filter(
            Feed.tab_id.in_(tab_ids),
            FeedItem.is_read.is_(False)).group_by(Feed.tab_id))
    unread_counts = dict(unread_counts_query.all())

    return jsonify([
        tab.to_dict(unread_count=unread_counts.get(tab.id, 0)) for tab in tabs
    ])


@tabs_bp.route("", methods=["POST"])
def create_tab():
    """Creates a new tab.

    Returns:
        A tuple containing a JSON response and the HTTP status code.
    """
    data = request.get_json()
    # Validate input data
    if not data or "name" not in data or not data["name"].strip():
        return jsonify({"error": "Missing or empty tab name"}), 400

    tab_name = data["name"].strip()

    # Check for duplicate tab name
    existing_tab = Tab.query.filter_by(name=tab_name).first()
    if existing_tab:
        return (
            jsonify({"error": f'Tab with name "{tab_name}" already exists'}),
            409,
        )  # Conflict

    # Determine the order for the new tab (append to the end)
    max_order = db.session.query(db.func.max(Tab.order)).scalar()
    new_order = (max_order or -1) + 1

    try:
        new_tab = Tab(name=tab_name, order=new_order)
        db.session.add(new_tab)
        db.session.commit()
        invalidate_tabs_cache()
        logger.info("Created new tab '%s' with id %s.", new_tab.name,
                    new_tab.id)
        return jsonify(new_tab.to_dict(unread_count=0)), 201  # Created
    except IntegrityError:
        db.session.rollback()
        logger.warning("Attempted to create a tab with a duplicate name '%s'",
                       tab_name)
        return jsonify({"error":
                        f'Tab with name "{tab_name}" already exists'}), 409
    except Exception as e:
        db.session.rollback()
        logger.error("Error creating tab '%s': %s", tab_name, e, exc_info=True)
        return (
            jsonify({
                "error":
                "An internal error occurred while creating the tab."
            }),
            500,
        )


@tabs_bp.route("/<int:tab_id>", methods=["PUT"])
def rename_tab(tab_id):
    """Renames an existing tab.

    Args:
        tab_id (int): The ID of the tab to rename.

    Returns:
        A tuple containing a JSON response and the HTTP status code.
    """
    # Find the tab or return 404
    tab = db.get_or_404(Tab, tab_id)

    data = request.get_json()
    # Validate input data
    if not data or "name" not in data or not data["name"].strip():
        return jsonify({"error": "Missing or empty new tab name"}), 400

    new_name = data["name"].strip()

    # Check if the new name is already taken by another tab
    existing_tab = Tab.query.filter(Tab.id != tab_id,
                                    Tab.name == new_name).first()
    if existing_tab:
        return (
            jsonify({"error": f'Tab name "{new_name}" is already in use'}),
            409,
        )  # Conflict

    try:
        original_name = tab.name
        tab.name = new_name
        db.session.commit()
        invalidate_tabs_cache()
        logger.info("Renamed tab %s from '%s' to '%s'.", tab_id, original_name,
                    new_name)
        return jsonify(tab.to_dict()), 200  # OK
    except IntegrityError:
        db.session.rollback()
        logger.warning(
            "Failed to rename tab %s to '%s' due to duplicate name.", tab_id,
            new_name)
        return jsonify({"error":
                        f'Tab name "{new_name}" is already in use'}), 409
    except Exception as e:
        db.session.rollback()
        logger.error("Error renaming tab %s to '%s': %s",
                     tab_id,
                     new_name,
                     str(e),
                     exc_info=True)
        return (
            jsonify({
                "error":
                "An internal error occurred while renaming the tab."
            }),
            500,
        )


@tabs_bp.route("/<int:tab_id>", methods=["DELETE"])
def delete_tab(tab_id):
    """Deletes a tab and its associated feeds/items."""
    # Find the tab or return 404
    tab = db.get_or_404(Tab, tab_id)

    try:
        tab_name = tab.name
        # Associated feeds/items are deleted due to cascade settings in the model
        db.session.delete(tab)
        db.session.commit()
        invalidate_tabs_cache()
        logger.info("Deleted tab '%s' with id %s.", tab_name, tab_id)
        # OK
        return jsonify({"message": f"Tab {tab_id} deleted successfully"}), 200
    except Exception as e:
        db.session.rollback()
        logger.error("Error deleting tab %s: %s", tab_id, e, exc_info=True)
        return (
            jsonify({
                "error":
                "An internal error occurred while deleting the tab."
            }),
            500,
        )


@tabs_bp.route("/<int:tab_id>/feeds", methods=["GET"])
@cache.cached(make_cache_key=make_tab_feeds_cache_key)
def get_feeds_for_tab(tab_id):
    """
    Returns a list of feeds for a tab, including recent items for each feed.
    This is highly optimized to prevent the N+1 query problem.
    """
    # Ensure tab exists, or return 404.
    db.get_or_404(Tab, tab_id)

    # Get limit for items from query string, default to DEFAULT_FEED_ITEMS_LIMIT.
    limit = request.args.get("limit", DEFAULT_FEED_ITEMS_LIMIT, type=int)
    # Clamp limit to a sensible range to avoid surprising behavior with negative values.
    limit = max(0, min(limit, MAX_PAGINATION_LIMIT))

    # Query 1: Get all feeds for the given tab.
    feeds = Feed.query.filter_by(tab_id=tab_id).all()
    if not feeds:
        return jsonify([])

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

    return jsonify(response_data)
