import logging

from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required
from sqlalchemy import and_, func, or_, select
from sqlalchemy.exc import IntegrityError

from ..cache_utils import (
    invalidate_tabs_cache,
    make_tab_feeds_cache_key,
    make_tabs_cache_key,
)
from ..constants import DEFAULT_FEED_ITEMS_LIMIT, MAX_PAGINATION_LIMIT
from ..extensions import cache, db
from ..models import FeedItem, Subscription, Tab, UserItemState

logger = logging.getLogger(__name__)

tabs_bp = Blueprint("tabs", __name__, url_prefix="/api/tabs")


@tabs_bp.route("", methods=["GET"])
@login_required
@cache.cached(make_cache_key=make_tabs_cache_key)
def get_tabs():
    """Returns a list of all tabs for the current user, ordered by their 'order' field."""
    tabs = Tab.query.filter_by(
        user_id=current_user.id).order_by(Tab.order).all()

    tab_ids = [tab.id for tab in tabs]
    if not tab_ids:
        return jsonify([])

    # Pre-calculate unread counts for all tabs in a single query to avoid N+1
    unread_counts_query = (
        db.session.query(Subscription.tab_id, func.count(FeedItem.id))
        .join(FeedItem, Subscription.feed_id == FeedItem.feed_id)
        .outerjoin(
            UserItemState,
            and_(
                UserItemState.item_id == FeedItem.id,
                UserItemState.user_id == current_user.id,
            ),
        )
        .filter(
            Subscription.tab_id.in_(tab_ids),
            or_(UserItemState.is_read.is_(False),
                UserItemState.is_read.is_(None)),
        )
        .group_by(Subscription.tab_id)
    )
    unread_counts = dict(unread_counts_query.all())

    return jsonify(
        [tab.to_dict(unread_count=unread_counts.get(tab.id, 0))
         for tab in tabs]
    )


@tabs_bp.route("", methods=["POST"])
@login_required
def create_tab():
    """Creates a new tab for the current user."""
    data = request.get_json()
    if not data or "name" not in data or not data["name"].strip():
        return jsonify({"error": "Missing or empty tab name"}), 400

    tab_name = data["name"].strip()

    # Check for duplicate tab name for THIS user
    existing_tab = Tab.query.filter_by(
        user_id=current_user.id, name=tab_name).first()
    if existing_tab:
        return (
            jsonify({"error": f'Tab with name "{tab_name}" already exists'}),
            409,
        )

    max_order = (
        db.session.query(func.max(Tab.order))
        .filter_by(user_id=current_user.id)
        .scalar()
    )
    new_order = (max_order or -1) + 1

    try:
        new_tab = Tab(user_id=current_user.id, name=tab_name, order=new_order)
        db.session.add(new_tab)
        db.session.commit()
        invalidate_tabs_cache()
        logger.info(
            "User %s created new tab '%s' with id %s.",
            current_user.username,
            new_tab.name,
            new_tab.id,
        )
        return jsonify(new_tab.to_dict(unread_count=0)), 201
    except IntegrityError:
        db.session.rollback()
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
    """Renames an existing tab for the current user."""
    tab = (
        db.session.query(Tab)
        .filter_by(id=tab_id, user_id=current_user.id)
        .first_or_404()
    )

    data = request.get_json()
    if not data or "name" not in data or not data["name"].strip():
        return jsonify({"error": "Missing or empty new tab name"}), 400

    new_name = data["name"].strip()

    existing_tab = Tab.query.filter(
        Tab.user_id == current_user.id, Tab.id != tab_id, Tab.name == new_name
    ).first()
    if existing_tab:
        return (jsonify({"error": f'Tab name "{new_name}" is already in use'}), 409)

    try:
        tab.name = new_name
        db.session.commit()
        invalidate_tabs_cache()
        return jsonify(tab.to_dict()), 200
    except IntegrityError:
        db.session.rollback()
        return jsonify({"error": f'Tab name "{new_name}" is already in use'}), 409
    except Exception as e:
        db.session.rollback()
        logger.error("Error renaming tab %s: %s", tab_id, e, exc_info=True)
        return (
            jsonify({"error": "An internal error occurred while renaming the tab."}),
            500,
        )


@tabs_bp.route("/<int:tab_id>", methods=["DELETE"])
@login_required
def delete_tab(tab_id):
    """Deletes a tab and its associated subscriptions."""
    tab = (
        db.session.query(Tab)
        .filter_by(id=tab_id, user_id=current_user.id)
        .first_or_404()
    )

    try:
        db.session.delete(tab)
        db.session.commit()
        invalidate_tabs_cache()
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
    """Returns a list of subscriptions for a tab, including recent items for each."""
    db.session.query(Tab).filter_by(
        id=tab_id, user_id=current_user.id).first_or_404()

    limit = request.args.get("limit", DEFAULT_FEED_ITEMS_LIMIT, type=int)
    limit = max(0, min(limit, MAX_PAGINATION_LIMIT))

    subscriptions = Subscription.query.filter_by(
        tab_id=tab_id, user_id=current_user.id
    ).all()
    if not subscriptions:
        return jsonify([])

    feed_ids = [s.feed_id for s in subscriptions]

    # Query 2: Get unread counts for all subscriptions in this tab
    unread_counts_query = (
        db.session.query(Subscription.feed_id, func.count(FeedItem.id))
        .join(FeedItem, Subscription.feed_id == FeedItem.feed_id)
        .outerjoin(
            UserItemState,
            and_(
                UserItemState.item_id == FeedItem.id,
                UserItemState.user_id == current_user.id,
            ),
        )
        .filter(
            Subscription.tab_id == tab_id,
            or_(UserItemState.is_read.is_(False),
                UserItemState.is_read.is_(None)),
        )
        .group_by(Subscription.feed_id)
    )
    unread_counts = dict(unread_counts_query.all())

    # Query 3: Get the top N items for ALL those feeds
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

    # Join with UserItemState to get is_read status
    item_ids = [item_row.id for item_row in top_items_results]
    item_states = {}
    if item_ids:
        states = UserItemState.query.filter(
            UserItemState.user_id == current_user.id,
            UserItemState.item_id.in_(item_ids),
        ).all()
        item_states = {s.item_id: s.is_read for s in states}

    items_by_feed = {}
    for item_row in top_items_results:
        item_dict = {
            "id": item_row.id,
            "feed_id": item_row.feed_id,
            "title": item_row.title,
            "link": item_row.link,
            "published_time": FeedItem.to_iso_z_string(item_row.published_time),
            "fetched_time": FeedItem.to_iso_z_string(item_row.fetched_time),
            "is_read": item_states.get(item_row.id, False),
            "guid": item_row.guid,
        }
        feed_id = item_row.feed_id
        if feed_id not in items_by_feed:
            items_by_feed[feed_id] = []
        items_by_feed[feed_id].append(item_dict)

    response_data = []
    for sub in subscriptions:
        sub_dict = sub.to_dict(unread_count=unread_counts.get(sub.feed_id, 0))
        sub_dict["items"] = items_by_feed.get(sub.feed_id, [])
        response_data.append(sub_dict)

    return jsonify(response_data)
