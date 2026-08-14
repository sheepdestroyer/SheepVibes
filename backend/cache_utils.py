"""Caching utilities for partitioned user views."""

import logging
import urllib.parse

from flask import g, has_request_context, request, session

from .extensions import cache

logger = logging.getLogger(__name__)


def _resolve_user_id(user_id=None):
    """Resolves the user id from explicit argument, Flask g, or session."""
    if user_id is not None:
        return user_id
    if has_request_context():
        if hasattr(g, "_current_user") and g._current_user:
            return g._current_user.id
        return session.get("user_id") or "anon"
    return "anon"


def get_version(key, default=1):
    """Gets a version number for a cache key from the cache.

    Args:
        key (str): The cache key for the version number.
        default (int): The default version number to return if the key is not found.

    Returns:
        int: The version number.
    """
    return cache.get(key) or default


def make_tabs_cache_key(user_id=None, *args, **kwargs):
    """Creates a cache key for the main tabs list, partitioned by user.

    Args:
        user_id (int | None): User identifier if known.
        *args: Additional arguments (unused).
        **kwargs: Additional keyword arguments (unused).

    Returns:
        str: The generated cache key.
    """
    uid = _resolve_user_id(user_id)
    version_key = f"user_{uid}_tabs_version"
    version = get_version(version_key)
    return f"view/user/{uid}/tabs/v{version}"


def make_tab_feeds_cache_key(tab_id, user_id=None, *args, **kwargs):
    """Creates a cache key for a specific tab's feeds, partitioned by user.

    Args:
        tab_id (int): The ID of the tab.
        user_id (int | None): User identifier if known.
        *args: Additional arguments (unused).
        **kwargs: Additional keyword arguments (unused).

    Returns:
        str: The generated cache key.
    """
    uid = _resolve_user_id(user_id)
    tabs_version = get_version(f"user_{uid}_tabs_version")
    tab_version = get_version(f"user_{uid}_tab_{tab_id}_version")
    query_string = ""
    if has_request_context():
        used_params = ["limit"]
        sorted_query = sorted(
            (k, v) for k, v in request.args.items(multi=True) if k in used_params
        )
        query_string = urllib.parse.urlencode(sorted_query)
    return f"view/user/{uid}/tab/{tab_id}/v{tab_version}/tabs_v{tabs_version}/?{query_string}"


def invalidate_tabs_cache(user_id=None):
    """Invalidates the tabs list cache for a user by incrementing its version."""
    uid = _resolve_user_id(user_id)
    version_key = f"user_{uid}_tabs_version"
    new_version = get_version(version_key) + 1
    cache.set(version_key, new_version)
    logger.info("Invalidated tabs cache for user %s. New version: %s", uid, new_version)


def invalidate_tab_feeds_cache(tab_id, user_id=None, invalidate_tabs=True):
    """Invalidates a specific tab's feed cache and optionally the main tabs list cache.

    Args:
        tab_id (int): The ID of the tab to invalidate the cache for.
        user_id (int | None): The user ID if known.
        invalidate_tabs (bool): If True, also invalidates the main tabs list cache.
    """
    uid = _resolve_user_id(user_id)
    version_key = f"user_{uid}_tab_{tab_id}_version"
    new_version = get_version(version_key) + 1
    cache.set(version_key, new_version)
    logger.info(
        "Invalidated cache for user %s tab %s. New version: %s",
        uid,
        tab_id,
        new_version,
    )
    if invalidate_tabs:
        invalidate_tabs_cache(uid)


def invalidate_user_caches(user_id):
    """Invalidates all cached views for a specific user."""
    invalidate_tabs_cache(user_id=user_id)

