import logging
from flask import request
from .extensions import cache

logger = logging.getLogger(__name__)

def get_version(key, default=1):
    """Gets a version number for a cache key from the cache.

    Args:
        key (str): The cache key for the version number.
        default (int): The default version number to return if the key is not found.

    Returns:
        int: The version number.
    """
    return cache.get(key) or default


def make_tabs_cache_key(*args, **kwargs):
    """Creates a cache key for the main tabs list, incorporating a version.

    Args:
        *args: Additional arguments (unused).
        **kwargs: Additional keyword arguments (unused).

    Returns:
        str: The generated cache key.
    """
    version = get_version("tabs_version")
    return f"view/tabs/v{version}"


def make_tab_feeds_cache_key(tab_id):
    """Creates a cache key for a specific tab's feeds, incorporating version and query params.

    Args:
        tab_id (int): The ID of the tab.

    Returns:
        str: The generated cache key.
    """
    tabs_version = get_version("tabs_version")  # For unread counts
    tab_version = get_version(f"tab_{tab_id}_version")
    query_string = request.query_string.decode().replace("&", "_")  # Sanitize for key
    return f"view/tab/{tab_id}/v{tab_version}/tabs_v{tabs_version}/?{query_string}"


def invalidate_tabs_cache():
    """Invalidates the tabs list cache by incrementing its version."""
    version_key = "tabs_version"
    new_version = get_version(version_key) + 1
    cache.set(version_key, new_version)
    logger.info(f"Invalidated tabs cache. New version: {new_version}")


def invalidate_tab_feeds_cache(tab_id):
    """Invalidates a specific tab's feed cache and the main tabs list cache.

    Args:
        tab_id (int): The ID of the tab to invalidate the cache for.
    """
    version_key = f"tab_{tab_id}_version"
    new_version = get_version(version_key) + 1
    cache.set(version_key, new_version)
    logger.info(
        f"Invalidated cache for tab {tab_id}. New version: {new_version}")
    # Also invalidate the main tabs list because unread counts will have changed.
    invalidate_tabs_cache()
