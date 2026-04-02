import logging
import urllib.parse

from flask import request

from .extensions import cache

logger = logging.getLogger(__name__)

TABS_VERSION_KEY = "tabs_version"


def get_tab_version_key(tab_id):
    """Helper to generate a version key for a specific tab."""
    return f"tab_{tab_id}_version"


def get_version(key, default=1):
    """Gets a version number for a cache key from the cache.

    Args:
        key (str): The cache key for the version number.
        default (int): The default version number to return if the key is not found.

    Returns:
        int: The version number.
    """
    version = cache.get(key)
    return version if version is not None else default


def make_tabs_cache_key(*args, **kwargs):
    """Creates a cache key for the main tabs list, incorporating a version.

    Args:
        *args: Additional arguments (unused).
        **kwargs: Additional keyword arguments (unused).

    Returns:
        str: The generated cache key.
    """
    version = get_version(TABS_VERSION_KEY)
    return f"view/tabs/v{version}"


def make_tab_feeds_cache_key(tab_id):
    """Creates a cache key for a specific tab's feeds, incorporating version and query params.

    Args:
        tab_id (int): The ID of the tab.

    Returns:
        str: The generated cache key.
    """
    tabs_version = get_version(TABS_VERSION_KEY)  # For unread counts
    tab_version = get_version(get_tab_version_key(tab_id))
    # Only include parameters that are used by the endpoint in the cache key.
    used_params = ["limit"]
    sorted_query = sorted(
        (k, v) for k, v in request.args.items(multi=True) if k in used_params
    )
    query_string = urllib.parse.urlencode(sorted_query)
    base_key = f"view/tab/{tab_id}/v{tab_version}/tabs_v{tabs_version}/"
    return f"{base_key}?{query_string}" if query_string else base_key


def invalidate_tabs_cache():
    """Invalidates the tabs list cache by incrementing its version."""
    new_version = get_version(TABS_VERSION_KEY) + 1
    cache.set(TABS_VERSION_KEY, new_version)
    logger.info("Invalidated tabs cache. New version: %s", new_version)


def invalidate_tab_feeds_cache(tab_id, invalidate_tabs=True):
    """Invalidates a specific tab's feed cache and the main tabs list cache.

    Args:
        tab_id (int): The ID of the tab to invalidate the cache for.
        invalidate_tabs (bool): If True, also invalidates the main tabs list cache.
    """
    version_key = get_tab_version_key(tab_id)
    new_version = get_version(version_key) + 1
    cache.set(version_key, new_version)
    logger.info("Invalidated cache for tab %s. New version: %s",
                tab_id, new_version)
    if invalidate_tabs:
        # Also invalidate the main tabs list because unread counts will have changed.
        invalidate_tabs_cache()


def invalidate_multiple_tabs_cache(tab_ids, invalidate_tabs=True):
    """Invalidates multiple tabs' feed caches efficiently using get_many/set_many.

    Args:
        tab_ids (iterable): The IDs of the tabs to invalidate the cache for.
        invalidate_tabs (bool): If True, also invalidates the main tabs list cache.
    """
    if not tab_ids:
        return

    keys = [get_tab_version_key(tab_id) for tab_id in tab_ids]
    # get_many returns a list of values in the same order as the keys
    versions = cache.get_many(*keys)

    # Handle None values and increment
    updates = {}
    for i, key in enumerate(keys):
        current_version = versions[i] if versions[i] is not None else 1
        updates[key] = current_version + 1

    cache.set_many(updates)
    logger.info("Invalidated cache for multiple tabs: %s", tab_ids)

    if invalidate_tabs:
        invalidate_tabs_cache()
