import pytest

from backend.app import app
from backend.cache_utils import (
    get_version,
    invalidate_tab_feeds_cache,
    invalidate_tabs_cache,
    make_tab_feeds_cache_key,
    make_tabs_cache_key,
)
from backend.extensions import cache


@pytest.fixture(autouse=True)
def app_context():
    """Provide an app context and clear the cache for each test."""
    with app.app_context():
        cache.clear()
        yield
        cache.clear()


def test_get_version_default():
    """Test get_version returns default when key is not in cache."""
    # Default is 1 if not specified
    assert get_version("non_existent_key") == 1
    # Explicit default
    assert get_version("non_existent_key", default=5) == 5


def test_get_version_cached():
    """Test get_version returns cached value when key exists."""
    cache.set("test_key", 10)
    assert get_version("test_key") == 10


def test_make_tabs_cache_key():
    """Test make_tabs_cache_key incorporates version correctly."""
    # Initial version is 1 (default)
    assert make_tabs_cache_key() == "view/tabs/v1"

    # After invalidating tabs cache, version should be 2
    invalidate_tabs_cache()
    assert make_tabs_cache_key() == "view/tabs/v2"


@pytest.mark.parametrize(
    "url, tab_id, cache_versions, expected_key",
    [
        pytest.param(
            "/api/tabs/1/feeds", 1, {},
            "view/tab/1/v1/tabs_v1/?",
            id="default_versions_no_query_params"
        ),
        pytest.param(
            "/api/tabs/1/feeds", 1, {"tabs_version": 3, "tab_1_version": 4},
            "view/tab/1/v4/tabs_v3/?",
            id="custom_versions_no_query_params"
        ),
        pytest.param(
            "/api/tabs/1/feeds?limit=10&other=ignored", 1, {"tabs_version": 3, "tab_1_version": 4},
            "view/tab/1/v4/tabs_v3/?limit=10",
            id="with_query_params"
        ),
        # Case 4: Multiple values for the same used param ('limit')
        # Verifies that request.args.items(multi=True) and urllib.parse.urlencode
        # correctly preserve repeated keys in the generated cache key.
        pytest.param(
            "/api/tabs/1/feeds?limit=10&limit=20", 1, {"tabs_version": 3, "tab_1_version": 4},
            "view/tab/1/v4/tabs_v3/?limit=10&limit=20",
            id="multiple_values_for_query_param"
        ),
    ],
)
def test_make_tab_feeds_cache_key(url, tab_id, cache_versions, expected_key):
    """Test make_tab_feeds_cache_key incorporates versions and query params."""
    for k, v in cache_versions.items():
        cache.set(k, v)

    with app.test_request_context(url):
        key = make_tab_feeds_cache_key(tab_id)
        assert key == expected_key


def test_invalidate_tabs_cache():
    """Test invalidate_tabs_cache increments version in cache."""
    assert get_version("tabs_version") == 1
    invalidate_tabs_cache()
    assert get_version("tabs_version") == 2
    invalidate_tabs_cache()
    assert get_version("tabs_version") == 3


def test_invalidate_tab_feeds_cache():
    """Test invalidate_tab_feeds_cache increments versions correctly."""
    # Test basic invalidation (defaults to also invalidating tabs)
    assert get_version("tab_1_version") == 1
    assert get_version("tabs_version") == 1

    invalidate_tab_feeds_cache(1)
    assert get_version("tab_1_version") == 2
    assert get_version("tabs_version") == 2

    # Test invalidation of specific tab without invalidating all tabs
    invalidate_tab_feeds_cache(1, invalidate_tabs=False)
    assert get_version("tab_1_version") == 3
    assert get_version("tabs_version") == 2

    # Test invalidation of another tab
    invalidate_tab_feeds_cache(2, invalidate_tabs=True)
    assert get_version("tab_2_version") == 2
    assert get_version("tab_1_version") == 3
    assert get_version("tabs_version") == 3
