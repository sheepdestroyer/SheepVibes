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
def clear_cache():
    """Clear the cache before each test to ensure isolation."""
    with app.app_context():
        cache.clear()
    yield
    with app.app_context():
        cache.clear()


def test_get_version_default():
    """Test get_version returns default when key is not in cache."""
    with app.app_context():
        # Default is 1 if not specified
        assert get_version("non_existent_key") == 1
        # Explicit default
        assert get_version("non_existent_key", default=5) == 5


def test_get_version_cached():
    """Test get_version returns cached value when key exists."""
    with app.app_context():
        cache.set("test_key", 10)
        assert get_version("test_key") == 10


def test_make_tabs_cache_key():
    """Test make_tabs_cache_key incorporates version correctly."""
    with app.app_context():
        # Initial version is 1 (default)
        assert make_tabs_cache_key() == "view/tabs/v1"

        # After invalidating tabs cache, version should be 2
        invalidate_tabs_cache()
        assert make_tabs_cache_key() == "view/tabs/v2"


def test_make_tab_feeds_cache_key():
    """Test make_tab_feeds_cache_key incorporates versions and query params."""
    with app.app_context():
        # Case 1: Default versions, no query params
        with app.test_request_context("/api/tabs/1/feeds"):
            key = make_tab_feeds_cache_key(1)
            assert key == "view/tab/1/v1/tabs_v1/?"

        # Case 2: Custom versions in cache
        cache.set("tabs_version", 3)
        cache.set("tab_1_version", 4)
        with app.test_request_context("/api/tabs/1/feeds"):
            key = make_tab_feeds_cache_key(1)
            assert key == "view/tab/1/v4/tabs_v3/?"

        # Case 3: With query params (ensure 'limit' is used and 'other' is ignored)
        with app.test_request_context(
                "/api/tabs/1/feeds?limit=10&other=ignored"):
            key = make_tab_feeds_cache_key(1)
            # The function sorts query params, though here we only have one 'used' param
            assert key == "view/tab/1/v4/tabs_v3/?limit=10"

        # Case 4: Multiple used query params (if there were more than one)
        # For now only 'limit' is in used_params, but let's test if it handles multiple values for limit
        with app.test_request_context("/api/tabs/1/feeds?limit=10&limit=20"):
            key = make_tab_feeds_cache_key(1)
            # urllib.parse.urlencode with multiple values
            assert key == "view/tab/1/v4/tabs_v3/?limit=10&limit=20"


def test_invalidate_tabs_cache():
    """Test invalidate_tabs_cache increments version in cache."""
    with app.app_context():
        assert get_version("tabs_version") == 1
        invalidate_tabs_cache()
        assert get_version("tabs_version") == 2
        invalidate_tabs_cache()
        assert get_version("tabs_version") == 3


def test_invalidate_tab_feeds_cache():
    """Test invalidate_tab_feeds_cache increments versions correctly."""
    with app.app_context():
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
