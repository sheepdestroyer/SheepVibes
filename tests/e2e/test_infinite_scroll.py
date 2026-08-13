"""E2E test for infinite scroll functionality.

Tests that scrolling to the bottom of a feed widget loads additional items
via the infinite scroll mechanism.

Note:
    This test requires the Flask server to have network access to fetch
    external RSS feeds. In environments where external network access is
    restricted (e.g., CI with TESTING=true and in-memory DB), feeds will be
    created but items won't be populated, causing this test to skip gracefully.
"""

from pathlib import Path

import pytest
from playwright.sync_api import Page, expect


def open_settings_menu(page: Page):
    """Ensure the settings menu dropdown is open via user click."""
    if not page.locator("#settings-menu").is_visible():
        page.click("#settings-button")


@pytest.mark.e2e
def test_infinite_scroll_loads_more_items(
    page: Page, live_server: str, opml_file_path: Path
):
    """Verify infinite scroll loads more feed items when scrolling to bottom."""
    base_url = live_server

    # 1. Setup: Navigate to the app
    page.goto(base_url, timeout=10000)

    # 2. Setup: Import feeds to ensure we have content
    open_settings_menu(page)
    page.set_input_files('input[type="file"]', str(opml_file_path))
    # Wait for import to finish (state="attached" because .hidden makes it
    # invisible, so we check for DOM class presence, not visibility)
    page.wait_for_selector(
        "#progress-container.hidden", state="attached", timeout=60000
    )

    # 3. Setup: Refresh feeds to ensure items are populated
    open_settings_menu(page)
    page.click("#refresh-all-feeds-button")
    page.wait_for_selector(
        "#progress-container.hidden", state="attached", timeout=60000
    )

    # Reload page to ensure clean state and fresh render of feeds
    page.reload()

    # Wait for the feed widget to populate
    item_selector = ".feed-widget li.read, .feed-widget li.unread"
    try:
        page.wait_for_selector(item_selector, timeout=15000)
    except Exception:
        pytest.skip(
            "No feed items loaded — likely no network access to fetch "
            "external RSS feeds. Run with a server that has internet access."
        )

    # 4. Action: Scroll to bottom
    initial_items = page.locator(item_selector).count()
    if initial_items < 5:
        pytest.skip(
            f"Only {initial_items} items loaded — not enough to test "
            "infinite scroll pagination. Need at least 5 items."
        )

    # Scroll the feed widget's list element to the bottom
    # Use timeout longer than throttle delay (200ms) to ensure the throttle
    # window has passed
    page.evaluate(f"""
        const list = document.querySelector("{item_selector}").closest("ul");
        list.scrollTop = list.scrollHeight;
        setTimeout(() => {{
            list.dispatchEvent(new Event('scroll'));
        }}, 300);
    """)

    # 5. Verification: Wait for more items to load
    try:
        expect(page.locator(item_selector)).not_to_have_count(
            initial_items, timeout=15000
        )
    except AssertionError:
        print(
            f"Warning: Item count did not increase. Initial: {initial_items}")
        raise

    # Verify new count is greater
    new_items = page.locator(item_selector).count()
    assert new_items > initial_items, "Infinite scroll should load more items"
