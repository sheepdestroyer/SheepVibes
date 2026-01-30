import os
import re
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

import pytest
from playwright.sync_api import Page, expect


@pytest.mark.skipif(
    os.getenv("CI") == "true",
    reason="Skipping in CI, requires local server",
)
def test_infinite_scroll_loads_more_items(page: Page, opml_file_path: Path):
    base_url = os.environ.get("TEST_BASE_URL", "http://localhost:5000")

    # 1. Setup: Verify server is running
    parsed = urlparse(base_url)
    if parsed.scheme not in {"http", "https"}:
        pytest.skip(f"Unsupported scheme for TEST_BASE_URL: {parsed.scheme}")
    try:
        urllib.request.urlopen(base_url, timeout=1).close()
    except OSError:
        pytest.skip(f"Server at {base_url} is not running. Skipping E2E test.")

    # 2. Setup: Import feeds to ensure we have content
    page.goto(base_url)
    page.click("#settings-button")
    page.set_input_files('input[type="file"]', str(opml_file_path))
    expect(page.locator("#progress-container")).to_be_visible()
    # Wait for import to finish
    page.wait_for_selector("#progress-container.hidden", timeout=30000)

    # 3. Setup: Refresh feeds to ensure items are populated
    # Ensure settings menu is open (it might have closed or stayed open depending on UI)
    if not page.is_visible("#refresh-all-feeds-button"):
        page.click("#settings-button")

    page.click("#refresh-all-feeds-button")
    page.wait_for_selector("#progress-container.hidden", timeout=30000)

    # Reload page to ensure clean state and fresh render of feeds
    page.reload()

    # 4. Action: Scroll to bottom
    # Get initial item count (items have 'read' or 'unread' class)
    # We use a composite selector or just count li elements with links
    item_selector = ".feed-widget li.read, .feed-widget li.unread"
    initial_items = page.locator(item_selector).count()

    # Scroll to bottom
    page.evaluate("window.scrollTo(0, document.documentElement.scrollHeight)")

    # 5. Verification: Wait for more items to load
    try:
        expect(page.locator(item_selector)).not_to_have_count(
            initial_items, timeout=10000
        )
    except AssertionError:
        print(
            f"Warning: Item count did not increase. Initial: {initial_items}")
        raise

    # Verify new count is greater
    new_items = page.locator(item_selector).count()
    assert new_items > initial_items, "Infinite scroll should load more items"
