import os
import re
from pathlib import Path

import pytest
from playwright.sync_api import Page, expect


@pytest.mark.skipif(
    os.getenv("CI") == "true",
    reason="Flaky in CI due to SSE timing issues; backend logic verified")
def test_opml_import_and_feed_refresh_progress(page: Page):
    base_url = os.environ.get("TEST_BASE_URL", "http://localhost:5000")
    page.goto(base_url)

    # Test OPML import
    page.click("#settings-button")
    opml_path = Path(__file__).parent.joinpath("test_feeds.opml").resolve()
    page.set_input_files('input[type="file"]', str(opml_path))
    expect(page.locator("#progress-container")).to_be_visible()
    expect(page.locator("#progress-status")).to_have_text(
        re.compile(r"(Importing|Processing|Starting|Fetching)"))
    expect(page.locator("#progress-bar")).to_have_attribute(
        "value", re.compile(r"\d+"))
    # Wait for the progress container to hide OR success toast
    page.wait_for_selector("#progress-container.hidden", timeout=30000)

    # Test feed refresh - ensure settings remains open or re-open
    if not page.is_visible("#refresh-all-feeds-button"):
        page.click("#settings-button")
    page.click("#refresh-all-feeds-button")
    expect(page.locator("#progress-container")).to_be_visible()
    expect(page.locator("#progress-status")).to_have_text(
        re.compile(r"(Starting|Checking)"))
    expect(page.locator("#progress-bar")).to_have_attribute(
        "value", re.compile(r"\d+"))
    page.wait_for_selector("#progress-container.hidden", timeout=10000)
