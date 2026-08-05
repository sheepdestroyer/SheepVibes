"""E2E test for OPML import and feed refresh progress UI.

Tests that the progress bar, status text, and progress container correctly
display during OPML import and feed refresh operations.
"""

import re
from pathlib import Path

import pytest
from playwright.sync_api import Page, expect


@pytest.mark.e2e
def test_opml_import_and_feed_refresh_progress(
    page: Page, live_server: str, opml_file_path: Path
):
    """Verify OPML import and feed refresh show correct progress UI."""
    base_url = live_server

    # Navigate to the app
    page.goto(base_url, timeout=10000)

    # Test OPML import
    page.click("#settings-button", timeout=10000)
    page.set_input_files('input[type="file"]', str(opml_file_path))
    expect(page.locator("#progress-container")).to_be_visible(timeout=10000)
    expect(page.locator("#progress-status")).to_have_text(
        re.compile(r"(Importing|Processing|Starting|Fetching)")
    )
    expect(page.locator("#progress-bar")
           ).to_have_attribute("value", re.compile(r"\d+"))
    # Wait for the progress container to hide OR success toast
    page.wait_for_selector("#progress-container.hidden", state="attached", timeout=60000)

    # Test feed refresh - ensure settings remains open or re-open
    if not page.is_visible("#refresh-all-feeds-button"):
        page.click("#settings-button")
    page.click("#refresh-all-feeds-button")
    expect(page.locator("#progress-container")).to_be_visible(timeout=10000)
    expect(page.locator("#progress-status")).to_have_text(
        re.compile(r"(Starting|Checking)")
    )
    expect(page.locator("#progress-bar")
           ).to_have_attribute("value", re.compile(r"\d+"))
    page.wait_for_selector("#progress-container.hidden", state="attached", timeout=60000)
