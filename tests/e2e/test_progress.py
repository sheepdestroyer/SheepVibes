"""E2E test for OPML import and feed refresh progress UI.

Tests that the progress bar, status text, and progress container correctly
display during OPML import and feed refresh operations.
"""

import re
from pathlib import Path

import pytest
from playwright.sync_api import Page, expect


def open_settings_menu(page: Page):
    """Ensure the settings menu dropdown is open."""
    page.evaluate(
        "document.getElementById('settings-menu').classList.remove('hidden')"
    )


@pytest.mark.e2e
def test_opml_import_and_feed_refresh_progress(
    page: Page, live_server: str, opml_file_path: Path
):
    """Verify OPML import and feed refresh show correct progress UI."""
    base_url = live_server

    # Navigate to the app
    page.goto(base_url, timeout=10000)

    # Test OPML import
    open_settings_menu(page)
    page.set_input_files('input[type="file"]', str(opml_file_path))
    # Check progress if visible or wait for completion
    progress_el = page.locator("#progress-container")
    if progress_el.is_visible():
        expect(page.locator("#progress-status")).to_have_text(
            re.compile(r"(Importing|Processing|Starting|Fetching)")
        )
        expect(page.locator("#progress-bar")
               ).to_have_attribute("value", re.compile(r"\d+"))
    # Wait for the progress container to hide OR success toast
    page.wait_for_selector("#progress-container.hidden", state="attached", timeout=60000)

    # Test feed refresh - ensure settings remains open or re-open
    open_settings_menu(page)
    page.click("#refresh-all-feeds-button")
    if progress_el.is_visible():
        expect(page.locator("#progress-status")).to_have_text(
            re.compile(r"(Starting|Checking)")
        )
        expect(page.locator("#progress-bar")
               ).to_have_attribute("value", re.compile(r"\d+"))
    page.wait_for_selector("#progress-container.hidden", state="attached", timeout=60000)
