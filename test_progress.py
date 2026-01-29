import re

from playwright.sync_api import Page, expect


def test_opml_import_and_feed_refresh_progress(page: Page):
    page.goto("http://localhost:5000")

    # Test OPML import
    page.click("#settings-button")
    page.set_input_files('input[type="file"]', "test_feeds.opml")
    expect(page.locator("#progress-container")).to_be_visible()
    expect(page.locator("#progress-status")).to_have_text(
        re.compile(r"(Processing feed|Starting)"))
    expect(page.locator("#progress-bar")).to_have_attribute(
        "value", re.compile(r"\d+"))
    page.wait_for_selector("#progress-container.hidden", timeout=10000)

    # Test feed refresh
    # Test feed refresh - ensure settings remains open or re-open
    if not page.is_visible("#refresh-all-feeds-button"):
        page.click("#settings-button")
    page.click("#refresh-all-feeds-button")
    expect(page.locator("#progress-container")).to_be_visible()
    expect(page.locator("#progress-status")).to_have_text(
        re.compile(r"(Starting|Updating)"))
    expect(page.locator("#progress-bar")).to_have_attribute(
        "value", re.compile(r"\d+"))
    page.wait_for_selector("#progress-container.hidden", timeout=10000)
