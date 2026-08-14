"""E2E test suite for feed widget title bars and canonical single-line rendering."""

import pytest
from playwright.sync_api import Page, expect


def setup_mock_feeds_for_titles(page: Page, live_server: str):
    """Intercept backend API routes to provide deterministic feeds with long and canonical titles."""
    mock_tabs = [
        {
            "id": 1,
            "name": "News",
            "order": 0,
            "unread_count": 0,
        }
    ]

    mock_feeds = [
        {
            "id": 1,
            "tab_id": 1,
            "name": "Wccftech",
            "url": "https://wccftech.com/feed/",
            "site_link": "https://wccftech.com/",
            "unread_count": 0,
            "items": [
                {
                    "id": 101,
                    "feed_id": 1,
                    "title": "NVIDIA GeForce RTX 5090 Benchmark Leak",
                    "link": "https://wccftech.com/article-1",
                    "comments_url": None,
                    "is_read": False,
                    "published_time": "2026-08-14T08:00:00Z",
                    "fetched_time": "2026-08-14T08:05:00Z",
                }
            ],
        },
        {
            "id": 2,
            "tab_id": 1,
            "name": "The Register",
            "url": "https://www.theregister.com/headlines.atom",
            "site_link": "https://www.theregister.com/",
            "unread_count": 0,
            "items": [
                {
                    "id": 102,
                    "feed_id": 2,
                    "title": "Linux Kernel 6.18 Released With Major Upgrades",
                    "link": "https://www.theregister.com/article-2",
                    "comments_url": None,
                    "is_read": False,
                    "published_time": "2026-08-14T07:30:00Z",
                    "fetched_time": "2026-08-14T07:35:00Z",
                }
            ],
        },
    ]

    page.route(
        "**/api/tabs",
        lambda route: route.fulfill(
            status=200,
            content_type="application/json",
            body=__import__("json").dumps(mock_tabs),
        ),
    )

    page.route(
        "**/api/tabs/1/feeds",
        lambda route: route.fulfill(
            status=200,
            content_type="application/json",
            body=__import__("json").dumps(mock_feeds),
        ),
    )

    page.route("**/api/events", lambda route: route.fulfill(status=200, body=""))


def test_widget_title_bar_single_line_and_tooltip(page: Page, live_server: str):
    """Verifies that feed widget title bars enforce single-line ellipsis truncation and tooltips."""
    setup_mock_feeds_for_titles(page, live_server)
    page.goto(live_server)

    page.wait_for_selector('.feed-widget[data-feed-id="1"]')
    page.wait_for_selector('.feed-widget[data-feed-id="2"]')

    wccf_widget = page.locator('.feed-widget[data-feed-id="1"]')
    wccf_header = wccf_widget.locator("h2")
    wccf_title_link = wccf_header.locator("a.feed-widget-title")

    expect(wccf_title_link).to_be_visible()
    expect(wccf_title_link).to_have_text("Wccftech")
    expect(wccf_title_link).to_have_attribute("title", "Wccftech")
    expect(wccf_title_link).to_have_attribute("href", "https://wccftech.com/")

    # Verify CSS single-line truncation properties
    white_space = wccf_title_link.evaluate("el => window.getComputedStyle(el).whiteSpace")
    overflow = wccf_title_link.evaluate("el => window.getComputedStyle(el).overflow")
    text_overflow = wccf_title_link.evaluate("el => window.getComputedStyle(el).textOverflow")

    assert white_space == "nowrap"
    assert overflow == "hidden"
    assert text_overflow == "ellipsis"

    # Verify header height is compact (single line, under 50px)
    header_box = wccf_header.bounding_box()
    assert header_box is not None
    assert header_box["height"] <= 48, f"Header height {header_box['height']}px exceeds 48px"

    # Verify The Register widget
    reg_widget = page.locator('.feed-widget[data-feed-id="2"]')
    reg_title_link = reg_widget.locator("h2 a.feed-widget-title")
    expect(reg_title_link).to_be_visible()
    expect(reg_title_link).to_have_text("The Register")
    expect(reg_title_link).to_have_attribute("title", "The Register")
