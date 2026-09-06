"""E2E test suite for feed editing and custom feed names (Issue #552)."""

import json
import re
from playwright.sync_api import Page, expect


def test_edit_feed_custom_name(page: Page, live_server: str):
    """Verifies opening the edit feed modal, changing the feed name, saving, and verifying updated title."""
    mock_tabs = [
        {
            "id": 1,
            "name": "General",
            "order": 0,
            "unread_count": 0,
        }
    ]

    mock_feeds = [
        {
            "id": 1,
            "tab_id": 1,
            "name": "Original Feed Name",
            "url": "https://example.com/rss",
            "site_link": "https://example.com",
            "unread_count": 0,
            "items": [
                {
                    "id": 101,
                    "feed_id": 1,
                    "title": "Welcome Article",
                    "link": "https://example.com/post-1",
                    "comments_url": None,
                    "is_read": False,
                    "published_time": "2026-09-06T12:00:00Z",
                    "fetched_time": "2026-09-06T12:05:00Z",
                }
            ],
        }
    ]

    updated_feed_response = {
        "id": 1,
        "tab_id": 1,
        "name": "My Custom Tech Digest",
        "url": "https://example.com/rss",
        "site_link": "https://example.com",
        "unread_count": 0,
        "items": [
            {
                "id": 101,
                "feed_id": 1,
                "title": "Welcome Article",
                "link": "https://example.com/post-1",
                "comments_url": None,
                "is_read": False,
                "published_time": "2026-09-06T12:00:00Z",
                "fetched_time": "2026-09-06T12:05:00Z",
            }
        ],
    }

    put_payloads = []

    page.route(
        "**/api/auth/status",
        lambda route: route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps({
                "setup_required": False,
                "authenticated": True,
                "user": {"id": 1, "username": "e2e_user", "is_admin": False},
            }),
        ),
    )

    page.route(
        "**/api/tabs",
        lambda route: route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps(mock_tabs),
        ),
    )

    page.route(
        "**/api/tabs/1/feeds",
        lambda route: route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps(mock_feeds),
        ),
    )

    page.route("**/api/events", lambda route: route.fulfill(status=200, body=""))

    def handle_put_feed(route):
        post_data = route.request.post_data
        if post_data:
            put_payloads.append(json.loads(post_data))
        route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps(updated_feed_response),
        )

    page.route("**/api/feeds/1", handle_put_feed)

    page.goto(live_server)

    # Verify widget loads with original name
    page.wait_for_selector('.feed-widget[data-feed-id="1"]')
    widget = page.locator('.feed-widget[data-feed-id="1"]')
    title_link = widget.locator("h2 a.feed-widget-title")
    expect(title_link).to_have_text("Original Feed Name")
    expect(title_link).to_have_attribute("title", "Original Feed Name")

    # Click edit button
    edit_button = widget.locator(".edit-feed-button")
    edit_button.click()

    # Modal should be open
    modal = page.locator("#edit-feed-modal")
    expect(modal).to_have_class(re.compile(r"is-active"))

    # Name input should NOT be readonly and should be populated with current name
    name_input = page.locator("#edit-feed-name")
    expect(name_input).to_be_editable()
    expect(name_input).to_have_value("Original Feed Name")

    # Edit feed name
    name_input.fill("My Custom Tech Digest")

    # Save changes
    page.click("#save-feed-button")

    # Modal should close
    expect(modal).not_to_have_class(re.compile(r"is-active"))

    # Verify widget title updated in DOM immediately
    updated_title = page.locator('.feed-widget[data-feed-id="1"] h2 a.feed-widget-title')
    expect(updated_title).to_have_text("My Custom Tech Digest")
    expect(updated_title).to_have_attribute("title", "My Custom Tech Digest")

    # Verify the PUT payload sent to backend
    assert len(put_payloads) == 1
    assert put_payloads[0]["name"] == "My Custom Tech Digest"
    assert put_payloads[0]["url"] == "https://example.com/rss"

    # Click edit button again to verify populated with new custom name
    page.locator('.feed-widget[data-feed-id="1"] .edit-feed-button').click()
    expect(modal).to_have_class(re.compile(r"is-active"))
    expect(name_input).to_have_value("My Custom Tech Digest")

    # Cancel edit
    page.click("#cancel-edit-button")
    expect(modal).not_to_have_class(re.compile(r"is-active"))
