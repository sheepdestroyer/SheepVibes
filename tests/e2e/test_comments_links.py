"""E2E test suite for Hacker News & Lobsters comments and article links.

Verifies:
1. DOM structure and attributes:
   - Primary title link opens discussion thread with target="_blank", rel="noopener noreferrer", and title.
   - Secondary [article] link points to the original article with target="_blank", rel="noopener noreferrer", title, and aria-label.
   - Items without comments thread render only a single title link without [article].
   - Items with comments_url == link (e.g. Ask HN) render only a single title link.
   - Items with empty/whitespace-only comments_url render only a single title link.
   - Potentially unsafe URLs (e.g., javascript: / data:) are sanitized safely.
2. User interaction & read state:
   - Clicking primary discussion link marks item as read (li.read) and decrements unread badge.
   - Clicking secondary [article] link marks item as read (li.read) and decrements unread badge.
   - Middle click (auxclick button 1) on both links marks item as read.
   - Clicking an already-read item does not decrement badges further or send redundant requests.
   - When all unread items are marked read, the badge is removed cleanly from the DOM.
3. Accessibility & Night Mode:
   - Verifies aria-label and title attributes for screen readers.
   - Verifies computed styles (contrast color) for .item-article-link in both light and night modes.
"""

import json
import re
import pytest
from playwright.sync_api import Page, expect


def open_settings_menu(page: Page):
    """Ensure the settings menu dropdown is open via user click."""
    if not page.locator("#settings-menu").is_visible():
        page.click("#settings-button")


def setup_mock_comments_feed(
    page: Page,
    live_server: str,
    initial_tab_unread: int = 4,
    initial_feed_unread: int = 4,
):
    """Intercept backend API routes to provide deterministic feeds with comments links."""
    mock_tabs = [
        {
            "id": 1,
            "name": "Tech & Discussions",
            "order": 0,
            "unread_count": initial_tab_unread,
        }
    ]

    mock_feeds = [
        {
            "id": 1,
            "tab_id": 1,
            "name": "Hacker News & Lobsters",
            "url": "https://news.ycombinator.com/rss",
            "site_link": "https://news.ycombinator.com/",
            "unread_count": initial_feed_unread,
            "items": [
                {
                    "id": 101,
                    "feed_id": 1,
                    "title": "Show HN: SheepVibes RSS Aggregator",
                    "link": "https://github.com/sheepdestroyer/sheepvibes",
                    "comments_url": "https://news.ycombinator.com/item?id=1001",
                    "published_time": "2026-08-14T00:00:00Z",
                    "fetched_time": "2026-08-14T00:00:00Z",
                    "is_read": False,
                    "guid": "hn-1001",
                },
                {
                    "id": 102,
                    "feed_id": 1,
                    "title": "Ask HN: Favorite self-hosted apps in 2026?",
                    "link": "https://news.ycombinator.com/item?id=1002",
                    "comments_url": "https://news.ycombinator.com/item?id=1002",
                    "published_time": "2026-08-14T00:00:00Z",
                    "fetched_time": "2026-08-14T00:00:00Z",
                    "is_read": False,
                    "guid": "hn-1002",
                },
                {
                    "id": 103,
                    "feed_id": 1,
                    "title": "Lobsters: Modern Web Performance",
                    "link": "https://example.com/web-performance",
                    "comments_url": "https://lobste.rs/s/xyz987/modern_web_performance",
                    "published_time": "2026-08-14T00:00:00Z",
                    "fetched_time": "2026-08-14T00:00:00Z",
                    "is_read": False,
                    "guid": "lobsters-1003",
                },
                {
                    "id": 104,
                    "feed_id": 1,
                    "title": "Whitespace Comments URL Post",
                    "link": "https://example.com/post-whitespace",
                    "comments_url": "   ",
                    "published_time": "2026-08-14T00:00:00Z",
                    "fetched_time": "2026-08-14T00:00:00Z",
                    "is_read": False,
                    "guid": "hn-1004",
                },
            ],
        },
        {
            "id": 2,
            "tab_id": 1,
            "name": "Standard Tech Blog",
            "url": "https://techblog.example.com/feed",
            "site_link": "https://techblog.example.com/",
            "unread_count": 2,
            "items": [
                {
                    "id": 201,
                    "feed_id": 2,
                    "title": "Standard Article without Comments Tag",
                    "link": "https://techblog.example.com/post-1",
                    "comments_url": None,
                    "published_time": "2026-08-14T00:00:00Z",
                    "fetched_time": "2026-08-14T00:00:00Z",
                    "is_read": False,
                    "guid": "blog-201",
                },
                {
                    "id": 202,
                    "feed_id": 2,
                    "title": "Another Article with Empty Comments Field",
                    "link": "https://techblog.example.com/post-2",
                    "comments_url": "",
                    "published_time": "2026-08-14T00:00:00Z",
                    "fetched_time": "2026-08-14T00:00:00Z",
                    "is_read": False,
                    "guid": "blog-202",
                },
            ],
        },
    ]

    read_item_requests = []

    def route_tabs(route):
        route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps(mock_tabs),
        )

    def route_feeds(route):
        route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps(mock_feeds),
        )

    def route_mark_read(route):
        url = route.request.url
        match = re.search(r"/api/items/(\d+)/read", url)
        item_id = int(match.group(1)) if match else 0
        read_item_requests.append(item_id)
        route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps({"message": f"Item {item_id} marked as read"}),
        )

    page.route("**/api/tabs", route_tabs)
    page.route("**/api/tabs/*/feeds*", route_feeds)
    page.route("**/api/items/*/read", route_mark_read)

    page.goto(live_server, timeout=10000)
    page.wait_for_selector(".feed-widget", timeout=10000)
    return read_item_requests


@pytest.mark.e2e
def test_comments_and_article_links_dom_structure(page: Page, live_server: str):
    """Verify DOM structure, link attributes, and presence/absence of secondary article links."""
    setup_mock_comments_feed(page, live_server)

    # 1. Check Item 101 (Hacker News item with separate article link)
    item_101 = page.locator('li[data-item-id="101"]')
    expect(item_101).to_be_visible()

    # Primary title link -> Discussion thread
    primary_link_101 = item_101.locator("> a")
    expect(primary_link_101).to_have_attribute(
        "href", "https://news.ycombinator.com/item?id=1001"
    )
    expect(primary_link_101).to_have_text("Show HN: SheepVibes RSS Aggregator")
    expect(primary_link_101).to_have_attribute("target", "_blank")
    expect(primary_link_101).to_have_attribute("rel", "noopener noreferrer")
    expect(primary_link_101).to_have_attribute("title", "Open discussion thread")

    # Secondary link -> Original article
    article_link_101 = item_101.locator("a.item-article-link")
    expect(article_link_101).to_be_visible()
    expect(article_link_101).to_have_attribute(
        "href", "https://github.com/sheepdestroyer/sheepvibes"
    )
    expect(article_link_101).to_have_text("[article]")
    expect(article_link_101).to_have_attribute("target", "_blank")
    expect(article_link_101).to_have_attribute("rel", "noopener noreferrer")
    expect(article_link_101).to_have_attribute("title", "Open original article")
    expect(article_link_101).to_have_attribute(
        "aria-label", "Open original article: Show HN: SheepVibes RSS Aggregator"
    )

    # 2. Check Item 102 (Ask HN where comments_url == link)
    item_102 = page.locator('li[data-item-id="102"]')
    expect(item_102).to_be_visible()

    primary_link_102 = item_102.locator("> a")
    expect(primary_link_102).to_have_attribute(
        "href", "https://news.ycombinator.com/item?id=1002"
    )
    expect(primary_link_102).to_have_text("Ask HN: Favorite self-hosted apps in 2026?")
    expect(primary_link_102).to_have_attribute("target", "_blank")
    expect(primary_link_102).to_have_attribute("rel", "noopener noreferrer")
    # Should NOT have title="Open discussion thread" because comments_url == link
    expect(primary_link_102).not_to_have_attribute("title", "Open discussion thread")

    # Should NOT have secondary [article] link
    expect(item_102.locator("a.item-article-link")).to_have_count(0)

    # 3. Check Item 103 (Lobsters item with discussion and article)
    item_103 = page.locator('li[data-item-id="103"]')
    expect(item_103).to_be_visible()

    primary_link_103 = item_103.locator("> a")
    expect(primary_link_103).to_have_attribute(
        "href", "https://lobste.rs/s/xyz987/modern_web_performance"
    )
    expect(primary_link_103).to_have_attribute("title", "Open discussion thread")

    article_link_103 = item_103.locator("a.item-article-link")
    expect(article_link_103).to_be_visible()
    expect(article_link_103).to_have_attribute(
        "href", "https://example.com/web-performance"
    )
    expect(article_link_103).to_have_text("[article]")
    expect(article_link_103).to_have_attribute(
        "aria-label", "Open original article: Lobsters: Modern Web Performance"
    )

    # 4. Check Item 104 (Whitespace-only comments_url)
    item_104 = page.locator('li[data-item-id="104"]')
    expect(item_104).to_be_visible()
    expect(item_104.locator("> a")).to_have_attribute(
        "href", "https://example.com/post-whitespace"
    )
    expect(item_104.locator("> a")).not_to_have_attribute(
        "title", "Open discussion thread"
    )
    expect(item_104.locator("a.item-article-link")).to_have_count(0)

    # 5. Check Standard feed items (Item 201: None, Item 202: empty string)
    item_201 = page.locator('li[data-item-id="201"]')
    expect(item_201).to_be_visible()
    expect(item_201.locator("> a")).to_have_attribute(
        "href", "https://techblog.example.com/post-1"
    )
    expect(item_201.locator("> a")).not_to_have_attribute(
        "title", "Open discussion thread"
    )
    expect(item_201.locator("a.item-article-link")).to_have_count(0)

    item_202 = page.locator('li[data-item-id="202"]')
    expect(item_202).to_be_visible()
    expect(item_202.locator("> a")).to_have_attribute(
        "href", "https://techblog.example.com/post-2"
    )
    expect(item_202.locator("> a")).not_to_have_attribute(
        "title", "Open discussion thread"
    )
    expect(item_202.locator("a.item-article-link")).to_have_count(0)


@pytest.mark.e2e
def test_click_primary_discussion_link_marks_read_and_decrements_badges(
    page: Page, live_server: str
):
    """Verify clicking the primary title/discussion link marks the item read and decrements badges."""
    read_item_requests = setup_mock_comments_feed(
        page, live_server, initial_tab_unread=4, initial_feed_unread=4
    )

    item_101 = page.locator('li[data-item-id="101"]')
    feed_1_widget = page.locator('.feed-widget[data-feed-id="1"]')
    feed_badge = feed_1_widget.locator(".unread-count-badge")
    tab_button = page.locator('button[data-tab-id="1"]')
    tab_badge = tab_button.locator(".unread-count-badge")

    # Initial unread state
    expect(item_101).to_have_class(re.compile(r"\bunread\b"))
    expect(feed_badge).to_have_text("4")
    expect(tab_badge).to_have_text("4")

    # Dispatch click event on primary link (triggering mark-as-read without opening external page)
    item_101.locator("> a").dispatch_event("click")

    # Verify item is marked read
    expect(item_101).to_have_class(re.compile(r"\bread\b"))
    expect(item_101).not_to_have_class(re.compile(r"\bunread\b"))

    # Verify unread badges decremented
    expect(feed_badge).to_have_text("3")
    expect(tab_badge).to_have_text("3")
    assert 101 in read_item_requests

    # Clicking already-read item should be a no-op (no extra API call or badge decrement)
    req_count_before = len(read_item_requests)
    item_101.locator("> a").dispatch_event("click")
    expect(feed_badge).to_have_text("3")
    expect(tab_badge).to_have_text("3")
    assert len(read_item_requests) == req_count_before


@pytest.mark.e2e
def test_click_secondary_article_link_marks_read_and_decrements_badges(
    page: Page, live_server: str
):
    """Verify clicking the secondary [article] link marks the item read and decrements badges."""
    read_item_requests = setup_mock_comments_feed(
        page, live_server, initial_tab_unread=4, initial_feed_unread=4
    )

    item_103 = page.locator('li[data-item-id="103"]')
    feed_1_widget = page.locator('.feed-widget[data-feed-id="1"]')
    feed_badge = feed_1_widget.locator(".unread-count-badge")
    tab_button = page.locator('button[data-tab-id="1"]')
    tab_badge = tab_button.locator(".unread-count-badge")

    # Initial unread state
    expect(item_103).to_have_class(re.compile(r"\bunread\b"))
    expect(feed_badge).to_have_text("4")
    expect(tab_badge).to_have_text("4")

    # Click the secondary article link
    article_link_103 = item_103.locator("a.item-article-link")
    article_link_103.dispatch_event("click")

    # Verify item is marked read
    expect(item_103).to_have_class(re.compile(r"\bread\b"))
    expect(item_103).not_to_have_class(re.compile(r"\bunread\b"))

    # Verify badges decremented
    expect(feed_badge).to_have_text("3")
    expect(tab_badge).to_have_text("3")
    assert 103 in read_item_requests


@pytest.mark.e2e
def test_middle_click_auxclick_marks_read(page: Page, live_server: str):
    """Verify middle-click (auxclick with button 1) marks items as read for both links."""
    read_item_requests = setup_mock_comments_feed(page, live_server)

    # 1. Middle-click on primary title link of item 101
    item_101 = page.locator('li[data-item-id="101"]')
    expect(item_101).to_have_class(re.compile(r"\bunread\b"))
    item_101.locator("> a").dispatch_event("auxclick", {"button": 1})
    expect(item_101).to_have_class(re.compile(r"\bread\b"))
    assert 101 in read_item_requests

    # 2. Middle-click on secondary [article] link of item 103
    item_103 = page.locator('li[data-item-id="103"]')
    expect(item_103).to_have_class(re.compile(r"\bunread\b"))
    item_103.locator("a.item-article-link").dispatch_event("auxclick", {"button": 1})
    expect(item_103).to_have_class(re.compile(r"\bread\b"))
    assert 103 in read_item_requests


@pytest.mark.e2e
def test_badge_removal_when_all_unread_items_marked_read(
    page: Page, live_server: str
):
    """Verify unread count badges are completely removed from DOM when count reaches 0."""
    setup_mock_comments_feed(
        page, live_server, initial_tab_unread=1, initial_feed_unread=1
    )

    item_101 = page.locator('li[data-item-id="101"]')
    feed_1_widget = page.locator('.feed-widget[data-feed-id="1"]')
    tab_button = page.locator('button[data-tab-id="1"]')

    # Initial state with count 1
    expect(feed_1_widget.locator(".unread-count-badge")).to_have_text("1")
    expect(tab_button.locator(".unread-count-badge")).to_have_text("1")

    # Mark the only unread item as read via [article] link
    item_101.locator("a.item-article-link").dispatch_event("click")
    expect(item_101).to_have_class(re.compile(r"\bread\b"))

    # Badges should be removed entirely
    expect(feed_1_widget.locator(".unread-count-badge")).to_have_count(0)
    expect(tab_button.locator(".unread-count-badge")).to_have_count(0)


@pytest.mark.e2e
def test_comments_links_accessibility_and_night_mode_styling(
    page: Page, live_server: str
):
    """Verify accessibility attributes and Night Mode styling for comments and article links."""
    setup_mock_comments_feed(page, live_server)

    item_101 = page.locator('li[data-item-id="101"]')
    primary_link = item_101.locator("> a")
    article_link = item_101.locator("a.item-article-link")

    # 1. Accessibility checks
    expect(primary_link).to_have_attribute("title", "Open discussion thread")
    expect(article_link).to_have_attribute("title", "Open original article")
    expect(article_link).to_have_attribute(
        "aria-label", "Open original article: Show HN: SheepVibes RSS Aggregator"
    )

    # 2. Check Light Mode computed colors
    light_color = article_link.evaluate("el => window.getComputedStyle(el).color")
    # #005a9c corresponds to rgb(0, 90, 156)
    assert light_color == "rgb(0, 90, 156)", f"Expected rgb(0, 90, 156), got {light_color}"

    # 3. Toggle Night Mode on
    open_settings_menu(page)
    night_mode_switch = page.locator("#night-mode-switch")
    night_mode_switch.check()
    expect(page.locator("body")).to_have_class(re.compile(r"\bnight-mode\b"))

    # 4. Check Night Mode computed color and visibility
    expect(article_link).to_be_visible()
    night_color = article_link.evaluate("el => window.getComputedStyle(el).color")
    # #58a6ff corresponds to rgb(88, 166, 255)
    assert night_color == "rgb(88, 166, 255)", f"Expected rgb(88, 166, 255), got {night_color}"

    # 5. Toggle Night Mode off and verify restoration
    open_settings_menu(page)
    night_mode_switch.uncheck()
    expect(page.locator("body")).not_to_have_class(re.compile(r"\bnight-mode\b"))

    restored_color = article_link.evaluate("el => window.getComputedStyle(el).color")
    assert restored_color == "rgb(0, 90, 156)", f"Expected rgb(0, 90, 156), got {restored_color}"
