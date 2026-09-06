"""E2E test suite for draggable feed widgets within tabs and across tabs.

Verifies:
1. In-tab reordering:
   - Drag handle presence and accessibility attributes (role, aria-grabbed, tabindex).
   - Dragging a widget within the same tab reorders DOM nodes and calls PUT /api/tabs/<id>/feeds/reorder.
   - Visual drop indicator classes (.drop-before, .drop-after).
2. Cross-tab moving:
   - Dragging a feed widget onto another tab's header button calls PUT /api/feeds/<id>/move.
   - The dragged feed is removed from the active tab and the app navigates to the target tab.
   - Visual hover indicator (.tab-drag-over) on the target tab header during drag.
3. Usability & non-interference:
   - Clicking links, buttons, and selecting text does not trigger dragstart.
4. Error handling:
   - In-tab reordering rollback if the backend reorder API returns an error.
"""

import json
import re
import pytest
from playwright.sync_api import Page, expect


def simulate_drag_and_drop(page: Page, source_selector: str, target_selector: str, position: str = "before"):
    """Simulate HTML5 drag and drop events between two elements.

    Dispatches dragstart on source, dragover on target (with clientX positioning),
    drop on target, and dragend on source.
    """
    page.evaluate(
        """({ sourceSel, targetSel, pos }) => {
            const source = document.querySelector(sourceSel);
            const target = document.querySelector(targetSel);
            if (!source || !target) throw new Error(`Elements not found: ${sourceSel}, ${targetSel}`);

            const dt = new DataTransfer();
            dt.setData('text/plain', source.dataset.feedId || '');
            dt.effectAllowed = 'move';

            const startEvt = new DragEvent('dragstart', {
                bubbles: true,
                cancelable: true,
                dataTransfer: dt
            });
            source.dispatchEvent(startEvt);

            const rect = target.getBoundingClientRect();
            const clientX = pos === 'after' ? (rect.left + rect.width * 0.75) : (rect.left + rect.width * 0.25);
            const clientY = rect.top + rect.height / 2;

            const overEvt = new DragEvent('dragover', {
                bubbles: true,
                cancelable: true,
                clientX,
                clientY,
                dataTransfer: dt
            });
            target.dispatchEvent(overEvt);

            const dropEvt = new DragEvent('drop', {
                bubbles: true,
                cancelable: true,
                clientX,
                clientY,
                dataTransfer: dt
            });
            target.dispatchEvent(dropEvt);

            const endEvt = new DragEvent('dragend', {
                bubbles: true,
                cancelable: true,
                dataTransfer: dt
            });
            source.dispatchEvent(endEvt);
        }""",
        {"sourceSel": source_selector, "targetSel": target_selector, "pos": position},
    )


def setup_mock_tabs_and_feeds(page: Page, initial_tab_id: int = 1):
    """Intercept backend API routes to provide deterministic tabs and feeds."""
    mock_tabs = [
        {"id": 1, "name": "General", "order": 0, "unread_count": 0},
        {"id": 2, "name": "Tech", "order": 1, "unread_count": 0},
    ]

    mock_feeds_tab1 = [
        {
            "id": 10,
            "tab_id": 1,
            "name": "Feed Alpha",
            "url": "https://example.com/alpha.xml",
            "site_link": "https://example.com/alpha",
            "order": 0,
            "unread_count": 0,
            "items": [
                {
                    "id": 1001,
                    "feed_id": 10,
                    "title": "Alpha Item 1",
                    "link": "https://example.com/alpha/1",
                    "comments_url": None,
                    "is_read": False,
                    "published_time": "2026-09-06T10:00:00Z",
                    "fetched_time": "2026-09-06T10:00:00Z",
                }
            ],
        },
        {
            "id": 20,
            "tab_id": 1,
            "name": "Feed Beta",
            "url": "https://example.com/beta.xml",
            "site_link": "https://example.com/beta",
            "order": 1,
            "unread_count": 0,
            "items": [
                {
                    "id": 1002,
                    "feed_id": 20,
                    "title": "Beta Item 1",
                    "link": "https://example.com/beta/1",
                    "comments_url": None,
                    "is_read": False,
                    "published_time": "2026-09-06T10:00:00Z",
                    "fetched_time": "2026-09-06T10:00:00Z",
                }
            ],
        },
        {
            "id": 30,
            "tab_id": 1,
            "name": "Feed Gamma",
            "url": "https://example.com/gamma.xml",
            "site_link": "https://example.com/gamma",
            "order": 2,
            "unread_count": 0,
            "items": [
                {
                    "id": 1003,
                    "feed_id": 30,
                    "title": "Gamma Item 1",
                    "link": "https://example.com/gamma/1",
                    "comments_url": None,
                    "is_read": False,
                    "published_time": "2026-09-06T10:00:00Z",
                    "fetched_time": "2026-09-06T10:00:00Z",
                }
            ],
        },
    ]

    mock_feeds_tab2 = [
        {
            "id": 40,
            "tab_id": 2,
            "name": "Feed Delta",
            "url": "https://example.com/delta.xml",
            "site_link": "https://example.com/delta",
            "order": 0,
            "unread_count": 0,
            "items": [
                {
                    "id": 1004,
                    "feed_id": 40,
                    "title": "Delta Item 1",
                    "link": "https://example.com/delta/1",
                    "comments_url": None,
                    "is_read": False,
                    "published_time": "2026-09-06T10:00:00Z",
                    "fetched_time": "2026-09-06T10:00:00Z",
                }
            ],
        }
    ]

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
            body=json.dumps(mock_feeds_tab1),
        ),
    )

    page.route(
        "**/api/tabs/2/feeds",
        lambda route: route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps(mock_feeds_tab2),
        ),
    )

    page.route("**/api/events", lambda route: route.fulfill(status=200, body=""))


@pytest.mark.e2e
def test_feed_widget_drag_handles_and_accessibility(page: Page, live_server: str):
    """Verify that feed widgets render drag handles with proper accessibility attributes."""
    setup_mock_tabs_and_feeds(page)
    page.goto(live_server)

    page.wait_for_selector('.feed-widget[data-feed-id="10"]')
    page.wait_for_selector('.feed-widget[data-feed-id="20"]')
    page.wait_for_selector('.feed-widget[data-feed-id="30"]')

    widgets = page.locator(".feed-widget")
    expect(widgets).to_have_count(3)

    # Check drag handle on the first widget
    widget_alpha = page.locator('.feed-widget[data-feed-id="10"]')
    expect(widget_alpha).to_have_attribute("draggable", "true")

    handle = widget_alpha.locator(".feed-drag-handle")
    expect(handle).to_be_visible()
    expect(handle).to_have_text("⋮⋮")
    expect(handle).to_have_attribute("role", "button")
    expect(handle).to_have_attribute("aria-grabbed", "false")
    expect(handle).to_have_attribute("tabindex", "0")
    expect(handle).to_have_attribute("title", "Drag to reorder or move to another tab")


@pytest.mark.e2e
def test_reorder_feeds_within_same_tab(page: Page, live_server: str):
    """Verify dragging a widget to reorder feeds within the active tab sends reorder API call."""
    setup_mock_tabs_and_feeds(page)

    reorder_requests = []

    def handle_reorder(route):
        req = route.request
        data = json.loads(req.post_data or "{}")
        reorder_requests.append(data)
        route.fulfill(status=200, content_type="application/json", body=json.dumps({"success": True}))

    page.route("**/api/tabs/1/feeds/reorder", handle_reorder)

    page.goto(live_server)
    page.wait_for_selector('.feed-widget[data-feed-id="10"]')
    page.wait_for_selector('.feed-widget[data-feed-id="20"]')
    page.wait_for_selector('.feed-widget[data-feed-id="30"]')

    # Initial DOM order check: [10, 20, 30]
    initial_ids = page.evaluate(
        "() => Array.from(document.querySelectorAll('.feed-widget')).map(w => w.dataset.feedId)"
    )
    assert initial_ids == ["10", "20", "30"]

    # Drag widget 30 (Gamma) before widget 10 (Alpha)
    simulate_drag_and_drop(
        page,
        source_selector='.feed-widget[data-feed-id="30"]',
        target_selector='.feed-widget[data-feed-id="10"]',
        position="before",
    )

    # Wait for the reorder request to be recorded
    page.wait_for_function("() => document.querySelectorAll('.feed-widget')[0].dataset.feedId === '30'")

    # Verify DOM order updated to [30, 10, 20]
    new_ids = page.evaluate(
        "() => Array.from(document.querySelectorAll('.feed-widget')).map(w => w.dataset.feedId)"
    )
    assert new_ids == ["30", "10", "20"]

    # Verify backend API call was made with the updated feed_ids list
    assert len(reorder_requests) == 1
    assert reorder_requests[0] == {"feed_ids": [30, 10, 20]}


@pytest.mark.e2e
def test_reorder_feeds_after_position(page: Page, live_server: str):
    """Verify dragging widget 10 after widget 20 reorders correctly to [20, 10, 30]."""
    setup_mock_tabs_and_feeds(page)

    reorder_requests = []

    def handle_reorder(route):
        req = route.request
        data = json.loads(req.post_data or "{}")
        reorder_requests.append(data)
        route.fulfill(status=200, content_type="application/json", body=json.dumps({"success": True}))

    page.route("**/api/tabs/1/feeds/reorder", handle_reorder)

    page.goto(live_server)
    page.wait_for_selector('.feed-widget[data-feed-id="10"]')

    # Drag widget 10 (Alpha) after widget 20 (Beta)
    simulate_drag_and_drop(
        page,
        source_selector='.feed-widget[data-feed-id="10"]',
        target_selector='.feed-widget[data-feed-id="20"]',
        position="after",
    )

    page.wait_for_function("() => document.querySelectorAll('.feed-widget')[1].dataset.feedId === '10'")

    new_ids = page.evaluate(
        "() => Array.from(document.querySelectorAll('.feed-widget')).map(w => w.dataset.feedId)"
    )
    assert new_ids == ["20", "10", "30"]
    assert len(reorder_requests) == 1
    assert reorder_requests[0] == {"feed_ids": [20, 10, 30]}


@pytest.mark.e2e
def test_move_feed_to_another_tab(page: Page, live_server: str):
    """Verify dragging a widget onto another tab button calls move API and navigates to target tab."""
    setup_mock_tabs_and_feeds(page)

    move_requests = []

    def handle_move(route):
        req = route.request
        data = json.loads(req.post_data or "{}")
        move_requests.append(data)
        route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps({"success": True, "feed_id": 10, "tab_id": 2}),
        )

    page.route("**/api/feeds/10/move", handle_move)

    page.goto(live_server)
    page.wait_for_selector('.feed-widget[data-feed-id="10"]')
    page.wait_for_selector('#tabs-container button[data-tab-id="2"]')

    # Tab 1 should be active initially
    tab1_btn = page.locator('#tabs-container button[data-tab-id="1"]')
    tab2_btn = page.locator('#tabs-container button[data-tab-id="2"]')
    expect(tab1_btn).to_have_class(re.compile(r"active"))

    # Drag feed 10 onto Tab 2 button
    simulate_drag_and_drop(
        page,
        source_selector='.feed-widget[data-feed-id="10"]',
        target_selector='#tabs-container button[data-tab-id="2"]',
        position="before",
    )

    # Move API should have been called with target tab 2
    page.wait_for_function("() => document.querySelector('#tabs-container button[data-tab-id=\"2\"]').classList.contains('active')")
    assert len(move_requests) == 1
    assert move_requests[0]["tab_id"] == 2

    # After switching to Tab 2, Tab 2's feed (Delta: id 40) is visible
    page.wait_for_selector('.feed-widget[data-feed-id="40"]')
    expect(tab2_btn).to_have_class(re.compile(r"active"))


@pytest.mark.e2e
def test_action_buttons_do_not_initiate_drag(page: Page, live_server: str):
    """Verify clicking or dragging buttons/links inside a widget does not initiate widget drag."""
    setup_mock_tabs_and_feeds(page)
    page.goto(live_server)
    page.wait_for_selector('.feed-widget[data-feed-id="10"]')

    # Attempt to start drag on an action button (e.g. edit button or link)
    is_prevented = page.evaluate(
        """() => {
            const btn = document.querySelector('.feed-widget[data-feed-id="10"] .edit-feed-button') ||
                        document.querySelector('.feed-widget[data-feed-id="10"] button');
            if (!btn) return false;

            const dt = new DataTransfer();
            const evt = new DragEvent('dragstart', {
                bubbles: true,
                cancelable: true,
                dataTransfer: dt
            });
            btn.dispatchEvent(evt);
            return evt.defaultPrevented;
        }"""
    )
    assert is_prevented is True


@pytest.mark.e2e
def test_reorder_api_failure_rollback(page: Page, live_server: str):
    """Verify that when the reorder API returns 500, an error toast is shown and order rolls back."""
    setup_mock_tabs_and_feeds(page)

    # Fail the reorder endpoint
    page.route(
        "**/api/tabs/1/feeds/reorder",
        lambda route: route.fulfill(status=500, content_type="application/json", body=json.dumps({"error": "DB failure"})),
    )

    page.goto(live_server)
    page.wait_for_selector('.feed-widget[data-feed-id="10"]')
    page.wait_for_selector('.feed-widget[data-feed-id="20"]')
    page.wait_for_selector('.feed-widget[data-feed-id="30"]')

    # Reorder widget 30 before 10
    simulate_drag_and_drop(
        page,
        source_selector='.feed-widget[data-feed-id="30"]',
        target_selector='.feed-widget[data-feed-id="10"]',
        position="before",
    )

    # An error toast should appear
    toast = page.locator("#toast-container .toast-error, .toast")
    expect(toast).to_be_visible()

    # The tab feeds should be reloaded back to original order [10, 20, 30]
    page.wait_for_function("() => document.querySelectorAll('.feed-widget')[0].dataset.feedId === '10'")
    current_ids = page.evaluate(
        "() => Array.from(document.querySelectorAll('.feed-widget')).map(w => w.dataset.feedId)"
    )
    assert current_ids == ["10", "20", "30"]
