"""E2E test for Night Mode feature.

Tests that toggling the Night Mode switch toggles the body's 'night-mode' class,
and that the theme preference persists across page reloads using localStorage.
"""

import pytest
from playwright.sync_api import Page, expect


def open_settings_menu(page: Page):
    """Ensure the settings menu dropdown is open."""
    page.evaluate(
        "document.getElementById('settings-menu').classList.remove('hidden')"
    )


@pytest.mark.e2e
def test_night_mode_toggle_and_persistence(page: Page, live_server: str):
    """Verify night mode toggling and persistence via localStorage."""
    page.on("console", lambda msg: print(f"CONSOLE: {msg.text} ({msg.type})"))
    page.on("pageerror", lambda err: print(f"PAGE ERROR: {err}"))
    base_url = live_server

    # 1. Navigate to the app
    page.goto(base_url, timeout=10000)

    # 2. Check initial state (should be light/default theme)
    open_settings_menu(page)
    night_mode_switch = page.locator("#night-mode-switch")
    expect(night_mode_switch).not_to_be_checked()
    expect(page.locator("body")).not_to_have_class("night-mode")

    # 3. Toggle Night Mode on
    night_mode_switch.check()
    expect(night_mode_switch).to_be_checked()
    expect(page.locator("body")).to_have_class("night-mode")

    # 4. Reload page to verify persistence
    page.reload()
    open_settings_menu(page)
    night_mode_switch = page.locator("#night-mode-switch")
    expect(night_mode_switch).to_be_checked()
    expect(page.locator("body")).to_have_class("night-mode")

    # 5. Toggle Night Mode off
    night_mode_switch.uncheck()
    expect(night_mode_switch).not_to_be_checked()
    expect(page.locator("body")).not_to_have_class("night-mode")

    # 6. Reload page to verify persistence of off state
    page.reload()
    open_settings_menu(page)
    night_mode_switch = page.locator("#night-mode-switch")
    expect(night_mode_switch).not_to_be_checked()
    expect(page.locator("body")).not_to_have_class("night-mode")
