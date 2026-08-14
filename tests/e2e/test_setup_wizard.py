"""Playwright E2E test suite for the First-Run Setup Onboarding Wizard."""

import pytest
from playwright.sync_api import Page, expect


def setup_wizard_e2e_routes(page: Page, setup_initially_required: bool = True):
    """Sets up API route mocks for setup wizard testing."""
    is_setup_done = not setup_initially_required
    current_admin = None

    def handle_auth_status(route):
        if not is_setup_done:
            route.fulfill(
                status=200,
                content_type="application/json",
                json={
                    "setup_required": True,
                    "authenticated": False,
                    "user": None
                }
            )
        else:
            route.fulfill(
                status=200,
                content_type="application/json",
                json={
                    "setup_required": False,
                    "authenticated": True,
                    "user": current_admin or {
                        "id": 1,
                        "username": "master_admin",
                        "email": "admin@example.com",
                        "role": "admin",
                        "is_active": True
                    }
                }
            )

    def handle_auth_setup(route):
        nonlocal is_setup_done, current_admin
        if is_setup_done:
            route.fulfill(
                status=403,
                content_type="application/json",
                body='{"error": "Setup has already been completed"}'
            )
            return

        data = route.request.post_data_json
        current_admin = {
            "id": 1,
            "username": data.get("username"),
            "email": data.get("email"),
            "role": "admin",
            "is_active": True
        }
        is_setup_done = True
        route.fulfill(
            status=201,
            content_type="application/json",
            json={
                "message": "Master administrator created successfully",
                "user": current_admin
            }
        )

    page.route("**/api/auth/status", handle_auth_status)
    page.route("**/api/auth/setup", handle_auth_setup)
    page.route("**/api/tabs", lambda r: r.fulfill(status=200, content_type="application/json", json=[{"id": 1, "name": "General", "order": 0, "feeds": []}]))


@pytest.mark.e2e
def test_setup_wizard_onboarding_flow(page: Page, live_server: str):
    """Verifies that an unconfigured instance boots into the setup wizard and finishes onboarding."""
    setup_wizard_e2e_routes(page, setup_initially_required=True)
    page.goto(live_server)

    # 1. Wizard modal should be visible
    wizard_modal = page.locator("#setup-wizard-modal")
    expect(wizard_modal).to_be_visible()
    expect(page.locator("#setup-wizard-title")).to_have_text("Welcome to SheepVibes")

    # 2. Test password mismatch client validation
    page.fill("#setup-username", "chief_admin")
    page.fill("#setup-email", "chief@example.com")
    page.fill("#setup-password", "ValidMasterPass123!")
    page.fill("#setup-password-confirm", "DifferentPassword123!")
    page.click("#setup-wizard-submit-button")

    error_banner = page.locator("#setup-wizard-error")
    expect(error_banner).to_be_visible()
    expect(error_banner).to_contain_text("Passwords do not match")

    # 3. Fix password and complete setup
    page.fill("#setup-password-confirm", "ValidMasterPass123!")
    page.click("#setup-wizard-submit-button")

    # 4. Wizard should close and dashboard should be active with administrator user
    expect(wizard_modal).not_to_be_visible()
    expect(page.locator("#user-menu-container")).to_be_visible()
    expect(page.locator("#user-display-name")).to_have_text("chief_admin")
    expect(page.locator("#tabs-container")).to_contain_text("General")
