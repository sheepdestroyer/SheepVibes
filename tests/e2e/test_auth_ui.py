"""Playwright E2E test suite for user authentication, login modals, and session state."""

import pytest
from playwright.sync_api import Page, expect


def setup_auth_routes(page: Page, authenticated: bool = False, role: str = "user"):
    """Sets up API route mocks for auth endpoints."""
    if not authenticated:
        page.context.clear_cookies()
    current_auth_state = {"authenticated": authenticated, "role": role}

    def handle_auth_me(route):
        if current_auth_state["authenticated"]:
            route.fulfill(
                status=200,
                content_type="application/json",
                body='{"authenticated": true, "user": {"id": 1, "username": "alice", "email": "alice@example.com", "role": "' + current_auth_state["role"] + '", "is_active": true}}',
            )
        else:
            route.fulfill(status=200, content_type="application/json", body='{"authenticated": false, "user": null}')

    def handle_login(route):
        req = route.request
        data = req.post_data_json
        if data and data.get("username") == "alice" and data.get("password") == "Secret123!":
            current_auth_state["authenticated"] = True
            route.fulfill(
                status=200,
                content_type="application/json",
                body='{"message": "Login successful", "user": {"id": 1, "username": "alice", "role": "' + current_auth_state["role"] + '", "is_active": true}}',
            )
        else:
            route.fulfill(
                status=401,
                content_type="application/json",
                body='{"error": "Invalid username or password"}',
            )

    def handle_logout(route):
        current_auth_state["authenticated"] = False
        route.fulfill(status=200, content_type="application/json", body='{"message": "Logged out successfully"}')

    def handle_password(route):
        req = route.request
        data = req.post_data_json
        if data and data.get("current_password") == "Secret123!" and len(data.get("new_password", "")) >= 8:
            route.fulfill(status=200, content_type="application/json", body='{"message": "Password updated successfully"}')
        else:
            route.fulfill(status=400, content_type="application/json", body='{"error": "Invalid current password"}')

    def handle_tabs(route):
        if current_auth_state["authenticated"]:
            route.fulfill(
                status=200,
                content_type="application/json",
                body='[{"id": 1, "name": "General", "order": 0, "unread_count": 0}]',
            )
        else:
            route.fulfill(status=401, content_type="application/json", body='{"error": "Unauthorized"}')

    def handle_feeds(route):
        if current_auth_state["authenticated"]:
            route.fulfill(status=200, content_type="application/json", body='[]')
        else:
            route.fulfill(status=401, content_type="application/json", body='{"error": "Unauthorized"}')

    page.route("**/api/auth/me", handle_auth_me)
    page.route("**/api/auth/login", handle_login)
    page.route("**/api/auth/logout", handle_logout)
    page.route("**/api/auth/password", handle_password)
    page.route("**/api/tabs", handle_tabs)
    page.route("**/api/tabs/*/feeds", handle_feeds)


def test_unauthenticated_user_sees_login_modal(page: Page, live_server: str):
    """Verifies that an unauthenticated user is prompted with the login modal."""
    setup_auth_routes(page, authenticated=False)
    page.goto(live_server)

    login_modal = page.locator("#login-modal")
    expect(login_modal).to_be_visible()
    expect(page.locator("#login-modal-title")).to_have_text("Log In to SheepVibes")
    expect(page.locator("#login-username")).to_be_visible()
    expect(page.locator("#login-password")).to_be_visible()
    expect(page.locator("#login-submit-button")).to_be_visible()
    expect(page.locator("#user-menu-container")).to_be_hidden()


def test_login_flow_with_error_and_success(page: Page, live_server: str):
    """Verifies login failure with bad credentials followed by successful authentication."""
    setup_auth_routes(page, authenticated=False)
    page.goto(live_server)

    # 1. Submit invalid credentials
    page.fill("#login-username", "alice")
    page.fill("#login-password", "wrongpass")
    page.click("#login-submit-button")

    error_banner = page.locator("#login-error")
    expect(error_banner).to_be_visible()
    expect(error_banner).to_contain_text("Invalid username or password")

    # 2. Submit valid credentials
    page.fill("#login-password", "Secret123!")
    page.click("#login-submit-button")

    # Modal should close and header user menu should be visible
    expect(page.locator("#login-modal")).to_be_hidden()
    expect(page.locator("#user-menu-container")).to_be_visible()
    expect(page.locator("#user-display-name")).to_have_text("alice")
    expect(page.locator("#tabs-container")).to_contain_text("General")


def test_user_menu_and_change_password_modal(page: Page, live_server: str):
    """Verifies opening user menu, changing password with validation, and logging out."""
    setup_auth_routes(page, authenticated=True, role="admin")
    page.goto(live_server)

    # User is initially authenticated
    expect(page.locator("#user-menu-container")).to_be_visible()
    expect(page.locator("#user-display-name")).to_have_text("alice")

    # Open User menu
    page.click("#user-button")
    user_menu = page.locator("#user-menu")
    expect(user_menu).to_be_visible()
    expect(page.locator("#user-role-badge")).to_have_text("admin")
    expect(page.locator("#admin-panel-button")).to_be_visible()

    # Open Change Password modal
    page.click("#change-password-button")
    expect(user_menu).to_be_hidden()
    pwd_modal = page.locator("#change-password-modal")
    expect(pwd_modal).to_be_visible()

    # Validate mismatch
    page.fill("#change-password-current", "Secret123!")
    page.fill("#change-password-new", "BrandNewPass888")
    page.fill("#change-password-confirm", "MismatchPass999")
    page.click("#change-password-submit-button")

    pwd_error = page.locator("#change-password-error")
    expect(pwd_error).to_be_visible()
    expect(pwd_error).to_have_text("New passwords do not match.")

    # Successful password update
    page.fill("#change-password-confirm", "BrandNewPass888")
    page.click("#change-password-submit-button")

    pwd_success = page.locator("#change-password-success")
    expect(pwd_success).to_be_visible()
    expect(pwd_success).to_have_text("Password updated successfully!")

    # Close modal and log out
    page.click("#change-password-modal-close-button")
    expect(pwd_modal).to_be_hidden()

    page.click("#user-button")
    page.click("#logout-button")

    # After logout, user menu is hidden and login modal is shown
    expect(page.locator("#login-modal")).to_be_visible()
    expect(page.locator("#user-menu-container")).to_be_hidden()
