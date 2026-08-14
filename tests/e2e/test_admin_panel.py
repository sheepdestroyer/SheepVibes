"""Playwright E2E test suite for the Admin Panel, user management, and diagnostics."""

import pytest
from playwright.sync_api import Page, expect


def setup_admin_e2e_routes(page: Page, is_admin: bool = True):
    """Sets up API route mocks for admin panel E2E testing."""
    users_db = [
        {
            "id": 1,
            "username": "admin",
            "email": "admin@example.com",
            "role": "admin",
            "is_active": True,
            "tabs_count": 2,
            "feeds_count": 8,
            "created_at": "2026-08-14T08:00:00Z"
        },
        {
            "id": 2,
            "username": "john_doe",
            "email": "john@example.com",
            "role": "user",
            "is_active": True,
            "tabs_count": 1,
            "feeds_count": 3,
            "created_at": "2026-08-14T09:00:00Z"
        }
    ]

    current_role = "admin" if is_admin else "user"

    def handle_auth_me(route):
        route.fulfill(
            status=200,
            content_type="application/json",
            body='{"authenticated": true, "user": {"id": 1, "username": "testuser", "email": "test@example.com", "role": "' + current_role + '", "is_active": true}}',
        )

    def handle_admin_users_get(route):
        if current_role != "admin":
            route.fulfill(status=403, content_type="application/json", body='{"error": "Admin privileges required"}')
            return
        route.fulfill(
            status=200,
            content_type="application/json",
            json={"users": users_db}
        )

    def handle_admin_users_post(route):
        if current_role != "admin":
            route.fulfill(status=403, content_type="application/json", body='{"error": "Admin privileges required"}')
            return
        data = route.request.post_data_json
        new_user = {
            "id": len(users_db) + 1,
            "username": data.get("username"),
            "email": data.get("email"),
            "role": data.get("role", "user"),
            "is_active": True,
            "tabs_count": 1,
            "feeds_count": 0,
            "created_at": "2026-08-14T10:00:00Z"
        }
        users_db.append(new_user)
        route.fulfill(status=201, content_type="application/json", json={"user": new_user, "message": "User created successfully"})

    def handle_admin_user_put(route):
        if current_role != "admin":
            route.fulfill(status=403, content_type="application/json", body='{"error": "Admin privileges required"}')
            return
        user_id = int(route.request.url.split("/")[-1])
        data = route.request.post_data_json
        target = next((u for u in users_db if u["id"] == user_id), None)
        if target:
            if "role" in data:
                target["role"] = data["role"]
            if "is_active" in data:
                target["is_active"] = data["is_active"]
            if "email" in data:
                target["email"] = data["email"]
            route.fulfill(status=200, content_type="application/json", json={"user": target, "message": "User updated"})
        else:
            route.fulfill(status=404, content_type="application/json", body='{"error": "User not found"}')

    def handle_admin_user_delete(route):
        if current_role != "admin":
            route.fulfill(status=403, content_type="application/json", body='{"error": "Admin privileges required"}')
            return
        user_id = int(route.request.url.split("/")[-1])
        nonlocal users_db
        users_db = [u for u in users_db if u["id"] != user_id]
        route.fulfill(status=200, content_type="application/json", body='{"message": "User deleted successfully"}')

    def handle_admin_system_stats(route):
        if current_role != "admin":
            route.fulfill(status=403, content_type="application/json", body='{"error": "Admin privileges required"}')
            return
        route.fulfill(
            status=200,
            content_type="application/json",
            json={
                "stats": {
                    "users_count": 2,
                    "tabs_count": 3,
                    "feeds_count": 11,
                    "items_count": 250,
                    "unread_items_count": 45,
                    "db_size_bytes": 1048576,
                    "cache_type": "RedisCache",
                    "cache_status": "active",
                    "python_version": "3.14.6"
                }
            }
        )

    page.route("**/api/auth/me", handle_auth_me)
    page.route("**/api/admin/users", lambda r: handle_admin_users_get(r) if r.request.method == "GET" else handle_admin_users_post(r))
    page.route("**/api/admin/users/*", lambda r: handle_admin_user_put(r) if r.request.method == "PUT" else handle_admin_user_delete(r))
    page.route("**/api/admin/system/stats", handle_admin_system_stats)
    page.route("**/api/tabs", lambda r: r.fulfill(status=200, content_type="application/json", body="[]"))


@pytest.mark.e2e
def test_admin_button_visibility_by_role(page: Page, live_server: str):
    """Verifies that the Admin Panel button in the user dropdown is only shown to admins."""
    # 1. As regular user
    setup_admin_e2e_routes(page, is_admin=False)
    page.goto(live_server)

    page.click("#user-button")
    admin_btn = page.locator("#admin-panel-button")
    expect(admin_btn).to_have_class("hidden")

    # 2. As administrator
    setup_admin_e2e_routes(page, is_admin=True)
    page.goto(live_server)

    page.click("#user-button")
    expect(admin_btn).not_to_have_class("hidden")


@pytest.mark.e2e
def test_admin_user_management_crud_flow(page: Page, live_server: str):
    """Verifies opening Admin Panel, creating a user, editing their role, and deleting them."""
    setup_admin_e2e_routes(page, is_admin=True)
    page.goto(live_server)

    # 1. Open User Menu and click Admin Panel
    page.click("#user-button")
    page.click("#admin-panel-button")

    admin_modal = page.locator("#admin-modal")
    expect(admin_modal).to_be_visible()

    # 2. Verify initial users in table
    user_rows = page.locator("#admin-users-table-body tr")
    expect(user_rows).to_have_count(2)
    expect(page.locator("#admin-users-table-body")).to_contain_text("john_doe")

    # 3. Add a new user
    page.click("#admin-open-add-user-button")
    add_modal = page.locator("#admin-add-user-modal")
    expect(add_modal).to_be_visible()

    page.fill("#admin-add-username", "sarah_connor")
    page.fill("#admin-add-email", "sarah@example.com")
    page.fill("#admin-add-password", "Skynet123!")
    page.select_option("#admin-add-role", "admin")
    page.click("#admin-add-user-submit-button")

    expect(add_modal).not_to_be_visible()
    expect(page.locator("#admin-users-table-body")).to_contain_text("sarah_connor")
    expect(user_rows).to_have_count(3)

    # 4. Edit newly created user
    sarah_row = page.locator("tr", has_text="sarah_connor")
    sarah_row.locator(".admin-edit-user-trigger").click()

    edit_modal = page.locator("#admin-edit-user-modal")
    expect(edit_modal).to_be_visible()
    expect(page.locator("#admin-edit-username")).to_have_value("sarah_connor")

    # Change email and status
    page.fill("#admin-edit-email", "sarah_new@example.com")
    page.click("#admin-edit-user-submit-button")

    expect(edit_modal).not_to_be_visible()
    expect(page.locator("#admin-users-table-body")).to_contain_text("sarah_new@example.com")

    # 5. Delete the user
    sarah_row = page.locator("tr", has_text="sarah_connor")
    sarah_row.locator(".admin-edit-user-trigger").click()
    expect(edit_modal).to_be_visible()

    page.on("dialog", lambda dialog: dialog.accept())
    page.click("#admin-delete-user-button")

    expect(edit_modal).not_to_be_visible()
    expect(page.locator("#admin-users-table-body")).not_to_contain_text("sarah_connor")
    expect(user_rows).to_have_count(2)


@pytest.mark.e2e
def test_admin_system_diagnostics_tab(page: Page, live_server: str):
    """Verifies system diagnostics data and backup button in admin modal."""
    setup_admin_e2e_routes(page, is_admin=True)
    page.goto(live_server)

    page.click("#user-button")
    page.click("#admin-panel-button")

    # Switch to System tab
    page.click("#admin-tab-system")

    system_section = page.locator("#admin-section-system")
    expect(system_section).to_be_visible()

    # Check diagnostic values
    expect(page.locator("#admin-stat-users")).to_have_text("2")
    expect(page.locator("#admin-stat-tabs")).to_have_text("3")
    expect(page.locator("#admin-stat-feeds")).to_have_text("11")
    expect(page.locator("#admin-stat-items")).to_have_text("250")
    expect(page.locator("#admin-stat-unread")).to_have_text("45")
    expect(page.locator("#admin-stat-db-size")).to_have_text("1 MB")
    expect(page.locator("#admin-stat-cache")).to_contain_text("RedisCache (active)")
    expect(page.locator("#admin-stat-python")).to_have_text("3.14.6")

    # Check backup download button
    backup_btn = page.locator("#admin-download-backup-button")
    expect(backup_btn).to_be_visible()
    expect(backup_btn).to_have_attribute("href", "/api/admin/backup")
