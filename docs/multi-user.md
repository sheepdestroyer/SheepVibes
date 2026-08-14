# Multi-User Accounts & Administration Guide

SheepVibes includes a robust multi-user authentication architecture, complete per-user tenant isolation, an interactive first-run onboarding wizard, and a comprehensive web-based Administration Panel.

---

## 1. Overview & Architecture

### User Data Model & Multi-Tenancy
- **User Accounts**: Each user account is stored in the `users` table with secure password hashing (`generate_password_hash` via `scrypt`/`pbkdf2`), unique case-insensitive usernames, optional email addresses, an `is_active` status flag, and a role (`admin` or `user`).
- **Tenant Isolation**: All user-specific resources (`Tab`, `Feed`, `FeedItem`) are bound to the authenticated `user_id`. Queries and mutation endpoints enforce strict ownership checks. Accessing or attempting to mutate foreign resources returns `404 Not Found`.
- **Composite Uniqueness**: Tab names are unique per-user (`UniqueConstraint("user_id", "name")`), allowing multiple users to have tabs with identical names (such as "News", "Tech", or "General") without conflict.

### Partitioned Caching
Cache keys are partitioned by user ID:
```
view/user/{user_id}/tabs/v{version}
view/user/{user_id}/tab/{tab_id}/feeds/v{version}
```
When user data changes, cache version keys are incremented specifically for that user (`user:{user_id}:tabs_version`), guaranteeing instantaneous invalidation without affecting other users or causing cross-tenant cache contamination.

---

## 2. First-Run Onboarding Wizard

When SheepVibes is launched on a fresh database with no existing user accounts:
1. The frontend queries `GET /api/auth/status` and detects `setup_required: true`.
2. The interactive **First-Run Onboarding Wizard** modal is presented.
3. The administrator enters their desired username (3-30 characters, alphanumeric with `-` and `_`), an optional email address, and a master password (minimum 8 characters).
4. Submitting the wizard calls `POST /api/auth/setup`, which:
   - Creates the master administrator account (`role: "admin"`).
   - Generates an initial default tab ("General").
   - Authenticates the session cookie immediately.
   - Automatically closes setup and launches the dashboard.
5. All subsequent calls to `POST /api/auth/setup` are permanently rejected with `403 Forbidden`.

---

## 3. Administration Panel

Users with the `admin` role have access to the **Admin Panel** via the account dropdown in the header.

### User Management
- **List Users**: View all registered accounts, their roles, active status, tab count, feed count, and registration date.
- **Create User**: Add new users directly with custom roles (`user` or `admin`) and initial passwords. Newly created users receive an automatic default "General" tab.
- **Edit User**:
  - Update username, email address, and role.
  - Reset account passwords.
  - Toggle active/deactivated status. Deactivated users are immediately blocked from logging in.
- **Delete User**: Permanently remove a user account. This cascades and deletes all associated tabs, feeds, and articles.
- **Self-Account Safeguards**: Administrators cannot deactivate, demote, or delete their own active account, preventing accidental lockouts.

### System Diagnostics
- **Usage Metrics**: Real-time counts of total users, tabs, feeds, articles, and unread items.
- **Database Size**: Live byte-level file size calculation for SQLite database storage.
- **Cache Engine Health**: Diagnostic check verifying the operational status of the caching backend (Valkey/Redis or SimpleCache).
- **Environment**: Active Python runtime version and UTC server time.

### Point-in-Time Database Backup
- Under the **System Diagnostics** tab, administrators can click **Download Database Backup** (`GET /api/admin/backup`).
- Backups utilize SQLite's online backup API (`sqlite3.backup()`), ensuring non-blocking, point-in-time consistent `.db` file exports without taking the service offline.

---

## 4. Configuration & Deployment

SheepVibes supports several environment variables to tune authentication and session behavior:

| Variable | Default | Description |
|---|---|---|
| `SECRET_KEY` | `sheepvibes-default-secret-key-change-in-prod` | Secret key used to cryptographically sign session cookies. Must be set to a strong random value in production. |
| `SESSION_COOKIE_SECURE` | `False` | When set to `True`, ensures session cookies are transmitted only over HTTPS connections. |
| `SESSION_COOKIE_HTTPONLY` | `True` | Prevents client-side scripts from reading session cookies. |
| `SESSION_COOKIE_SAMESITE` | `Lax` | Restricts cookie sending to same-site and top-level navigation. |
| `SESSION_LIFETIME_DAYS` | `30` | Number of days before an idle session expires. |

### Example: Production Quadlet / Podman Environment

```ini
[Unit]
Description=SheepVibes News Reader
After=network-online.target

[Container]
Image=ghcr.io/sheepdestroyer/sheepvibes:latest
PublishPort=5000:5000
Volume=/var/lib/sheepvibes/data:/app/data:Z
Environment=SECRET_KEY=generate_with_openssl_rand_hex_32
Environment=SESSION_COOKIE_SECURE=true
Environment=SESSION_LIFETIME_DAYS=30
Environment=CACHE_TYPE=RedisCache
Environment=CACHE_REDIS_URL=redis://valkey:6379/0

[Install]
WantedBy=default.target
```
