/**
 * @vitest-environment jsdom
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
    initAdminPanel,
    openAdminModal,
    closeAdminModal,
    switchAdminTab,
    renderAdminUsersTable,
    openAddUserModal,
    closeAddUserModal,
    openEditUserModal,
    closeEditUserModal,
    loadAdminSystemStats
} from './admin.js';
import { api } from './api.js';

describe('Admin Panel Controller', () => {
    beforeEach(() => {
        document.body.innerHTML = `
            <div id="user-menu-container">
                <button id="user-button" aria-haspopup="true" aria-expanded="false"></button>
                <div id="user-menu" class="hidden">
                    <button id="admin-panel-button"></button>
                </div>
            </div>
            <div id="modal-root">
                <div id="admin-modal" class="modal">
                    <button id="admin-modal-close-button"></button>
                    <div class="admin-nav-tabs">
                        <button id="admin-tab-users" class="admin-nav-tab is-active" aria-selected="true"></button>
                        <button id="admin-tab-system" class="admin-nav-tab" aria-selected="false"></button>
                    </div>
                    <div id="admin-section-users" class="admin-section">
                        <button id="admin-open-add-user-button"></button>
                        <button id="admin-refresh-users-button"></button>
                        <table id="admin-users-table">
                            <tbody id="admin-users-table-body"></tbody>
                        </table>
                    </div>
                    <div id="admin-section-system" class="admin-section hidden">
                        <div id="admin-stat-users"></div>
                        <div id="admin-stat-tabs"></div>
                        <div id="admin-stat-feeds"></div>
                        <div id="admin-stat-items"></div>
                        <div id="admin-stat-unread"></div>
                        <div id="admin-stat-db-size"></div>
                        <div id="admin-stat-cache"></div>
                        <div id="admin-stat-python"></div>
                    </div>
                </div>
                <div id="admin-add-user-modal" class="modal">
                    <button id="admin-add-user-close-button"></button>
                    <button id="admin-add-user-cancel-button"></button>
                    <div id="admin-add-user-error" class="error-banner hidden"></div>
                    <form id="admin-add-user-form">
                        <input id="admin-add-username" value="">
                        <input id="admin-add-email" value="">
                        <input id="admin-add-password" value="">
                        <select id="admin-add-role">
                            <option value="user" selected>User</option>
                            <option value="admin">Admin</option>
                        </select>
                        <button type="submit" id="admin-add-user-submit-button"></button>
                    </form>
                </div>
                <div id="admin-edit-user-modal" class="modal">
                    <button id="admin-edit-user-close-button"></button>
                    <button id="admin-edit-user-cancel-button"></button>
                    <div id="admin-edit-user-error" class="error-banner hidden"></div>
                    <form id="admin-edit-user-form">
                        <input id="admin-edit-user-id" value="">
                        <input id="admin-edit-username" value="">
                        <input id="admin-edit-email" value="">
                        <select id="admin-edit-role">
                            <option value="user">User</option>
                            <option value="admin">Admin</option>
                        </select>
                        <select id="admin-edit-status">
                            <option value="true">Active</option>
                            <option value="false">Deactivated</option>
                        </select>
                        <input id="admin-edit-password" value="">
                        <button type="submit" id="admin-edit-user-submit-button"></button>
                        <button type="button" id="admin-delete-user-button"></button>
                    </form>
                </div>
            </div>
            <div id="toast-container"></div>
        `;
        vi.clearAllMocks();
    });

    it('renders empty table when no users exist', () => {
        renderAdminUsersTable([]);
        const tbody = document.getElementById('admin-users-table-body');
        expect(tbody.innerHTML).toContain('No users found.');
    });

    it('renders user rows correctly with role badges and edit actions', () => {
        const users = [
            {
                id: 1,
                username: 'alice',
                email: 'alice@example.com',
                role: 'admin',
                is_active: true,
                tabs_count: 3,
                feeds_count: 12,
                created_at: '2026-08-14T10:00:00Z'
            },
            {
                id: 2,
                username: 'bob',
                email: null,
                role: 'user',
                is_active: false,
                tabs_count: 1,
                feeds_count: 0,
                created_at: '2026-08-14T11:00:00Z'
            }
        ];

        renderAdminUsersTable(users);
        const tbody = document.getElementById('admin-users-table-body');
        const rows = tbody.querySelectorAll('tr');
        expect(rows).toHaveLength(2);

        // Check Alice (admin, active)
        expect(rows[0].textContent).toContain('alice');
        expect(rows[0].textContent).toContain('alice@example.com');
        expect(rows[0].innerHTML).toContain('role-admin');
        expect(rows[0].innerHTML).toContain('status-active');
        expect(rows[0].textContent).toContain('3');
        expect(rows[0].textContent).toContain('12');

        // Check Bob (user, inactive, no email)
        expect(rows[1].textContent).toContain('bob');
        expect(rows[1].textContent).toContain('None');
        expect(rows[1].innerHTML).toContain('role-user');
        expect(rows[1].innerHTML).toContain('status-inactive');
    });

    it('opens and closes admin modal', async () => {
        vi.spyOn(api, 'getAdminUsers').mockResolvedValue({ users: [] });
        const modal = document.getElementById('admin-modal');

        await openAdminModal();
        expect(modal.classList.contains('is-active')).toBe(true);

        closeAdminModal();
        expect(modal.classList.contains('is-active')).toBe(false);
    });

    it('switches between users and system tabs', async () => {
        const getAdminUsersSpy = vi.spyOn(api, 'getAdminUsers').mockResolvedValue({ users: [] });
        const getAdminStatsSpy = vi.spyOn(api, 'getAdminSystemStats').mockResolvedValue({
            stats: {
                users_count: 2,
                tabs_count: 4,
                feeds_count: 10,
                items_count: 100,
                unread_items_count: 25,
                db_size_bytes: 1048576,
                cache_type: 'SimpleCache',
                cache_status: 'active',
                python_version: '3.14.6'
            }
        });

        const usersSection = document.getElementById('admin-section-users');
        const systemSection = document.getElementById('admin-section-system');

        await switchAdminTab('system');
        expect(usersSection.classList.contains('hidden')).toBe(true);
        expect(systemSection.classList.contains('hidden')).toBe(false);
        expect(getAdminStatsSpy).toHaveBeenCalledTimes(1);

        await switchAdminTab('users');
        expect(usersSection.classList.contains('hidden')).toBe(false);
        expect(systemSection.classList.contains('hidden')).toBe(true);
        expect(getAdminUsersSpy).toHaveBeenCalledTimes(1);
    });

    it('loads and populates system stats properly', async () => {
        vi.spyOn(api, 'getAdminSystemStats').mockResolvedValue({
            stats: {
                users_count: 5,
                tabs_count: 10,
                feeds_count: 25,
                items_count: 500,
                unread_items_count: 42,
                db_size_bytes: 2097152, // 2MB
                cache_type: 'RedisCache',
                cache_status: 'active',
                python_version: '3.14.6'
            }
        });

        await loadAdminSystemStats();

        expect(document.getElementById('admin-stat-users').textContent).toBe('5');
        expect(document.getElementById('admin-stat-tabs').textContent).toBe('10');
        expect(document.getElementById('admin-stat-feeds').textContent).toBe('25');
        expect(document.getElementById('admin-stat-items').textContent).toBe('500');
        expect(document.getElementById('admin-stat-unread').textContent).toBe('42');
        expect(document.getElementById('admin-stat-db-size').textContent).toBe('2 MB');
        expect(document.getElementById('admin-stat-cache').textContent).toContain('RedisCache (active)');
        expect(document.getElementById('admin-stat-python').textContent).toBe('3.14.6');
    });

    it('opens and closes add user modal', () => {
        const modal = document.getElementById('admin-add-user-modal');
        openAddUserModal();
        expect(modal.classList.contains('is-active')).toBe(true);

        closeAddUserModal();
        expect(modal.classList.contains('is-active')).toBe(false);
    });

    it('opens and populates edit user modal', () => {
        const modal = document.getElementById('admin-edit-user-modal');
        const user = {
            id: 42,
            username: 'charlie',
            email: 'charlie@example.com',
            role: 'admin',
            is_active: false
        };

        openEditUserModal(user);
        expect(modal.classList.contains('is-active')).toBe(true);
        expect(document.getElementById('admin-edit-user-id').value).toBe('42');
        expect(document.getElementById('admin-edit-username').value).toBe('charlie');
        expect(document.getElementById('admin-edit-email').value).toBe('charlie@example.com');
        expect(document.getElementById('admin-edit-role').value).toBe('admin');
        expect(document.getElementById('admin-edit-status').value).toBe('false');

        closeEditUserModal();
        expect(modal.classList.contains('is-active')).toBe(false);
    });
});
