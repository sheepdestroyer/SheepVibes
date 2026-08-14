/**
 * Administration Panel Controller
 * Handles user management, account modifications, system statistics, and database backups.
 */

import { api } from './api.js';
import { showToast } from './ui.js';

let cachedUsers = [];

/**
 * Initializes all Admin Panel event listeners.
 */
export function initAdminPanel() {
    // Open/Close main admin modal
    document.getElementById('admin-panel-button')?.addEventListener('click', () => {
        const userMenu = document.getElementById('user-menu');
        const userButton = document.getElementById('user-button');
        if (userMenu) userMenu.classList.add('hidden');
        if (userButton) userButton.setAttribute('aria-expanded', 'false');
        openAdminModal();
    });

    document.getElementById('admin-modal-close-button')?.addEventListener('click', closeAdminModal);

    // Modal navigation tabs
    document.getElementById('admin-tab-users')?.addEventListener('click', () => switchAdminTab('users'));
    document.getElementById('admin-tab-system')?.addEventListener('click', () => switchAdminTab('system'));

    // Toolbar buttons
    document.getElementById('admin-open-add-user-button')?.addEventListener('click', openAddUserModal);
    document.getElementById('admin-refresh-users-button')?.addEventListener('click', loadAdminUsers);

    // Add User Modal listeners
    document.getElementById('admin-add-user-close-button')?.addEventListener('click', closeAddUserModal);
    document.getElementById('admin-add-user-cancel-button')?.addEventListener('click', closeAddUserModal);
    document.getElementById('admin-add-user-form')?.addEventListener('submit', handleAddUserSubmit);

    // Edit User Modal listeners
    document.getElementById('admin-edit-user-close-button')?.addEventListener('click', closeEditUserModal);
    document.getElementById('admin-edit-user-cancel-button')?.addEventListener('click', closeEditUserModal);
    document.getElementById('admin-edit-user-form')?.addEventListener('submit', handleEditUserSubmit);
    document.getElementById('admin-delete-user-button')?.addEventListener('click', handleDeleteUserClick);
}

/**
 * Opens the Admin Modal and loads initial data.
 */
export async function openAdminModal() {
    const modal = document.getElementById('admin-modal');
    if (!modal) return;
    modal.classList.add('is-active');
    switchAdminTab('users');
}

/**
 * Closes the Admin Modal.
 */
export function closeAdminModal() {
    const modal = document.getElementById('admin-modal');
    if (modal) modal.classList.remove('is-active');
}

/**
 * Switches between 'users' and 'system' tabs in the admin panel.
 * @param {'users'|'system'} tabName 
 */
export async function switchAdminTab(tabName) {
    const usersTab = document.getElementById('admin-tab-users');
    const systemTab = document.getElementById('admin-tab-system');
    const usersSection = document.getElementById('admin-section-users');
    const systemSection = document.getElementById('admin-section-system');

    if (tabName === 'users') {
        usersTab?.classList.add('is-active');
        usersTab?.setAttribute('aria-selected', 'true');
        systemTab?.classList.remove('is-active');
        systemTab?.setAttribute('aria-selected', 'false');

        usersSection?.classList.remove('hidden');
        systemSection?.classList.add('hidden');
        await loadAdminUsers();
    } else {
        systemTab?.classList.add('is-active');
        systemTab?.setAttribute('aria-selected', 'true');
        usersTab?.classList.remove('is-active');
        usersTab?.setAttribute('aria-selected', 'false');

        systemSection?.classList.remove('hidden');
        usersSection?.classList.add('hidden');
        await loadAdminSystemStats();
    }
}

/**
 * Fetches and renders the list of registered users.
 */
export async function loadAdminUsers() {
    const tbody = document.getElementById('admin-users-table-body');
    if (tbody) {
        tbody.innerHTML = '<tr><td colspan="9" class="loading-cell">Loading users...</td></tr>';
    }

    try {
        const response = await api.getAdminUsers();
        cachedUsers = (response && response.users) || [];
        renderAdminUsersTable(cachedUsers);
    } catch (err) {
        console.error('Failed to load admin users:', err);
        if (tbody) {
            tbody.innerHTML = `<tr><td colspan="9" class="error-cell">Failed to load users: ${err.backendMessage || err.message}</td></tr>`;
        }
    }
}

/**
 * Renders the users table in DOM.
 * @param {Array<object>} users 
 */
export function renderAdminUsersTable(users) {
    const tbody = document.getElementById('admin-users-table-body');
    if (!tbody) return;

    if (!users || users.length === 0) {
        tbody.innerHTML = '<tr><td colspan="9" class="empty-cell">No users found.</td></tr>';
        return;
    }

    tbody.innerHTML = '';
    users.forEach(user => {
        const tr = document.createElement('tr');
        tr.dataset.userId = user.id;

        const createdDate = user.created_at ? new Date(user.created_at).toLocaleDateString() : '-';
        const statusBadge = user.is_active
            ? '<span class="status-badge status-active">Active</span>'
            : '<span class="status-badge status-inactive">Deactivated</span>';
        const roleBadge = `<span class="badge role-${user.role || 'user'}">${user.role || 'user'}</span>`;

        tr.innerHTML = `
            <td>${user.id}</td>
            <td><strong>${escapeHtml(user.username)}</strong></td>
            <td>${user.email ? escapeHtml(user.email) : '<span class="text-muted">None</span>'}</td>
            <td>${roleBadge}</td>
            <td>${statusBadge}</td>
            <td>${user.tabs_count ?? 0}</td>
            <td>${user.feeds_count ?? 0}</td>
            <td>${createdDate}</td>
            <td>
                <button class="table-action-button admin-edit-user-trigger" data-user-id="${user.id}">Edit</button>
            </td>
        `;

        const editButton = tr.querySelector('.admin-edit-user-trigger');
        editButton?.addEventListener('click', () => openEditUserModal(user));

        tbody.appendChild(tr);
    });
}

/**
 * Opens Add User modal.
 */
export function openAddUserModal() {
    const modal = document.getElementById('admin-add-user-modal');
    if (!modal) return;
    const form = document.getElementById('admin-add-user-form');
    if (form) form.reset();
    const errorBanner = document.getElementById('admin-add-user-error');
    if (errorBanner) {
        errorBanner.textContent = '';
        errorBanner.classList.add('hidden');
    }
    modal.classList.add('is-active');
    document.getElementById('admin-add-username')?.focus();
}

/**
 * Closes Add User modal.
 */
export function closeAddUserModal() {
    const modal = document.getElementById('admin-add-user-modal');
    if (modal) modal.classList.remove('is-active');
}

/**
 * Handles Add User form submission.
 * @param {Event} e 
 */
export async function handleAddUserSubmit(e) {
    e.preventDefault();
    const username = document.getElementById('admin-add-username').value.trim();
    const email = document.getElementById('admin-add-email').value.trim() || null;
    const password = document.getElementById('admin-add-password').value;
    const role = document.getElementById('admin-add-role').value;
    const errorBanner = document.getElementById('admin-add-user-error');
    const submitButton = document.getElementById('admin-add-user-submit-button');

    if (password.length < 8) {
        if (errorBanner) {
            errorBanner.textContent = 'Password must be at least 8 characters long.';
            errorBanner.classList.remove('hidden');
        }
        return;
    }

    submitButton.disabled = true;
    submitButton.textContent = 'Creating...';

    try {
        await api.createAdminUser({ username, email, password, role });
        showToast(`User '${username}' created successfully!`, 'success');
        closeAddUserModal();
        await loadAdminUsers();
    } catch (err) {
        if (errorBanner) {
            errorBanner.textContent = err.backendMessage || 'Failed to create user.';
            errorBanner.classList.remove('hidden');
        }
    } finally {
        submitButton.disabled = false;
        submitButton.textContent = 'Create User';
    }
}

/**
 * Opens Edit User modal for a target user.
 * @param {object} user 
 */
export function openEditUserModal(user) {
    const modal = document.getElementById('admin-edit-user-modal');
    if (!modal) return;

    document.getElementById('admin-edit-user-id').value = user.id;
    document.getElementById('admin-edit-username').value = user.username;
    document.getElementById('admin-edit-email').value = user.email || '';
    document.getElementById('admin-edit-role').value = user.role || 'user';
    document.getElementById('admin-edit-status').value = user.is_active ? 'true' : 'false';
    document.getElementById('admin-edit-password').value = '';

    const errorBanner = document.getElementById('admin-edit-user-error');
    if (errorBanner) {
        errorBanner.textContent = '';
        errorBanner.classList.add('hidden');
    }

    modal.classList.add('is-active');
}

/**
 * Closes Edit User modal.
 */
export function closeEditUserModal() {
    const modal = document.getElementById('admin-edit-user-modal');
    if (modal) modal.classList.remove('is-active');
}

/**
 * Handles Edit User form submission.
 * @param {Event} e 
 */
export async function handleEditUserSubmit(e) {
    e.preventDefault();
    const userId = document.getElementById('admin-edit-user-id').value;
    const username = document.getElementById('admin-edit-username').value.trim();
    const email = document.getElementById('admin-edit-email').value.trim() || null;
    const role = document.getElementById('admin-edit-role').value;
    const isActive = document.getElementById('admin-edit-status').value === 'true';
    const password = document.getElementById('admin-edit-password').value;
    const errorBanner = document.getElementById('admin-edit-user-error');
    const submitButton = document.getElementById('admin-edit-user-submit-button');

    const updatePayload = {
        username,
        email,
        role,
        is_active: isActive
    };

    if (password) {
        if (password.length < 8) {
            if (errorBanner) {
                errorBanner.textContent = 'Password must be at least 8 characters long.';
                errorBanner.classList.remove('hidden');
            }
            return;
        }
        updatePayload.password = password;
    }

    submitButton.disabled = true;
    submitButton.textContent = 'Saving...';

    try {
        await api.updateAdminUser(userId, updatePayload);
        showToast(`User '${username}' updated successfully!`, 'success');
        closeEditUserModal();
        await loadAdminUsers();
    } catch (err) {
        if (errorBanner) {
            errorBanner.textContent = err.backendMessage || 'Failed to update user.';
            errorBanner.classList.remove('hidden');
        }
    } finally {
        submitButton.disabled = false;
        submitButton.textContent = 'Save Changes';
    }
}

/**
 * Handles Delete User button click inside Edit User modal.
 */
export async function handleDeleteUserClick() {
    const userId = document.getElementById('admin-edit-user-id').value;
    const username = document.getElementById('admin-edit-username').value;
    const errorBanner = document.getElementById('admin-edit-user-error');

    if (!confirm(`Are you sure you want to permanently delete user '${username}' and all their tabs/feeds?`)) {
        return;
    }

    try {
        await api.deleteAdminUser(userId);
        showToast(`User '${username}' deleted successfully.`, 'info');
        closeEditUserModal();
        await loadAdminUsers();
    } catch (err) {
        if (errorBanner) {
            errorBanner.textContent = err.backendMessage || 'Failed to delete user.';
            errorBanner.classList.remove('hidden');
        }
    }
}

/**
 * Fetches and displays system diagnostics.
 */
export async function loadAdminSystemStats() {
    try {
        const response = await api.getAdminSystemStats();
        const stats = (response && response.stats) || {};

        document.getElementById('admin-stat-users').textContent = stats.users_count ?? '-';
        document.getElementById('admin-stat-tabs').textContent = stats.tabs_count ?? '-';
        document.getElementById('admin-stat-feeds').textContent = stats.feeds_count ?? '-';
        document.getElementById('admin-stat-items').textContent = stats.items_count ?? '-';
        document.getElementById('admin-stat-unread').textContent = stats.unread_items_count ?? '-';
        document.getElementById('admin-stat-db-size').textContent = formatBytes(stats.db_size_bytes ?? 0);
        document.getElementById('admin-stat-cache').textContent = `${stats.cache_type || 'Unknown'} (${stats.cache_status || 'unknown'})`;
        document.getElementById('admin-stat-python').textContent = stats.python_version || '-';
    } catch (err) {
        console.error('Failed to load system stats:', err);
        showToast('Failed to load system statistics.', 'error');
    }
}

function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}
