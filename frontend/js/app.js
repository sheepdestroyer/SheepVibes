import { throttle } from './utils.js';
import { api, API_BASE_URL } from './api.js';
import {
    showToast,
    createFeedWidget,
    renderTabs,
    showEditFeedModal,
    closeEditFeedModal,
    appendItemsToFeedWidget,
    showProgress,
    updateProgress,
    hideProgress,
    updateProgressBarPosition,
    renderAdminUsers
} from './ui.js';

const PROGRESS_FALLBACK_TIMEOUT_MS = 15000;
let progressFallbackTimeoutId = null;

// State
let activeTabId = parseInt(localStorage.getItem('activeTabId'), 10) || null;
let allTabs = [];
const loadedTabs = new Set();
const ITEMS_PER_PAGE = 10;
let currentUser = null;

// --- Initialization ---

document.addEventListener('DOMContentLoaded', async () => {
    setupEventListeners();
    await checkAuth();
    updateProgressBarPosition();
    window.addEventListener('resize', updateProgressBarPosition);
    window.addEventListener('auth-required', () => handleLogout());
});

function setupEventListeners() {
    // Auth listeners
    document.getElementById('login-form').addEventListener('submit', handleLogin);
    document.getElementById('register-form').addEventListener('submit', handleRegister);
    document.getElementById('show-register').onclick = (e) => { e.preventDefault(); showAuthView('register'); };
    document.getElementById('show-login').onclick = (e) => { e.preventDefault(); showAuthView('login'); };
    document.getElementById('logout-button').addEventListener('click', handleLogout);

    // Tab listeners
    document.getElementById('add-tab-button').addEventListener('click', handleAddTab);
    document.getElementById('rename-tab-button').addEventListener('click', handleRenameTab);
    document.getElementById('delete-tab-button').addEventListener('click', handleDeleteTab);

    // Feed/Settings listeners
    document.getElementById('settings-button').addEventListener('click', () => document.getElementById('settings-menu').classList.toggle('hidden'));
    document.getElementById('add-feed-button').addEventListener('click', handleAddFeed);
    document.getElementById('refresh-all-feeds-button').addEventListener('click', handleRefreshAllFeeds);
    document.getElementById('export-opml-button').addEventListener('click', handleExportOpml);
    document.getElementById('import-opml-button').addEventListener('click', () => document.getElementById('opml-file-input').click());
    document.getElementById('opml-file-input').addEventListener('change', handleImportOpmlFileSelect);

    // Admin listeners
    document.getElementById('admin-button').onclick = handleOpenAdmin;
    document.getElementById('close-admin-button').onclick = () => document.getElementById('admin-view').classList.add('hidden');
    document.getElementById('admin-export-db-button').onclick = handleExportDb;

    // Modal listeners
    document.getElementById('edit-feed-modal-close-button').addEventListener('click', closeEditFeedModal);
    document.getElementById('cancel-edit-button').addEventListener('click', closeEditFeedModal);
    document.getElementById('edit-feed-form').addEventListener('submit', handleEditFeedSubmit);

    // Close settings on click outside
    document.addEventListener('click', (e) => {
        const menu = document.getElementById('settings-menu');
        const btn = document.getElementById('settings-button');
        if (!menu.classList.contains('hidden') && !menu.contains(e.target) && !btn.contains(e.target)) {
            menu.classList.add('hidden');
        }
    });
}

// --- Auth ---

async function checkAuth() {
    try {
        currentUser = await api.getMe();
        onLoggedIn();
    } catch (e) {
        onLoggedOut();
    }
}

function onLoggedIn() {
    currentUser = currentUser || {};
    document.body.classList.replace('logged-out', 'logged-in');
    document.getElementById('username-display').textContent = currentUser.username;
    if (currentUser.is_admin) {
        document.getElementById('admin-button').classList.remove('hidden');
    } else {
        document.getElementById('admin-button').classList.add('hidden');
    }
    initializeTabs();
    initializeSSE();
}

function onLoggedOut() {
    currentUser = null;
    document.body.classList.replace('logged-in', 'logged-out');
    document.getElementById('feed-grid').innerHTML = '';
    loadedTabs.clear();
}

function showAuthView(view) {
    document.querySelectorAll('.auth-view').forEach(v => v.classList.add('hidden'));
    document.getElementById(`${view}-view`).classList.remove('hidden');
}

async function handleLogin(e) {
    e.preventDefault();
    const u = document.getElementById('login-username').value;
    const p = document.getElementById('login-password').value;
    try {
        currentUser = await api.login(u, p);
        showToast(`Welcome, ${currentUser.username}!`, 'success');
        onLoggedIn();
    } catch (err) {
        showToast(err.message, 'error');
    }
}

async function handleRegister(e) {
    e.preventDefault();
    const u = document.getElementById('register-username').value;
    const email = document.getElementById('register-email').value;
    const p = document.getElementById('register-password').value;
    try {
        await api.register(u, p, email);
        showToast('Registration successful! Please login.', 'success');
        showAuthView('login');
    } catch (err) {
        showToast(err.message, 'error');
    }
}

async function handleLogout() {
    try { await api.logout(); } catch (e) {}
    onLoggedOut();
    showToast('Logged out.', 'info');
}

// --- Tabs ---

async function initializeTabs() {
    try {
        allTabs = await api.getTabs();
        if (!allTabs.some(t => t.id === activeTabId)) {
            activeTabId = allTabs.length > 0 ? allTabs[0].id : null;
        }
        renderTabs(allTabs, activeTabId, { onSwitchTab: switchTab });
        if (activeTabId) {
            await (loadedTabs.has(activeTabId) ? Promise.resolve(toggleWidgetsVisibility()) : loadFeedsForTab(activeTabId));
        }
    } catch (err) {
        showToast('Failed to load tabs.', 'error');
    }
}

async function switchTab(tabId) {
    if (tabId === activeTabId) return;
    activeTabId = tabId;
    localStorage.setItem('activeTabId', tabId);
    renderTabs(allTabs, activeTabId, { onSwitchTab: switchTab });
    toggleWidgetsVisibility();
    if (!loadedTabs.has(tabId)) await loadFeedsForTab(tabId);
}

function toggleWidgetsVisibility() {
    const widgets = document.querySelectorAll('.feed-widget');
    widgets.forEach(w => {
        w.style.display = (w.dataset.tabId == activeTabId) ? 'block' : 'none';
    });
}

async function loadFeedsForTab(tabId) {
    if (loadedTabs.has(tabId)) return;
    const grid = document.getElementById('feed-grid');
    try {
        const subs = await api.getFeedsForTab(tabId);
        grid.querySelectorAll(`.empty-tab-message[data-tab-id="${tabId}"]`).forEach(p => p.remove());
        if (subs && subs.length > 0) {
            subs.forEach(sub => {
                grid.appendChild(createFeedWidget(sub, {
                    onEdit: (id, url, name) => showEditFeedModal(id, url, name),
                    onDelete: handleDeleteFeed,
                    onMarkItemRead: handleMarkItemRead,
                    onLoadMore: handleLoadMoreItems
                }));
            });
        } else {
            const msg = document.createElement('div');
            msg.className = 'feed-widget empty-tab-message';
            msg.dataset.tabId = tabId;
            msg.innerHTML = '<p>No feeds in this tab.</p>';
            grid.appendChild(msg);
        }
        loadedTabs.add(tabId);
        toggleWidgetsVisibility();
    } catch (err) {
        showToast('Failed to load feeds.', 'error');
    }
}

// --- Handlers ---

async function handleAddTab() {
    const name = prompt("New tab name:");
    if (!name) return;
    try {
        await api.createTab(name);
        await initializeTabs();
        showToast('Tab created!', 'success');
    } catch (e) { showToast(e.message, 'error'); }
}

async function handleRenameTab() {
    if (!activeTabId) return;
    const tab = allTabs.find(t => t.id === activeTabId);
    const newName = prompt("Rename tab to:", tab.name);
    if (!newName || newName === tab.name) return;
    try {
        await api.updateTab(activeTabId, newName);
        await initializeTabs();
        showToast('Tab renamed.', 'success');
    } catch (e) { showToast(e.message, 'error'); }
}

async function handleDeleteTab() {
    if (!activeTabId || !confirm("Delete tab and all its feeds?")) return;
    try {
        await api.deleteTab(activeTabId);
        document.querySelectorAll(`.feed-widget[data-tab-id="${activeTabId}"]`).forEach(w => w.remove());
        loadedTabs.delete(activeTabId);
        activeTabId = null;
        await initializeTabs();
        showToast('Tab deleted.', 'success');
    } catch (e) { showToast(e.message, 'error'); }
}

async function handleAddFeed() {
    const input = document.getElementById('feed-url-input');
    const url = input.value.trim();
    if (!url || !activeTabId) return showToast('Enter URL and select a tab', 'error');
    const btn = document.getElementById('add-feed-button');
    btn.disabled = true;
    try {
        await api.addFeed(url, activeTabId);
        input.value = '';
        showToast('Feed added!', 'success');
        await reloadTab(activeTabId);
    } catch (e) { showToast(e.message, 'error'); }
    finally { btn.disabled = false; }
}

async function handleDeleteFeed(subId) {
    if (!confirm("Delete this subscription?")) return;
    try {
        await api.deleteFeed(subId);
        document.querySelector(`.feed-widget[data-sub-id="${subId}"]`)?.remove();
        showToast('Feed deleted.', 'success');
    } catch (e) { showToast(e.message, 'error'); }
}

async function handleEditFeedSubmit(e) {
    e.preventDefault();
    const id = document.getElementById('edit-feed-id').value;
    const url = document.getElementById('edit-feed-url').value;
    const name = document.getElementById('edit-feed-name').value;
    try {
        const updated = await api.updateFeed(id, url, name);
        const old = document.querySelector(`.feed-widget[data-sub-id="${id}"]`);
        if (old) {
            old.replaceWith(createFeedWidget(updated, {
                onEdit: (fid, furl, fname) => showEditFeedModal(fid, furl, fname),
                onDelete: handleDeleteFeed,
                onMarkItemRead: handleMarkItemRead,
                onLoadMore: handleLoadMoreItems
            }));
        }
        closeEditFeedModal();
        showToast('Subscription updated.', 'success');
    } catch (err) { showToast(err.message, 'error'); }
}

async function handleMarkItemRead(itemId, li, subId, tabId) {
    if (li.classList.contains('read')) return;
    try {
        await api.markItemRead(itemId);
        li.classList.replace('unread', 'read');
        updateUnreadBadge(li.closest('.feed-widget'));
        updateUnreadBadge(document.querySelector(`button[data-tab-id="${tabId}"]`));
    } catch (e) { console.error(e); }
}

function updateUnreadBadge(el) {
    const b = el?.querySelector('.unread-count-badge');
    if (!b) return;
    const count = parseInt(b.textContent, 10) - 1;
    if (count > 0) b.textContent = count; else b.remove();
}

async function handleLoadMoreItems(list) {
    if (list.dataset.loading === 'true' || list.dataset.allItemsLoaded === 'true') return;
    list.dataset.loading = 'true';
    try {
        const items = await api.getFeedItems(list.dataset.subId, parseInt(list.dataset.offset, 10), ITEMS_PER_PAGE);
        if (items?.length) appendItemsToFeedWidget(list, items, { onMarkItemRead: handleMarkItemRead });
        else list.dataset.allItemsLoaded = 'true';
    } catch (e) { console.error(e); }
    finally { list.dataset.loading = 'false'; }
}

// --- Admin ---

async function handleOpenAdmin() {
    const view = document.getElementById('admin-view');
    view.classList.remove('hidden');
    try {
        const users = await api.getAdminUsers();
        renderAdminUsers(users, {
            onDeleteUser: async (id) => {
                if (confirm(`Delete user ${id}?`)) {
                    await api.deleteUser(id);
                    handleOpenAdmin();
                }
            },
            onToggleAdmin: async (id) => {
                await api.toggleUserAdmin(id);
                handleOpenAdmin();
            }
        });
    } catch (e) { showToast('Admin access denied or error.', 'error'); }
}

async function handleExportDb() {
    try {
        const blob = await api.exportDb();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'sheepvibes_backup.db';
        a.click();
        URL.revokeObjectURL(url);
    } catch (e) { showToast('Failed to export database.', 'error'); }
}

// --- Progress/OPML ---

async function handleRefreshAllFeeds() {
    showProgress('Refreshing feeds...');
    _startProgressFallback();
    try { await api.updateAllFeeds(); }
    catch (e) { showToast(e.message, 'error'); hideProgress(); _clearProgressFallback(); }
}

async function handleExportOpml() {
    try {
        const xml = await api.exportOpml();
        const blob = new Blob([xml], { type: 'application/xml' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = `sheepvibes_${currentUser.username}.opml`;
        a.click();
    } catch (e) { showToast('Export failed.', 'error'); }
}

async function handleImportOpmlFileSelect(e) {
    const file = e.target.files[0];
    if (!file) return;
    const fd = new FormData();
    fd.append('file', file);
    if (activeTabId) fd.append('tab_id', activeTabId);
    showProgress('Importing OPML...');
    _startProgressFallback();
    try {
        await api.importOpml(fd);
        await initializeTabs();
        // SSE will hide progress
    } catch (err) { showToast(err.message, 'error'); hideProgress(); }
    finally { e.target.value = ''; }
}

// --- Helpers ---

async function reloadTab(tabId) {
    if (activeTabId === tabId) {
        document.querySelectorAll(`.feed-widget[data-tab-id="${tabId}"]`).forEach(w => w.remove());
        loadedTabs.delete(tabId);
        await loadFeedsForTab(tabId);
    } else loadedTabs.delete(tabId);
}

function _startProgressFallback() {
    _clearProgressFallback();
    progressFallbackTimeoutId = setTimeout(() => { hideProgress(); }, PROGRESS_FALLBACK_TIMEOUT_MS);
}
function _clearProgressFallback() { if (progressFallbackTimeoutId) clearTimeout(progressFallbackTimeoutId); }

function initializeSSE() {
    const es = new EventSource(`${API_BASE_URL}/api/stream`);
    es.onmessage = async (e) => {
        try {
            const data = JSON.parse(e.data);
            if (data.type === 'progress') { _startProgressFallback(); updateProgress(data.status, data.value, data.max); }
            else if (data.type === 'progress_complete') { _clearProgressFallback(); hideProgress(); showToast(data.status || 'Done!', 'success'); }
            else if (data.new_items > 0) {
                showToast(`New items: ${data.new_items}`, 'info');
                allTabs = await api.getTabs();
                renderTabs(allTabs, activeTabId, { onSwitchTab: switchTab });
                (data.affected_tab_ids || []).forEach(id => { loadedTabs.delete(id); if (id == activeTabId) reloadTab(id); });
            }
        } catch (err) {}
    };
}
