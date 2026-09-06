import { throttle, getStorageItem, setStorageItem, removeStorageItem } from './utils.js';
import { api, API_BASE_URL, setUnauthorizedHandler } from './api.js';
import { initAdminPanel } from './admin.js';
import {
    showToast,
    createFeedWidget,
    renderTabs,
    openEditFeedModal,
    showEditFeedModal,
    closeEditFeedModal,
    updateFeedWidgetTitle,
    showLoginModal,
    closeLoginModal,
    showSetupWizardModal,
    closeSetupWizardModal,
    showChangePasswordModal,
    closeChangePasswordModal,
    renderUserState,
    clearUserState,
    appendItemsToFeedWidget,
    showProgress,
    updateProgress,
    hideProgress,
    updateProgressBarPosition,
    updateUnreadCount
} from './ui.js';

const PROGRESS_FALLBACK_TIMEOUT_MS = 15000;
let progressFallbackTimeoutId = null;

// Immediate Night Mode application to prevent FOUC
if (getStorageItem('nightMode') === 'enabled') {
    if (document.body) {
        document.body.classList.add('night-mode');
    } else {
        document.addEventListener('DOMContentLoaded', () => {
            if (document.body) document.body.classList.add('night-mode');
        });
    }
}

// State
let currentUser = null;
const storedTabId = getStorageItem('activeTabId');
const parsedTabId = storedTabId !== null ? parseInt(storedTabId, 10) : NaN;
let activeTabId = !isNaN(parsedTabId) ? parsedTabId : null;
let allTabs = [];
const loadedTabs = new Set();
const ITEMS_PER_PAGE = 10;
let eventSourceInstance = null;

// --- Progress Fallback Helpers ---

function _startProgressFallback() {
    _clearProgressFallback();
    progressFallbackTimeoutId = setTimeout(() => {
        console.warn('Progress SSE timeout reached. Hiding progress bar.');
        hideProgress();
        progressFallbackTimeoutId = null;
    }, PROGRESS_FALLBACK_TIMEOUT_MS);
}

function _clearProgressFallback() {
    if (progressFallbackTimeoutId) {
        clearTimeout(progressFallbackTimeoutId);
        progressFallbackTimeoutId = null;
    }
}

// --- Initialization ---

document.addEventListener('DOMContentLoaded', async () => {
    // Night Mode initialization
    const nightModeEnabled = getStorageItem('nightMode') === 'enabled';
    const nightModeSwitch = document.getElementById('night-mode-switch');
    if (nightModeSwitch) {
        nightModeSwitch.checked = nightModeEnabled;
        nightModeSwitch.setAttribute('aria-checked', nightModeEnabled ? 'true' : 'false');
        nightModeSwitch.addEventListener('change', handleNightModeToggle);
    }
    if (nightModeEnabled && document.body) {
        document.body.classList.add('night-mode');
    }

    // Setup tab and feed event listeners
    document.getElementById('add-tab-button')?.addEventListener('click', handleAddTab);
    document.getElementById('rename-tab-button')?.addEventListener('click', handleRenameTab);
    document.getElementById('delete-tab-button')?.addEventListener('click', handleDeleteTab);
    document.getElementById('settings-button')?.addEventListener('click', toggleSettingsMenu);
    document.getElementById('add-feed-button')?.addEventListener('click', handleAddFeed);
    document.getElementById('refresh-all-feeds-button')?.addEventListener('click', handleRefreshAllFeeds);
    document.getElementById('export-opml-button')?.addEventListener('click', handleExportOpml);
    document.getElementById('import-opml-button')?.addEventListener('click', () => document.getElementById('opml-file-input')?.click());
    document.getElementById('opml-file-input')?.addEventListener('change', handleImportOpmlFileSelect);

    // User and Auth event listeners
    document.getElementById('user-button')?.addEventListener('click', toggleUserMenu);
    document.getElementById('logout-button')?.addEventListener('click', handleLogout);
    document.getElementById('change-password-button')?.addEventListener('click', () => {
        document.getElementById('user-menu')?.classList.add('hidden');
        showChangePasswordModal();
    });
    document.getElementById('setup-wizard-form')?.addEventListener('submit', handleSetupWizardSubmit);
    document.getElementById('login-form')?.addEventListener('submit', handleLoginSubmit);
    document.getElementById('change-password-form')?.addEventListener('submit', handleChangePasswordSubmit);
    document.getElementById('change-password-modal-close-button')?.addEventListener('click', closeChangePasswordModal);
    document.getElementById('change-password-cancel-button')?.addEventListener('click', closeChangePasswordModal);

    // Edit Feed Modal listeners
    document.getElementById('edit-feed-modal-close-button')?.addEventListener('click', closeEditFeedModal);
    document.getElementById('cancel-edit-button')?.addEventListener('click', closeEditFeedModal);
    document.getElementById('edit-feed-form')?.addEventListener('submit', handleEditFeedSubmit);

    // Initialize Admin Panel
    initAdminPanel();

    // Register 401 unauthorized interceptor
    setUnauthorizedHandler(handleUnauthorized);

    // Close menus on click outside
    document.addEventListener('click', (event) => {
        const settingsMenu = document.getElementById('settings-menu');
        const settingsButton = document.getElementById('settings-button');
        if (settingsMenu && settingsButton &&
            !settingsMenu.classList.contains('hidden') &&
            !settingsMenu.contains(event.target) &&
            !settingsButton.contains(event.target)) {
            settingsMenu.classList.add('hidden');
            settingsButton.setAttribute('aria-expanded', 'false');
        }

        const userMenu = document.getElementById('user-menu');
        const userButton = document.getElementById('user-button');
        if (userMenu && userButton &&
            !userMenu.classList.contains('hidden') &&
            !userMenu.contains(event.target) &&
            !userButton.contains(event.target)) {
            userMenu.classList.add('hidden');
            userButton.setAttribute('aria-expanded', 'false');
        }
    });

    // Verify session & initial load
    await checkAuthAndInitialize();
    updateProgressBarPosition();
    window.addEventListener('resize', updateProgressBarPosition);
});

// --- Auth & Session Logic ---

async function checkAuthAndInitialize() {
    try {
        const authStatus = await api.getAuthStatus();
        if (authStatus && authStatus.setup_required) {
            closeLoginModal();
            showSetupWizardModal();
            return;
        }

        if (authStatus && authStatus.authenticated && authStatus.user) {
            currentUser = authStatus.user;
            renderUserState(currentUser);
            closeLoginModal();
            closeSetupWizardModal();
            await initializeTabs();
            initializeSSE();
        } else {
            handleUnauthorized();
        }
    } catch (e) {
        handleUnauthorized();
    }
}

async function handleSetupWizardSubmit(e) {
    e.preventDefault();
    const usernameInput = document.getElementById('setup-username');
    const emailInput = document.getElementById('setup-email');
    const passwordInput = document.getElementById('setup-password');
    const confirmInput = document.getElementById('setup-password-confirm');
    const submitButton = document.getElementById('setup-wizard-submit-button');

    const username = usernameInput.value.trim();
    const email = emailInput.value.trim() || null;
    const password = passwordInput.value;
    const confirmPassword = confirmInput.value;

    if (password !== confirmPassword) {
        showSetupWizardModal('Passwords do not match.');
        return;
    }

    if (password.length < 8) {
        showSetupWizardModal('Password must be at least 8 characters long.');
        return;
    }

    submitButton.disabled = true;
    submitButton.textContent = 'Setting up...';

    try {
        const result = await api.setupMasterAdmin({ username, email, password });
        currentUser = result.user;
        renderUserState(currentUser);
        closeSetupWizardModal();
        showToast(`Welcome to SheepVibes, Administrator ${currentUser.username}!`, 'success');
        await initializeTabs();
        initializeSSE();
    } catch (err) {
        const errorMsg = err.backendMessage || 'Failed to complete setup.';
        showSetupWizardModal(errorMsg);
    } finally {
        submitButton.disabled = false;
        submitButton.textContent = 'Complete Setup & Launch';
    }
}

function handleUnauthorized() {
    currentUser = null;
    activeTabId = null;
    allTabs = [];
    loadedTabs.clear();
    clearUserState();
    if (eventSourceInstance) {
        eventSourceInstance.close();
        eventSourceInstance = null;
    }
    document.getElementById('feed-grid').innerHTML = '';
    renderTabs([], null, {});
    closeSetupWizardModal();
    showLoginModal();
}

async function handleLoginSubmit(e) {
    e.preventDefault();
    const usernameInput = document.getElementById('login-username');
    const passwordInput = document.getElementById('login-password');
    const submitButton = document.getElementById('login-submit-button');

    const username = usernameInput.value.trim();
    const password = passwordInput.value;

    if (!username || !password) {
        showLoginModal('Please enter both username and password.');
        return;
    }

    submitButton.disabled = true;
    submitButton.textContent = 'Logging in...';

    try {
        const result = await api.login(username, password);
        currentUser = result.user;
        renderUserState(currentUser);
        closeLoginModal();
        showToast(`Welcome back, ${currentUser.username}!`, 'success');
        await initializeTabs();
        initializeSSE();
    } catch (err) {
        const errorMsg = err.backendMessage || 'Invalid username or password.';
        showLoginModal(errorMsg);
    } finally {
        submitButton.disabled = false;
        submitButton.textContent = 'Log In';
    }
}

async function handleLogout() {
    try {
        await api.logout();
    } catch (e) {
        console.error('Logout error:', e);
    } finally {
        handleUnauthorized();
        showToast('Logged out successfully.', 'info');
    }
}

async function handleChangePasswordSubmit(e) {
    e.preventDefault();
    const currentPasswordInput = document.getElementById('change-password-current');
    const newPasswordInput = document.getElementById('change-password-new');
    const confirmPasswordInput = document.getElementById('change-password-confirm');
    const submitButton = document.getElementById('change-password-submit-button');

    const currentPassword = currentPasswordInput.value;
    const newPassword = newPasswordInput.value;
    const confirmPassword = confirmPasswordInput.value;

    if (newPassword !== confirmPassword) {
        showChangePasswordModal('New passwords do not match.');
        return;
    }

    if (newPassword.length < 8) {
        showChangePasswordModal('New password must be at least 8 characters long.');
        return;
    }

    submitButton.disabled = true;
    submitButton.textContent = 'Updating...';

    try {
        await api.changePassword(currentPassword, newPassword);
        document.getElementById('change-password-form')?.reset();
        showChangePasswordModal(null, 'Password updated successfully!', true);
        showToast('Password updated successfully.', 'success');
        setTimeout(() => {
            closeChangePasswordModal();
        }, 1200);
    } catch (err) {
        const errorMsg = err.backendMessage || 'Failed to update password.';
        showChangePasswordModal(errorMsg);
    } finally {
        submitButton.disabled = false;
        submitButton.textContent = 'Update Password';
    }
}

function toggleUserMenu() {
    const menu = document.getElementById('user-menu');
    const button = document.getElementById('user-button');
    if (!menu) return;
    const isHidden = menu.classList.toggle('hidden');
    if (button) {
        button.setAttribute('aria-expanded', isHidden ? 'false' : 'true');
    }
}

// --- Core Logic ---

async function initializeTabs() {
    try {
        allTabs = await api.getTabs();

        if (!allTabs.some(t => t.id === activeTabId)) {
            activeTabId = allTabs.length > 0 ? allTabs[0].id : null;
        }

        renderTabs(allTabs, activeTabId, {
            onSwitchTab: switchTab,
            onMoveFeedToTab: handleMoveFeedToTab
        });

        if (activeTabId) {
            if (!loadedTabs.has(activeTabId)) {
                await loadFeedsForTab(activeTabId);
            } else {
                toggleWidgetsVisibility();
            }
        }
    } catch (error) {
        console.error('Error initializing tabs:', error);
        if (currentUser) {
            showToast('Failed to load tabs.', 'error');
        }
    }
}

async function switchTab(tabId) {
    if (tabId === activeTabId) return;
    activeTabId = tabId;
    setStorageItem('activeTabId', tabId);

    renderTabs(allTabs, activeTabId, {
        onSwitchTab: switchTab,
        onMoveFeedToTab: handleMoveFeedToTab
    });
    toggleWidgetsVisibility();

    if (!loadedTabs.has(tabId)) {
        await loadFeedsForTab(tabId);
    }
}

function toggleWidgetsVisibility() {
    const feedGrid = document.getElementById('feed-grid');
    const widgets = feedGrid.querySelectorAll('.feed-widget');

    widgets.forEach(widget => {
        if (widget.dataset.tabId == activeTabId) {
            widget.classList.remove('hidden');
        } else {
            widget.classList.add('hidden');
        }
    });
}

async function loadFeedsForTab(tabId) {
    const feedGrid = document.getElementById('feed-grid');
    if (loadedTabs.has(tabId)) return;

    try {
        const feeds = await api.getFeedsForTab(tabId);

        const placeholders = feedGrid.querySelectorAll(
            `.empty-tab-message[data-tab-id="${tabId}"]`
        );
        placeholders.forEach(p => p.remove());

        if (feeds && feeds.length > 0) {
            feeds.forEach(feed => {
                const widget = createFeedWidget(feed, {
                    onEdit: (id, url, name) => openEditFeedModal(id, url, name),
                    onDelete: handleDeleteFeed,
                    onMarkItemRead: handleMarkItemRead,
                    onLoadMore: handleLoadMoreItems,
                    onReorderFeeds: handleReorderFeeds,
                    onMoveFeedToTab: handleMoveFeedToTab
                });
                feedGrid.appendChild(widget);
            });
        } else {
            const msg = document.createElement('div');
            msg.className = 'feed-widget empty-tab-message';
            msg.dataset.tabId = tabId;
            msg.innerHTML = '<p>No feeds found for this tab. Add one using the form above!</p>';
            feedGrid.appendChild(msg);
        }
        loadedTabs.add(tabId);
        toggleWidgetsVisibility();
    } catch (error) {
        console.error('Error loading feeds:', error);
        if (currentUser) {
            showToast('Failed to load feeds.', 'error');
        }
    }
}

// --- Handlers ---

function toggleSettingsMenu() {
    const menu = document.getElementById('settings-menu');
    const button = document.getElementById('settings-button');
    if (!menu) return;
    const isHidden = menu.classList.toggle('hidden');
    if (button) {
        button.setAttribute('aria-expanded', isHidden ? 'false' : 'true');
    }
}

async function handleAddTab() {
    const name = prompt("Enter new tab name:");
    if (!name) return;
    try {
        await api.createTab(name);
        await initializeTabs();
        showToast('Tab created!', 'success');
    } catch (e) {
        showToast(e.message, 'error');
    }
}

async function handleRenameTab() {
    if (!activeTabId) return;
    const tab = allTabs.find(t => t.id === activeTabId);
    if (!tab) return;
    const newName = prompt("Enter new name:", tab.name);
    if (!newName || newName === tab.name) return;

    try {
        await api.updateTab(activeTabId, newName);
        await initializeTabs();
        showToast('Tab renamed.', 'success');
    } catch (e) {
        showToast(e.message, 'error');
    }
}

async function handleDeleteTab() {
    if (!activeTabId || !confirm("Delete this tab and all its feeds?")) return;
    try {
        const deletedTabId = activeTabId;
        await api.deleteTab(deletedTabId);

        document.querySelectorAll(`.feed-widget[data-tab-id="${deletedTabId}"]`).forEach(w => w.remove());
        loadedTabs.delete(deletedTabId);
        activeTabId = null;
        removeStorageItem('activeTabId');

        await initializeTabs();
        showToast('Tab deleted.', 'success');
    } catch (e) {
        showToast(e.message, 'error');
    }
}

async function handleAddFeed() {
    const urlInput = document.getElementById('feed-url-input');
    const url = urlInput.value.trim();
    if (!url) {
        showToast('Please enter a URL', 'error');
        return;
    }
    if (!activeTabId) {
        showToast('No active tab selected', 'error');
        return;
    }

    const btn = document.getElementById('add-feed-button');
    const originalText = btn.textContent;
    btn.textContent = 'Adding...';
    btn.disabled = true;

    try {
        await api.addFeed(url, activeTabId);
        urlInput.value = '';
        showToast('Feed added!', 'success');
        await reloadTab(activeTabId);
    } catch (e) {
        showToast(e.message, 'error');
    } finally {
        btn.textContent = originalText;
        btn.disabled = false;
    }
}

async function handleDeleteFeed(feedId) {
    if (!confirm("Delete feed?")) return;
    try {
        await api.deleteFeed(feedId);
        const widget = document.querySelector(`.feed-widget[data-feed-id="${feedId}"]`);
        if (widget) widget.remove();
        showToast('Feed deleted.', 'success');
    } catch (e) {
        showToast(e.message, 'error');
    }
}

async function handleEditFeedSubmit(e) {
    e.preventDefault();
    const id = document.getElementById('edit-feed-id').value;
    const url = document.getElementById('edit-feed-url').value;
    const name = document.getElementById('edit-feed-name').value;
    try {
        const updatedFeed = await api.updateFeed(id, { url, name });
        updateFeedWidgetTitle(id, updatedFeed.name, updatedFeed.site_link);
        const oldWidget = document.querySelector(`.feed-widget[data-feed-id="${id}"]`);
        if (oldWidget) {
            const newWidget = createFeedWidget(updatedFeed, {
                onEdit: (fid, furl, fname) => openEditFeedModal(fid, furl, fname),
                onDelete: handleDeleteFeed,
                onMarkItemRead: handleMarkItemRead,
                onLoadMore: handleLoadMoreItems,
                onReorderFeeds: handleReorderFeeds,
                onMoveFeedToTab: handleMoveFeedToTab
            });
            oldWidget.replaceWith(newWidget);
        }
        closeEditFeedModal();
        showToast('Feed updated.', 'success');
    } catch (err) {
        showToast(err.message, 'error');
    }
}

async function handleRefreshAllFeeds() {
    showProgress('Starting feed refresh...');
    _startProgressFallback();
    try {
        await api.updateAllFeeds();
    } catch (e) {
        showToast('Failed to refresh: ' + e.message, 'error');
        _clearProgressFallback();
        hideProgress();
    }
}

async function handleExportOpml() {
    try {
        const xml = await api.exportOpml();
        const blob = new Blob([xml], { type: 'application/xml' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'sheepvibes_feeds.opml';
        a.rel = 'noopener noreferrer';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    } catch (e) {
        showToast(e.message, 'error');
    }
}

async function handleImportOpmlFileSelect(e) {
    const file = e.target.files[0];
    if (!file) return;

    const formData = new FormData();
    formData.append('file', file);
    if (activeTabId !== null) formData.append('tab_id', activeTabId);

    showProgress('Importing OPML file...');
    _startProgressFallback();
    try {
        const data = await api.importOpml(formData);
        await initializeTabs();

        if (data.imported_count > 0) {
            const tabsToReload = new Set(data.affected_tab_ids || []);
            if (data.tab_id) {
                tabsToReload.add(data.tab_id);
            }
            for (const tabId of tabsToReload) {
                if (loadedTabs.has(tabId)) {
                    await reloadTab(tabId);
                }
            }
        }
    } catch (err) {
        showToast(err.message, 'error');
        _clearProgressFallback();
        hideProgress();
    } finally {
        e.target.value = '';
    }
}

async function handleMarkItemRead(itemId, liElement, feedId, tabId) {
    if (liElement.classList.contains('read')) return;
    try {
        await api.markItemRead(itemId);
        liElement.classList.replace('unread', 'read');
        updateUnreadCount(liElement.closest('.feed-widget'));
        updateUnreadCount(document.querySelector(`button[data-tab-id="${tabId}"]`));
    } catch (e) {
        console.error('Failed to mark read', e);
    }
}

async function handleLoadMoreItems(listElement) {
    if (listElement.dataset.loading === 'true' || listElement.dataset.allItemsLoaded === 'true') return;

    listElement.dataset.loading = 'true';
    const feedId = listElement.dataset.feedId;
    const offset = parseInt(listElement.dataset.offset, 10) || 0;

    try {
        const items = await api.getFeedItems(feedId, offset, ITEMS_PER_PAGE);
        if (items && items.length > 0) {
            appendItemsToFeedWidget(listElement, items, {
                onMarkItemRead: handleMarkItemRead
            });
        } else {
            listElement.dataset.allItemsLoaded = 'true';
        }
    } catch (e) {
        console.error(e);
    } finally {
        listElement.dataset.loading = 'false';
    }
}

// Helpers

async function handleReorderFeeds(tabId, feedIds) {
    try {
        await api.reorderTabFeeds(tabId, feedIds);
        showToast('Feeds reordered!', 'info');
    } catch (error) {
        console.error('Error reordering feeds:', error);
        showToast('Failed to save feed order.', 'error');
        await reloadTab(tabId);
    }
}

async function handleMoveFeedToTab(feedId, targetTabId) {
    try {
        await api.moveFeedToTab(feedId, targetTabId);
        showToast('Feed moved to tab!', 'success');

        const feedGrid = document.getElementById('feed-grid');
        const widget = feedGrid ? feedGrid.querySelector(`.feed-widget[data-feed-id="${feedId}"]`) : null;
        const sourceTabId = widget ? parseInt(widget.dataset.tabId, 10) : activeTabId;

        if (widget) {
            widget.remove();
        }

        loadedTabs.delete(sourceTabId);
        loadedTabs.delete(targetTabId);

        if (feedGrid) {
            const remainingWidgets = feedGrid.querySelectorAll(`.feed-widget[data-tab-id="${sourceTabId}"]`);
            if (remainingWidgets.length === 0) {
                const msg = document.createElement('div');
                msg.className = 'feed-widget empty-tab-message';
                msg.dataset.tabId = sourceTabId;
                msg.innerHTML = '<p>No feeds found for this tab. Add one using the form above!</p>';
                feedGrid.appendChild(msg);
            }
        }

        allTabs = await api.getTabs();
        await switchTab(targetTabId);
    } catch (error) {
        console.error('Error moving feed to tab:', error);
        showToast('Failed to move feed to tab.', 'error');
    }
}

async function reloadTab(tabId) {
    if (activeTabId === tabId) {
        document.querySelectorAll(`.feed-widget[data-tab-id="${tabId}"]`).forEach(w => w.remove());
        loadedTabs.delete(tabId);
        await loadFeedsForTab(tabId);
    } else {
        loadedTabs.delete(tabId);
    }
}

function initializeSSE() {
    if (eventSourceInstance) {
        eventSourceInstance.close();
    }
    eventSourceInstance = new EventSource(`${API_BASE_URL}/api/stream`);

    eventSourceInstance.onmessage = async (event) => {
        try {
            const data = JSON.parse(event.data);

            if (data.type === 'progress') {
                _startProgressFallback();
                updateProgress(data.status, data.value, data.max);
                return;
            }
            if (data.type === 'progress_complete') {
                _clearProgressFallback();
                hideProgress();
                showToast(data.status || 'Operation complete!', 'success');
                return;
            }

            if (data.new_items > 0) {
                showToast(`Updates: ${data.new_items} new items`, 'info');
                allTabs = await api.getTabs();
                renderTabs(allTabs, activeTabId, {
                    onSwitchTab: switchTab,
                    onMoveFeedToTab: handleMoveFeedToTab
                });

                const affectedIds = data.affected_tab_ids || [];
                affectedIds.forEach(id => {
                    loadedTabs.delete(id);
                });

                if (activeTabId && affectedIds.includes(activeTabId)) {
                    await reloadTab(activeTabId);
                }
            }
        } catch (e) {
            console.error('SSE message parsing failed:', e);
        }
    };

    eventSourceInstance.onerror = (err) => {
        console.error('SSE connection failed:', err);
    };
}

function handleNightModeToggle(e) {
    const isChecked = e.target.checked;
    e.target.setAttribute('aria-checked', isChecked ? 'true' : 'false');
    if (isChecked) {
        document.body.classList.add('night-mode');
        setStorageItem('nightMode', 'enabled');
    } else {
        document.body.classList.remove('night-mode');
        setStorageItem('nightMode', 'disabled');
    }
}
