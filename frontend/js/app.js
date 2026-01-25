import { api } from './api.js';
import {
    showToast,
    createFeedWidget,
    renderTabs,
    showEditFeedModal,
    closeEditFeedModal,
    appendItemsToFeedWidget
} from './ui.js';
import { throttle } from './utils.js';

// State
let activeTabId = parseInt(localStorage.getItem('activeTabId')) || null;
let allTabs = [];
const loadedTabs = new Set();
const ITEMS_PER_PAGE = 10;

// --- Initialization ---

document.addEventListener('DOMContentLoaded', async () => {
    // Setup event listeners
    document.getElementById('add-tab-button').addEventListener('click', handleAddTab);
    document.getElementById('rename-tab-button').addEventListener('click', handleRenameTab);
    document.getElementById('delete-tab-button').addEventListener('click', handleDeleteTab);
    document.getElementById('settings-button').addEventListener('click', toggleSettingsMenu);
    document.getElementById('add-feed-button').addEventListener('click', handleAddFeed);
    document.getElementById('refresh-all-feeds-button').addEventListener('click', handleRefreshAllFeeds);
    document.getElementById('export-opml-button').addEventListener('click', handleExportOpml);
    document.getElementById('import-opml-button').addEventListener('click', () => document.getElementById('opml-file-input').click());
    document.getElementById('opml-file-input').addEventListener('change', handleImportOpmlFileSelect);

    // Modal listeners
    document.getElementById('edit-feed-modal-close-button').addEventListener('click', closeEditFeedModal);
    document.getElementById('cancel-edit-button').addEventListener('click', closeEditFeedModal);
    document.getElementById('edit-feed-form').addEventListener('submit', handleEditFeedSubmit);

    // Initial load
    await initializeTabs();
    initializeSSE();

    // Close settings on click outside
    document.addEventListener('click', (event) => {
        const settingsMenu = document.getElementById('settings-menu');
        const settingsButton = document.getElementById('settings-button');
        if (!settingsMenu.classList.contains('hidden') &&
            !settingsMenu.contains(event.target) &&
            !settingsButton.contains(event.target)) {
            settingsMenu.classList.add('hidden');
        }
    });
});

// --- Core Logic ---

async function initializeTabs(preserveActive = false) {
    try {
        allTabs = await api.getTabs();

        // Validation: if activeTabId is no longer in valid tabs, reset it
        if (!allTabs.some(t => t.id === activeTabId)) {
            activeTabId = allTabs.length > 0 ? allTabs[0].id : null;
        }

        renderTabs(allTabs, activeTabId, { onSwitchTab: switchTab });

        if (activeTabId && !loadedTabs.has(activeTabId)) {
            await loadFeedsForTab(activeTabId);
        }
    } catch (error) {
        console.error('Error initializing tabs:', error);
        showToast('Failed to load tabs.', 'error');
    }
}

async function switchTab(tabId) {
    if (tabId === activeTabId) return;
    activeTabId = tabId;
    localStorage.setItem('activeTabId', tabId);

    // Update UI active state and re-render tabs logic
    renderTabs(allTabs, activeTabId, { onSwitchTab: switchTab });

    // Show/Hide widgets
    toggleWidgetsVisibility();

    // Load content if not loaded
    if (!loadedTabs.has(tabId)) {
        await loadFeedsForTab(tabId);
    }
}

function toggleWidgetsVisibility() {
    const feedGrid = document.getElementById('feed-grid');
    const widgets = feedGrid.querySelectorAll('.feed-widget');
    let hasVisible = false;

    // Hide all first
    widgets.forEach(widget => {
        if (widget.dataset.tabId == activeTabId) {
            widget.style.display = 'block';
            hasVisible = true;
        } else {
            widget.style.display = 'none';
        }
    });

    // Handle "empty" message visibility (simplified)
    // Ideally we would check if we HAVE feeds for this tab.
    // We loaded them in loadFeedsForTab.
    // If loadedTabs has it, but no widgets match -> empty.
}

async function loadFeedsForTab(tabId) {
    const feedGrid = document.getElementById('feed-grid');

    // If already loaded, just return (toggleWidgetsVisibility handles display)
    if (loadedTabs.has(tabId)) return;

    try {
        const feeds = await api.getFeedsForTab(tabId);

        // Remove ANY existing "no feeds" messages to be clean
        const placeholders = feedGrid.querySelectorAll('.empty-tab-message');
        placeholders.forEach(p => p.remove());

        if (feeds && feeds.length > 0) {
            feeds.forEach(feed => {
                const widget = createFeedWidget(feed, {
                    onEdit: (id, url, name) => showEditFeedModal(id, url, name),
                    onDelete: handleDeleteFeed,
                    onMarkItemRead: handleMarkItemRead,
                    onLoadMore: handleLoadMoreItems
                });
                feedGrid.appendChild(widget);
            });
        } else {
            const p = document.createElement('p');
            p.textContent = 'No feeds found for this tab. Add one using the form above!';
            // We can't attach dataset.tabId easily to a P in the generic grid without logic in toggle.
            // But for now, if grid is empty visually, it shows.
            // If we have other tabs' widgets hidden, this P might be visible always?
            // Fix: Only append if we are viewing this tab? Yes we are.
            // But if we switch tabs, this P remains?
            // Solution: Wrap the P in a div with tabId? 
            // Or simpler: Don't use persistent P, check on toggle.
            // For MVP refactor, assume toggle handles widgets, but p needs care.
            // Let's create a message container for this tab.
            const msg = document.createElement('div');
            msg.className = 'feed-widget empty-tab-message'; // Reuse class but add distinct marker
            msg.dataset.tabId = tabId;
            msg.innerHTML = '<p>No feeds found for this tab. Add one using the form above!</p>';
            feedGrid.appendChild(msg);
        }
        loadedTabs.add(tabId);
        toggleWidgetsVisibility();
    } catch (error) {
        console.error('Error loading feeds:', error);
        showToast('Failed to load feeds.', 'error');
    }
}

// --- Handlers ---

function toggleSettingsMenu() {
    document.getElementById('settings-menu').classList.toggle('hidden');
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
    const newName = prompt("Enter new name:", tab ? tab.name : "");
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
        await api.deleteTab(activeTabId);
        activeTabId = null;
        loadedTabs.clear();
        document.getElementById('feed-grid').innerHTML = '';
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
    try {
        const updatedFeed = await api.updateFeed(id, url);
        const oldWidget = document.querySelector(`.feed-widget[data-feed-id="${id}"]`);
        if (oldWidget) {
            const newWidget = createFeedWidget(updatedFeed, {
                onEdit: (fid, furl, fname) => showEditFeedModal(fid, furl, fname),
                onDelete: handleDeleteFeed,
                onMarkItemRead: handleMarkItemRead,
                onLoadMore: handleLoadMoreItems
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
    try {
        await api.updateAllFeeds();
        showToast('Refresh triggered. Updates will appear shortly.', 'success');
    } catch (e) {
        showToast('Failed to refresh: ' + e.message, 'error');
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
    if (activeTabId) formData.append('tab_id', activeTabId);

    try {
        const data = await api.importOpml(formData);
        showToast(data.message, 'success');
        if (data.imported_count > 0) {
            // Re-fetch tab data to update names and unread counts on all tab buttons.
            await initializeTabs();

            // Use the `affected_tab_ids` from the backend to perform a more targeted refresh.
            const tabsToReload = new Set(data.affected_tab_ids || []);
            if (data.tab_id) { // The default tab for loose feeds might also be affected.
                tabsToReload.add(data.tab_id);
            }

            for (const tabId of tabsToReload) {
                // If the tab is currently cached/loaded, refresh it.
                if (loadedTabs.has(tabId)) {
                    await reloadTab(tabId);
                }
            }
        }
    } catch (err) {
        showToast(err.message, 'error');
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

function updateUnreadCount(element) {
    if (!element) return;
    const badge = element.querySelector('.unread-count-badge');
    if (badge) {
        const newCount = parseInt(badge.textContent) - 1;
        if (newCount > 0) {
            badge.textContent = newCount;
        } else {
            badge.remove();
        }
    }
}

async function handleLoadMoreItems(listElement) {
    if (listElement.dataset.loading === 'true' || listElement.dataset.allItemsLoaded === 'true') return;

    listElement.dataset.loading = 'true';
    const feedId = listElement.dataset.feedId;
    const offset = parseInt(listElement.dataset.offset) || 0;

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

async function reloadTab(tabId) {
    if (activeTabId === tabId) {
        // Remove existing for this tab
        document.querySelectorAll(`.feed-widget[data-tab-id="${tabId}"]`).forEach(w => w.remove());
        loadedTabs.delete(tabId);
        await loadFeedsForTab(tabId);
    } else {
        loadedTabs.delete(tabId);
    }
}

function initializeSSE() {
    const eventSource = new EventSource('/api/stream');
    eventSource.onmessage = async (event) => {
        try {
            const data = JSON.parse(event.data);
            if (data.new_items > 0) {
                showToast(`Updates: ${data.new_items} new items`, 'info');

                // Re-fetch tab data to update unread counts on all tab buttons
                try {
                    allTabs = await api.getTabs();
                    renderTabs(allTabs, activeTabId, { onSwitchTab: switchTab });

                    // If the active tab's content is currently displayed, reload it in place
                    if (activeTabId && loadedTabs.has(activeTabId)) {
                        await reloadTab(activeTabId);
                    }

                    // Mark all other tabs as unloaded so they fetch fresh data when selected
                    const previouslyLoaded = Array.from(loadedTabs);
                    loadedTabs.clear();
                    if (activeTabId && previouslyLoaded.includes(activeTabId)) {
                        loadedTabs.add(activeTabId);
                    }
                } catch (err) {
                    console.error('Error updating UI after SSE:', err);
                }
            }
        } catch (e) { console.error(e); }
    };
}
