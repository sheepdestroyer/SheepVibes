// Wait for the DOM to be fully loaded before executing script
document.addEventListener('DOMContentLoaded', () => {
    // Get references to key DOM elements
    const tabsContainer = document.getElementById('tabs-container');
    const feedGrid = document.getElementById('feed-grid');
    const addFeedButton = document.getElementById('add-feed-button');
    const feedUrlInput = document.getElementById('feed-url-input');
    const addTabButton = document.getElementById('add-tab-button');
    const renameTabButton = document.getElementById('rename-tab-button');
    const deleteTabButton = document.getElementById('delete-tab-button');
    
    // State variables
    let activeTabId = null; // ID of the currently selected tab
    let allTabs = []; // Cache of tab data fetched from the API
    let pollingIntervalId = null; // ID for the feed update polling interval
    const POLLING_INTERVAL_MS = 5 * 60 * 1000; // Poll feeds every 5 minutes

    // --- Helper Functions ---

    /**
     * Formats an ISO date string into a user-friendly relative or absolute time.
     * @param {string | null} isoString - The ISO date string to format.
     * @returns {string} A formatted date string (e.g., "5 min ago", "Apr 20, 2025").
     */
    function formatDate(isoString) {
        if (!isoString) return 'No date';
        try {
            const date = new Date(isoString);
            const now = new Date();
            const diffSeconds = Math.round((now - date) / 1000);
            const diffMinutes = Math.round(diffSeconds / 60);
            const diffHours = Math.round(diffMinutes / 60);
            const diffDays = Math.round(diffHours / 24);

            if (diffSeconds < 60) return `${diffSeconds} sec ago`;
            if (diffMinutes < 60) return `${diffMinutes} min ago`;
            if (diffHours < 24) return `${diffHours} hr ago`;
            if (diffDays <= 7) return `${diffDays} day(s) ago`;
            
            return date.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
        } catch (e) {
            console.error('Error formatting date:', isoString, e);
            return 'Invalid date';
        }
    }

    /**
     * Fetches data from the specified API endpoint.
     * Handles JSON parsing, error reporting, and different response types.
     * @param {string} url - The API endpoint URL.
     * @param {object} options - Optional fetch options (method, headers, body).
     * @returns {Promise<object|null>} A promise resolving to the JSON data, {success: true} for successful non-JSON responses, or null on failure.
     */
    async function fetchData(url, options = {}) {
        try {
            const response = await fetch(url, options);
            if (!response.ok) {
                let errorMsg = `HTTP error! status: ${response.status}`;
                try {
                    const errorData = await response.json();
                    if (errorData && errorData.error) {
                        errorMsg += `, message: ${errorData.error}`;
                    }
                } catch (e) {
                    errorMsg += `, message: ${response.statusText}`;
                }
                throw new Error(errorMsg);
            }
            if (response.status === 204 || response.headers.get('content-length') === '0') {
                return { success: true };
            }
            return await response.json();
        } catch (error) {
            console.error('Error fetching data:', error);
            alert(`Operation failed: ${error.message}`);
            return null;
        }
    }

    /**
     * Creates a span element for displaying unread counts if count > 0.
     * @param {number} count - The unread count.
     * @returns {HTMLSpanElement | null} The badge element or null.
     */
    function createBadge(count) {
        if (count > 0) {
            const badge = document.createElement('span');
            badge.classList.add('unread-count-badge');
            badge.textContent = count;
            return badge;
        }
        return null;
    }

    // --- Rendering Functions ---

    /**
     * Renders the tab buttons in the header.
     * @param {Array<object>} tabs - An array of tab objects from the API.
     */
    function renderTabs(tabs) {
        allTabs = tabs;
        tabsContainer.innerHTML = '';
        if (!tabs || tabs.length === 0) {
            tabsContainer.innerHTML = '<span>No tabs found.</span>';
            renameTabButton.disabled = true;
            deleteTabButton.disabled = true;
            activeTabId = null;
            feedGrid.innerHTML = '<p>Create a tab to get started!</p>';
            return;
        }

        tabs.sort((a, b) => a.order - b.order);

        let firstTabId = null;
        tabs.forEach((tab, index) => {
            const button = document.createElement('button');
            button.textContent = tab.name;
            button.dataset.tabId = tab.id;
            button.addEventListener('click', () => switchTab(tab.id));

            const badge = createBadge(tab.unread_count);
            if (badge) {
                button.appendChild(badge);
            }

            tabsContainer.appendChild(button);

            if (index === 0) {
                firstTabId = tab.id;
            }
        });

        renameTabButton.disabled = false;
        deleteTabButton.disabled = tabs.length <= 1;

        let tabToActivate = activeTabId;
        if (!tabToActivate || !tabs.some(t => t.id === tabToActivate)) {
            tabToActivate = firstTabId;
        }

        if (tabToActivate) {
            setActiveTab(tabToActivate);
        } else {
            activeTabId = null;
            feedGrid.innerHTML = '<p>Select a tab.</p>';
        }
    }

    /**
     * Renders a single feed widget or updates an existing one.
     * During updates, only prepends new items not already present.
     * @param {object} feed - The feed object from the API (including unread_count).
     * @param {Array<object>} items - An array of feed item objects from the API.
     * @param {boolean} [isUpdate=false] - Indicates if this is an update to an existing widget.
     */
    function renderFeedWidget(feed, items, isUpdate = false) {
        let widget = feedGrid.querySelector(`.feed-widget[data-feed-id="${feed.id}"]`);
        let itemList;
        let titleElement;

        if (widget) {
            // Widget exists, update title and items
            titleElement = widget.querySelector('h2');
            itemList = widget.querySelector('ul');
            // Don't clear innerHTML on update, we'll prepend new items
        } else {
            // Create new widget if it doesn't exist
            isUpdate = false; // Cannot be an update if widget is new
            widget = document.createElement('div');
            widget.classList.add('feed-widget');
            widget.dataset.feedId = feed.id;

            // ... (delete button setup) ...
            const deleteButton = document.createElement('button');
            deleteButton.classList.add('delete-feed-button');
            deleteButton.textContent = 'X';
            deleteButton.title = 'Delete Feed';
            deleteButton.addEventListener('click', (e) => {
                e.stopPropagation();
                handleDeleteFeed(feed.id);
            });
            widget.appendChild(deleteButton);

            titleElement = document.createElement('h2');
            widget.appendChild(titleElement);

            itemList = document.createElement('ul');
            widget.appendChild(itemList);

            // Prepend new widgets when added manually, append otherwise (e.g., initial load)
            // This logic might need refinement depending on desired order
            const prependWidget = document.getElementById('add-feed-button').disabled; // Heuristic: prepend if add button was just used
            if (prependWidget) {
                 feedGrid.prepend(widget);
            } else {
                 feedGrid.appendChild(widget);
            }
        }

        // Update title text and badge (remove old badge first)
        const oldBadge = titleElement.querySelector('.unread-count-badge');
        if(oldBadge) oldBadge.remove();
        titleElement.textContent = feed.name;
        const badge = createBadge(feed.unread_count);
        if (badge) {
            titleElement.appendChild(badge);
        }

        // Render items
        if (items && items.length > 0) {
            // Get IDs of items currently displayed in this widget
            const existingItemIds = new Set();
            if (isUpdate) {
                itemList.querySelectorAll('li[data-item-id]').forEach(li => {
                    existingItemIds.add(li.dataset.itemId);
                });
            }

            let prependedItemsCount = 0;
            items.forEach(item => {
                // If it's an update, only add items that are not already displayed
                if (isUpdate && existingItemIds.has(String(item.id))) {
                    return; // Skip already displayed item
                }

                // Create list item elements
                const listItem = document.createElement('li');
                listItem.dataset.itemId = item.id;
                listItem.classList.add(item.is_read ? 'read' : 'unread');

                const link = document.createElement('a');
                link.href = item.link;
                link.textContent = item.title;
                link.target = '_blank';
                link.addEventListener('click', () => handleMarkItemRead(item.id, listItem, feed.id, feed.tab_id));
                listItem.appendChild(link);

                const timestamp = document.createElement('span');
                timestamp.textContent = formatDate(item.published_time || item.fetched_time);
                listItem.appendChild(timestamp);

                // Prepend new items during updates, append otherwise
                if (isUpdate) {
                    itemList.prepend(listItem);
                    prependedItemsCount++;
                } else {
                    itemList.appendChild(listItem);
                }
            });

            if (isUpdate && prependedItemsCount > 0) {
                 console.log(`Prepended ${prependedItemsCount} new items to feed ${feed.id}`);
                 // Optional: Add visual indication of update?
            }

        } else if (!isUpdate) {
            // Only show "No items" message if it's not an update (i.e., initial render)
            itemList.innerHTML = '<li>No items found for this feed.</li>';
        }
    }

    /**
     * Loads and renders all feeds for a given tab ID.
     * @param {number} tabId - The ID of the tab to load feeds for.
     * @param {boolean} [isPollingUpdate=false] - Indicates if the call is from the polling mechanism.
     */
    async function loadFeedsForTab(tabId, isPollingUpdate = false) {
        if (!isPollingUpdate) {
            feedGrid.innerHTML = '<p>Loading feeds...</p>';
        }
        const feeds = await fetchData(`/api/tabs/${tabId}/feeds`);

        // Only clear the grid completely on initial load/tab switch, not during polling
        if (!isPollingUpdate) {
             feedGrid.innerHTML = '';
        }

        if (feeds === null && !isPollingUpdate) {
            feedGrid.innerHTML = '<p>Error loading feeds. Please check the console or try again.</p>';
            return;
        }

        if (feeds && feeds.length > 0) {
            // Sort feeds (optional, could be based on name, last update, etc.)
            // feeds.sort((a, b) => a.name.localeCompare(b.name));

            // Fetch items concurrently
            await Promise.all(feeds.map(async (feed) => {
                const items = await fetchData(`/api/feeds/${feed.id}/items?limit=10`); // Limit fetch
                if (items !== null) {
                    // Pass feed object and items. Pass `isPollingUpdate` to indicate if it's an update.
                    renderFeedWidget(feed, items, isPollingUpdate);
                }
            }));

            // Handle empty state only on initial load
            if (!isPollingUpdate && feedGrid.children.length === 0) {
                 feedGrid.innerHTML = '<p>Feeds loaded, but no items found or items failed to load.</p>';
            }
        } else if (!isPollingUpdate) {
            // No feeds found for the tab (not an error)
            feedGrid.innerHTML = '<p>No feeds found for this tab. Add one using the form above!</p>';
        }
        // If polling and feeds is null/empty, existing widgets are kept.
    }

    // --- Polling Logic ---

    /** Starts the periodic polling to check for feed updates for the active tab. */
    function startPolling() {
        stopPolling();
        if (activeTabId) {
            console.log(`Starting polling for tab ${activeTabId} every ${POLLING_INTERVAL_MS / 1000} seconds`);
            pollingIntervalId = setInterval(async () => {
                if (activeTabId) {
                    console.log(`Polling update for tab ${activeTabId}...`);
                    await loadFeedsForTab(activeTabId, true);
                }
            }, POLLING_INTERVAL_MS);
        } else {
            console.log("No active tab, polling not started.");
        }
    }

    /** Stops the periodic polling. */
    function stopPolling() {
        if (pollingIntervalId) {
            console.log("Stopping polling.");
            clearInterval(pollingIntervalId);
            pollingIntervalId = null;
        }
    }

    // --- Tab Switching Logic ---

    /**
     * Sets the specified tab as active, updates UI, loads its feeds, and starts polling.
     * @param {number} tabId - The ID of the tab to activate.
     */
    function setActiveTab(tabId) {
        if (activeTabId === tabId) return;

        activeTabId = tabId;
        const buttons = tabsContainer.querySelectorAll('button');
        buttons.forEach(button => {
            if (button.dataset.tabId == tabId) {
                button.classList.add('active');
            } else {
                button.classList.remove('active');
            }
        });
        deleteTabButton.disabled = allTabs.length <= 1;

        loadFeedsForTab(tabId, false).then(() => {
            startPolling();
        });
    }

    /**
     * Switches the active tab, stopping polling for the old tab first.
     * @param {number} tabId - The ID of the tab to switch to.
     */
    function switchTab(tabId) {
        if (tabId !== activeTabId) {
            stopPolling();
            setActiveTab(tabId);
        }
    }

    // --- Feed Management Logic ---

    /** Handles the click event for the "Add Feed" button. */
    async function handleAddFeed() {
        const url = feedUrlInput.value.trim();
        if (!url) {
            alert('Please enter a feed URL.');
            return;
        }
        if (!activeTabId) {
            alert('Please select a tab first.');
            return;
        }

        console.log(`Adding feed: ${url} to tab: ${activeTabId}`);
        addFeedButton.disabled = true;
        addFeedButton.textContent = 'Adding...';

        const newFeedData = await fetchData('/api/feeds', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: url, tab_id: activeTabId }),
        });

        addFeedButton.disabled = false;
        addFeedButton.textContent = 'Add Feed';

        if (newFeedData) {
            console.log('Feed added:', newFeedData);
            feedUrlInput.value = '';
            const items = await fetchData(`/api/feeds/${newFeedData.id}/items?limit=10`);
            if (items !== null) {
                if (feedGrid.querySelector('p')) {
                    feedGrid.innerHTML = '';
                }
                renderFeedWidget(newFeedData, items, true);
            }
            await initializeTabs();
        } else {
            console.error('Failed to add feed.');
        }
    }

    /**
     * Handles the click event for a feed widget's delete button.
     * @param {number} feedId - The ID of the feed to delete.
     */
    async function handleDeleteFeed(feedId) {
        if (!confirm('Are you sure you want to delete this feed?')) {
            return;
        }

        console.log(`Deleting feed: ${feedId}`);
        const widget = feedGrid.querySelector(`.feed-widget[data-feed-id="${feedId}"]`);
        if (widget) widget.style.opacity = '0.5';

        const result = await fetchData(`/api/feeds/${feedId}`, { method: 'DELETE' });

        if (result && result.success) {
            console.log(`Feed ${feedId} deleted successfully.`);
            if (widget) widget.remove();
            if (feedGrid.children.length === 0) {
                feedGrid.innerHTML = '<p>No feeds found for this tab. Add one using the form above!</p>';
            }
            await initializeTabs();
        } else {
            console.error(`Failed to delete feed ${feedId}.`);
            if (widget) widget.style.opacity = '1';
        }
    }

    // --- Mark Item as Read Logic ---

    /**
     * Handles the click event on a feed item link to mark it as read.
     * @param {number} itemId - The ID of the item to mark as read.
     * @param {HTMLElement} listItemElement - The <li> element of the item.
     * @param {number} feedId - The ID of the parent feed.
     * @param {number} tabId - The ID of the parent tab.
     */
    async function handleMarkItemRead(itemId, listItemElement, feedId, tabId) {
        if (listItemElement.classList.contains('unread')) {
            console.log(`Marking item ${itemId} as read`);
            const result = await fetchData(`/api/items/${itemId}/read`, { method: 'POST' });

            if (result && result.success) {
                console.log(`Successfully marked item ${itemId} as read.`);
                listItemElement.classList.remove('unread');
                listItemElement.classList.add('read');
                updateUnreadCount(feedId, -1);
                updateUnreadCount(tabId, -1, true);
            } else {
                console.error(`Failed to mark item ${itemId} as read.`);
            }
        }
    }

    /**
     * Updates the unread count badge for a given feed or tab.
     * @param {number} id - The ID of the feed or tab.
     * @param {number} change - The amount to change the count by (e.g., -1).
     * @param {boolean} [isTab=false] - Whether the ID refers to a tab.
     */
    function updateUnreadCount(id, change, isTab = false) {
        const selector = isTab ? `#tabs-container button[data-tab-id="${id}"]` : `.feed-widget[data-feed-id="${id}"] h2`;
        const element = document.querySelector(selector);
        if (!element) return;

        const badgeSelector = '.unread-count-badge';
        let badge = element.querySelector(badgeSelector);

        let currentCount = 0;
        if (badge) {
            currentCount = parseInt(badge.textContent) || 0;
        }

        const newCount = Math.max(0, currentCount + change);

        if (newCount > 0) {
            if (badge) {
                badge.textContent = newCount;
            } else {
                badge = createBadge(newCount);
                if (badge) {
                    element.appendChild(badge);
                }
            }
        } else {
            if (badge) {
                badge.remove();
            }
        }
    }

    // --- Tab Management Logic ---

    /** Handles the click event for the "Add Tab" button. */
    async function handleAddTab() {
        const newTabName = prompt('Enter the name for the new tab:');
        if (!newTabName || !newTabName.trim()) {
            alert('Tab name cannot be empty.');
            return;
        }

        console.log(`Adding tab: ${newTabName}`);
        const newTabData = await fetchData('/api/tabs', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name: newTabName.trim() }),
        });

        if (newTabData) {
            console.log('Tab added:', newTabData);
            stopPolling();
            await initializeTabs();
            setActiveTab(newTabData.id);
        } else {
            console.error('Failed to add tab.');
        }
    }

    /** Handles the click event for the "Rename Tab" button. */
    async function handleRenameTab() {
        if (!activeTabId) {
            alert('Please select a tab to rename.');
            return;
        }

        const currentTab = allTabs.find(t => t.id === activeTabId);
        const newTabName = prompt('Enter the new name for the tab:', currentTab ? currentTab.name : '');
        if (!newTabName || !newTabName.trim()) {
            alert('Tab name cannot be empty.');
            return;
        }
        if (currentTab && newTabName.trim() === currentTab.name) {
            return;
        }

        console.log(`Renaming tab ${activeTabId} to: ${newTabName}`);
        const updatedTabData = await fetchData(`/api/tabs/${activeTabId}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name: newTabName.trim() }),
        });

        if (updatedTabData) {
            console.log('Tab renamed:', updatedTabData);
            const tabButton = tabsContainer.querySelector(`button[data-tab-id="${activeTabId}"]`);
            if (tabButton) {
                const oldBadge = tabButton.querySelector('.unread-count-badge');
                if(oldBadge) oldBadge.remove();
                tabButton.textContent = updatedTabData.name;
                const badge = createBadge(updatedTabData.unread_count);
                if (badge) tabButton.appendChild(badge);
            }
            const tabIndex = allTabs.findIndex(t => t.id === activeTabId);
            if (tabIndex > -1) {
                allTabs[tabIndex].name = updatedTabData.name;
            }
        } else {
            console.error('Failed to rename tab.');
        }
    }

    /** Handles the click event for the "Delete Tab" button. */
    async function handleDeleteTab() {
        if (!activeTabId) {
            alert('Please select a tab to delete.');
            return;
        }
        if (allTabs.length <= 1) {
            alert('Cannot delete the last tab.');
            return;
        }

        const currentTab = allTabs.find(t => t.id === activeTabId);
        if (!confirm(`Are you sure you want to delete the tab "${currentTab ? currentTab.name : activeTabId}" and all its feeds?`)) {
            return;
        }

        console.log(`Deleting tab: ${activeTabId}`);
        const result = await fetchData(`/api/tabs/${activeTabId}`, { method: 'DELETE' });

        if (result && result.success) {
            console.log(`Tab ${activeTabId} deleted successfully.`);
            stopPolling();
            activeTabId = null;
            await initializeTabs();
        } else {
            console.error(`Failed to delete tab ${activeTabId}.`);
        }
    }

    // --- Initial Load ---

    /** Fetches the initial list of tabs from the API and renders them. */
    async function initializeTabs() {
        const tabs = await fetchData('/api/tabs');
        if (tabs) {
            renderTabs(tabs);
        } else {
            renderTabs([]);
            stopPolling();
        }
    }

    /** Main initialization function called on DOMContentLoaded. */
    async function initialize() {
        // Add event listeners for all interactive elements
        addTabButton.addEventListener('click', handleAddTab);
        renameTabButton.addEventListener('click', handleRenameTab);
        deleteTabButton.addEventListener('click', handleDeleteTab);
        addFeedButton.addEventListener('click', handleAddFeed);
        feedUrlInput.addEventListener('keypress', (event) => {
            if (event.key === 'Enter') {
                handleAddFeed();
            }
        });

        // Fetch initial tabs to start the application
        await initializeTabs();
        // Polling starts automatically when the first tab is activated within initializeTabs/renderTabs
    }

    // Add listener to stop polling when the user navigates away or closes the tab
    window.addEventListener('beforeunload', stopPolling);

    // Start the application initialization process
    initialize();
});
