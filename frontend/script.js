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
    const refreshAllFeedsButton = document.getElementById('refresh-all-feeds-button');
    
    // State variables
    let activeTabId = null; // ID of the currently selected tab
    let allTabs = []; // Cache of tab data fetched from the API
    const loadedTabs = new Set(); // Cache to track which tabs have been loaded

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

    // --- Real-Time Update Logic (SSE) ---

    /** Initializes the Server-Sent Events (SSE) connection to receive real-time updates. */
    async function initializeSSE() {
        console.log('Initializing SSE connection...');
        const eventSource = new EventSource('/api/stream');

        eventSource.onmessage = async (event) => {
            if (!event.data) return;
            
            try {
                const data = JSON.parse(event.data);
                console.log('SSE message received (feeds updated):', data);

                if (data.new_items > 0) {
                    console.log(`Feeds updated in background. Found ${data.new_items} new items. Refreshing UI.`);
                    // 1. Reload tab data to update unread counts on all tab buttons
                    await initializeTabs(true);

                    // 2. If the updated content affects a tab that is already loaded (specifically the active one),
                    // clear its content and reload it.
                    if (activeTabId && loadedTabs.has(activeTabId)) {
                        // Remove existing widgets for the active tab
                        document.querySelectorAll(`.feed-widget[data-tab-id="${activeTabId}"]`).forEach(w => w.remove());
                        loadedTabs.delete(activeTabId); // Mark tab as not loaded
                        await loadFeedsForTab(activeTabId); // Reload its content
                    }
                } else {
                    console.log('SSE update received: No new items found.');
                }
            } catch (e) {
                console.error('Error parsing SSE message data:', event.data, e);
            }
        };

        eventSource.onerror = (err) => {
            console.error('EventSource failed:', err);
        };
    }

    // --- Feed Refresh Logic ---

    /** Handles the click event for the "Refresh All Feeds" button. */
    async function handleRefreshAllFeeds() {
        console.log("Triggering refresh for all feeds...");
        const originalButtonText = refreshAllFeedsButton.textContent;
        refreshAllFeedsButton.disabled = true;
        refreshAllFeedsButton.textContent = 'Refreshing...';

        try {
            const result = await fetchData('/api/feeds/update-all', { method: 'POST' });

            if (result && result.message) {
                console.log('All feeds refresh triggered successfully:', result);
            } else if (result && result.error) {
                alert(`Failed to refresh all feeds: ${result.error}`);
                console.error('Error refreshing all feeds:', result.error);
            } else if (!result) {
                console.error('Failed to refresh all feeds. fetchData returned null.');
            }
        } catch (error) {
            console.error('Unexpected error in handleRefreshAllFeeds:', error);
            alert('An unexpected error occurred while refreshing feeds.');
        } finally {
            refreshAllFeedsButton.disabled = false;
            refreshAllFeedsButton.textContent = originalButtonText;
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
     * Renders a single feed widget and appends it to the main grid.
     * @param {object} feed - The feed object from the API (including unread_count and items).
     */
    function renderFeedWidget(feed) {
        const widget = document.createElement('div');
        widget.classList.add('feed-widget');
        widget.dataset.feedId = feed.id;
        widget.dataset.tabId = feed.tab_id; // Associate widget with a tab

        const deleteButton = document.createElement('button');
        deleteButton.classList.add('delete-feed-button');
        deleteButton.textContent = 'X';
        deleteButton.title = 'Delete Feed';
        deleteButton.addEventListener('click', (e) => {
            e.stopPropagation();
            handleDeleteFeed(feed.id);
        });
        widget.appendChild(deleteButton);

        const titleElement = document.createElement('h2');
        widget.appendChild(titleElement);
        
        const badge = createBadge(feed.unread_count);
        if (badge) {
            titleElement.appendChild(badge);
        }
        titleElement.prepend(feed.name);

        const itemList = document.createElement('ul');
        widget.appendChild(itemList);

        // Append the whole widget to the grid
        feedGrid.appendChild(widget);

        // Render items
        if (feed.items && feed.items.length > 0) {
            feed.items.forEach(item => {
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

                itemList.appendChild(listItem);
            });
        } else {
            itemList.innerHTML = '<li>No items found for this feed.</li>';
        }
    }

    /**
     * Loads and renders all feeds for a given tab ID.
     * @param {number} tabId - The ID of the tab to load feeds for.
     */
    async function loadFeedsForTab(tabId) {
        // Show a loading message only if the grid is completely empty
        if (feedGrid.children.length === 0) {
            feedGrid.innerHTML = '<p>Loading feeds...</p>';
        }

        const feedsWithItems = await fetchData(`/api/tabs/${tabId}/feeds`);

        // If we were showing a global loading message, clear it.
        if (feedGrid.querySelector('p')) {
            feedGrid.innerHTML = '';
        }

        if (feedsWithItems === null) {
            feedGrid.innerHTML = '<p>Error loading feeds. Please check the console or try again.</p>';
            return;
        }

        if (feedsWithItems && feedsWithItems.length > 0) {
            feedsWithItems.forEach(feed => {
                renderFeedWidget(feed);
            });
        } else if (feedGrid.children.length === 0) {
            // Only show 'no feeds' if the entire grid is empty after attempting to load
            feedGrid.innerHTML = '<p>No feeds found for this tab. Add one using the form above!</p>';
        }

        loadedTabs.add(tabId); // Mark this tab's content as loaded
    }

    // --- Tab Switching Logic ---

    /**
     * Sets the specified tab as active, loads its content if needed, and shows/hides widgets.
     * @param {number} tabId - The ID of the tab to activate.
     */
    async function setActiveTab(tabId) {
        activeTabId = tabId;

        // Update active class on tab buttons
        tabsContainer.querySelectorAll('button').forEach(button => {
            button.classList.toggle('active', button.dataset.tabId == tabId);
        });

        // Load content if it's not cached
        if (!loadedTabs.has(tabId)) {
            await loadFeedsForTab(tabId);
        }

        // Show/hide widgets based on the active tab
        feedGrid.querySelectorAll('.feed-widget').forEach(widget => {
            widget.style.display = widget.dataset.tabId == tabId ? 'block' : 'none';
        });

        deleteTabButton.disabled = allTabs.length <= 1;
    }

    /**
     * Switches the active tab.
     * @param {number} tabId - The ID of the tab to switch to.
     */
    function switchTab(tabId) {
        if (tabId !== activeTabId) {
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
            // Invalidate and reload the current tab to show the new feed
            if (loadedTabs.has(activeTabId)) {
                document.querySelectorAll(`.feed-widget[data-tab-id="${activeTabId}"]`).forEach(w => w.remove());
                loadedTabs.delete(activeTabId);
            }
            await setActiveTab(activeTabId); // Reload and display the current tab
            await initializeTabs(true); // Update unread counts
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
            await initializeTabs(true);
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
            return;
        }

        console.log(`Adding tab: ${newTabName}`);
        addTabButton.disabled = true;
        addTabButton.textContent = 'Adding...';

        const newTabData = await fetchData('/api/tabs', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name: newTabName.trim() }),
        });

        addTabButton.disabled = false;
        addTabButton.textContent = 'Add Tab';

        if (newTabData) {
            console.log('Tab added:', newTabData);
            await initializeTabs();
            await setActiveTab(newTabData.id);
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
            await initializeTabs(true);
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
            // Remove the deleted tab's widgets from the DOM
            document.querySelectorAll(`.feed-widget[data-tab-id="${activeTabId}"]`).forEach(w => w.remove());
            loadedTabs.delete(activeTabId);
            activeTabId = null;
            await initializeTabs();
        } else {
            console.error(`Failed to delete tab ${activeTabId}.`);
        }
    }

    // --- Initial Load ---

    /** 
     * Fetches the list of tabs from the API and renders them.
     * @param {boolean} [isUpdate=false] - If true, keeps the current active tab.
     */
    async function initializeTabs(isUpdate = false) {
        const currentActiveId = isUpdate ? activeTabId : null;
        const tabs = await fetchData('/api/tabs');
        if (tabs) {
            activeTabId = currentActiveId; // Restore active tab ID before rendering
            renderTabs(tabs);
        } else {
            renderTabs([]);
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
        refreshAllFeedsButton.addEventListener('click', handleRefreshAllFeeds);

        // Fetch initial tabs to start the application
        await initializeTabs();
        
        // Start listening for real-time updates from the server
        initializeSSE();
    }

    // Start the application initialization process
    initialize();
});
