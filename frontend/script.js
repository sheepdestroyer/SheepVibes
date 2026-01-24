// Wait for the DOM to be fully loaded before executing script
document.addEventListener('DOMContentLoaded', () => {
    // API configuration
    // Derive base URL from current location, with optional configurable override.
    // This avoids CORS issues when frontend and API share an origin, but still supports
    // non-standard deployments (different host/port/path) via configuration.
    const API_BASE_URL =
        // Highest priority: explicit config object if provided
        (window.APP_CONFIG && window.APP_CONFIG.API_BASE_URL) ||
        // Next: global override (e.g. set in HTML before this script)
        window.API_BASE_URL ||
        // Fallback: relative path (same origin)
        '';

    // Get references to key DOM elements
    const tabsContainer = document.getElementById('tabs-container');
    const feedGrid = document.getElementById('feed-grid');
    const addFeedButton = document.getElementById('add-feed-button');
    const feedUrlInput = document.getElementById('feed-url-input');
    const addTabButton = document.getElementById('add-tab-button');
    const renameTabButton = document.getElementById('rename-tab-button');
    const deleteTabButton = document.getElementById('delete-tab-button');
    const refreshAllFeedsButton = document.getElementById('refresh-all-feeds-button');
    const exportOpmlButton = document.getElementById('export-opml-button');
    const importOpmlButton = document.getElementById('import-opml-button');
    const opmlFileInput = document.getElementById('opml-file-input');
    const settingsButton = document.getElementById('settings-button');
    const settingsMenu = document.getElementById('settings-menu');

    // State variables
    let activeTabId = null; // ID of the currently selected tab
    let allTabs = []; // Cache of tab data fetched from the API
    const loadedTabs = new Set(); // Cache to track which tabs have been loaded


    // --- Toast Notification Functions ---

    /**
     * Displays a toast notification.
     * @param {string} message The message to display.
     * @param {string} [type='info'] The type of toast ('success', 'error', 'info').
     * @param {number} [duration=3000] The duration in milliseconds.
     */
    function showToast(message, type = 'info', duration = 3000) {
        const toastContainer = document.getElementById('toast-container');
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.textContent = message;

        toastContainer.appendChild(toast);

        // Animate in
        setTimeout(() => {
            toast.classList.add('show');
        }, 100);

        // Animate out and remove
        setTimeout(() => {
            toast.classList.remove('show');
            const removalTimeout = setTimeout(() => toast.remove(), 500); // 500ms > 0.3s transition in CSS
            toast.addEventListener('transitionend', () => {
                clearTimeout(removalTimeout);
                toast.remove();
            }, { once: true });
        }, duration);
    }

    // --- Helper Functions ---

    // Constants for infinite scrolling
    const SCROLL_BUFFER = 20; // pixels from bottom to trigger loading
    const ITEMS_PER_PAGE = 10; // number of items to load per scroll
    const SCROLL_THROTTLE_DELAY = 200; // milliseconds to throttle scroll events

    /**
     * A simple throttle utility function to limit function execution frequency.
     * @param {function} callback - The function to throttle.
     * @param {number} delay - The delay in milliseconds between executions.
     * @returns {function} The throttled function.
     */
    function throttle(callback, delay) {
        let isThrottled = false;
        return function (...args) {
            if (!isThrottled) {
                callback.apply(this, args);
                isThrottled = true;
                setTimeout(() => {
                    isThrottled = false;
                }, delay);
            }
        };
    }

    /**
     * Creates a list item element for a feed item.
     * @param {object} item - The feed item object.
     * @param {function} clickHandler - The function to execute on link click.
     * @returns {HTMLLIElement} The created list item element.
     */
    function createFeedItemElement(item, clickHandler) {
        const listItem = document.createElement('li');
        listItem.dataset.itemId = item.id;
        listItem.classList.add(item.is_read ? 'read' : 'unread');

        const link = document.createElement('a');
        link.href = item.link;
        link.textContent = item.title;
        link.target = '_blank';
        link.addEventListener('click', () => clickHandler(listItem));
        listItem.appendChild(link);

        const timestamp = document.createElement('span');
        timestamp.textContent = formatDate(item.published_time || item.fetched_time);
        listItem.appendChild(timestamp);

        return listItem;
    }

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

    /**
     * Initializes the Server-Sent Events (SSE) connection to receive real-time updates.
     */
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

    /**
     * Handles the click event for the "Refresh All Feeds" button.
     */
    async function handleRefreshAllFeeds() {
        console.log("Triggering refresh for all feeds...");
        const originalButtonText = refreshAllFeedsButton.textContent;
        refreshAllFeedsButton.disabled = true;
        refreshAllFeedsButton.textContent = 'Refreshing...';

        try {
            const result = await fetchData('/api/feeds/update-all', { method: 'POST' });

            if (result && result.message) {
                console.log('All feeds refresh triggered successfully:', result);
            }
        } catch (error) {
            console.error('Error in handleRefreshAllFeeds:', error);
            const displayMessage = error.backendMessage || error.message || 'An unexpected error occurred while refreshing feeds.';
            showToast(`Failed to refresh all feeds: ${displayMessage}`, 'error');
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
            const response = await fetch(`${API_BASE_URL}${url}`, options);
            if (!response.ok) {
                const error = new Error(`HTTP error! status: ${response.status}`);
                try {
                    const errorData = await response.json();
                    if (errorData && errorData.error) {
                        error.backendMessage = errorData.error; // Attach structured data
                        error.message += `, message: ${errorData.error}`; // Keep original message for logging
                    }
                } catch (e) {
                    error.message += `, message: ${response.statusText}`;
                }
                throw error;
            }
            if (response.status === 204 || response.headers.get('content-length') === '0') {
                return { success: true };
            }
            return await response.json();
        } catch (error) {
            console.error('Error fetching data:', error);
            throw error; // Re-throw the error instead of returning null
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

    // --- OPML Export/Import Functions ---

    /**
     * Handles the click event for the "Export OPML" button.
     */
    async function handleExportOpml() {
        console.log("Exporting OPML...");
        const originalButtonText = exportOpmlButton.textContent;
        exportOpmlButton.disabled = true;
        exportOpmlButton.textContent = 'Exporting...';

        try {
            const response = await fetch('/api/opml/export');
            if (!response.ok) {
                let errorMsg = `HTTP error! status: ${response.status}`;
                try {
                    const errorData = await response.text(); // Use text() for potential non-JSON error
                    errorMsg += `, message: ${errorData || response.statusText}`;
                } catch (e) {
                    errorMsg += `, message: ${response.statusText}`;
                }
                throw new Error(errorMsg);
            }

            const opmlText = await response.text();
            const blob = new Blob([opmlText], { type: 'application/xml' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'sheepvibes_feeds.opml';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            console.log("OPML export successful.");

        } catch (error) {
            console.error('Error exporting OPML:', error);
            showToast(`Failed to export OPML: ${error.message}`, 'error');
        } finally {
            exportOpmlButton.disabled = false;
            exportOpmlButton.textContent = originalButtonText;
        }
    }

    /**
     * Handles the file selection for OPML import.
     * @param {Event} event The file input change event.
     */
    async function handleImportOpmlFileSelect(event) {
        const file = event.target.files[0];
        if (!file) {
            return;
        }

        console.log(`Importing OPML file: ${file.name}`);
        const originalButtonText = importOpmlButton.textContent;
        importOpmlButton.disabled = true;
        importOpmlButton.textContent = 'Importing...';
        opmlFileInput.disabled = true;

        const formData = new FormData();
        formData.append('file', file);

        // Optionally, add the active tab ID to import into that specific tab
        if (activeTabId) {
            formData.append('tab_id', activeTabId);
        }

        try {
            const response = await fetch('/api/opml/import', {
                method: 'POST',
                body: formData, // fetch automatically sets Content-Type for FormData
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || `HTTP error! status: ${response.status}`);
            }

            showToast(data.message, 'success');
            console.log('OPML import successful:', data);

            if (data.imported_count > 0) {
                await initializeTabs(true); // Update unread counts on all tabs

                // Clear the loaded state of the target tab to force a reload
                if (data.tab_id) {
                    loadedTabs.delete(data.tab_id);
                    // If the import was into the currently active tab, reload its content
                    if (data.tab_id === activeTabId) {
                        // Remove existing widgets for the active tab before reloading
                        document.querySelectorAll(`.feed-widget[data-tab-id="${activeTabId}"]`).forEach(w => w.remove());
                        await setActiveTab(activeTabId);
                    }
                } else { // Fallback if tab_id wasn't in response for some reason, refresh active tab
                    if (activeTabId) {
                        document.querySelectorAll(`.feed-widget[data-tab-id="${activeTabId}"]`).forEach(w => w.remove());
                        loadedTabs.delete(activeTabId);
                        await setActiveTab(activeTabId);
                    }
                }
            }
        } catch (error) {
            console.error('Error importing OPML:', error);
            showToast(`Failed to import OPML: ${error.message}`, 'error');
        } finally {
            importOpmlButton.disabled = false;
            importOpmlButton.textContent = 'Import OPML';
            opmlFileInput.value = ''; // Reset file input
            opmlFileInput.disabled = false;
        }
    }

    // --- Rendering Functions ---

    /**
     * Renders the tab buttons in the header.
     * @param {Array<object>} tabs An array of tab objects from the API.
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

        let tabToActivate = null;
        // Prioritize activeTabId (potentially from localStorage or previous state)
        if (activeTabId && tabs.some(t => t.id === activeTabId)) {
            tabToActivate = activeTabId;
        } else if (firstTabId) { // Fallback to the first tab if current activeTabId is invalid or not set
            tabToActivate = firstTabId;
        }
        // If still no tab to activate (e.g., all tabs were deleted), activeTabId remains null.

        if (tabToActivate) {
            setActiveTab(tabToActivate); // This will also update localStorage
        } else {
            // No tabs exist or active tab became invalid and no firstTabId to fallback to (e.g. all tabs deleted)
            setActiveTab(null); // Explicitly set to null, which clears localStorage and updates UI
            feedGrid.innerHTML = '<p>No tabs available. Please create a new tab.</p>';
            renameTabButton.disabled = true; // Ensure buttons are disabled if no tabs
            deleteTabButton.disabled = true;
        }
    }

    /**
     * Creates a single feed widget.
     * @param {object} feed The feed object from the API (including unread_count and items).
     * @returns {HTMLDivElement} The feed widget element.
     */
    function createFeedWidget(feed) {
        const widget = document.createElement('div');
        widget.classList.add('feed-widget');
        widget.dataset.feedId = feed.id;
        widget.dataset.tabId = feed.tab_id; // Associate widget with a tab

        // Create button container for edit and delete buttons
        const buttonContainer = document.createElement('div');
        buttonContainer.classList.add('feed-widget-buttons');

        const editButton = document.createElement('button');
        editButton.classList.add('edit-feed-button');
        editButton.textContent = '✎';
        editButton.title = 'Edit Feed';
        editButton.addEventListener('click', (e) => {
            e.stopPropagation();
            handleEditFeed(feed.id, feed.url, feed.name);
        });
        buttonContainer.appendChild(editButton);

        const deleteButton = document.createElement('button');
        deleteButton.classList.add('delete-feed-button');
        deleteButton.textContent = 'X';
        deleteButton.title = 'Delete Feed';
        deleteButton.addEventListener('click', (e) => {
            e.stopPropagation();
            handleDeleteFeed(feed.id);
        });
        buttonContainer.appendChild(deleteButton);

        const titleElement = document.createElement('h2');
        const titleTextNode = document.createTextNode(feed.name); // Create text node for the name

        // Determine the link for the feed title
        const feedLinkUrl = feed.site_link || feed.url; // Prioritize site_link, fallback to feed's own XML URL

        if (feedLinkUrl) {
            const titleLink = document.createElement('a');
            titleLink.href = feedLinkUrl;
            titleLink.target = '_blank'; // Open in new tab
            titleLink.rel = 'noopener noreferrer'; // Security measure
            titleLink.appendChild(titleTextNode); // Add name text to link
            titleElement.appendChild(titleLink);
        } else {
            titleElement.appendChild(titleTextNode); // Add name text directly if no link
        }

        // Add unread counter to the left of buttons
        const badge = createBadge(feed.unread_count);
        if (badge) {
            buttonContainer.prepend(badge);
        }

        titleElement.appendChild(buttonContainer);
        widget.appendChild(titleElement);

        const itemList = document.createElement('ul');
        widget.appendChild(itemList);

        // Keep track of the number of items currently shown
        itemList.dataset.offset = feed.items.length;
        itemList.dataset.feedId = feed.id;
        itemList.dataset.tabId = feed.tab_id; // Store tabId to avoid DOM traversal
        // Flags to prevent multiple loads and to know when all items have been loaded
        itemList.dataset.loading = 'false';
        itemList.dataset.allItemsLoaded = 'false';

        // Add the scroll event listener
        itemList.addEventListener('scroll', throttle(handleScrollLoadMore, SCROLL_THROTTLE_DELAY));

        // Render items
        if (feed.items && feed.items.length > 0) {
            const fragment = document.createDocumentFragment();
            feed.items.forEach(item => {
                const listItem = createFeedItemElement(item, (li) => {
                    handleMarkItemRead(item.id, li, feed.id, feed.tab_id);
                });
                fragment.appendChild(listItem);
            });
            itemList.appendChild(fragment);
        } else {
            itemList.innerHTML = '<li>No items found for this feed.</li>';
        }

        // Return the widget without appending it to the DOM
        return widget;
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

        try {
            const feedsWithItems = await fetchData(`/api/tabs/${tabId}/feeds`);

            // If we were showing a global loading message, clear it.
            if (feedGrid.querySelector('p')) {
                feedGrid.innerHTML = '';
            }

            if (feedsWithItems && feedsWithItems.length > 0) {
                feedsWithItems.forEach(feed => {
                    const widget = createFeedWidget(feed);
                    feedGrid.appendChild(widget);
                });
            } else if (feedGrid.children.length === 0) {
                // Only show 'no feeds' if the entire grid is empty after attempting to load
                feedGrid.innerHTML = '<p>No feeds found for this tab. Add one using the form above!</p>';
            }

            loadedTabs.add(tabId); // Mark this tab's content as loaded
        } catch (error) {
            console.error('Error loading feeds for tab:', error);
            feedGrid.innerHTML = '<p>Error loading feeds. Please check the console or try again.</p>';
        }
    }

    // --- Tab Switching Logic ---

    /**
     * Sets the specified tab as active, loads its content if needed, and shows/hides widgets.
     * @param {number} tabId The ID of the tab to activate.
     */
    async function setActiveTab(tabId) {
        activeTabId = tabId;
        if (tabId) {
            localStorage.setItem('activeTabId', tabId);
        } else {
            localStorage.removeItem('activeTabId'); // Clear if tabId is null
        }

        // Update active class on tab buttons
        tabsContainer.querySelectorAll('button').forEach(button => {
            button.classList.toggle('active', button.dataset.tabId == tabId);
        });

        // Load content if it's not cached and tabId is valid
        if (tabId && !loadedTabs.has(tabId)) {
            await loadFeedsForTab(tabId);
        }

        // Show/hide widgets based on the active tab
        feedGrid.querySelectorAll('.feed-widget').forEach(widget => {
            widget.style.display = widget.dataset.tabId == tabId ? 'block' : 'none';
        });

        // If no tab is active (e.g., after deleting the last one), clear the grid.
        if (!tabId) {
            feedGrid.innerHTML = '<p>No active tab. Create one or select one if available.</p>';
        }

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
        const errorElement = document.getElementById('add-feed-error');

        // Clear previous errors
        errorElement.style.display = 'none';

        if (!url) {
            errorElement.textContent = 'Please enter a feed URL.';
            errorElement.style.display = 'block';
            return;
        }
        if (!activeTabId) {
            errorElement.textContent = 'Please select a tab first.';
            errorElement.style.display = 'block';
            return;
        }

        console.log(`Adding feed: ${url} to tab: ${activeTabId}`);
        addFeedButton.disabled = true;
        addFeedButton.textContent = 'Adding...';

        try {
            const newFeedData = await fetchData('/api/feeds', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: url, tab_id: activeTabId }),
            });

            console.log('Feed added:', newFeedData);
            feedUrlInput.value = '';
            // Invalidate and reload the current tab to show the new feed
            if (loadedTabs.has(activeTabId)) {
                document.querySelectorAll(`.feed-widget[data-tab-id="${activeTabId}"]`).forEach(w => w.remove());
                loadedTabs.delete(activeTabId);
            }
            await setActiveTab(activeTabId); // Reload and display the current tab
            await initializeTabs(true); // Update unread counts
        } catch (error) {
            console.error('Error adding feed:', error);
            const displayMessage = error.backendMessage || error.message || 'An unexpected error occurred.';
            errorElement.textContent = displayMessage;
            errorElement.style.display = 'block';
        } finally {
            addFeedButton.disabled = false;
            addFeedButton.textContent = 'Add Feed';
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

        try {
            const result = await fetchData(`/api/feeds/${feedId}`, { method: 'DELETE' });

            console.log(`Feed ${feedId} deleted successfully.`);
            if (widget) widget.remove();
            if (feedGrid.children.length === 0) {
                feedGrid.innerHTML = '<p>No feeds found for this tab. Add one using the form above!</p>';
            }
            await initializeTabs(true);
        } catch (error) {
            console.error(`Failed to delete feed ${feedId}:`, error);
            const displayMessage = error.backendMessage || error.message || 'An unexpected error occurred.';
            showToast(`Failed to delete feed: ${displayMessage}`, 'error');
            if (widget) widget.style.opacity = '1';
        }
    }

    // --- Edit Feed Logic ---

    /**
     * Handles the click event for a feed widget's edit button.
     * @param {number} feedId The ID of the feed to edit.
     * @param {string} currentUrl The current URL of the feed.
     * @param {string} currentName The current name of the feed.
     */
    function handleEditFeed(feedId, currentUrl, currentName) {
        console.log(`Editing feed: ${feedId}`);

        const modal = document.getElementById('edit-feed-modal');
        const feedIdInput = document.getElementById('edit-feed-id');
        const feedUrlInput = document.getElementById('edit-feed-url');
        const feedNameInput = document.getElementById('edit-feed-name');

        // Populate the form with current values
        feedIdInput.value = feedId;
        feedUrlInput.value = currentUrl;
        feedNameInput.value = currentName;

        // Show the modal
        modal.classList.add('is-active');
    }

    /**
     * Handles the submission of the edit feed form.
     * @param {Event} event - The form submission event.
     */
    async function handleEditFeedSubmit(event) {
        event.preventDefault();

        const modal = document.getElementById('edit-feed-modal');
        const feedIdInput = document.getElementById('edit-feed-id');
        const feedUrlInput = document.getElementById('edit-feed-url');
        const saveButton = document.getElementById('save-feed-button');

        const feedId = parseInt(feedIdInput.value, 10);
        const newUrl = feedUrlInput.value.trim();
        const errorElement = document.getElementById('edit-feed-error');

        // Clear previous errors
        errorElement.style.display = 'none';

        if (isNaN(feedId)) {
            errorElement.textContent = 'Invalid Feed ID. Please try again.';
            errorElement.style.display = 'block';
            return;
        }

        if (!newUrl) {
            errorElement.textContent = 'Please enter a feed URL.';
            errorElement.style.display = 'block';
            return;
        }

        // Disable the save button and show loading state
        const originalButtonText = saveButton.textContent;
        const cancelButton = document.getElementById('cancel-edit-button');
        saveButton.disabled = true;
        cancelButton.disabled = true;
        saveButton.textContent = 'Saving...';

        try {
            const result = await fetchData(`/api/feeds/${feedId}`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ url: newUrl })
            });

            console.log('Feed updated successfully:', result);
            // Close the modal
            modal.classList.remove('is-active');

            // Update just the edited widget instead of reloading entire tab
            const widget = document.querySelector(`.feed-widget[data-feed-id="${feedId}"]`);
            if (widget) {
                // Replace the widget with updated content
                const newWidget = createFeedWidget(result);
                widget.replaceWith(newWidget);
            } else {
                // Fallback: reload the tab if widget not found
                console.warn('Widget not found, falling back to tab reload');
                if (loadedTabs.has(activeTabId)) {
                    document.querySelectorAll(`.feed-widget[data-tab-id="${activeTabId}"]`).forEach(w => w.remove());
                    loadedTabs.delete(activeTabId);
                }
                await setActiveTab(activeTabId);
            }
            await initializeTabs(true); // Update unread counts
        } catch (error) {
            console.error('Error updating feed:', error);
            const displayMessage = error.backendMessage || error.message || 'An unexpected error occurred.';
            errorElement.textContent = displayMessage;
            errorElement.style.display = 'block';
        } finally {
            // Re-enable the save and cancel buttons
            saveButton.disabled = false;
            cancelButton.disabled = false;
            saveButton.textContent = originalButtonText;
        }
    }

    /**
     * Handles the cancellation of the edit feed form.
     */
    function handleEditFeedCancel() {
        const saveButton = document.getElementById('save-feed-button');
        // Prevent closing the modal if a save operation is in progress.
        if (saveButton.disabled) {
            return;
        }
        const modal = document.getElementById('edit-feed-modal');
        modal.classList.remove('is-active');
    }

    // --- Mark Item as Read Logic ---

    /**
     * Handles scrolling to load more items when reaching the bottom of a feed's item list.
     * @param {Event} event - The scroll event.
     */
    async function handleScrollLoadMore(event) {
        const itemList = event.target;

        // Check if we are near the bottom of the list
        const isAtBottom = (itemList.scrollTop + itemList.clientHeight) >= itemList.scrollHeight - SCROLL_BUFFER;
        const isLoading = itemList.dataset.loading === 'true';
        const allItemsLoaded = itemList.dataset.allItemsLoaded === 'true';

        if (!isAtBottom || isLoading || allItemsLoaded) {
            return; // Exit if not at the bottom, or if we're already loading or all items are loaded
        }

        itemList.dataset.loading = 'true'; // Set loading flag

        const feedId = itemList.dataset.feedId;
        const tabId = itemList.dataset.tabId; // Use stored tabId instead of DOM traversal
        let offset = parseInt(itemList.dataset.offset, 10);
        const limit = ITEMS_PER_PAGE; // Number of items to fetch per scroll

        try {
            const newItems = await fetchData(`/api/feeds/${feedId}/items?offset=${offset}&limit=${limit}`);

            if (newItems && newItems.length > 0) {
                const fragment = document.createDocumentFragment();
                newItems.forEach(item => {
                    const listItem = createFeedItemElement(item, (li) => {
                        handleMarkItemRead(item.id, li, feedId, tabId);
                    });
                    fragment.appendChild(listItem);
                });
                itemList.appendChild(fragment);

                // Update the offset for the next fetch
                itemList.dataset.offset = offset + newItems.length;
            } else {
                // No more items to load
                itemList.dataset.allItemsLoaded = 'true';
                const noMoreItemsMsg = document.createElement('li');
                noMoreItemsMsg.textContent = 'No more items';
                noMoreItemsMsg.classList.add('no-more-items-message');
                itemList.appendChild(noMoreItemsMsg);
            }
        } catch (error) {
            console.error('Error loading more items:', error);
            showToast('Error loading more items. Please try again later.', 'error');
        } finally {
            itemList.dataset.loading = 'false'; // Reset loading flag
        }
    }

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
            try {
                await fetchData(`/api/items/${itemId}/read`, { method: 'POST' });

                // If fetchData completes without throwing, the operation was successful.
                console.log(`Successfully marked item ${itemId} as read.`);
                listItemElement.classList.remove('unread');
                listItemElement.classList.add('read');
                updateUnreadCount(feedId, -1);
                updateUnreadCount(tabId, -1, true);
            } catch (error) {
                console.error('Error marking item as read:', error);
                // Don't show alert for this as it's a frequent operation
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
        const badgeSelector = '.unread-count-badge';
        let element;
        let prepend = false;

        if (isTab) {
            // For tabs, the badge is appended to the button
            element = document.querySelector(`#tabs-container button[data-tab-id="${id}"]`);
        } else {
            // For feed widgets, the badge is prepended to the button container
            element = document.querySelector(`.feed-widget[data-feed-id="${id}"] .feed-widget-buttons`);
            prepend = true;
        }

        if (!element) return;

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
                if (prepend) {
                    element.prepend(badge);
                } else {
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

        try {
            const newTabData = await fetchData('/api/tabs', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name: newTabName.trim() }),
            });

            console.log('Tab added:', newTabData);
            await initializeTabs();
            await setActiveTab(newTabData.id);
        } catch (error) {
            console.error('Error adding tab:', error);
            const displayMessage = error.backendMessage || error.message || 'An unexpected error occurred while adding the tab.';
            showToast(`Failed to add tab: ${displayMessage}`, 'error');
        } finally {
            addTabButton.disabled = false;
            addTabButton.textContent = 'Add Tab';
        }
    }

    /** Handles the click event for the "Rename Tab" button. */
    async function handleRenameTab() {
        if (!activeTabId) {
            showToast('Please select a tab to rename.', 'info');
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
        try {
            const updatedTabData = await fetchData(`/api/tabs/${activeTabId}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name: newTabName.trim() }),
            });

            console.log('Tab renamed:', updatedTabData);
            await initializeTabs(true);
        } catch (error) {
            console.error('Error renaming tab:', error);
            const displayMessage = error.backendMessage || error.message || 'An unexpected error occurred while renaming the tab.';
            showToast(`Failed to rename tab: ${displayMessage}`, 'error');
        }
    }

    /** Handles the click event for the "Delete Tab" button. */
    async function handleDeleteTab() {
        if (!activeTabId) {
            showToast('Please select a tab to delete.', 'info');
            return;
        }
        // Removed: if (allTabs.length <= 1) check to allow deleting the last tab.

        const currentTab = allTabs.find(t => t.id === activeTabId);
        if (!confirm(`Are you sure you want to delete the tab "${currentTab ? currentTab.name : activeTabId}" and all its feeds?`)) {
            return;
        }

        console.log(`Deleting tab: ${activeTabId}`);
        try {
            await fetchData(`/api/tabs/${activeTabId}`, { method: 'DELETE' });

            console.log(`Tab ${activeTabId} deleted successfully.`);
            // If the deleted tab was the active one, clear activeTabId before re-initializing
            const deletedTabId = currentTab ? currentTab.id : activeTabId; // Get the actual ID being deleted
            if (activeTabId === deletedTabId) {
                activeTabId = null;
                localStorage.removeItem('activeTabId'); // Explicitly clear from storage
            }

            // Remove the deleted tab's widgets from the DOM
            document.querySelectorAll(`.feed-widget[data-tab-id="${deletedTabId}"]`).forEach(w => w.remove());
            loadedTabs.delete(deletedTabId);
            // activeTabId is already set to null if it was the one deleted.
            // initializeTabs will handle selecting a new active tab or setting to null if no tabs remain.
            await initializeTabs();
        } catch (error) {
            console.error('Error deleting tab:', error);
            const displayMessage = error.backendMessage || error.message || 'An unexpected error occurred while deleting the tab.';
            showToast(`Failed to delete tab: ${displayMessage}`, 'error');
        }
    }

    // --- Initial Load ---

    /**
     * Fetches the list of tabs from the API and renders them.
     * @param {boolean} [isUpdate=false] - If true, keeps the current active tab.
     */
    async function initializeTabs(isUpdate = false) {
        const currentActiveId = isUpdate ? activeTabId : localStorage.getItem('activeTabId');
        try {
            const tabs = await fetchData('/api/tabs');
            if (tabs) {
                // Attempt to restore activeTabId from localStorage if not doing a specific update that preserves it
                let storedActiveTabId = localStorage.getItem('activeTabId');
                if (storedActiveTabId && tabs.some(t => t.id == storedActiveTabId)) {
                    activeTabId = parseInt(storedActiveTabId);
                } else if (currentActiveId && tabs.some(t => t.id == currentActiveId)) {
                    activeTabId = parseInt(currentActiveId); // Use current if valid and stored is not
                } else {
                    activeTabId = null; // Fallback if stored/current is invalid
                    localStorage.removeItem('activeTabId'); // Clean up invalid stored ID
                }
                renderTabs(tabs);
            } else {
                renderTabs([]);
                localStorage.removeItem('activeTabId'); // No tabs, so no active tab
            }
        } catch (error) {
            console.error('Error initializing tabs:', error);
            renderTabs([]);
            localStorage.removeItem('activeTabId'); // Clear invalid stored ID on error
        }
    }

    function handleEditFeedCancel() {
        const saveButton = document.getElementById('save-feed-button');
        // Prevent closing the modal if a save operation is in progress.
        if (saveButton.disabled) {
            return;
        }
        const modal = document.getElementById('edit-feed-modal');
        modal.classList.remove('is-active');
    }

    /** Main initialization function called on DOMContentLoaded. */
    async function initialize() {
        // Move modal to its root container for proper stacking context
        const modalRoot = document.getElementById('modal-root');
        const modal = document.getElementById('edit-feed-modal');
        if (modalRoot && modal) {
            modalRoot.appendChild(modal);
        }

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
        exportOpmlButton.addEventListener('click', handleExportOpml);
        importOpmlButton.addEventListener('click', () => opmlFileInput.click());
        opmlFileInput.addEventListener('change', handleImportOpmlFileSelect);

        // Add event listeners for edit feed modal
        document.getElementById('edit-feed-form').addEventListener('submit', handleEditFeedSubmit);
        document.getElementById('cancel-edit-button').addEventListener('click', handleEditFeedCancel);
        const closeBtn = document.getElementById('edit-feed-modal-close-button');
        if (closeBtn) {
            closeBtn.addEventListener('click', handleEditFeedCancel);
        }

        // Close modal when clicking outside the content
        document.getElementById('edit-feed-modal').addEventListener('click', (event) => {
            if (event.target.id === 'edit-feed-modal') {
                handleEditFeedCancel();
            }
        });

        // Settings menu toggle
        settingsButton.addEventListener('click', (event) => {
            event.stopPropagation(); // Prevent the document click listener from immediately closing the menu
            settingsMenu.classList.toggle('hidden');
        });

        // Close settings menu when clicking outside
        document.addEventListener('click', (event) => {
            // If the menu is visible AND the click was not inside the menu AND the click was not the settings button
            if (!settingsMenu.classList.contains('hidden') && !settingsMenu.contains(event.target) && event.target !== settingsButton) {
                settingsMenu.classList.add('hidden');
            }
        });

        // Fetch initial tabs to start the application
        await initializeTabs();

        // Start listening for real-time updates from the server
        initializeSSE();
    }

    // Start the application initialization process
    initialize();
});
