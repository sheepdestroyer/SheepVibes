document.addEventListener('DOMContentLoaded', () => {
    // DOM Elements
    const tabsContainer = document.getElementById('tabs-container');
    const feedGrid = document.getElementById('feed-grid');
    const addFeedButton = document.getElementById('add-feed-button');
    const feedUrlInput = document.getElementById('feed-url-input');
    const addTabButton = document.getElementById('add-tab-button');
    const renameTabButton = document.getElementById('rename-tab-button');
    const deleteTabButton = document.getElementById('delete-tab-button');
    const refreshAllFeedsButton = document.getElementById('refresh-all-feeds-button');

    // Auth DOM Elements
    const loginForm = document.getElementById('login-form');
    const registerForm = document.getElementById('register-form');
    const loginUsernameInput = document.getElementById('login-username');
    const loginPasswordInput = document.getElementById('login-password');
    const registerUsernameInput = document.getElementById('register-username');
    const registerPasswordInput = document.getElementById('register-password');
    const logoutButton = document.getElementById('logout-button');
    const authContainer = document.getElementById('auth-container');
    const mainContentContainer = document.getElementById('main-content');
    const authMessagesDiv = document.getElementById('auth-messages');

    // State variables
    let activeTabId = null;
    let allTabs = [];
    const loadedTabs = new Set();

    // --- Token Management ---
    const getToken = () => localStorage.getItem('authToken');
    const saveToken = (token) => localStorage.setItem('authToken', token);
    const removeToken = () => localStorage.removeItem('authToken');

    // --- UI Update Functions ---
    function displayAuthMessage(message, isError = false) {
        authMessagesDiv.textContent = message;
        authMessagesDiv.className = isError ? 'error-message' : 'success-message';
        authMessagesDiv.style.display = 'block';
    }

    function clearAuthMessages() {
        authMessagesDiv.textContent = '';
        authMessagesDiv.style.display = 'none';
    }

    function showLoginForm() {
        authContainer.style.display = 'block';
        mainContentContainer.style.display = 'none';
        logoutButton.style.display = 'none';
        clearAuthMessages();
        clearMainContent(); // Clear tabs and feeds
    }

    function showAuthenticatedView() {
        authContainer.style.display = 'none';
        mainContentContainer.style.display = 'block';
        logoutButton.style.display = 'block'; // Show logout button in header
        clearAuthMessages();
    }

    function clearMainContent() {
        tabsContainer.innerHTML = '';
        feedGrid.innerHTML = '';
        allTabs = [];
        loadedTabs.clear();
        activeTabId = null;
    }


    // --- API Helper ---
    async function fetchWithAuth(url, options = {}) {
        const token = getToken();
        const headers = { ...options.headers };
        if (token) {
            headers['Authorization'] = `Bearer ${token}`;
        }
        if (!headers['Content-Type'] && options.body && typeof options.body === 'object') {
            headers['Content-Type'] = 'application/json';
        }
        if (options.body && typeof options.body === 'object' && headers['Content-Type'] === 'application/json') {
            options.body = JSON.stringify(options.body);
        }


        try {
            const response = await fetch(url, { ...options, headers });

            if (response.status === 401) {
                removeToken();
                showLoginForm();
                displayAuthMessage('Session expired or token invalid. Please log in again.', true);
                return null; // Or throw an error to stop further processing
            }

            if (!response.ok) {
                let errorMsg = `HTTP error! status: ${response.status}`;
                try {
                    const errorData = await response.json();
                    if (errorData && errorData.error) {
                        errorMsg += `, message: ${errorData.error}`;
                    } else if (errorData && errorData.message) {
                         errorMsg += `, message: ${errorData.message}`;
                    }
                } catch (e) {
                    errorMsg += `, message: ${response.statusText}`;
                }
                throw new Error(errorMsg);
            }

            if (response.status === 204 || response.headers.get('content-length') === '0') {
                return { success: true, status: response.status };
            }
            const data = await response.json();
            return { ...data, success: true, status: response.status }; // Add success and status for easier handling

        } catch (error) {
            console.error('Error fetching data with auth:', error);
            // Display error in auth messages if it's an auth-related screen, or use alert for general errors
            if (authContainer.style.display === 'block') {
                 displayAuthMessage(error.message || 'Operation failed.', true);
            } else {
                alert(`Operation failed: ${error.message}`);
            }
            return null;
        }
    }

    // Re-define fetchData to use fetchWithAuth
    const fetchData = fetchWithAuth;


    // --- Helper Functions (Existing - some might need minor adjustments) ---
    function formatDate(isoString) {
        if (!isoString) return 'No date';
        try {
            const date = new Date(isoString);
            const now = new Date();
            const diffSeconds = Math.round((now - date) / 1000);
            // ... (rest of the function remains the same)
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

    let eventSource = null; // Keep a reference to close it on logout
    function initializeSSE() {
        if (eventSource) {
            eventSource.close();
        }
        console.log('Initializing SSE connection...');
        eventSource = new EventSource('/api/stream'); // No auth needed for SSE itself if it's just generic updates

        eventSource.onmessage = async (event) => {
            if (!event.data) return;
            try {
                const data = JSON.parse(event.data);
                console.log('SSE message received (feeds updated):', data);
                if (data.new_items > 0 && getToken()) { // Only process if logged in
                    console.log(`Feeds updated in background. Found ${data.new_items} new items. Refreshing UI.`);
                    await initializeTabs(true);
                    if (activeTabId && loadedTabs.has(activeTabId)) {
                        document.querySelectorAll(`.feed-widget[data-tab-id="${activeTabId}"]`).forEach(w => w.remove());
                        loadedTabs.delete(activeTabId);
                        await loadFeedsForTab(activeTabId);
                    }
                }
            } catch (e) {
                console.error('Error parsing SSE message data:', event.data, e);
            }
        };
        eventSource.onerror = (err) => {
            console.error('EventSource failed:', err);
            if (eventSource) eventSource.close();
        };
    }

    function closeSSE() {
        if (eventSource) {
            eventSource.close();
            console.log('SSE connection closed.');
            eventSource = null;
        }
    }


    async function handleRefreshAllFeeds() {
        console.log("Triggering refresh for all feeds...");
        const originalButtonText = refreshAllFeedsButton.textContent;
        refreshAllFeedsButton.disabled = true;
        refreshAllFeedsButton.textContent = 'Refreshing...';
        const result = await fetchData('/api/feeds/update-all', { method: 'POST' });
        if (result && result.success) {
            console.log('All feeds refresh triggered successfully:', result);
        }
        refreshAllFeedsButton.disabled = false;
        refreshAllFeedsButton.textContent = originalButtonText;
    }

    function createBadge(count) {
        if (count > 0) {
            const badge = document.createElement('span');
            badge.classList.add('unread-count-badge');
            badge.textContent = count;
            return badge;
        }
        return null;
    }

    // --- Rendering Functions (Existing - check for dependencies on fetchData) ---
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
            if (badge) button.appendChild(badge);
            tabsContainer.appendChild(button);
            if (index === 0) firstTabId = tab.id;
        });
        renameTabButton.disabled = false;
        deleteTabButton.disabled = tabs.length <= 1;
        let tabToActivate = activeTabId;
        if (!tabToActivate || !tabs.some(t => t.id === tabToActivate)) {
            tabToActivate = firstTabId;
        }
        if (tabToActivate) setActiveTab(tabToActivate);
        else {
            activeTabId = null;
            feedGrid.innerHTML = '<p>Select a tab.</p>';
        }
    }

    function renderFeedWidget(feed) {
        const widget = document.createElement('div');
        widget.classList.add('feed-widget');
        widget.dataset.feedId = feed.id;
        widget.dataset.tabId = feed.tab_id;
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
        if (badge) titleElement.appendChild(badge);
        titleElement.prepend(feed.name);
        const itemList = document.createElement('ul');
        widget.appendChild(itemList);
        feedGrid.appendChild(widget);
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

    async function loadFeedsForTab(tabId) {
        if (feedGrid.children.length === 0) feedGrid.innerHTML = '<p>Loading feeds...</p>';
        const feedsWithItems = await fetchData(`/api/tabs/${tabId}/feeds`);
        if (feedGrid.querySelector('p')) feedGrid.innerHTML = '';
        if (feedsWithItems === null) {
            // Error already handled by fetchData or 401 redirect
            if (getToken()) { // Only show error if still logged in
                 feedGrid.innerHTML = '<p>Error loading feeds. Please check the console or try again.</p>';
            }
            return;
        }
        if (feedsWithItems && feedsWithItems.length > 0) {
            feedsWithItems.forEach(feed => renderFeedWidget(feed));
        } else if (feedGrid.children.length === 0) {
            feedGrid.innerHTML = '<p>No feeds found for this tab. Add one using the form above!</p>';
        }
        loadedTabs.add(tabId);
    }

    async function setActiveTab(tabId) {
        activeTabId = tabId;
        tabsContainer.querySelectorAll('button').forEach(button => {
            button.classList.toggle('active', button.dataset.tabId == tabId);
        });
        if (!loadedTabs.has(tabId)) await loadFeedsForTab(tabId);
        feedGrid.querySelectorAll('.feed-widget').forEach(widget => {
            widget.style.display = widget.dataset.tabId == tabId ? 'block' : 'none';
        });
        deleteTabButton.disabled = allTabs.length <= 1;
    }

    function switchTab(tabId) {
        if (tabId !== activeTabId) setActiveTab(tabId);
    }

    async function handleAddFeed() {
        const url = feedUrlInput.value.trim();
        if (!url) { alert('Please enter a feed URL.'); return; }
        if (!activeTabId) { alert('Please select a tab first.'); return; }
        addFeedButton.disabled = true; addFeedButton.textContent = 'Adding...';
        const newFeedData = await fetchData('/api/feeds', {
            method: 'POST',
            body: { url: url, tab_id: activeTabId },
        });
        addFeedButton.disabled = false; addFeedButton.textContent = 'Add Feed';
        if (newFeedData && newFeedData.success) {
            feedUrlInput.value = '';
            if (loadedTabs.has(activeTabId)) {
                document.querySelectorAll(`.feed-widget[data-tab-id="${activeTabId}"]`).forEach(w => w.remove());
                loadedTabs.delete(activeTabId);
            }
            await setActiveTab(activeTabId);
            await initializeTabs(true);
        }
    }

    async function handleDeleteFeed(feedId) {
        if (!confirm('Are you sure you want to delete this feed?')) return;
        const widget = feedGrid.querySelector(`.feed-widget[data-feed-id="${feedId}"]`);
        if (widget) widget.style.opacity = '0.5';
        const result = await fetchData(`/api/feeds/${feedId}`, { method: 'DELETE' });
        if (result && result.success) {
            if (widget) widget.remove();
            if (feedGrid.children.length === 0) feedGrid.innerHTML = '<p>No feeds found. Add one!</p>';
            await initializeTabs(true);
        } else if (widget) widget.style.opacity = '1';
    }

    async function handleMarkItemRead(itemId, listItemElement, feedId, tabId) {
        if (listItemElement.classList.contains('unread')) {
            const result = await fetchData(`/api/items/${itemId}/read`, { method: 'POST' });
            if (result && result.success) {
                listItemElement.classList.remove('unread');
                listItemElement.classList.add('read');
                updateUnreadCount(feedId, -1);
                updateUnreadCount(tabId, -1, true);
            }
        }
    }

    function updateUnreadCount(id, change, isTab = false) {
        const selector = isTab ? `#tabs-container button[data-tab-id="${id}"]` : `.feed-widget[data-feed-id="${id}"] h2`;
        const element = document.querySelector(selector);
        if (!element) return;
        const badgeSelector = '.unread-count-badge';
        let badge = element.querySelector(badgeSelector);
        let currentCount = badge ? (parseInt(badge.textContent) || 0) : 0;
        const newCount = Math.max(0, currentCount + change);
        if (newCount > 0) {
            if (badge) badge.textContent = newCount;
            else {
                badge = createBadge(newCount);
                if (badge) element.appendChild(badge);
            }
        } else if (badge) badge.remove();
    }

    async function handleAddTab() {
        const newTabName = prompt('Enter the name for the new tab:');
        if (!newTabName || !newTabName.trim()) return;
        addTabButton.disabled = true; addTabButton.textContent = 'Adding...';
        const newTabData = await fetchData('/api/tabs', {
            method: 'POST',
            body: { name: newTabName.trim() },
        });
        addTabButton.disabled = false; addTabButton.textContent = '+';
        if (newTabData && newTabData.success) {
            await initializeTabs();
            await setActiveTab(newTabData.id); // setActiveTab expects full newTabData object from API
        }
    }

    async function handleRenameTab() {
        if (!activeTabId) { alert('Please select a tab to rename.'); return; }
        const currentTab = allTabs.find(t => t.id === activeTabId);
        const newTabName = prompt('Enter new name:', currentTab ? currentTab.name : '');
        if (!newTabName || !newTabName.trim() || (currentTab && newTabName.trim() === currentTab.name)) return;
        const updatedTabData = await fetchData(`/api/tabs/${activeTabId}`, {
            method: 'PUT',
            body: { name: newTabName.trim() },
        });
        if (updatedTabData && updatedTabData.success) await initializeTabs(true);
    }

    async function handleDeleteTab() {
        if (!activeTabId) { alert('Please select a tab to delete.'); return; }
        if (allTabs.length <= 1) { alert('Cannot delete the last tab.'); return; }
        const currentTab = allTabs.find(t => t.id === activeTabId);
        if (!confirm(`Delete tab "${currentTab ? currentTab.name : activeTabId}"?`)) return;
        const result = await fetchData(`/api/tabs/${activeTabId}`, { method: 'DELETE' });
        if (result && result.success) {
            document.querySelectorAll(`.feed-widget[data-tab-id="${activeTabId}"]`).forEach(w => w.remove());
            loadedTabs.delete(activeTabId);
            activeTabId = null;
            await initializeTabs();
        }
    }

    // --- Initial Load & Auth Logic ---
    async function initializeTabs(isUpdate = false) {
        const currentActiveId = isUpdate ? activeTabId : null;
        const tabs = await fetchData('/api/tabs'); // fetchData now uses fetchWithAuth
        if (tabs && tabs.success) { // Check for successful fetch (not 401)
             activeTabId = currentActiveId;
             renderTabs(tabs); // tabs here is the array from the response
        } else if (!getToken()) { // If fetch failed AND there's no token, render empty.
             renderTabs([]);
        }
        // If fetch failed due to 401, showLoginForm() was already called by fetchWithAuth
    }

    async function appInit() {
        // Auth Event Listeners
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            clearAuthMessages();
            const username = loginUsernameInput.value;
            const password = loginPasswordInput.value;
            const result = await fetchWithAuth('/api/auth/login', { // Use fetchWithAuth
                method: 'POST',
                body: { username, password },
            });
            if (result && result.token) {
                saveToken(result.token);
                showAuthenticatedView();
                await initializeTabs(); // Load initial data
                initializeSSE(); // Start SSE after successful login
            } else if (result && result.message) {
                displayAuthMessage(result.message, true);
            } else if (!result) {
                // displayAuthMessage already handled by fetchWithAuth for network/HTTP errors
            }
        });

        registerForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            clearAuthMessages();
            const username = registerUsernameInput.value;
            const password = registerPasswordInput.value;
            const result = await fetchWithAuth('/api/auth/register', { // Use fetchWithAuth
                method: 'POST',
                body: { username, password },
            });
            if (result && result.status === 201) {
                displayAuthMessage(result.message || 'Registration successful! Please login.', false);
                registerForm.reset();
                loginUsernameInput.value = username; // Pre-fill login form
                loginPasswordInput.focus();
            } else if (result && result.message) {
                displayAuthMessage(result.message, true);
            } else if (!result) {
                // displayAuthMessage already handled by fetchWithAuth
            }
        });

        logoutButton.addEventListener('click', () => {
            removeToken();
            showLoginForm();
            closeSSE(); // Stop SSE on logout
        });

        // Non-Auth Event Listeners (from original initialize)
        addTabButton.addEventListener('click', handleAddTab);
        renameTabButton.addEventListener('click', handleRenameTab);
        deleteTabButton.addEventListener('click', handleDeleteTab);
        addFeedButton.addEventListener('click', handleAddFeed);
        feedUrlInput.addEventListener('keypress', (event) => {
            if (event.key === 'Enter') handleAddFeed();
        });
        refreshAllFeedsButton.addEventListener('click', handleRefreshAllFeeds);

        // Check token on load
        if (getToken()) {
            // Try to fetch initial data. If token is invalid, fetchWithAuth will handle redirect.
            const tabs = await fetchData('/api/tabs');
            if (tabs && tabs.success) { // tabs is the actual array here
                showAuthenticatedView();
                renderTabs(tabs);
                initializeSSE(); // Start SSE if already logged in
            } else {
                // If fetching tabs failed (e.g. 401), showLoginForm() was called by fetchWithAuth
                // If it's another error, and we still have a token, it's an issue.
                // For now, fetchWithAuth handles the 401 by calling showLoginForm.
                // If there's a token but tabs is null for other reasons, we might end up here.
                // Consider if showLoginForm() should be explicitly called if tabs is null and token exists.
                if (getToken()) { // If still has token but tabs failed for non-401 reason
                    // This case might indicate a server issue if token is valid but data fails.
                    // For now, if fetchWithAuth didn't clear token and redirect, assume valid session but no data.
                    // This might be okay if the user has no tabs yet.
                     showAuthenticatedView(); // Show main view but it might be empty
                     renderTabs([]); // Render empty tabs state
                     initializeSSE();
                } else {
                     showLoginForm(); // Fallback if token was cleared by failed fetch
                }
            }
        } else {
            showLoginForm();
        }
    }

    appInit();
});

// Minor adjustments to formatDate as it was incomplete in previous thought block
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
