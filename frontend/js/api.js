// API configuration
// Derive base URL from current location, with optional configurable override.
export const API_BASE_URL =
    (window.APP_CONFIG && window.APP_CONFIG.API_BASE_URL) ||
    window.API_BASE_URL ||
    (window.location.pathname.startsWith('/sheepvibes') ? '/sheepvibes' : '');

let onUnauthorizedCallback = null;

/**
 * Registers a global callback to invoke when a 401 Unauthorized response is received.
 * @param {Function} callback
 */
export function setUnauthorizedHandler(callback) {
    onUnauthorizedCallback = callback;
}

/**
 * Fetches data from the specified API endpoint.
 * Handles JSON parsing, error reporting, and different response types.
 * @param {string} url - The API endpoint URL.
 * @param {object} options - Optional fetch options (method, headers, body).
 * @param {string} responseType - Expected response type ('json' or 'text').
 * @returns {Promise<object|string|null>} A promise resolving to the data or status.
 */
export async function fetchData(url, options = {}, responseType = 'json') {
    try {
        const response = await fetch(`${API_BASE_URL}${url}`, options);
        if (!response.ok) {
            if (response.status === 401 && typeof onUnauthorizedCallback === 'function' && !url.startsWith('/api/auth/login') && !url.startsWith('/api/auth/password')) {
                onUnauthorizedCallback();
            }

            const error = new Error(`HTTP error! status: ${response.status}`);
            error.status = response.status;
            try {
                const contentType = response.headers.get('content-type');
                if (contentType && contentType.includes('application/json')) {
                    const errorData = await response.json();
                    if (errorData && errorData.error) {
                        error.backendMessage = errorData.error;
                        error.message += `, message: ${errorData.error}`;
                    }
                } else {
                    const errorText = await response.text();
                    error.message += `, message: ${errorText}`;
                }
            } catch (e) {
                error.message += `, message: ${response.statusText}`;
            }
            throw error;
        }
        if (response.status === 204 || response.headers.get('content-length') === '0') {
            return { success: true };
        }

        if (responseType === 'text') {
            return await response.text();
        }
        return await response.json();
    } catch (error) {
        console.error('Error fetching data:', error);
        throw error;
    }
}

// --- API Methods ---

export const api = {
    // Auth
    login: (username, password) => fetchData('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
    }),
    logout: () => fetchData('/api/auth/logout', { method: 'POST' }),
    getCurrentUser: () => fetchData('/api/auth/me'),
    changePassword: (currentPassword, newPassword) => fetchData('/api/auth/password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ current_password: currentPassword, new_password: newPassword })
    }),

    // Tabs
    getTabs: () => fetchData('/api/tabs'),
    createTab: (name) => fetchData('/api/tabs', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name })
    }),
    updateTab: (tabId, name) => fetchData(`/api/tabs/${encodeURIComponent(tabId)}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name })
    }),
    deleteTab: (tabId) => fetchData(`/api/tabs/${encodeURIComponent(tabId)}`, { method: 'DELETE' }),

    // Feeds
    getFeedsForTab: (tabId) => fetchData(`/api/tabs/${encodeURIComponent(tabId)}/feeds`),
    addFeed: (url, tabId) => fetchData('/api/feeds', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url, tab_id: tabId })
    }),
    updateFeed: (feedId, url, name) => fetchData(`/api/feeds/${encodeURIComponent(feedId)}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url, name })
    }),
    deleteFeed: (feedId) => fetchData(`/api/feeds/${encodeURIComponent(feedId)}`, { method: 'DELETE' }),
    updateAllFeeds: () => fetchData('/api/feeds/update-all', { method: 'POST' }),

    // Items
    getFeedItems: (feedId, offset, limit) => fetchData(`/api/feeds/${encodeURIComponent(feedId)}/items?offset=${encodeURIComponent(offset)}&limit=${encodeURIComponent(limit)}`),
    markItemRead: (itemId) => fetchData(`/api/items/${encodeURIComponent(itemId)}/read`, { method: 'POST' }),

    // OPML
    exportOpml: () => fetchData('/api/opml/export', { method: 'GET' }, 'text'),
    importOpml: (formData) => fetchData('/api/opml/import', {
        method: 'POST',
        body: formData
    }),

    // Handler setter
    setUnauthorizedHandler
};
