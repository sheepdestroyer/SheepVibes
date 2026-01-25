// API configuration
// Derive base URL from current location, with optional configurable override.
export const API_BASE_URL =
    (window.APP_CONFIG && window.APP_CONFIG.API_BASE_URL) ||
    window.API_BASE_URL ||
    '';

/**
 * Fetches data from the specified API endpoint.
 * Handles JSON parsing, error reporting, and different response types.
 * @param {string} url - The API endpoint URL.
 * @param {object} options - Optional fetch options (method, headers, body).
 * @returns {Promise<object|null>} A promise resolving to the JSON data, {success: true} for successful non-JSON responses, or null on failure.
 */
export async function fetchData(url, options = {}) {
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

// --- API Methods ---

export const api = {
    // Tabs
    getTabs: () => fetchData('/api/tabs'),
    createTab: (name) => fetchData('/api/tabs', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name })
    }),
    updateTab: (id, name) => fetchData(`/api/tabs/${id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name })
    }),
    deleteTab: (id) => fetchData(`/api/tabs/${id}`, { method: 'DELETE' }),

    // Feeds
    getFeedsForTab: (tabId) => fetchData(`/api/tabs/${tabId}/feeds`),
    addFeed: (url, tabId) => fetchData('/api/feeds', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url, tab_id: tabId })
    }),
    updateFeed: (id, url) => fetchData(`/api/feeds/${id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url })
    }),
    deleteFeed: (id) => fetchData(`/api/feeds/${id}`, { method: 'DELETE' }),
    updateAllFeeds: () => fetchData('/api/feeds/update-all', { method: 'POST' }),

    // Items
    getFeedItems: (feedId, offset, limit) => fetchData(`/api/feeds/${feedId}/items?offset=${offset}&limit=${limit}`),
    markItemRead: (itemId) => fetchData(`/api/items/${itemId}/read`, { method: 'POST' }),

    // OPML
    exportOpml: () => fetch('/api/opml/export').then(async res => {
        if (!res.ok) throw new Error(`HTTP error! status: ${res.status}`);
        return await res.text();
    }),
    importOpml: (formData) => fetch('/api/opml/import', {
        method: 'POST',
        body: formData
    }).then(async res => {
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || `HTTP error! status: ${res.status}`);
        return data;
    })
};
