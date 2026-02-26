// API configuration
// Derive base URL from current location, with optional configurable override.
export const API_BASE_URL =
    (window.APP_CONFIG && window.APP_CONFIG.API_BASE_URL) ||
    window.API_BASE_URL ||
    '';

/**
 * Retrieves a cookie by name.
 * @param {string} name - The name of the cookie.
 * @returns {string|null} The cookie value or null if not found.
 */
function getCookie(name) {
    let cookieValue = null;
    if (document.cookie && document.cookie !== '') {
        const cookies = document.cookie.split(';');
        for (let i = 0; i < cookies.length; i++) {
            const cookie = cookies[i].trim();
            if (cookie.substring(0, name.length + 1) === (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}

/**
 * Fetches data from the specified API endpoint.
 * Handles JSON parsing, error reporting, and different response types.
 * @param {string} url - The API endpoint URL.
 * @param {object} options - Optional fetch options (method, headers, body).
 * @returns {Promise<object|null>} A promise resolving to the JSON data, {success: true} for successful non-JSON responses, or null on failure.
 */
export async function fetchData(url, options = {}, responseType = 'json') {
    // Add CSRF token to headers for unsafe methods
    if (['POST', 'PUT', 'DELETE', 'PATCH'].includes((options.method || 'GET').toUpperCase())) {
        const csrftoken = getCookie('csrf_token');
        if (csrftoken) {
            options.headers = options.headers || {};
            // Ensure headers is a plain object or Headers object
            if (options.headers instanceof Headers) {
                options.headers.append('X-CSRFToken', csrftoken);
            } else {
                options.headers['X-CSRFToken'] = csrftoken;
            }
        }
    }

    try {
        const response = await fetch(`${API_BASE_URL}${url}`, options);
        if (!response.ok) {
            const error = new Error(`HTTP error! status: ${response.status}`);
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
    updateFeed: (id, url, name) => fetchData(`/api/feeds/${id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url, name })
    }),
    deleteFeed: (id) => fetchData(`/api/feeds/${id}`, { method: 'DELETE' }),
    updateAllFeeds: () => fetchData('/api/feeds/update-all', { method: 'POST' }),

    // Items
    getFeedItems: (feedId, offset, limit) => fetchData(`/api/feeds/${feedId}/items?offset=${offset}&limit=${limit}`),
    markItemRead: (itemId) => fetchData(`/api/items/${itemId}/read`, { method: 'POST' }),

    // OPML
    exportOpml: () => fetchData('/api/opml/export', { method: 'GET' }, 'text'),
    importOpml: (formData) => fetchData('/api/opml/import', {
        method: 'POST',
        body: formData
    })
};
