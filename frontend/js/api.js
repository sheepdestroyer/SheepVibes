// API configuration
export const API_BASE_URL =
    (window.APP_CONFIG && window.APP_CONFIG.API_BASE_URL) ||
    window.API_BASE_URL ||
    '';

/**
 * Fetches data from the specified API endpoint.
 */
export async function fetchData(url, options = {}, responseType = 'json') {
    try {
        const response = await fetch(`${API_BASE_URL}${url}`, options);

        if (response.status === 401 && !url.includes('/api/auth/me')) {
            // Trigger logout / redirect to login if session expired
            window.dispatchEvent(new CustomEvent('auth-required'));
        }

        if (!response.ok) {
            const error = new Error(`HTTP error! status: ${response.status}`);
            try {
                const contentType = response.headers.get('content-type');
                if (contentType && contentType.includes('application/json')) {
                    const errorData = await response.json();
                    if (errorData && errorData.error) {
                        error.backendMessage = errorData.error;
                        error.message = errorData.error;
                    }
                }
            } catch (e) {}
            throw error;
        }
        if (response.status === 204 || response.headers.get('content-length') === '0') {
            return { success: true };
        }
        if (responseType === 'text') return await response.text();
        if (responseType === 'blob') return await response.blob();
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
    register: (username, password, email) => fetchData('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password, email })
    }),
    logout: () => fetchData('/api/auth/logout', { method: 'POST' }),
    getMe: () => fetchData('/api/auth/me'),

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

    // Feeds (Subscriptions)
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
    getFeedItems: (subId, offset, limit) => fetchData(`/api/feeds/${subId}/items?offset=${offset}&limit=${limit}`),
    markItemRead: (itemId) => fetchData(`/api/items/${itemId}/read`, { method: 'POST' }),

    // OPML
    exportOpml: () => fetchData('/api/opml/export', { method: 'GET' }, 'text'),
    importOpml: (formData) => fetchData('/api/opml/import', {
        method: 'POST',
        body: formData
    }),

    // Admin
    getAdminUsers: () => fetchData('/api/admin/users'),
    deleteUser: (userId) => fetchData(`/api/admin/users/${userId}`, { method: 'DELETE' }),
    toggleUserAdmin: (userId) => fetchData(`/api/admin/users/${userId}/toggle-admin`, { method: 'POST' }),
    exportDb: () => fetchData('/api/admin/export-db', { method: 'GET' }, 'blob')
};
