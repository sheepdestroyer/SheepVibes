/**
 * A simple throttle utility function to limit function execution frequency.
 * @param {function} callback - The function to throttle.
 * @param {number} delay - The delay in milliseconds between executions.
 * @returns {function} The throttled function.
 */
export function throttle(callback, delay) {
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
 * Formats an ISO date string into a user-friendly relative or absolute time.
 * @param {string | null} isoString - The ISO date string to format.
 * @returns {string} A formatted date string (e.g., "5 min ago", "Apr 20, 2025").
 */
export function formatDate(isoString) {
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
 * Validates and returns the active tab ID.
 * If the current ID is invalid or not in the list, it defaults to the first tab or null.
 * @param {Array} tabs - The list of available tabs.
 * @param {number|string|null} currentActiveId - The currently active tab ID.
 * @returns {number|null} The validated active tab ID.
 */
export function validateActiveTab(tabs, currentActiveId) {
    if (!tabs || tabs.length === 0) {
        return null;
    }
    // Check if currentActiveId is valid and exists in tabs
    const isValid = tabs.some(t => t.id === currentActiveId);
    if (isValid) {
        return currentActiveId;
    }
    // Default to first tab if invalid
    return tabs[0].id;
}
