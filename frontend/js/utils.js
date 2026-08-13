/**
 * A simple throttle utility function to limit function execution frequency.
 * @param {function} callback - The function to throttle.
 * @param {number} delay - The delay in milliseconds between executions.
 * @returns {function} The throttled function.
 */
export function throttle(callback, delay) {
    let isThrottled = false;
    let lastArgs = null;
    let lastThis = null;

    return function (...args) {
        if (isThrottled) {
            lastArgs = args;
            lastThis = this;
            return;
        }

        callback.apply(this, args);
        isThrottled = true;

        const checkTrailing = () => {
            setTimeout(() => {
                if (lastArgs) {
                    const args = lastArgs;
                    const ctx = lastThis;
                    lastArgs = null;
                    lastThis = null;
                    try {
                        callback.apply(ctx, args);
                    } finally {
                        checkTrailing();
                    }
                } else {
                    isThrottled = false;
                }
            }, delay);
        };

        checkTrailing();
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
        if (isNaN(date.getTime())) return 'Invalid date';
        const now = new Date();
        const rawDiffSeconds = Math.round((now - date) / 1000);
        const diffSeconds = Math.max(0, rawDiffSeconds);
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
 * Sanitizes a URL to ensure it uses an allowed scheme (http, https, /, mailto).
 * Returns '#' if the scheme is unsafe (e.g. javascript:, data:).
 * @param {string} url - The URL to sanitize.
 * @returns {string} The sanitized URL or '#'.
 */
export function sanitizeUrl(url) {
    if (!url || typeof url !== 'string') return '#';
    const trimmed = url.trim();
    if (trimmed.startsWith('/')) {
        return trimmed;
    }
    const lower = trimmed.toLowerCase();
    if (
        lower.startsWith('http://') ||
        lower.startsWith('https://') ||
        lower.startsWith('mailto:')
    ) {
        return trimmed;
    }
    return '#';
}

/**
 * Safely retrieves an item from localStorage.
 * @param {string} key - The key to retrieve.
 * @returns {string | null} The item value or null if unavailable/error.
 */
export function getStorageItem(key) {
    try {
        return localStorage.getItem(key);
    } catch (e) {
        console.warn(`localStorage getItem failed for key "${key}":`, e);
        return null;
    }
}

/**
 * Safely sets an item in localStorage.
 * @param {string} key - The key to set.
 * @param {string} value - The value to store.
 */
export function setStorageItem(key, value) {
    try {
        localStorage.setItem(key, value);
    } catch (e) {
        console.warn(`localStorage setItem failed for key "${key}":`, e);
    }
}

/**
 * Safely removes an item from localStorage.
 * @param {string} key - The key to remove.
 */
export function removeStorageItem(key) {
    try {
        localStorage.removeItem(key);
    } catch (e) {
        console.warn(`localStorage removeItem failed for key "${key}":`, e);
    }
}

