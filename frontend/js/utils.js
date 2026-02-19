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
 * A simple debounce utility function to delay function execution until a pause in calls.
 * @param {function} callback - The function to debounce.
 * @param {number} delay - The delay in milliseconds.
 * @returns {function} The debounced function.
 */
export function debounce(callback, delay) {
    let timeoutId;
    return function (...args) {
        if (timeoutId) {
            clearTimeout(timeoutId);
        }
        timeoutId = setTimeout(() => {
            callback.apply(this, args);
        }, delay);
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
