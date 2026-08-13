/**
 * @vitest-environment jsdom
 */
import { describe, it, expect, vi, afterEach } from 'vitest';
import { formatDate, throttle, sanitizeUrl, getStorageItem, setStorageItem, removeStorageItem } from './utils.js';

describe('formatDate', () => {
    it('returns "No date" for null or empty input', () => {
        expect(formatDate(null)).toBe('No date');
        expect(formatDate('')).toBe('No date');
    });

    it('returns "Invalid date" for invalid ISO string', () => {
        expect(formatDate('invalid-date')).toBe('Invalid date');
        expect(formatDate('not a date')).toBe('Invalid date');
    });

    it('clamps negative seconds to 0 sec ago for future dates', () => {
        const futureDate = new Date(Date.now() + 10000).toISOString();
        expect(formatDate(futureDate)).toBe('0 sec ago');
    });

    it('formats past dates correctly', () => {
        const pastDate = new Date(Date.now() - 120000).toISOString();
        expect(formatDate(pastDate)).toBe('2 min ago');
    });
});

describe('throttle', () => {
    it('executes leading edge and trailing edge if called during cooldown', async () => {
        vi.useFakeTimers();
        const callback = vi.fn();
        const throttled = throttle(callback, 200);

        throttled('first');
        expect(callback).toHaveBeenCalledTimes(1);
        expect(callback).toHaveBeenCalledWith('first');

        throttled('second');
        expect(callback).toHaveBeenCalledTimes(1);

        vi.advanceTimersByTime(200);
        expect(callback).toHaveBeenCalledTimes(2);
        expect(callback).toHaveBeenCalledWith('second');

        vi.useRealTimers();
    });

    it('resets isThrottled on trailing edge even if callback throws an error', () => {
        vi.useFakeTimers();
        const callback = vi.fn((val) => {
            if (val === 'error') {
                throw new Error('Callback failed');
            }
        });
        const throttled = throttle(callback, 200);

        throttled('first');
        expect(callback).toHaveBeenCalledWith('first');

        throttled('error');

        expect(() => {
            vi.advanceTimersByTime(200);
        }).toThrow('Callback failed');

        vi.advanceTimersByTime(200);

        throttled('third');
        expect(callback).toHaveBeenCalledWith('third');

        vi.useRealTimers();
    });
});

describe('sanitizeUrl', () => {
    it('allows valid http and https URLs', () => {
        expect(sanitizeUrl('http://example.com')).toBe('http://example.com');
        expect(sanitizeUrl('https://example.com/feed.xml')).toBe('https://example.com/feed.xml');
    });

    it('allows relative URLs starting with /', () => {
        expect(sanitizeUrl('/api/feed')).toBe('/api/feed');
        expect(sanitizeUrl('/index.html')).toBe('/index.html');
    });

    it('allows mailto URLs', () => {
        expect(sanitizeUrl('mailto:user@example.com')).toBe('mailto:user@example.com');
    });

    it('blocks dangerous schemes like javascript: and data:', () => {
        expect(sanitizeUrl('javascript:alert(1)')).toBe('#');
        expect(sanitizeUrl('JAVASCRIPT:alert("xss")')).toBe('#');
        expect(sanitizeUrl('data:text/html,<script>alert(1)</script>')).toBe('#');
        expect(sanitizeUrl('vbscript:msgbox(1)')).toBe('#');
        expect(sanitizeUrl('file:///etc/passwd')).toBe('#');
    });

    it('returns # for invalid or empty inputs', () => {
        expect(sanitizeUrl(null)).toBe('#');
        expect(sanitizeUrl(undefined)).toBe('#');
        expect(sanitizeUrl('')).toBe('#');
        expect(sanitizeUrl(123)).toBe('#');
    });
});

describe('localStorage helpers', () => {
    afterEach(() => {
        vi.restoreAllMocks();
    });

    it('getStorageItem reads value or returns null on error', () => {
        localStorage.setItem('testKey', 'testVal');
        expect(getStorageItem('testKey')).toBe('testVal');
        expect(getStorageItem('nonExistentKey')).toBeNull();

        const getItemSpy = vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
            throw new Error('Access denied');
        });
        expect(getStorageItem('testKey')).toBeNull();
        getItemSpy.mockRestore();
    });

    it('setStorageItem stores value or handles errors gracefully', () => {
        setStorageItem('newKey', 'newVal');
        expect(localStorage.getItem('newKey')).toBe('newVal');

        const setItemSpy = vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
            throw new Error('Quota exceeded');
        });
        expect(() => setStorageItem('failKey', 'failVal')).not.toThrow();
        setItemSpy.mockRestore();
    });

    it('removeStorageItem removes value or handles errors gracefully', () => {
        localStorage.setItem('remKey', 'val');
        removeStorageItem('remKey');
        expect(localStorage.getItem('remKey')).toBeNull();

        const removeItemSpy = vi.spyOn(Storage.prototype, 'removeItem').mockImplementation(() => {
            throw new Error('Access denied');
        });
        expect(() => removeStorageItem('remKey')).not.toThrow();
        removeItemSpy.mockRestore();
    });
});

