/**
 * @vitest-environment jsdom
 */
import { describe, it, expect, vi } from 'vitest';
import { formatDate, throttle } from './utils.js';

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
