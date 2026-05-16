/**
 * @vitest-environment jsdom
 */
import { describe, it, expect } from 'vitest';
import { createBadge } from './ui.js';

describe('createBadge', () => {
    it('returns null if count is 0', () => {
        const badge = createBadge(0);
        expect(badge).toBeNull();
    });

    it('returns null if count is less than 0', () => {
        const badge = createBadge(-5);
        expect(badge).toBeNull();
    });

    it('creates a span element with correct classes and text content for a positive count', () => {
        const badge = createBadge(10);

        expect(badge).not.toBeNull();
        expect(badge.tagName).toBe('SPAN');
        expect(badge.classList.contains('unread-count-badge')).toBe(true);
        expect(badge.textContent).toBe('10');
    });
});
