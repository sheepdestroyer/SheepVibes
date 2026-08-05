/**
 * @vitest-environment jsdom
 */
import { describe, it, expect } from 'vitest';
import { createBadge, createFeedWidget } from './ui.js';

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

describe('createFeedWidget URL sanitization', () => {
    it('sanitizes unsafe link schemes in feed item links and widget title link', () => {
        const feed = {
            id: 1,
            tab_id: 1,
            name: 'Test Feed',
            site_link: 'javascript:alert("xss")',
            url: 'http://example.com/rss',
            unread_count: 0,
            items: [
                {
                    id: 101,
                    title: 'Unsafe Item',
                    link: 'javascript:alert(1)',
                    is_read: false,
                    published_time: '2026-01-01T00:00:00Z'
                }
            ]
        };

        const widget = createFeedWidget(feed, {
            onEdit: () => {},
            onDelete: () => {},
            onMarkItemRead: () => {},
            onLoadMore: () => {}
        });

        const titleLink = widget.querySelector('h2 a');
        expect(titleLink.getAttribute('href')).toBe('#');

        const itemLink = widget.querySelector('ul li a');
        expect(itemLink.getAttribute('href')).toBe('#');
    });
});
