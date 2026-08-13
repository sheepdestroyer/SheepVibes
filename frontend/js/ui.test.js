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
    it('sanitizes unsafe link schemes in feed item links, comments links, and widget title link', () => {
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
                    comments_url: 'javascript:alert(2)',
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

        const articleLink = widget.querySelector('.item-article-link');
        expect(articleLink.getAttribute('href')).toBe('#');
    });
});

describe('createFeedWidget comments_url and article link handling', () => {
    it('sets comments thread as primary title link and renders secondary article link when comments_url differs from link', () => {
        let markedReadId = null;
        const feed = {
            id: 1,
            tab_id: 1,
            name: 'Hacker News',
            url: 'https://news.ycombinator.com/rss',
            unread_count: 1,
            items: [
                {
                    id: 201,
                    title: 'Show HN: SheepVibes',
                    link: 'https://github.com/sheepdestroyer/SheepVibes',
                    comments_url: 'https://news.ycombinator.com/item?id=49289112',
                    is_read: false,
                    published_time: '2026-08-14T00:00:00Z'
                }
            ]
        };

        const widget = createFeedWidget(feed, {
            onEdit: () => {},
            onDelete: () => {},
            onMarkItemRead: (id) => { markedReadId = id; },
            onLoadMore: () => {}
        });

        const titleLink = widget.querySelector('ul li a:not(.item-article-link)');
        expect(titleLink).not.toBeNull();
        expect(titleLink.getAttribute('href')).toBe('https://news.ycombinator.com/item?id=49289112');
        expect(titleLink.textContent).toBe('Show HN: SheepVibes');
        expect(titleLink.getAttribute('title')).toBe('Open discussion thread');

        const articleLink = widget.querySelector('ul li .item-article-link');
        expect(articleLink).not.toBeNull();
        expect(articleLink.getAttribute('href')).toBe('https://github.com/sheepdestroyer/SheepVibes');
        expect(articleLink.textContent).toBe('[article]');
        expect(articleLink.getAttribute('title')).toBe('Open original article');

        // Test clicking title link triggers mark read
        titleLink.dispatchEvent(new MouseEvent('click', { bubbles: true }));
        expect(markedReadId).toBe(201);

        markedReadId = null;
        // Test clicking secondary article link triggers mark read
        articleLink.dispatchEvent(new MouseEvent('click', { bubbles: true }));
        expect(markedReadId).toBe(201);

        markedReadId = null;
        // Test middle-click (auxclick with button 1) triggers mark read
        articleLink.dispatchEvent(new MouseEvent('auxclick', { button: 1, bubbles: true }));
        expect(markedReadId).toBe(201);
    });

    it('uses article link as primary and does not render secondary article link when comments_url is missing or equal to link', () => {
        const feed = {
            id: 2,
            tab_id: 1,
            name: 'Standard Feed',
            url: 'https://example.com/rss',
            unread_count: 2,
            items: [
                {
                    id: 301,
                    title: 'Standard Item No Comments',
                    link: 'https://example.com/standard-post',
                    comments_url: null,
                    is_read: false,
                    published_time: '2026-08-14T00:00:00Z'
                },
                {
                    id: 302,
                    title: 'Ask HN / Self Post',
                    link: 'https://news.ycombinator.com/item?id=49289200',
                    comments_url: 'https://news.ycombinator.com/item?id=49289200',
                    is_read: false,
                    published_time: '2026-08-14T00:05:00Z'
                }
            ]
        };

        const widget = createFeedWidget(feed, {
            onEdit: () => {},
            onDelete: () => {},
            onMarkItemRead: () => {},
            onLoadMore: () => {}
        });

        const listItems = widget.querySelectorAll('ul li');
        expect(listItems.length).toBe(2);

        // First item (no comments_url)
        const item1TitleLink = listItems[0].querySelector('a');
        expect(item1TitleLink.getAttribute('href')).toBe('https://example.com/standard-post');
        expect(listItems[0].querySelector('.item-article-link')).toBeNull();

        // Second item (comments_url == link)
        const item2TitleLink = listItems[1].querySelector('a');
        expect(item2TitleLink.getAttribute('href')).toBe('https://news.ycombinator.com/item?id=49289200');
        expect(listItems[1].querySelector('.item-article-link')).toBeNull();
    });
});
