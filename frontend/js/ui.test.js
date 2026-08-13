/**
 * @vitest-environment jsdom
 */
import { describe, it, expect, vi } from 'vitest';
import {
    createBadge,
    updateUnreadCount,
    createFeedWidget,
    appendItemsToFeedWidget,
    renderTabs,
    showToast,
    showProgress,
    updateProgress,
    hideProgress,
    showEditFeedModal,
    closeEditFeedModal
} from './ui.js';

describe('createBadge', () => {
    it('returns null if count is 0', () => {
        const badge = createBadge(0);
        expect(badge).toBeNull();
    });

    it('returns null if count is less than 0', () => {
        const badge = createBadge(-5);
        expect(badge).toBeNull();
    });

    it('returns null if count is null or undefined', () => {
        expect(createBadge(null)).toBeNull();
        expect(createBadge(undefined)).toBeNull();
    });

    it('creates a span element with correct classes and text content for a positive count', () => {
        const badge = createBadge(10);

        expect(badge).not.toBeNull();
        expect(badge.tagName).toBe('SPAN');
        expect(badge.classList.contains('unread-count-badge')).toBe(true);
        expect(badge.textContent).toBe('10');
    });
});

describe('updateUnreadCount', () => {
    it('decrements unread badge count when count is greater than 1', () => {
        const container = document.createElement('div');
        const badge = createBadge(5);
        container.appendChild(badge);

        updateUnreadCount(container);
        expect(container.querySelector('.unread-count-badge')).not.toBeNull();
        expect(container.querySelector('.unread-count-badge').textContent).toBe('4');
    });

    it('removes unread badge element when count decrements to 0', () => {
        const container = document.createElement('div');
        const badge = createBadge(1);
        container.appendChild(badge);

        updateUnreadCount(container);
        expect(container.querySelector('.unread-count-badge')).toBeNull();
    });

    it('gracefully handles elements without badges or invalid content', () => {
        const emptyContainer = document.createElement('div');
        expect(() => updateUnreadCount(emptyContainer)).not.toThrow();

        const invalidBadgeContainer = document.createElement('div');
        const invalidBadge = document.createElement('span');
        invalidBadge.className = 'unread-count-badge';
        invalidBadge.textContent = 'not-a-number';
        invalidBadgeContainer.appendChild(invalidBadge);

        expect(() => updateUnreadCount(invalidBadgeContainer)).not.toThrow();
        expect(() => updateUnreadCount(null)).not.toThrow();
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

    it('preserves safe URL schemes for both discussion and article links', () => {
        const feed = {
            id: 1,
            tab_id: 1,
            name: 'Safe Feed',
            site_link: 'https://news.ycombinator.com',
            url: 'https://news.ycombinator.com/rss',
            unread_count: 0,
            items: [
                {
                    id: 102,
                    title: 'Safe Item',
                    link: 'https://example.com/article',
                    comments_url: 'https://news.ycombinator.com/item?id=123',
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

        const titleLink = widget.querySelector('ul li a:not(.item-article-link)');
        expect(titleLink.getAttribute('href')).toBe('https://news.ycombinator.com/item?id=123');

        const articleLink = widget.querySelector('.item-article-link');
        expect(articleLink.getAttribute('href')).toBe('https://example.com/article');
    });
});

describe('createFeedWidget comments_url and article link handling', () => {
    it('sets comments thread as primary title link and renders secondary article link when comments_url differs from link', () => {
        let markedReadCalls = [];
        const feed = {
            id: 1,
            tab_id: 2,
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
            onMarkItemRead: (id, li, feedId, tabId) => {
                markedReadCalls.push({ id, li, feedId, tabId });
            },
            onLoadMore: () => {}
        });

        const listItem = widget.querySelector('ul li');
        expect(listItem.classList.contains('unread')).toBe(true);
        expect(listItem.classList.contains('read')).toBe(false);
        expect(listItem.dataset.itemId).toBe('201');

        // Primary title link
        const titleLink = widget.querySelector('ul li a:not(.item-article-link)');
        expect(titleLink).not.toBeNull();
        expect(titleLink.getAttribute('href')).toBe('https://news.ycombinator.com/item?id=49289112');
        expect(titleLink.textContent).toBe('Show HN: SheepVibes');
        expect(titleLink.getAttribute('title')).toBe('Open discussion thread');
        expect(titleLink.getAttribute('target')).toBe('_blank');
        expect(titleLink.getAttribute('rel')).toBe('noopener noreferrer');

        // Secondary article link
        const metaSpan = widget.querySelector('ul li .item-meta');
        expect(metaSpan).not.toBeNull();
        expect(metaSpan.textContent).toContain(' · ');

        const articleLink = widget.querySelector('ul li .item-article-link');
        expect(articleLink).not.toBeNull();
        expect(articleLink.getAttribute('href')).toBe('https://github.com/sheepdestroyer/SheepVibes');
        expect(articleLink.textContent).toBe('[article]');
        expect(articleLink.getAttribute('title')).toBe('Open original article');
        expect(articleLink.getAttribute('aria-label')).toBe('Open original article: Show HN: SheepVibes');
        expect(articleLink.getAttribute('target')).toBe('_blank');
        expect(articleLink.getAttribute('rel')).toBe('noopener noreferrer');

        // Test clicking primary title link triggers mark read with proper arguments
        titleLink.dispatchEvent(new MouseEvent('click', { bubbles: true }));
        expect(markedReadCalls).toHaveLength(1);
        expect(markedReadCalls[0]).toEqual({
            id: 201,
            li: listItem,
            feedId: 1,
            tabId: 2
        });

        // Test middle-click (button 1) on primary title link
        titleLink.dispatchEvent(new MouseEvent('auxclick', { button: 1, bubbles: true }));
        expect(markedReadCalls).toHaveLength(2);

        // Test right-click (button 2) on primary title link does NOT trigger mark read
        titleLink.dispatchEvent(new MouseEvent('auxclick', { button: 2, bubbles: true }));
        expect(markedReadCalls).toHaveLength(2);

        // Test clicking secondary article link triggers mark read
        articleLink.dispatchEvent(new MouseEvent('click', { bubbles: true }));
        expect(markedReadCalls).toHaveLength(3);
        expect(markedReadCalls[2].id).toBe(201);

        // Test middle-click (button 1) on secondary article link
        articleLink.dispatchEvent(new MouseEvent('auxclick', { button: 1, bubbles: true }));
        expect(markedReadCalls).toHaveLength(4);

        // Test right-click (button 2) on secondary article link does NOT trigger mark read
        articleLink.dispatchEvent(new MouseEvent('auxclick', { button: 2, bubbles: true }));
        expect(markedReadCalls).toHaveLength(4);
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
                    is_read: true,
                    published_time: '2026-08-14T00:00:00Z'
                },
                {
                    id: 302,
                    title: 'Ask HN / Self Post',
                    link: 'https://news.ycombinator.com/item?id=49289200',
                    comments_url: 'https://news.ycombinator.com/item?id=49289200',
                    is_read: false,
                    published_time: '2026-08-14T00:05:00Z'
                },
                {
                    id: 303,
                    title: 'Whitespace Comments Item',
                    link: 'https://example.com/whitespace-comments',
                    comments_url: '   \t  ',
                    is_read: false,
                    published_time: '2026-08-14T00:10:00Z'
                },
                {
                    id: 304,
                    title: 'Non-string Comments Item',
                    link: 'https://example.com/non-string-comments',
                    comments_url: 12345,
                    is_read: false,
                    published_time: '2026-08-14T00:15:00Z'
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
        expect(listItems.length).toBe(4);

        // First item (no comments_url, read state)
        expect(listItems[0].classList.contains('read')).toBe(true);
        expect(listItems[0].classList.contains('unread')).toBe(false);
        const item1TitleLink = listItems[0].querySelector('a');
        expect(item1TitleLink.getAttribute('href')).toBe('https://example.com/standard-post');
        expect(item1TitleLink.hasAttribute('title')).toBe(false);
        expect(listItems[0].querySelector('.item-article-link')).toBeNull();

        // Second item (comments_url == link)
        expect(listItems[1].classList.contains('unread')).toBe(true);
        const item2TitleLink = listItems[1].querySelector('a');
        expect(item2TitleLink.getAttribute('href')).toBe('https://news.ycombinator.com/item?id=49289200');
        expect(item2TitleLink.hasAttribute('title')).toBe(false);
        expect(listItems[1].querySelector('.item-article-link')).toBeNull();

        // Third item (whitespace comments_url)
        const item3TitleLink = listItems[2].querySelector('a');
        expect(item3TitleLink.getAttribute('href')).toBe('https://example.com/whitespace-comments');
        expect(listItems[2].querySelector('.item-article-link')).toBeNull();

        // Fourth item (non-string comments_url)
        const item4TitleLink = listItems[3].querySelector('a');
        expect(item4TitleLink.getAttribute('href')).toBe('https://example.com/non-string-comments');
        expect(listItems[3].querySelector('.item-article-link')).toBeNull();
    });

    it('renders empty fallback text when feed has no items', () => {
        const feed = {
            id: 3,
            tab_id: 1,
            name: 'Empty Feed',
            url: 'https://example.com/empty.xml',
            unread_count: 0,
            items: []
        };

        const widget = createFeedWidget(feed, {
            onEdit: () => {},
            onDelete: () => {},
            onMarkItemRead: () => {},
            onLoadMore: () => {}
        });

        const listItems = widget.querySelectorAll('ul li');
        expect(listItems.length).toBe(1);
        expect(listItems[0].textContent).toBe('No items found for this feed.');
    });
});

describe('appendItemsToFeedWidget', () => {
    it('appends items with mixed comments_url configurations and wires mark-as-read callbacks', () => {
        let markedReadCalls = [];
        const widgetList = document.createElement('ul');
        widgetList.dataset.feedId = '10';
        widgetList.dataset.tabId = '5';
        widgetList.dataset.offset = '2';

        const newItems = [
            {
                id: 401,
                title: 'Appended HN Story',
                link: 'https://example.com/appended-story',
                comments_url: 'https://news.ycombinator.com/item?id=401',
                is_read: false,
                published_time: '2026-08-14T02:00:00Z'
            },
            {
                id: 402,
                title: 'Appended Plain Story',
                link: 'https://example.com/plain-story',
                comments_url: null,
                is_read: true,
                published_time: '2026-08-14T02:05:00Z'
            }
        ];

        appendItemsToFeedWidget(widgetList, newItems, {
            onMarkItemRead: (id, li, feedId, tabId) => {
                markedReadCalls.push({ id, li, feedId, tabId });
            }
        });

        // Offset updated
        expect(widgetList.dataset.offset).toBe('4');

        const listItems = widgetList.querySelectorAll('li');
        expect(listItems.length).toBe(2);

        // First item has discussion link and secondary article link
        const item1 = listItems[0];
        expect(item1.dataset.itemId).toBe('401');
        expect(item1.classList.contains('unread')).toBe(true);

        const item1Discussion = item1.querySelector('a:not(.item-article-link)');
        expect(item1Discussion.getAttribute('href')).toBe('https://news.ycombinator.com/item?id=401');
        expect(item1Discussion.getAttribute('title')).toBe('Open discussion thread');

        const item1Article = item1.querySelector('.item-article-link');
        expect(item1Article).not.toBeNull();
        expect(item1Article.getAttribute('href')).toBe('https://example.com/appended-story');

        // Test clicking appended article link marks item read
        item1Article.dispatchEvent(new MouseEvent('click', { bubbles: true }));
        expect(markedReadCalls).toHaveLength(1);
        expect(markedReadCalls[0]).toEqual({
            id: 401,
            li: item1,
            feedId: '10',
            tabId: '5'
        });

        // Second item has single link
        const item2 = listItems[1];
        expect(item2.dataset.itemId).toBe('402');
        expect(item2.classList.contains('read')).toBe(true);
        expect(item2.querySelector('.item-article-link')).toBeNull();
    });
});

describe('renderTabs', () => {
    it('renders tabs sorted by order with unread badges and active tab indicator', () => {
        document.body.innerHTML = `
            <div id="tabs-container"></div>
            <div id="feed-grid"></div>
            <button id="rename-tab-button"></button>
            <button id="delete-tab-button"></button>
        `;

        let switchedTabId = null;
        const tabs = [
            { id: 2, name: 'Tech', order: 1, unread_count: 3 },
            { id: 1, name: 'General', order: 0, unread_count: 0 }
        ];

        renderTabs(tabs, 2, {
            onSwitchTab: (id) => { switchedTabId = id; }
        });

        const buttons = document.querySelectorAll('#tabs-container button');
        expect(buttons.length).toBe(2);

        // Sorted by order
        expect(buttons[0].dataset.tabId).toBe('1');
        expect(buttons[0].textContent).toBe('General');
        expect(buttons[0].classList.contains('active')).toBe(false);
        expect(buttons[0].querySelector('.unread-count-badge')).toBeNull();

        expect(buttons[1].dataset.tabId).toBe('2');
        expect(buttons[1].textContent).toContain('Tech');
        expect(buttons[1].classList.contains('active')).toBe(true);
        expect(buttons[1].querySelector('.unread-count-badge').textContent).toBe('3');

        // Clicking switches tab
        buttons[0].dispatchEvent(new MouseEvent('click', { bubbles: true }));
        expect(switchedTabId).toBe(1);
    });

    it('handles empty tabs array gracefully', () => {
        document.body.innerHTML = `
            <div id="tabs-container"></div>
            <div id="feed-grid"></div>
            <button id="rename-tab-button"></button>
            <button id="delete-tab-button"></button>
        `;

        const result = renderTabs([], null, { onSwitchTab: () => {} });
        expect(result.activeTabId).toBeNull();
        expect(document.getElementById('tabs-container').textContent).toBe('No tabs found.');
        expect(document.getElementById('rename-tab-button').disabled).toBe(true);
        expect(document.getElementById('delete-tab-button').disabled).toBe(true);
    });
});

describe('Modals and Progress helpers', () => {
    it('opens and closes edit feed modal', () => {
        document.body.innerHTML = `
            <div id="edit-feed-modal">
                <input id="edit-feed-id" />
                <input id="edit-feed-url" />
                <input id="edit-feed-name" />
                <div id="edit-feed-error" class="hidden"></div>
            </div>
        `;

        showEditFeedModal('12', 'https://example.com/feed.xml', 'Example Feed');
        expect(document.getElementById('edit-feed-id').value).toBe('12');
        expect(document.getElementById('edit-feed-url').value).toBe('https://example.com/feed.xml');
        expect(document.getElementById('edit-feed-name').value).toBe('Example Feed');
        expect(document.getElementById('edit-feed-modal').classList.contains('is-active')).toBe(true);

        closeEditFeedModal();
        expect(document.getElementById('edit-feed-modal').classList.contains('is-active')).toBe(false);
    });

    it('shows, updates, and hides progress bar', () => {
        document.body.innerHTML = `
            <div id="progress-container" class="hidden">
                <span id="progress-status"></span>
                <progress id="progress-bar" value="0" max="100"></progress>
            </div>
        `;

        showProgress('Starting download...');
        expect(document.getElementById('progress-status').textContent).toBe('Starting download...');
        expect(document.getElementById('progress-bar').value).toBe(0);
        expect(document.getElementById('progress-container').classList.contains('hidden')).toBe(false);

        updateProgress('Processing items...', 50, 100);
        expect(document.getElementById('progress-status').textContent).toBe('Processing items...');
        expect(document.getElementById('progress-bar').value).toBe(50);
        expect(document.getElementById('progress-bar').max).toBe(100);

        hideProgress();
        expect(document.getElementById('progress-container').classList.contains('hidden')).toBe(true);
    });
});
