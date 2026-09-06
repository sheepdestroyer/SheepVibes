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
    openEditFeedModal,
    showEditFeedModal,
    closeEditFeedModal,
    updateFeedWidgetTitle,
    showLoginModal,
    closeLoginModal,
    showSetupWizardModal,
    closeSetupWizardModal,
    showChangePasswordModal,
    closeChangePasswordModal,
    renderUserState,
    clearUserState,
    getDraggedWidget,
    setDraggedWidget
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

        const itemLink = widget.querySelector('ul li a.item-title-link');
        expect(itemLink.getAttribute('href')).toBe('#');

        // Unsafe comments URL (sanitized to '#') should not render a comments link
        expect(widget.querySelector('.item-comments-link')).toBeNull();
    });

    it('suppresses comments link when comments_url after normalization matches article link', () => {
        const feed = {
            id: 1,
            tab_id: 1,
            name: 'Whitespace Match Feed',
            url: 'https://example.com/rss',
            unread_count: 0,
            items: [
                {
                    id: 103,
                    title: 'Whitespace Wrapped Match Item',
                    link: 'https://example.com/article-1',
                    comments_url: '   https://example.com/article-1 \t ',
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

        expect(widget.querySelector('.item-comments-link')).toBeNull();
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

        const titleLink = widget.querySelector('ul li .item-title-link');
        expect(titleLink.getAttribute('href')).toBe('https://example.com/article');

        const commentsLink = widget.querySelector('.item-comments-link');
        expect(commentsLink.getAttribute('href')).toBe('https://news.ycombinator.com/item?id=123');
    });

    it('renders widget title link with feed-widget-title class and title tooltip', () => {
        const feed = {
            id: 2,
            tab_id: 1,
            name: 'Wccftech',
            site_link: 'https://wccftech.com',
            url: 'https://wccftech.com/feed/',
            unread_count: 0,
            items: []
        };

        const widget = createFeedWidget(feed, {
            onEdit: () => {},
            onDelete: () => {},
            onMarkItemRead: () => {},
            onLoadMore: () => {}
        });

        const headerLink = widget.querySelector('h2 a.feed-widget-title');
        expect(headerLink).not.toBeNull();
        expect(headerLink.textContent).toBe('Wccftech');
        expect(headerLink.getAttribute('title')).toBe('Wccftech');
        expect(headerLink.getAttribute('href')).toBe('https://wccftech.com');
    });

    it('renders widget title span with feed-widget-title class and title tooltip when site_link is null', () => {
        const feed = {
            id: 3,
            tab_id: 1,
            name: 'Plain Feed',
            site_link: null,
            url: null,
            unread_count: 0,
            items: []
        };

        const widget = createFeedWidget(feed, {
            onEdit: () => {},
            onDelete: () => {},
            onMarkItemRead: () => {},
            onLoadMore: () => {}
        });

        const headerSpan = widget.querySelector('h2 span.feed-widget-title');
        expect(headerSpan).not.toBeNull();
        expect(headerSpan.textContent).toBe('Plain Feed');
        expect(headerSpan.getAttribute('title')).toBe('Plain Feed');
    });
});

describe('createFeedWidget comments_url and article link handling', () => {
    it('sets article as primary title link and renders secondary comments link when comments_url differs from link', () => {
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

        // Primary title link -> Original article
        const titleLink = widget.querySelector('ul li .item-title-link');
        expect(titleLink).not.toBeNull();
        expect(titleLink.getAttribute('href')).toBe('https://github.com/sheepdestroyer/SheepVibes');
        expect(titleLink.textContent).toBe('Show HN: SheepVibes');
        expect(titleLink.hasAttribute('title')).toBe(false);
        expect(titleLink.getAttribute('target')).toBe('_blank');
        expect(titleLink.getAttribute('rel')).toBe('noopener noreferrer');

        // Secondary comments link -> Discussion thread
        const metaSpan = widget.querySelector('ul li .item-meta');
        expect(metaSpan).not.toBeNull();
        expect(metaSpan.textContent).toContain(' · ');

        const commentsLink = widget.querySelector('ul li .item-comments-link');
        expect(commentsLink).not.toBeNull();
        expect(commentsLink.getAttribute('href')).toBe('https://news.ycombinator.com/item?id=49289112');
        expect(commentsLink.textContent).toBe('comments');
        expect(commentsLink.getAttribute('title')).toBe('Open discussion thread');
        expect(commentsLink.getAttribute('aria-label')).toBe('Open discussion thread: Show HN: SheepVibes');
        expect(commentsLink.getAttribute('target')).toBe('_blank');
        expect(commentsLink.getAttribute('rel')).toBe('noopener noreferrer');

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

        // Test clicking secondary comments link triggers mark read
        commentsLink.dispatchEvent(new MouseEvent('click', { bubbles: true }));
        expect(markedReadCalls).toHaveLength(3);
        expect(markedReadCalls[2].id).toBe(201);

        // Test middle-click (button 1) on secondary comments link
        commentsLink.dispatchEvent(new MouseEvent('auxclick', { button: 1, bubbles: true }));
        expect(markedReadCalls).toHaveLength(4);

        // Test right-click (button 2) on secondary comments link does NOT trigger mark read
        commentsLink.dispatchEvent(new MouseEvent('auxclick', { button: 2, bubbles: true }));
        expect(markedReadCalls).toHaveLength(4);
    });

    it('uses article link as primary and does not render secondary comments link when comments_url is missing or equal to link', () => {
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
        expect(listItems[0].querySelector('.item-comments-link')).toBeNull();

        // Second item (comments_url == link)
        expect(listItems[1].classList.contains('unread')).toBe(true);
        const item2TitleLink = listItems[1].querySelector('a');
        expect(item2TitleLink.getAttribute('href')).toBe('https://news.ycombinator.com/item?id=49289200');
        expect(item2TitleLink.hasAttribute('title')).toBe(false);
        expect(listItems[1].querySelector('.item-comments-link')).toBeNull();

        // Third item (whitespace comments_url)
        const item3TitleLink = listItems[2].querySelector('a');
        expect(item3TitleLink.getAttribute('href')).toBe('https://example.com/whitespace-comments');
        expect(listItems[2].querySelector('.item-comments-link')).toBeNull();

        // Fourth item (non-string comments_url)
        const item4TitleLink = listItems[3].querySelector('a');
        expect(item4TitleLink.getAttribute('href')).toBe('https://example.com/non-string-comments');
        expect(listItems[3].querySelector('.item-comments-link')).toBeNull();
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

        // First item has primary article link and secondary comments link
        const item1 = listItems[0];
        expect(item1.dataset.itemId).toBe('401');
        expect(item1.classList.contains('unread')).toBe(true);

        const item1Article = item1.querySelector('.item-title-link');
        expect(item1Article.getAttribute('href')).toBe('https://example.com/appended-story');

        const item1Comments = item1.querySelector('.item-comments-link');
        expect(item1Comments).not.toBeNull();
        expect(item1Comments.getAttribute('href')).toBe('https://news.ycombinator.com/item?id=401');
        expect(item1Comments.textContent).toBe('comments');
        expect(item1Comments.getAttribute('title')).toBe('Open discussion thread');

        // Test clicking appended comments link marks item read
        item1Comments.dispatchEvent(new MouseEvent('click', { bubbles: true }));
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
        expect(item2.querySelector('.item-comments-link')).toBeNull();
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
    it('opens and closes edit feed modal with editable custom name', () => {
        document.body.innerHTML = `
            <div id="edit-feed-modal">
                <input id="edit-feed-id" />
                <input id="edit-feed-url" />
                <input id="edit-feed-name" />
                <small>Enter a custom name, or leave empty to auto-derive from the feed title</small>
                <div id="edit-feed-error" class="hidden"></div>
            </div>
        `;

        const nameInput = document.getElementById('edit-feed-name');
        expect(nameInput.hasAttribute('readonly')).toBe(false);

        openEditFeedModal('12', 'https://example.com/feed.xml', 'Custom Feed Name');
        expect(document.getElementById('edit-feed-id').value).toBe('12');
        expect(document.getElementById('edit-feed-url').value).toBe('https://example.com/feed.xml');
        expect(document.getElementById('edit-feed-name').value).toBe('Custom Feed Name');
        expect(document.getElementById('edit-feed-modal').classList.contains('is-active')).toBe(true);

        closeEditFeedModal();
        expect(document.getElementById('edit-feed-modal').classList.contains('is-active')).toBe(false);

        // Test with null/undefined name defaults to empty string
        openEditFeedModal('13', 'https://example.com/feed2.xml', null);
        expect(document.getElementById('edit-feed-name').value).toBe('');
        closeEditFeedModal();
    });

    it('updates feed widget title in DOM immediately with updateFeedWidgetTitle', () => {
        document.body.innerHTML = `
            <div class="feed-widget" data-feed-id="42">
                <h2>
                    <a class="feed-widget-title" href="https://old.example.com" title="Old Title">Old Title</a>
                </h2>
            </div>
            <div class="feed-widget" data-feed-id="43">
                <h2>
                    <span class="feed-widget-title" title="Old Span Title">Old Span Title</span>
                </h2>
            </div>
        `;

        const updatedWidget = updateFeedWidgetTitle('42', 'New Custom Title', 'https://new.example.com');
        expect(updatedWidget).not.toBeNull();
        const link = document.querySelector('.feed-widget[data-feed-id="42"] h2 a.feed-widget-title');
        expect(link.textContent).toBe('New Custom Title');
        expect(link.getAttribute('title')).toBe('New Custom Title');
        expect(link.getAttribute('href')).toBe('https://new.example.com');

        // Test span widget without site link
        const updatedSpan = updateFeedWidgetTitle('43', 'New Span Title');
        expect(updatedSpan).not.toBeNull();
        const span = document.querySelector('.feed-widget[data-feed-id="43"] h2 span.feed-widget-title');
        expect(span.textContent).toBe('New Span Title');
        expect(span.getAttribute('title')).toBe('New Span Title');

        // Test non-existent widget
        expect(updateFeedWidgetTitle('999', 'Ghost')).toBeNull();
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

    it('handles login modal display and dismissal', () => {
        document.body.innerHTML = `
            <div id="login-modal">
                <input id="login-username" />
                <input id="login-password" />
                <div id="login-error" class="hidden"></div>
            </div>
        `;

        showLoginModal('Invalid username or password');
        expect(document.getElementById('login-modal').classList.contains('is-active')).toBe(true);
        expect(document.getElementById('login-error').textContent).toBe('Invalid username or password');
        expect(document.getElementById('login-error').classList.contains('hidden')).toBe(false);

        closeLoginModal();
        expect(document.getElementById('login-modal').classList.contains('is-active')).toBe(false);
        expect(document.getElementById('login-error').classList.contains('hidden')).toBe(true);
    });

    it('handles change password modal display and dismissal', () => {
        document.body.innerHTML = `
            <div id="change-password-modal">
                <input id="change-password-current" />
                <input id="change-password-new" />
                <input id="change-password-confirm" />
                <div id="change-password-error" class="hidden"></div>
                <div id="change-password-success" class="hidden"></div>
            </div>
        `;

        showChangePasswordModal('Passwords do not match');
        expect(document.getElementById('change-password-modal').classList.contains('is-active')).toBe(true);
        expect(document.getElementById('change-password-error').textContent).toBe('Passwords do not match');
        expect(document.getElementById('change-password-error').classList.contains('hidden')).toBe(false);

        showChangePasswordModal(null, 'Password updated successfully!');
        expect(document.getElementById('change-password-success').textContent).toBe('Password updated successfully!');
        expect(document.getElementById('change-password-success').classList.contains('hidden')).toBe(false);
        expect(document.getElementById('change-password-error').classList.contains('hidden')).toBe(true);

        closeChangePasswordModal();
        expect(document.getElementById('change-password-modal').classList.contains('is-active')).toBe(false);
    });

    it('renders and clears user state in navigation', () => {
        document.body.innerHTML = `
            <div id="user-menu-container" class="hidden">
                <span id="user-display-name"></span>
                <div id="user-menu" class="hidden">
                    <span id="user-menu-username"></span>
                    <span id="user-role-badge"></span>
                    <button id="admin-panel-button" class="hidden"></button>
                </div>
            </div>
        `;

        // Regular user
        renderUserState({ id: 1, username: 'testuser', role: 'user' });
        expect(document.getElementById('user-display-name').textContent).toBe('testuser');
        expect(document.getElementById('user-menu-username').textContent).toBe('testuser');
        expect(document.getElementById('user-role-badge').textContent).toBe('user');
        expect(document.getElementById('user-menu-container').classList.contains('hidden')).toBe(false);
        expect(document.getElementById('admin-panel-button').classList.contains('hidden')).toBe(true);

        // Admin user
        renderUserState({ id: 2, username: 'superadmin', role: 'admin' });
        expect(document.getElementById('user-display-name').textContent).toBe('superadmin');
        expect(document.getElementById('user-role-badge').textContent).toBe('admin');
        expect(document.getElementById('admin-panel-button').classList.contains('hidden')).toBe(false);

        // Clear user state
        clearUserState();
        expect(document.getElementById('user-menu-container').classList.contains('hidden')).toBe(true);
        expect(document.getElementById('user-menu').classList.contains('hidden')).toBe(true);
        expect(document.getElementById('admin-panel-button').classList.contains('hidden')).toBe(true);
    });

    it('opens and closes setup wizard modal with error banner support', () => {
        document.body.innerHTML = `
            <div id="setup-wizard-modal" class="modal">
                <input id="setup-username" />
                <div id="setup-wizard-error" class="hidden"></div>
            </div>
        `;

        showSetupWizardModal('Passwords do not match');
        expect(document.getElementById('setup-wizard-modal').classList.contains('is-active')).toBe(true);
        expect(document.getElementById('setup-wizard-error').textContent).toBe('Passwords do not match');
        expect(document.getElementById('setup-wizard-error').classList.contains('hidden')).toBe(false);

        closeSetupWizardModal();
        expect(document.getElementById('setup-wizard-modal').classList.contains('is-active')).toBe(false);
        expect(document.getElementById('setup-wizard-error').classList.contains('hidden')).toBe(true);
    });
});

describe('drag and drop widgets and tabs', () => {
    function createMockDataTransfer() {
        const data = {};
        return {
            effectAllowed: 'none',
            dropEffect: 'none',
            setData: (type, val) => { data[type] = val; },
            getData: (type) => data[type] || ''
        };
    }

    it('renders drag handle and sets draggable attribute on feed widget', () => {
        const feed = { id: 10, tab_id: 1, name: 'Tech Feed', url: 'https://example.com', unread_count: 0, items: [] };
        const callbacks = {
            onEdit: vi.fn(),
            onDelete: vi.fn(),
            onMarkItemRead: vi.fn(),
            onLoadMore: vi.fn(),
            onReorderFeeds: vi.fn()
        };

        const widget = createFeedWidget(feed, callbacks);
        expect(widget.getAttribute('draggable')).toBe('true');

        const dragHandle = widget.querySelector('.feed-drag-handle');
        expect(dragHandle).not.toBeNull();
        expect(dragHandle.getAttribute('role')).toBe('button');
        expect(dragHandle.getAttribute('aria-grabbed')).toBe('false');
        expect(dragHandle.textContent).toBe('⋮⋮');
    });

    it('initiates dragstart from handle or header and sets dragging state', () => {
        const feed = { id: 20, tab_id: 1, name: 'News Feed', url: 'https://example.com', unread_count: 0, items: [] };
        const widget = createFeedWidget(feed, {
            onEdit: vi.fn(),
            onDelete: vi.fn(),
            onMarkItemRead: vi.fn(),
            onLoadMore: vi.fn(),
            onReorderFeeds: vi.fn()
        });

        const dt = createMockDataTransfer();
        const dragHandle = widget.querySelector('.feed-drag-handle');
        const dragEvent = new Event('dragstart', { bubbles: true, cancelable: true });
        dragEvent.dataTransfer = dt;

        dragHandle.dispatchEvent(dragEvent);

        expect(widget.classList.contains('is-dragging')).toBe(true);
        expect(dragHandle.getAttribute('aria-grabbed')).toBe('true');
        expect(dt.effectAllowed).toBe('move');
        expect(dt.getData('text/plain')).toBe('20');
        expect(getDraggedWidget()).toBe(widget);

        // dragend resets state
        widget.dispatchEvent(new Event('dragend', { bubbles: true }));
        expect(widget.classList.contains('is-dragging')).toBe(false);
        expect(dragHandle.getAttribute('aria-grabbed')).toBe('false');
        expect(getDraggedWidget()).toBeNull();
    });

    it('cancels dragstart when initiated on an action button or link', () => {
        const feed = { id: 30, tab_id: 1, name: 'Blog Feed', url: 'https://example.com', unread_count: 0, items: [] };
        const widget = createFeedWidget(feed, {
            onEdit: vi.fn(),
            onDelete: vi.fn(),
            onMarkItemRead: vi.fn(),
            onLoadMore: vi.fn(),
            onReorderFeeds: vi.fn()
        });

        const editBtn = widget.querySelector('.edit-feed-button');
        const dt = createMockDataTransfer();
        const dragEvent = new Event('dragstart', { bubbles: true, cancelable: true });
        dragEvent.dataTransfer = dt;

        editBtn.dispatchEvent(dragEvent);

        expect(dragEvent.defaultPrevented).toBe(true);
        expect(widget.classList.contains('is-dragging')).toBe(false);
    });

    it('handles dragover and drop between widgets in the same tab and triggers onReorderFeeds', () => {
        const onReorderFeeds = vi.fn();
        const feedA = { id: 1, tab_id: 100, name: 'Feed A', url: 'https://a.com', unread_count: 0, items: [] };
        const feedB = { id: 2, tab_id: 100, name: 'Feed B', url: 'https://b.com', unread_count: 0, items: [] };

        const grid = document.createElement('div');
        grid.id = 'feed-grid';
        document.body.appendChild(grid);

        const widgetA = createFeedWidget(feedA, { onEdit: vi.fn(), onDelete: vi.fn(), onMarkItemRead: vi.fn(), onLoadMore: vi.fn(), onReorderFeeds });
        const widgetB = createFeedWidget(feedB, { onEdit: vi.fn(), onDelete: vi.fn(), onMarkItemRead: vi.fn(), onLoadMore: vi.fn(), onReorderFeeds });
        grid.appendChild(widgetA);
        grid.appendChild(widgetB);

        // Start dragging widgetA
        setDraggedWidget(widgetA);

        // Mock bounding rect for widgetB: left 100, width 200 (midpoint 200)
        widgetB.getBoundingClientRect = () => ({
            left: 100,
            right: 300,
            top: 0,
            bottom: 200,
            width: 200,
            height: 200
        });

        // Dragover to the right of midpoint (clientX: 250) -> drop-after
        const dragoverEvent = new Event('dragover', { bubbles: true, cancelable: true });
        dragoverEvent.clientX = 250;
        dragoverEvent.clientY = 50;
        dragoverEvent.dataTransfer = createMockDataTransfer();
        widgetB.dispatchEvent(dragoverEvent);

        expect(widgetB.classList.contains('drop-after')).toBe(true);
        expect(dragoverEvent.defaultPrevented).toBe(true);

        // Drop on widgetB
        const dropEvent = new Event('drop', { bubbles: true, cancelable: true });
        dropEvent.dataTransfer = createMockDataTransfer();
        widgetB.dispatchEvent(dropEvent);

        expect(widgetB.classList.contains('drop-after')).toBe(false);
        expect(onReorderFeeds).toHaveBeenCalledWith(100, [2, 1]);

        // Cleanup
        setDraggedWidget(null);
        grid.remove();
    });

    it('supports dragging widgets onto tab buttons to move feeds across tabs', () => {
        document.body.innerHTML = `
            <div id="tabs-container"></div>
            <div id="feed-grid"></div>
            <button id="rename-tab-button"></button>
            <button id="delete-tab-button"></button>
        `;

        const tabs = [
            { id: 1, name: 'Tab 1', order: 0, unread_count: 0 },
            { id: 2, name: 'Tab 2', order: 1, unread_count: 0 }
        ];
        const onMoveFeedToTab = vi.fn();
        renderTabs(tabs, 1, { onSwitchTab: vi.fn(), onMoveFeedToTab });

        const tabButtons = document.querySelectorAll('#tabs-container button');
        expect(tabButtons.length).toBe(2);

        // Create a dragged widget belonging to tab 1
        const feed = { id: 77, tab_id: 1, name: 'Feed 77', url: 'https://77.com', unread_count: 0, items: [] };
        const widget = createFeedWidget(feed, { onEdit: vi.fn(), onDelete: vi.fn(), onMarkItemRead: vi.fn(), onLoadMore: vi.fn() });
        setDraggedWidget(widget);

        // Dragover on Tab 2 button
        const tab2Btn = tabButtons[1];
        const dragoverEvent = new Event('dragover', { bubbles: true, cancelable: true });
        dragoverEvent.dataTransfer = createMockDataTransfer();
        tab2Btn.dispatchEvent(dragoverEvent);

        expect(tab2Btn.classList.contains('tab-drag-over')).toBe(true);
        expect(dragoverEvent.defaultPrevented).toBe(true);

        // Dragleave removes class
        tab2Btn.dispatchEvent(new Event('dragleave', { bubbles: true }));
        expect(tab2Btn.classList.contains('tab-drag-over')).toBe(false);

        // Drop on Tab 2 button
        tab2Btn.classList.add('tab-drag-over');
        const dropEvent = new Event('drop', { bubbles: true, cancelable: true });
        dropEvent.dataTransfer = createMockDataTransfer();
        tab2Btn.dispatchEvent(dropEvent);

        expect(tab2Btn.classList.contains('tab-drag-over')).toBe(false);
        expect(onMoveFeedToTab).toHaveBeenCalledWith(77, 2);

        setDraggedWidget(null);
    });
});

