import { formatDate, throttle, sanitizeUrl } from './utils.js';

const SCROLL_BUFFER = 200; // Pixels from bottom to trigger load
const SCROLL_THROTTLE = 200; // ms


// --- Toast Notification ---

export function showToast(message, type = 'info', duration = 3000) {
    const toastContainer = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;

    toastContainer.appendChild(toast);

    // Animate in
    setTimeout(() => {
        toast.classList.add('show');
    }, 100);

    // Animate out and remove
    setTimeout(() => {
        toast.classList.remove('show');
        const removalTimeout = setTimeout(() => toast.remove(), 500);
        toast.addEventListener('transitionend', () => {
            clearTimeout(removalTimeout);
            toast.remove();
        }, { once: true });
    }, duration);
}

// --- Badge ---

export function createBadge(count) {
    if (count > 0) {
        const badge = document.createElement('span');
        badge.classList.add('unread-count-badge');
        badge.textContent = count;
        return badge;
    }
    return null;
}

export function updateUnreadCount(element) {
    if (!element) return;
    const badge = element.querySelector('.unread-count-badge');
    if (badge) {
        const count = parseInt(badge.textContent, 10);
        if (!isNaN(count)) {
            const newCount = count - 1;
            if (newCount > 0) {
                badge.textContent = newCount;
            } else {
                badge.remove();
            }
        }
    }
}

// --- Feed Item ---

function createFeedItemElement(item, clickHandler) {
    const listItem = document.createElement('li');
    listItem.dataset.itemId = item.id;
    listItem.classList.add(item.is_read ? 'read' : 'unread');

    const hasComments = Boolean(
        item.comments_url &&
        typeof item.comments_url === 'string' &&
        item.comments_url.trim() !== '' &&
        item.comments_url !== item.link
    );

    // Primary link: Discussion thread if available (default/primary), otherwise article link
    const primaryUrl = hasComments ? item.comments_url : item.link;
    const link = document.createElement('a');
    link.href = sanitizeUrl(primaryUrl);
    link.textContent = item.title;
    link.target = '_blank';
    link.rel = 'noopener noreferrer';
    if (hasComments) {
        link.title = 'Open discussion thread';
    }
    link.addEventListener('click', () => clickHandler(listItem));
    link.addEventListener('auxclick', (event) => {
        if (event.button === 1) {
            clickHandler(listItem);
        }
    });
    listItem.appendChild(link);

    const timestamp = document.createElement('span');
    timestamp.className = 'item-meta';
    timestamp.textContent = formatDate(item.published_time || item.fetched_time);

    if (hasComments && item.link) {
        const separator = document.createTextNode(' · ');
        timestamp.appendChild(separator);

        const articleLink = document.createElement('a');
        articleLink.href = sanitizeUrl(item.link);
        articleLink.textContent = '[article]';
        articleLink.className = 'item-article-link';
        articleLink.target = '_blank';
        articleLink.rel = 'noopener noreferrer';
        articleLink.title = 'Open original article';
        articleLink.setAttribute('aria-label', `Open original article: ${item.title}`);
        articleLink.addEventListener('click', () => clickHandler(listItem));
        articleLink.addEventListener('auxclick', (event) => {
            if (event.button === 1) {
                clickHandler(listItem);
            }
        });
        timestamp.appendChild(articleLink);
    }

    listItem.appendChild(timestamp);

    return listItem;
}

// --- Feed Widget ---

export function createFeedWidget(feed, callbacks) {
    const { onEdit, onDelete, onMarkItemRead, onLoadMore } = callbacks;
    const widget = document.createElement('div');
    widget.classList.add('feed-widget');
    widget.dataset.feedId = feed.id;
    widget.dataset.tabId = feed.tab_id;

    // Header with buttons
    const buttonContainer = document.createElement('div');
    buttonContainer.classList.add('feed-widget-buttons');

    const editButton = document.createElement('button');
    editButton.classList.add('edit-feed-button');
    editButton.textContent = '✎';
    editButton.title = 'Edit Feed';
    editButton.setAttribute('aria-label', 'Edit Feed');
    editButton.addEventListener('click', (e) => {
        e.stopPropagation();
        onEdit(feed.id, feed.url, feed.name);
    });
    buttonContainer.appendChild(editButton);

    const deleteButton = document.createElement('button');
    deleteButton.classList.add('delete-feed-button');
    deleteButton.textContent = 'X';
    deleteButton.title = 'Delete Feed';
    deleteButton.setAttribute('aria-label', 'Delete Feed');
    deleteButton.addEventListener('click', (e) => {
        e.stopPropagation();
        onDelete(feed.id);
    });
    buttonContainer.appendChild(deleteButton);

    const titleElement = document.createElement('h2');
    const titleTextNode = document.createTextNode(feed.name);
    const feedLinkUrl = feed.site_link || feed.url;

    if (feedLinkUrl) {
        const titleLink = document.createElement('a');
        titleLink.href = sanitizeUrl(feedLinkUrl);
        titleLink.target = '_blank';
        titleLink.rel = 'noopener noreferrer';
        titleLink.appendChild(titleTextNode);
        titleElement.appendChild(titleLink);
    } else {
        titleElement.appendChild(titleTextNode);
    }

    const badge = createBadge(feed.unread_count);
    if (badge) {
        buttonContainer.prepend(badge);
    }

    titleElement.appendChild(buttonContainer);
    widget.appendChild(titleElement);

    // List
    const itemList = document.createElement('ul');
    widget.appendChild(itemList);

    const items = feed.items || [];
    itemList.dataset.offset = items.length;
    itemList.dataset.feedId = feed.id;
    itemList.dataset.tabId = feed.tab_id;
    itemList.dataset.loading = 'false';
    itemList.dataset.allItemsLoaded = 'false';

    // Infinite Scroll: Per-widget implementation
    const onScroll = () => {
        if (itemList.dataset.allItemsLoaded === 'true') {
            itemList.removeEventListener('scroll', throttledScroll);
            return;
        }
        if (itemList.offsetParent === null) return;

        if (itemList.scrollTop + itemList.clientHeight >= itemList.scrollHeight - SCROLL_BUFFER) {
            onLoadMore(itemList);
        }
    };
    const throttledScroll = throttle(onScroll, SCROLL_THROTTLE);
    itemList.addEventListener('scroll', throttledScroll);

    // Render Items
    if (feed.items && feed.items.length > 0) {
        const fragment = document.createDocumentFragment();
        feed.items.forEach(item => {
            const listItem = createFeedItemElement(item, (li) => {
                onMarkItemRead(item.id, li, feed.id, feed.tab_id);
            });
            fragment.appendChild(listItem);
        });
        itemList.appendChild(fragment);
    } else {
        itemList.innerHTML = '<li>No items found for this feed.</li>';
    }

    // Programmatically trigger a scroll event to handle cases where the initial
    // content is not enough to make the list scrollable.
    // Dispatch AFTER rendering so we check the actual content height.
    setTimeout(() => {
        itemList.dispatchEvent(new Event('scroll'));
    }, 0);

    return widget;
}

export function appendItemsToFeedWidget(widgetList, items, callbacks) {
    const { onMarkItemRead } = callbacks;
    const feedId = widgetList.dataset.feedId;
    const tabId = widgetList.dataset.tabId;
    const fragment = document.createDocumentFragment();

    items.forEach(item => {
        const listItem = createFeedItemElement(item, (li) => {
            onMarkItemRead(item.id, li, feedId, tabId);
        });
        fragment.appendChild(listItem);
    });
    widgetList.appendChild(fragment);

    // Update offset
    const currentOffset = parseInt(widgetList.dataset.offset) || 0;
    widgetList.dataset.offset = currentOffset + items.length;
}

// --- Tabs ---

export function renderTabs(tabs, activeTabId, callbacks) {
    const { onSwitchTab } = callbacks;
    const tabsContainer = document.getElementById('tabs-container');
    const feedGrid = document.getElementById('feed-grid');
    const renameTabButton = document.getElementById('rename-tab-button');
    const deleteTabButton = document.getElementById('delete-tab-button');

    tabsContainer.innerHTML = '';
    if (!tabs || tabs.length === 0) {
        tabsContainer.innerHTML = '<span>No tabs found.</span>';
        renameTabButton.disabled = true;
        deleteTabButton.disabled = true;
        feedGrid.innerHTML = '<p>Create a tab to get started!</p>';
        return { activeTabId: null };
    }

    tabs.sort((a, b) => a.order - b.order);

    tabs.forEach(tab => {
        const button = document.createElement('button');
        button.textContent = tab.name;
        button.dataset.tabId = tab.id;
        const isActive = tab.id == activeTabId;
        button.classList.toggle('active', isActive);
        button.setAttribute('role', 'tab');
        button.setAttribute('aria-selected', isActive ? 'true' : 'false');
        button.setAttribute('aria-controls', 'feed-grid');
        button.addEventListener('click', () => onSwitchTab(tab.id));

        const badge = createBadge(tab.unread_count);
        if (badge) {
            button.appendChild(badge);
        }

        tabsContainer.appendChild(button);
    });

    renameTabButton.disabled = false;
    deleteTabButton.disabled = tabs.length <= 1;

    return { activeTabId }; // Useful if selection logic was internal, but here it's passed in
}

// --- Modals ---

export function showEditFeedModal(feedId, currentUrl, currentName) {
    const modal = document.getElementById('edit-feed-modal');
    document.getElementById('edit-feed-id').value = feedId;
    document.getElementById('edit-feed-url').value = currentUrl;
    document.getElementById('edit-feed-name').value = currentName;
    document.getElementById('edit-feed-error').classList.add('hidden');
    modal.classList.add('is-active');
}

export function closeEditFeedModal() {
    document.getElementById('edit-feed-modal').classList.remove('is-active');
}

// --- Progress Bar ---

export function showProgress(message) {
    const progressContainer = document.getElementById('progress-container');
    const progressStatus = document.getElementById('progress-status');
    const progressBar = document.getElementById('progress-bar');

    progressStatus.textContent = message;
    progressBar.value = 0;
    progressContainer.classList.remove('hidden');
}

export function updateProgress(status, value, max) {
    const progressStatus = document.getElementById('progress-status');
    const progressBar = document.getElementById('progress-bar');

    progressStatus.textContent = status;
    progressBar.value = value;
    progressBar.max = max;
}

export function hideProgress() {
    const progressContainer = document.getElementById('progress-container');
    progressContainer.classList.add('hidden');
}

export function updateProgressBarPosition() {
    // No longer needed, handled by CSS .sticky-nav
}
