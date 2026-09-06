import { formatDate, throttle, sanitizeUrl, moveNode } from './utils.js';

let draggedWidget = null;

export function getDraggedWidget() {
    return draggedWidget;
}

export function setDraggedWidget(widget) {
    draggedWidget = widget;
}

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

    const articleUrl = sanitizeUrl(item.link || '');
    const commentsUrl = sanitizeUrl(item.comments_url || '');
    const hasComments = commentsUrl !== '#' && commentsUrl !== articleUrl;

    // Primary link: Main link is the article itself (with fallback to comments_url or '#')
    const primaryUrl = articleUrl !== '#' ? articleUrl : (commentsUrl !== '#' ? commentsUrl : '#');
    const link = document.createElement('a');
    link.className = 'item-title-link';
    link.href = primaryUrl;
    link.textContent = item.title;
    link.target = '_blank';
    link.rel = 'noopener noreferrer';
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

    if (hasComments) {
        const separator = document.createTextNode(' · ');
        timestamp.appendChild(separator);

        const commentsLink = document.createElement('a');
        commentsLink.href = commentsUrl;
        commentsLink.textContent = 'comments';
        commentsLink.className = 'item-comments-link';
        commentsLink.target = '_blank';
        commentsLink.rel = 'noopener noreferrer';
        commentsLink.title = 'Open discussion thread';
        commentsLink.setAttribute('aria-label', `Open discussion thread: ${item.title}`);
        commentsLink.addEventListener('click', () => clickHandler(listItem));
        commentsLink.addEventListener('auxclick', (event) => {
            if (event.button === 1) {
                clickHandler(listItem);
            }
        });
        timestamp.appendChild(commentsLink);
    }

    listItem.appendChild(timestamp);

    return listItem;
}

// --- Feed Widget ---

export function createFeedWidget(feed, callbacks) {
    const { onEdit, onDelete, onMarkItemRead, onLoadMore, onReorderFeeds } = callbacks;
    const widget = document.createElement('div');
    widget.classList.add('feed-widget');
    widget.dataset.feedId = feed.id;
    widget.dataset.tabId = feed.tab_id;
    widget.setAttribute('draggable', 'true');

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

    // Drag Handle
    const dragHandle = document.createElement('span');
    dragHandle.className = 'feed-drag-handle';
    dragHandle.setAttribute('role', 'button');
    dragHandle.setAttribute('aria-grabbed', 'false');
    dragHandle.setAttribute('aria-label', `Drag handle for feed ${feed.name}`);
    dragHandle.setAttribute('tabindex', '0');
    dragHandle.title = 'Drag to reorder or move to another tab';
    dragHandle.textContent = '⋮⋮';
    titleElement.appendChild(dragHandle);

    const titleTextNode = document.createTextNode(feed.name);
    const feedLinkUrl = feed.site_link || feed.url;

    if (feedLinkUrl) {
        const titleLink = document.createElement('a');
        titleLink.className = 'feed-widget-title';
        titleLink.href = sanitizeUrl(feedLinkUrl);
        titleLink.title = feed.name;
        titleLink.target = '_blank';
        titleLink.rel = 'noopener noreferrer';
        titleLink.appendChild(titleTextNode);
        titleElement.appendChild(titleLink);
    } else {
        const titleSpan = document.createElement('span');
        titleSpan.className = 'feed-widget-title';
        titleSpan.title = feed.name;
        titleSpan.appendChild(titleTextNode);
        titleElement.appendChild(titleSpan);
    }

    const badge = createBadge(feed.unread_count);
    if (badge) {
        buttonContainer.prepend(badge);
    }

    titleElement.appendChild(buttonContainer);
    widget.appendChild(titleElement);

    // Drag & Drop Event Listeners
    widget.addEventListener('dragstart', (e) => {
        if (e.target.closest('button, a, ul, input, .feed-widget-buttons')) {
            e.preventDefault();
            return;
        }
        draggedWidget = widget;
        dragHandle.setAttribute('aria-grabbed', 'true');
        widget.classList.add('is-dragging');
        if (e.dataTransfer) {
            e.dataTransfer.effectAllowed = 'move';
            e.dataTransfer.setData('text/plain', String(feed.id));
        }
    });

    widget.addEventListener('dragover', (e) => {
        if (!draggedWidget || draggedWidget === widget) return;
        if (draggedWidget.dataset.tabId !== widget.dataset.tabId) return;

        e.preventDefault();
        if (e.dataTransfer) {
            e.dataTransfer.dropEffect = 'move';
        }

        const rect = widget.getBoundingClientRect();
        const midX = rect.left + rect.width / 2;
        if (e.clientX > midX) {
            widget.classList.add('drop-after');
            widget.classList.remove('drop-before');
        } else {
            widget.classList.add('drop-before');
            widget.classList.remove('drop-after');
        }
    });

    widget.addEventListener('dragleave', (e) => {
        const rect = widget.getBoundingClientRect();
        if (e.clientX < rect.left || e.clientX >= rect.right || e.clientY < rect.top || e.clientY >= rect.bottom) {
            widget.classList.remove('drop-before', 'drop-after');
        }
    });

    widget.addEventListener('drop', (e) => {
        e.preventDefault();
        const isAfter = widget.classList.contains('drop-after');
        widget.classList.remove('drop-before', 'drop-after');

        if (!draggedWidget || draggedWidget === widget) return;
        if (draggedWidget.dataset.tabId !== widget.dataset.tabId) return;

        const parent = widget.parentElement;
        const referenceNode = isAfter ? widget.nextElementSibling : widget;

        if (draggedWidget !== referenceNode) {
            moveNode(parent, draggedWidget, referenceNode);

            const tabId = parseInt(draggedWidget.dataset.tabId, 10);
            const widgetsInTab = Array.from(parent.querySelectorAll(`.feed-widget[data-tab-id="${tabId}"]`));
            const feedIds = widgetsInTab.map(w => parseInt(w.dataset.feedId, 10)).filter(id => !isNaN(id));

            if (typeof onReorderFeeds === 'function') {
                onReorderFeeds(tabId, feedIds);
            }
        }
    });

    widget.addEventListener('dragend', () => {
        widget.classList.remove('is-dragging');
        dragHandle.setAttribute('aria-grabbed', 'false');
        const feedGrid = widget.parentElement;
        if (feedGrid) {
            feedGrid.querySelectorAll('.feed-widget').forEach(w => {
                w.classList.remove('drop-before', 'drop-after');
            });
        }
        const tabsContainer = document.getElementById('tabs-container');
        if (tabsContainer) {
            tabsContainer.querySelectorAll('button').forEach(b => {
                b.classList.remove('tab-drag-over');
            });
        }
        draggedWidget = null;
    });

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
    const { onSwitchTab, onMoveFeedToTab } = callbacks;
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

        // Drag & Drop onto tab headers to move feeds between tabs
        button.addEventListener('dragover', (e) => {
            if (draggedWidget) {
                const sourceTabId = parseInt(draggedWidget.dataset.tabId, 10);
                if (sourceTabId !== tab.id) {
                    e.preventDefault();
                    if (e.dataTransfer) {
                        e.dataTransfer.dropEffect = 'move';
                    }
                    button.classList.add('tab-drag-over');
                }
            }
        });

        button.addEventListener('dragleave', () => {
            button.classList.remove('tab-drag-over');
        });

        button.addEventListener('drop', (e) => {
            button.classList.remove('tab-drag-over');
            if (draggedWidget) {
                const targetTabId = parseInt(button.dataset.tabId, 10);
                const sourceTabId = parseInt(draggedWidget.dataset.tabId, 10);
                const feedId = parseInt(draggedWidget.dataset.feedId, 10);
                if (targetTabId !== sourceTabId && typeof onMoveFeedToTab === 'function') {
                    e.preventDefault();
                    onMoveFeedToTab(feedId, targetTabId);
                }
            }
        });

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
    if (!modal) return;
    document.getElementById('edit-feed-id').value = feedId;
    document.getElementById('edit-feed-url').value = currentUrl;
    document.getElementById('edit-feed-name').value = currentName;
    document.getElementById('edit-feed-error').classList.add('hidden');
    modal.classList.add('is-active');
}

export function closeEditFeedModal() {
    const modal = document.getElementById('edit-feed-modal');
    if (modal) modal.classList.remove('is-active');
}

export function showLoginModal(errorMessage = null) {
    const modal = document.getElementById('login-modal');
    if (!modal) return;
    const errorBanner = document.getElementById('login-error');
    if (errorBanner) {
        if (errorMessage) {
            errorBanner.textContent = errorMessage;
            errorBanner.classList.remove('hidden');
        } else {
            errorBanner.textContent = '';
            errorBanner.classList.add('hidden');
        }
    }
    const passwordInput = document.getElementById('login-password');
    if (passwordInput) passwordInput.value = '';
    modal.classList.add('is-active');
    const usernameInput = document.getElementById('login-username');
    if (usernameInput) usernameInput.focus();
}

export function showSetupWizardModal(errorMessage = null) {
    const modal = document.getElementById('setup-wizard-modal');
    if (!modal) return;
    const errorBanner = document.getElementById('setup-wizard-error');
    if (errorBanner) {
        if (errorMessage) {
            errorBanner.textContent = errorMessage;
            errorBanner.classList.remove('hidden');
        } else {
            errorBanner.textContent = '';
            errorBanner.classList.add('hidden');
        }
    }
    modal.classList.add('is-active');
    const usernameInput = document.getElementById('setup-username');
    if (usernameInput) usernameInput.focus();
}

export function closeSetupWizardModal() {
    const modal = document.getElementById('setup-wizard-modal');
    if (!modal) return;
    modal.classList.remove('is-active');
    const errorBanner = document.getElementById('setup-wizard-error');
    if (errorBanner) errorBanner.classList.add('hidden');
}

export function closeLoginModal() {
    const modal = document.getElementById('login-modal');
    if (!modal) return;
    modal.classList.remove('is-active');
    const errorBanner = document.getElementById('login-error');
    if (errorBanner) errorBanner.classList.add('hidden');
}

export function showChangePasswordModal(errorMessage = null, successMessage = null, clearInputs = false) {
    const modal = document.getElementById('change-password-modal');
    if (!modal) return;
    const errorBanner = document.getElementById('change-password-error');
    const successBanner = document.getElementById('change-password-success');

    if (errorBanner) {
        if (errorMessage) {
            errorBanner.textContent = errorMessage;
            errorBanner.classList.remove('hidden');
        } else {
            errorBanner.textContent = '';
            errorBanner.classList.add('hidden');
        }
    }

    if (successBanner) {
        if (successMessage) {
            successBanner.textContent = successMessage;
            successBanner.classList.remove('hidden');
        } else {
            successBanner.textContent = '';
            successBanner.classList.add('hidden');
        }
    }

    if (clearInputs || (!errorMessage && !successMessage)) {
        const cur = document.getElementById('change-password-current');
        const next = document.getElementById('change-password-new');
        const conf = document.getElementById('change-password-confirm');
        if (cur) cur.value = '';
        if (next) next.value = '';
        if (conf) conf.value = '';
    }
    modal.classList.add('is-active');
}

export function closeChangePasswordModal() {
    const modal = document.getElementById('change-password-modal');
    if (!modal) return;
    modal.classList.remove('is-active');
}

// --- User State ---

export function renderUserState(user) {
    const userContainer = document.getElementById('user-menu-container');
    const displayName = document.getElementById('user-display-name');
    const menuUsername = document.getElementById('user-menu-username');
    const roleBadge = document.getElementById('user-role-badge');
    const adminButton = document.getElementById('admin-panel-button');

    if (user && user.username) {
        if (displayName) displayName.textContent = user.username;
        if (menuUsername) menuUsername.textContent = user.username;
        if (roleBadge) {
            roleBadge.textContent = user.role || 'user';
            roleBadge.className = `badge role-${user.role || 'user'}`;
        }
        if (adminButton) {
            if (user.role === 'admin') {
                adminButton.classList.remove('hidden');
            } else {
                adminButton.classList.add('hidden');
            }
        }
        if (userContainer) userContainer.classList.remove('hidden');
    }
}

export function clearUserState() {
    const userContainer = document.getElementById('user-menu-container');
    const userMenu = document.getElementById('user-menu');
    const adminButton = document.getElementById('admin-panel-button');

    if (userContainer) userContainer.classList.add('hidden');
    if (userMenu) userMenu.classList.add('hidden');
    if (adminButton) adminButton.classList.add('hidden');
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
    // Handled by CSS .sticky-nav
}

