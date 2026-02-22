import { formatDate, throttle } from './utils.js';

const SCROLL_BUFFER = 200;
const SCROLL_THROTTLE = 200;

export function showToast(message, type = 'info', duration = 3000) {
    const toastContainer = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;
    toastContainer.appendChild(toast);
    setTimeout(() => toast.classList.add('show'), 100);
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => toast.remove(), 500);
    }, duration);
}

export function createBadge(count) {
    if (count > 0) {
        const badge = document.createElement('span');
        badge.classList.add('unread-count-badge');
        badge.textContent = count;
        return badge;
    }
    return null;
}

function createFeedItemElement(item, clickHandler) {
    const listItem = document.createElement('li');
    listItem.dataset.itemId = item.id;
    listItem.classList.add(item.is_read ? 'read' : 'unread');

    const link = document.createElement('a');
    link.href = item.link;
    link.textContent = item.title;
    link.target = '_blank';
    link.rel = 'noopener noreferrer';
    link.addEventListener('click', () => clickHandler(listItem));
    link.addEventListener('auxclick', (e) => { if (e.button === 1) clickHandler(listItem); });
    listItem.appendChild(link);

    const timestamp = document.createElement('span');
    timestamp.textContent = formatDate(item.published_time || item.fetched_time);
    listItem.appendChild(timestamp);
    return listItem;
}

export function createFeedWidget(sub, callbacks) {
    const { onEdit, onDelete, onMarkItemRead, onLoadMore } = callbacks;
    const widget = document.createElement('div');
    widget.classList.add('feed-widget');
    widget.dataset.subId = sub.id;
    widget.dataset.tabId = sub.tab_id;

    const buttonContainer = document.createElement('div');
    buttonContainer.classList.add('feed-widget-buttons');

    const editBtn = document.createElement('button');
    editBtn.className = 'edit-feed-button';
    editBtn.textContent = '✎';
    editBtn.title = 'Edit Subscription';
    editBtn.addEventListener('click', (e) => { e.stopPropagation(); onEdit(sub.id, sub.url, sub.name); });
    buttonContainer.appendChild(editBtn);

    const deleteBtn = document.createElement('button');
    deleteBtn.className = 'delete-feed-button';
    deleteBtn.textContent = 'X';
    deleteBtn.title = 'Delete Subscription';
    deleteBtn.addEventListener('click', (e) => { e.stopPropagation(); onDelete(sub.id); });
    buttonContainer.appendChild(deleteBtn);

    const titleElement = document.createElement('h2');
    const titleText = document.createTextNode(sub.name);
    const linkUrl = sub.site_link || sub.url;
    if (linkUrl) {
        const titleLink = document.createElement('a');
        titleLink.href = linkUrl;
        titleLink.target = '_blank';
        titleLink.rel = 'noopener noreferrer';
        titleLink.appendChild(titleText);
        titleElement.appendChild(titleLink);
    } else {
        titleElement.appendChild(titleText);
    }

    const badge = createBadge(sub.unread_count);
    if (badge) buttonContainer.prepend(badge);
    titleElement.appendChild(buttonContainer);
    widget.appendChild(titleElement);

    const itemList = document.createElement('ul');
    widget.appendChild(itemList);

    const items = sub.items || [];
    itemList.dataset.offset = items.length;
    itemList.dataset.subId = sub.id;
    itemList.dataset.tabId = sub.tab_id;
    itemList.dataset.loading = 'false';
    itemList.dataset.allItemsLoaded = 'false';

    itemList.addEventListener('scroll', throttle(() => {
        if (itemList.scrollTop + itemList.clientHeight >= itemList.scrollHeight - SCROLL_BUFFER) {
            onLoadMore(itemList);
        }
    }, SCROLL_THROTTLE));

    if (items.length > 0) {
        const frag = document.createDocumentFragment();
        items.forEach(item => {
            frag.appendChild(createFeedItemElement(item, (li) => onMarkItemRead(item.id, li, sub.id, sub.tab_id)));
        });
        itemList.appendChild(frag);
    } else {
        itemList.innerHTML = '<li>No items found.</li>';
    }

    setTimeout(() => itemList.dispatchEvent(new Event('scroll')), 0);
    return widget;
}

export function appendItemsToFeedWidget(widgetList, items, callbacks) {
    const { onMarkItemRead } = callbacks;
    const subId = widgetList.dataset.subId;
    const tabId = widgetList.dataset.tabId;
    const frag = document.createDocumentFragment();
    items.forEach(item => {
        frag.appendChild(createFeedItemElement(item, (li) => onMarkItemRead(item.id, li, subId, tabId)));
    });
    widgetList.appendChild(frag);
    widgetList.dataset.offset = (parseInt(widgetList.dataset.offset) || 0) + items.length;
}

export function renderTabs(tabs, activeTabId, callbacks) {
    const { onSwitchTab } = callbacks;
    const container = document.getElementById('tabs-container');
    const grid = document.getElementById('feed-grid');
    const renameBtn = document.getElementById('rename-tab-button');
    const deleteBtn = document.getElementById('delete-tab-button');

    container.innerHTML = '';
    if (!tabs || tabs.length === 0) {
        container.innerHTML = '<span>No tabs found.</span>';
        renameBtn.disabled = true;
        deleteBtn.disabled = true;
        grid.innerHTML = '<p>Create a tab to get started!</p>';
        return { activeTabId: null };
    }

    tabs.sort((a, b) => a.order - b.order).forEach(tab => {
        const btn = document.createElement('button');
        btn.textContent = tab.name;
        btn.dataset.tabId = tab.id;
        btn.classList.toggle('active', tab.id == activeTabId);
        btn.addEventListener('click', () => onSwitchTab(tab.id));
        const badge = createBadge(tab.unread_count);
        if (badge) btn.appendChild(badge);
        container.appendChild(btn);
    });

    renameBtn.disabled = false;
    deleteBtn.disabled = tabs.length <= 1;
    return { activeTabId };
}

export function renderAdminUsers(users, callbacks) {
    const tbody = document.getElementById('users-tbody');
    const { onDeleteUser, onToggleAdmin } = callbacks;
    tbody.innerHTML = '';
    users.forEach(user => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${user.id}</td>
            <td>${user.username}</td>
            <td>${user.is_admin ? '✅' : '❌'}</td>
            <td>
                <button class="toggle-admin-btn">${user.is_admin ? 'Demote' : 'Promote'}</button>
                <button class="delete-user-btn">Delete</button>
            </td>
        `;
        tr.querySelector('.toggle-admin-btn').onclick = () => onToggleAdmin(user.id);
        tr.querySelector('.delete-user-btn').onclick = () => onDeleteUser(user.id);
        tbody.appendChild(tr);
    });
}

export function showEditFeedModal(subId, currentUrl, currentName) {
    const modal = document.getElementById('edit-feed-modal');
    document.getElementById('edit-feed-id').value = subId;
    document.getElementById('edit-feed-url').value = currentUrl;
    document.getElementById('edit-feed-name').value = currentName || '';
    document.getElementById('edit-feed-error').style.display = 'none';
    modal.classList.add('is-active');
}

export function closeEditFeedModal() {
    document.getElementById('edit-feed-modal').classList.remove('is-active');
}

export function showProgress(message) {
    const container = document.getElementById('progress-container');
    document.getElementById('progress-status').textContent = message;
    document.getElementById('progress-bar').value = 0;
    container.classList.remove('hidden');
}

export function updateProgress(status, value, max) {
    document.getElementById('progress-status').textContent = status;
    const bar = document.getElementById('progress-bar');
    bar.value = value;
    bar.max = max;
}

export function hideProgress() {
    document.getElementById('progress-container').classList.add('hidden');
}

export function updateProgressBarPosition() {
    const header = document.querySelector('header');
    const container = document.getElementById('progress-container');
    if (header && container) container.style.top = `${header.offsetHeight}px`;
}
