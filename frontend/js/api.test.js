/**
 * @vitest-environment jsdom
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { api, setUnauthorizedHandler, fetchData } from './api.js';

describe('api parameter encoding and endpoints', () => {
    beforeEach(() => {
        vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
            ok: true,
            status: 200,
            headers: {
                get: () => null
            },
            json: async () => ({})
        }));
    });

    it('encodes path parameters in getFeedsForTab', async () => {
        await api.getFeedsForTab('tab/123&test=1');
        expect(fetch).toHaveBeenCalledWith('/api/tabs/tab%2F123%26test%3D1/feeds', expect.any(Object));
    });

    it('encodes query parameters in getFeedItems', async () => {
        await api.getFeedItems('feed/1', '0&bad=true', '10#hash');
        expect(fetch).toHaveBeenCalledWith('/api/feeds/feed%2F1/items?offset=0%26bad%3Dtrue&limit=10%23hash', expect.any(Object));
    });

    it('encodes itemId in markItemRead', async () => {
        await api.markItemRead('item/456');
        expect(fetch).toHaveBeenCalledWith('/api/items/item%2F456/read', expect.any(Object));
    });

    it('encodes tabId in updateTab and deleteTab', async () => {
        await api.updateTab('tab/1', 'New Name');
        expect(fetch).toHaveBeenCalledWith('/api/tabs/tab%2F1', expect.any(Object));

        await api.deleteTab('tab/1');
        expect(fetch).toHaveBeenCalledWith('/api/tabs/tab%2F1', expect.any(Object));
    });

    it('encodes tabId and formats payload in reorderTabFeeds', async () => {
        await api.reorderTabFeeds('tab/1', [3, 1, 2]);
        expect(fetch).toHaveBeenCalledWith('/api/tabs/tab%2F1/feeds/reorder', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ feed_ids: [3, 1, 2] })
        });
    });

    it('encodes feedId in updateFeed and deleteFeed', async () => {
        await api.updateFeed('feed/2', 'http://example.com', 'Name');
        expect(fetch).toHaveBeenCalledWith('/api/feeds/feed%2F2', expect.any(Object));

        await api.deleteFeed('feed/2');
        expect(fetch).toHaveBeenCalledWith('/api/feeds/feed%2F2', expect.any(Object));
    });

    it('encodes feedId and formats payload in moveFeedToTab', async () => {
        await api.moveFeedToTab('feed/5', 2, 0);
        expect(fetch).toHaveBeenCalledWith('/api/feeds/feed%2F5/move', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ tab_id: 2, position: 0 })
        });
    });

    it('sends getAuthStatus request', async () => {
        await api.getAuthStatus();
        expect(fetch).toHaveBeenCalledWith('/api/auth/status', {});
    });

    it('sends setupMasterAdmin request', async () => {
        await api.setupMasterAdmin({ username: 'root_admin', password: 'Password123!' });
        expect(fetch).toHaveBeenCalledWith('/api/auth/setup', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: 'root_admin', password: 'Password123!' })
        });
    });

    it('sends login request with credentials', async () => {
        await api.login('admin', 'secret123');
        expect(fetch).toHaveBeenCalledWith('/api/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: 'admin', password: 'secret123' })
        });
    });

    it('sends logout request', async () => {
        await api.logout();
        expect(fetch).toHaveBeenCalledWith('/api/auth/logout', { method: 'POST' });
    });

    it('sends getCurrentUser request', async () => {
        await api.getCurrentUser();
        expect(fetch).toHaveBeenCalledWith('/api/auth/me', expect.any(Object));
    });

    it('sends changePassword request', async () => {
        await api.changePassword('oldPass', 'newPass123');
        expect(fetch).toHaveBeenCalledWith('/api/auth/password', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ current_password: 'oldPass', new_password: 'newPass123' })
        });
    });

    it('triggers unauthorized handler when a protected endpoint returns 401', async () => {
        const mockUnauthorized = vi.fn();
        setUnauthorizedHandler(mockUnauthorized);

        vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
            ok: false,
            status: 401,
            headers: {
                get: () => 'application/json'
            },
            json: async () => ({ error: 'Unauthorized' })
        }));

        await expect(api.getTabs()).rejects.toThrow();
        expect(mockUnauthorized).toHaveBeenCalledTimes(1);
    });

    it('handles admin endpoints with correct HTTP methods and paths', async () => {
        // getAdminUsers
        fetch.mockResolvedValueOnce({
            ok: true,
            status: 200,
            headers: { get: () => null },
            json: async () => ({ users: [{ id: 1, username: 'admin' }] })
        });
        const usersRes = await api.getAdminUsers();
        expect(usersRes.users).toHaveLength(1);
        expect(fetch).toHaveBeenCalledWith('/api/admin/users', {});

        // createAdminUser
        fetch.mockResolvedValueOnce({
            ok: true,
            status: 201,
            headers: { get: () => null },
            json: async () => ({ user: { id: 2, username: 'newuser' } })
        });
        await api.createAdminUser({ username: 'newuser', password: 'Password123' });
        expect(fetch).toHaveBeenCalledWith('/api/admin/users', expect.objectContaining({
            method: 'POST',
            body: JSON.stringify({ username: 'newuser', password: 'Password123' })
        }));

        // updateAdminUser
        fetch.mockResolvedValueOnce({
            ok: true,
            status: 200,
            headers: { get: () => null },
            json: async () => ({ user: { id: 2, role: 'admin' } })
        });
        await api.updateAdminUser(2, { role: 'admin' });
        expect(fetch).toHaveBeenCalledWith('/api/admin/users/2', expect.objectContaining({
            method: 'PUT',
            body: JSON.stringify({ role: 'admin' })
        }));

        // deleteAdminUser
        fetch.mockResolvedValueOnce({
            ok: true,
            status: 200,
            headers: { get: () => null },
            json: async () => ({ message: 'User deleted' })
        });
        await api.deleteAdminUser(2);
        expect(fetch).toHaveBeenCalledWith('/api/admin/users/2', expect.objectContaining({
            method: 'DELETE'
        }));

        // getAdminSystemStats
        fetch.mockResolvedValueOnce({
            ok: true,
            status: 200,
            headers: { get: () => null },
            json: async () => ({ stats: { users_count: 5 } })
        });
        const statsRes = await api.getAdminSystemStats();
        expect(statsRes.stats.users_count).toBe(5);

        // getAdminBackupUrl
        expect(api.getAdminBackupUrl()).toBe('/api/admin/backup');
    });
});
