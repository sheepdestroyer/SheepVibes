/**
 * @vitest-environment jsdom
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { api } from './api.js';

describe('api parameter encoding', () => {
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

    it('encodes feedId in updateFeed and deleteFeed', async () => {
        await api.updateFeed('feed/2', 'http://example.com', 'Name');
        expect(fetch).toHaveBeenCalledWith('/api/feeds/feed%2F2', expect.any(Object));

        await api.deleteFeed('feed/2');
        expect(fetch).toHaveBeenCalledWith('/api/feeds/feed%2F2', expect.any(Object));
    });
});
