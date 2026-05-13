import { validateActiveTab } from '../../frontend/js/utils.js';
import assert from 'assert';

console.log('Testing validateActiveTab...');

try {
    // Test 1: Empty tabs -> null
    assert.strictEqual(validateActiveTab([], 1), null, 'Empty tabs should return null');
    assert.strictEqual(validateActiveTab(null, 1), null, 'Null tabs should return null');

    // Test 2: Valid ID -> return same ID
    const tabs = [{ id: 1 }, { id: 2 }];
    assert.strictEqual(validateActiveTab(tabs, 1), 1, 'Valid ID should be preserved');
    assert.strictEqual(validateActiveTab(tabs, 2), 2, 'Valid ID should be preserved');

    // Test 3: Invalid ID -> return first tab ID
    assert.strictEqual(validateActiveTab(tabs, 99), 1, 'Invalid ID should default to first tab');
    assert.strictEqual(validateActiveTab(tabs, null), 1, 'Null ID should default to first tab');

    console.log('All tests passed!');
} catch (e) {
    console.error('Test failed:', e.message);
    process.exit(1);
}
