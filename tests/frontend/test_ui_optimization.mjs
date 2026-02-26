// Mock minimal DOM environment

class HTMLElement {
    constructor(tagName) {
        this.tagName = tagName;
        this.children = [];
        this.textContent = '';
        this.classList = {
            add: (cls) => {},
            toggle: (cls, condition) => {},
            remove: (cls) => {},
            contains: (cls) => false,
        };
        this.style = {};
        this.dataset = {};
        this.listeners = {};
        this.innerHTML = '';
        this.appendChildCallCount = 0;
    }

    addEventListener(event, handler) {
        this.listeners[event] = handler;
    }

    appendChild(child) {
        this.children.push(child);
        this.appendChildCallCount++;
    }
}

class DocumentFragment {
    constructor() {
        this.children = [];
    }

    appendChild(child) {
        this.children.push(child);
    }
}

// Global mocks setup
global.HTMLElement = HTMLElement;
global.DocumentFragment = DocumentFragment;
global.mockElements = {};

global.document = {
    createElement: (tagName) => {
        return new HTMLElement(tagName);
    },
    getElementById: (id) => {
        if (!global.mockElements[id]) {
            const el = new HTMLElement(id === 'tabs-container' ? 'div' : 'unknown');
            el.id = id;
            global.mockElements[id] = el;
        }
        return global.mockElements[id];
    },
    createDocumentFragment: () => new DocumentFragment(),
    querySelector: (selector) => null, // Simplified
};


// Import the function to test (using dynamic import to handle ES modules)
import { renderTabs } from '../../frontend/js/ui.js';

async function testRenderTabs() {
    console.log('Running testRenderTabs...');

    // 1. Setup Test Data
    const tabs = [
        { id: 1, name: 'Tab 1', order: 1, unread_count: 0 },
        { id: 2, name: 'Tab 2', order: 2, unread_count: 5 },
        { id: 3, name: 'Tab 3', order: 3, unread_count: 0 }
    ];
    const activeTabId = 1;
    const callbacks = { onSwitchTab: () => {} };

    // 2. Clear previous mocks
    global.mockElements = {};

    // 3. Execution
    renderTabs(tabs, activeTabId, callbacks);

    // 4. Verification
    const tabsContainer = global.mockElements['tabs-container'];

    if (!tabsContainer) {
        console.error('FAIL: tabs-container was not accessed or created.');
        return;
    }

    const appendCount = tabsContainer.appendChildCallCount;
    console.log(`RESULT: appendChild was called ${appendCount} times.`);

    if (appendCount === 1) {
         if (tabsContainer.children[0] instanceof DocumentFragment) {
             console.log('PASS: Optimization successful (DocumentFragment used).');
         } else {
             console.log('PASS: Optimization successful (Single append).');
         }
    } else if (appendCount === tabs.length) {
        console.log(`FAIL: Optimization needed (Called ${appendCount} times, once per tab).`);
    } else {
        console.log(`INFO: Unexpected call count: ${appendCount}`);
    }
}

testRenderTabs();
