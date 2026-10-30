import { test, mock } from 'node:test';
import assert from 'node:assert/strict';

globalThis.document = {
  visibilityState: 'visible',
  addEventListener() {},
  removeEventListener() {},
};

const windowListeners = new Map();
globalThis.window = {
  addEventListener(type, fn) { windowListeners.set(type, fn); },
  removeEventListener(type, fn) { if (windowListeners.get(type) === fn) windowListeners.delete(type); },
};

const { startAutomationPolling, stopAutomationPolling, setAutomationWindowVisible, AUTOMATION_POLL_MS } = await import('./automation.js');

const settle = () => new Promise(resolve => setImmediate(resolve));

test('polling pauses while the window is hidden to the tray', async () => {
  mock.timers.enable({ apis: ['setInterval'] });
  try {
    let calls = 0;
    const service = { async GetAutomationPreview() { calls++; return { available: true }; } };
    startAutomationPolling(service);
    await settle();
    assert.equal(calls, 1, 'start refreshes once');

    mock.timers.tick(AUTOMATION_POLL_MS);
    await settle();
    assert.equal(calls, 2, 'visible window polls');

    setAutomationWindowVisible(false);
    mock.timers.tick(AUTOMATION_POLL_MS * 3);
    await settle();
    assert.equal(calls, 2, 'hidden window must not poll even though visibilityState is "visible"');

    setAutomationWindowVisible(true);
    await settle();
    assert.equal(calls, 3, 'showing the window refreshes immediately');

    mock.timers.tick(AUTOMATION_POLL_MS);
    await settle();
    assert.equal(calls, 4, 'polling resumes');
  } finally {
    stopAutomationPolling();
    mock.timers.reset();
  }
});

test('window focus re-arms polling that a missed visibility event left paused', async () => {
  mock.timers.enable({ apis: ['setInterval'] });
  try {
    let calls = 0;
    const service = { async GetAutomationPreview() { calls++; return { available: true }; } };
    startAutomationPolling(service);
    await settle();
    assert.equal(calls, 1);

    setAutomationWindowVisible(false);
    mock.timers.tick(AUTOMATION_POLL_MS * 2);
    await settle();
    assert.equal(calls, 1, 'paused while hidden');

    const onFocus = windowListeners.get('focus');
    assert.equal(typeof onFocus, 'function', 'a focus listener is registered');
    onFocus();
    await settle();
    assert.equal(calls, 2, 'focus refreshes immediately');

    mock.timers.tick(AUTOMATION_POLL_MS);
    await settle();
    assert.equal(calls, 3, 'polling resumes after focus');

    stopAutomationPolling();
    assert.equal(windowListeners.has('focus'), false, 'stop removes the focus listener');
  } finally {
    stopAutomationPolling();
    mock.timers.reset();
  }
});
