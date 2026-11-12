import { test, mock } from 'node:test';
import assert from 'node:assert/strict';
import { get } from 'svelte/store';
import { automationPreview, locationAuth, refreshAutomationStatus } from './automation.js';

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

const { startAutomationPolling, stopAutomationPolling, setAutomationWindowVisible, refreshAutomationPreview, AUTOMATION_POLL_MS, AUTOMATION_IDLE_POLL_MS } = await import('./automation.js');

const settle = () => new Promise(resolve => setImmediate(resolve));

function deferred() {
  let resolve, reject;
  const promise = new Promise((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
}

test('an old preview cannot overwrite a restarted service or request old permissions', async () => {
  const old = deferred();
  let permissionCalls = 0;
  try {
    startAutomationPolling({
      GetAutomationPreview: () => old.promise,
      CheckSSIDPermission: async () => { permissionCalls++; return {}; },
    });
    stopAutomationPolling();
    startAutomationPolling({ GetAutomationPreview: async () => ({ available: true, tunnels: [{ name: 'new' }] }) });
    await settle();
    old.resolve({ available: true, ssid_unknown: true, tunnels: [{ name: 'old' }] });
    await settle();
    assert.equal(get(automationPreview).tunnels[0].name, 'new');
    assert.equal(permissionCalls, 0);
  } finally { stopAutomationPolling(); }
});

test('a late rejection cannot clear a restarted preview', async () => {
  const old = deferred();
  try {
    startAutomationPolling({ GetAutomationPreview: () => old.promise });
    startAutomationPolling({ GetAutomationPreview: async () => ({ available: true, tunnels: [{ name: 'new' }] }) });
    await settle();
    old.reject(new Error('old service closed'));
    await settle();
    assert.equal(get(automationPreview).tunnels[0].name, 'new');
  } finally { stopAutomationPolling(); }
});

test('a late permission response cannot publish after restart', async () => {
  const permission = deferred();
  try {
    startAutomationPolling({
      GetAutomationPreview: async () => ({ available: true, ssid_unknown: true, tunnels: [] }),
      CheckSSIDPermission: () => permission.promise,
    });
    await settle();
    startAutomationPolling({ GetAutomationPreview: async () => ({ available: true, tunnels: [{ name: 'new' }] }) });
    await settle();
    locationAuth.set('unknown');
    permission.resolve({ has_wifi: true, has_permission: false });
    await settle();
    assert.equal(get(automationPreview).tunnels[0].name, 'new');
    assert.equal(get(locationAuth), 'unknown');
  } finally { stopAutomationPolling(); }
});

test('a burst of refresh requests coalesces into one follow-up request', async () => {
  const first = deferred();
  let calls = 0;
  try {
    startAutomationPolling({ GetAutomationPreview() {
      calls++;
      return calls === 1 ? first.promise : Promise.resolve({ available: true, tunnels: [] });
    } });
    for (let i = 0; i < 20; i++) refreshAutomationPreview();
    assert.equal(calls, 1);
    first.resolve({ available: true, tunnels: [] });
    await settle();
    assert.equal(calls, 2);
  } finally { stopAutomationPolling(); }
});

test('steady rules keep the 30-second fallback and status events ignore byte-only changes', async () => {
  mock.timers.enable({ apis: ['setTimeout', 'setInterval'] });
  try {
    const svc = makeService({ available: true, tunnels: [{ name: 'a' }], settled: true });
    startAutomationPolling(svc);
    await settle();
    await run(svc, 60000, 1000);
    assert.equal(svc.calls, 3);
    refreshAutomationStatus({ state: 'connected', active_tunnels: ['a', 'b'], rx_bytes: 1 });
    await settle();
    assert.equal(svc.calls, 4);
    refreshAutomationStatus({ state: 'connected', active_tunnels: ['b', 'a'], rx_bytes: 100 });
    await settle();
    assert.equal(svc.calls, 4);
    refreshAutomationStatus({ state: 'connected', active_tunnels: ['a'] });
    await settle();
    assert.equal(svc.calls, 5);
  } finally {
    stopAutomationPolling();
    mock.timers.reset();
  }
});

test('polling pauses while the window is hidden to the tray', async () => {
  mock.timers.enable({ apis: ['setTimeout', 'setInterval'] });
  try {
    let calls = 0;
    const service = { async GetAutomationPreview() { calls++; return { available: true, tunnels: [{}], has_negated_rules: true, settled: false }; } };
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
  mock.timers.enable({ apis: ['setTimeout', 'setInterval'] });
  try {
    let calls = 0;
    const service = { async GetAutomationPreview() { calls++; return { available: true, tunnels: [{}], has_negated_rules: true, settled: false }; } };
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

function makeService(initial) {
  const svc = {
    calls: 0,
    preview: initial,
    async GetAutomationPreview() { svc.calls++; return svc.preview; },
  };
  return svc;
}

async function run(svc, ms, step) {
  for (let t = 0; t < ms; t += step) {
    mock.timers.tick(step);
    await settle();
  }
}

test('no rules: a visible window polls at the slow cadence', async () => {
  mock.timers.enable({ apis: ['setTimeout', 'setInterval'] });
  try {
    const svc = makeService({ available: true, tunnels: [] });
    startAutomationPolling(svc);
    await settle();
    assert.equal(svc.calls, 1);
    await run(svc, 60000, 1000);
    console.log('observed no-rules calls in 60s:', svc.calls);
    assert.ok(svc.calls <= 3, `expected <= 3 calls, got ${svc.calls}`);
  } finally {
    stopAutomationPolling();
    mock.timers.reset();
  }
});

test('an unsettled negated rule polls at the fast cadence', async () => {
  mock.timers.enable({ apis: ['setTimeout', 'setInterval'] });
  try {
    const svc = makeService({ available: true, tunnels: [{}], has_negated_rules: true, settled: false });
    startAutomationPolling(svc);
    await settle();
    await run(svc, 60000, 500);
    const expected = 1 + 60000 / AUTOMATION_POLL_MS;
    console.log('observed rules calls in 60s:', svc.calls, 'expected', expected);
    assert.equal(svc.calls, expected);
  } finally {
    stopAutomationPolling();
    mock.timers.reset();
  }
});

test('a settling countdown switches to fast cadence immediately; completion switches back', async () => {
  mock.timers.enable({ apis: ['setTimeout', 'setInterval'] });
  try {
    const svc = makeService({ available: true, tunnels: [] });
    startAutomationPolling(svc);
    await settle();
    assert.equal(svc.calls, 1);

    svc.preview = { available: true, tunnels: [{}], has_negated_rules: true, settled: false };
    await refreshAutomationPreview();
    assert.equal(svc.calls, 2);

    // Slow timer must have been replaced: next call after the fast delay.
    mock.timers.tick(AUTOMATION_POLL_MS);
    await settle();
    assert.equal(svc.calls, 3, 'next poll uses the fast delay');

    svc.preview = { available: true, tunnels: [{}], has_negated_rules: true, settled: true };
    await refreshAutomationPreview();
    assert.equal(svc.calls, 4);
    if (AUTOMATION_POLL_MS < AUTOMATION_IDLE_POLL_MS) {
      mock.timers.tick(AUTOMATION_POLL_MS);
      await settle();
      assert.equal(svc.calls, 4, 'back on the slow cadence');
    }
    mock.timers.tick(AUTOMATION_IDLE_POLL_MS);
    await settle();
    assert.equal(svc.calls, 5);
  } finally {
    stopAutomationPolling();
    mock.timers.reset();
  }
});

test('hidden window: no calls from timers or explicit refreshes; one call on show', async () => {
  mock.timers.enable({ apis: ['setTimeout', 'setInterval'] });
  try {
    const svc = makeService({ available: true, tunnels: [{}], has_negated_rules: true, settled: false });
    startAutomationPolling(svc);
    await settle();
    assert.equal(svc.calls, 1);

    setAutomationWindowVisible(false);
    await run(svc, 60000, 1000);
    await refreshAutomationPreview();
    await refreshAutomationPreview();
    assert.equal(svc.calls, 1, 'hidden: nothing reaches the service');

    setAutomationWindowVisible(true);
    await settle();
    assert.equal(svc.calls, 2, 'one refresh on show');
    mock.timers.tick(AUTOMATION_POLL_MS);
    await settle();
    assert.equal(svc.calls, 3, 'polling resumes');
  } finally {
    stopAutomationPolling();
    mock.timers.reset();
  }
});

test('stopAutomationPolling leaves no pending timer and restart does not double the chain', async () => {
  mock.timers.enable({ apis: ['setTimeout', 'setInterval'] });
  try {
    const svc = makeService({ available: true, tunnels: [{}], has_negated_rules: true, settled: false });
    startAutomationPolling(svc);
    await settle();
    stopAutomationPolling();
    await run(svc, 60000, 1000);
    assert.equal(svc.calls, 1, 'no calls after stop');

    svc.calls = 0;
    startAutomationPolling(svc);
    startAutomationPolling(svc);
    await settle();
    const base = svc.calls;
    await run(svc, AUTOMATION_POLL_MS * 5, AUTOMATION_POLL_MS);
    console.log('observed restart calls:', svc.calls - base, 'for 5 ticks');
    assert.equal(svc.calls - base, 5, 'a single chain after restart');
  } finally {
    stopAutomationPolling();
    mock.timers.reset();
  }
});
