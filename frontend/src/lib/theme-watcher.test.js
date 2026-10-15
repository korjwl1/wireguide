import { test } from 'node:test';
import assert from 'node:assert/strict';
import { get } from 'svelte/store';
import { applyTheme, initThemeWatcher, resolvedTheme } from '../stores/theme.js';

test('OS theme listener is removed and can be installed again', () => {
  const previous = globalThis.window;
  let attached = 0, removed = 0, callback;
  const mql = {
    matches: false,
    addEventListener(_, fn) { attached++; callback = fn; },
    removeEventListener(_, fn) { assert.equal(fn, callback); removed++; },
  };
  globalThis.window = { matchMedia: () => mql };
  let stop;
  try {
    stop = initThemeWatcher();
    assert.equal(initThemeWatcher(), stop);
    applyTheme('system');
    mql.matches = true;
    callback();
    assert.equal(get(resolvedTheme), 'dark');
    stop();
    stop();
    assert.equal(removed, 1);
    stop = initThemeWatcher();
    assert.equal(attached, 2);
  } finally {
    stop?.();
    if (previous === undefined) delete globalThis.window;
    else globalThis.window = previous;
  }
});
