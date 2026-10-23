import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createEventScope } from './event-scope.js';

test('dispose releases all listeners once and rejects late registrations', () => {
  let subscriptions = 0, releases = 0, handled = 0;
  let callback;
  const scope = createEventScope((_, fn) => {
    subscriptions++;
    callback = fn;
    return () => { releases++; };
  });
  scope.on('status', () => { handled++; });
  callback();
  scope.dispose();
  scope.dispose();
  scope.on('late async startup', () => {});
  callback();
  assert.equal(subscriptions, 1);
  assert.equal(releases, 1);
  assert.equal(handled, 1);
});

test('async handler failures are reported without unhandled rejections', async () => {
  let callback, reported;
  const scope = createEventScope((_, fn) => { callback = fn; return () => {}; }, error => { reported = error; });
  scope.on('helper_reset', async () => { throw new Error('helper unavailable'); });
  callback();
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(reported?.message, 'helper unavailable');
  scope.dispose();
});
