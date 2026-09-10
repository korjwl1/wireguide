import { test } from 'node:test';
import assert from 'node:assert/strict';
import { errText } from './errors.js';

test('unwraps the serialized error shown by native Wails validation', () => {
  const payload = JSON.stringify({ message: 'add at least one ping target before enabling health checks', cause: {}, kind: 'RuntimeError' });
  for (const error of [payload, new Error(payload), { message: payload }]) {
    assert.equal(errText(error), 'add at least one ping target before enabling health checks');
  }
});

test('preserves plain messages and non-error JSON', () => {
  assert.equal(errText(new Error('connection closed')), 'connection closed');
  assert.equal(errText({ error: 'invalid address' }), 'invalid address');
  assert.equal(errText('{not json'), '{not json');
  assert.equal(errText('[1,2]'), '[1,2]');
  assert.equal(errText(null), 'unknown error');
});
