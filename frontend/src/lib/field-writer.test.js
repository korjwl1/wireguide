import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createFieldWriter } from './field-writer.js';

test('same profile writes keep edit order and coalesce duplicate blur/timer saves', async () => {
  const started = [];
  const completed = [];
  let release;
  const first = new Promise(resolve => { release = resolve; });
  const write = createFieldWriter(async (name, value) => {
    started.push(value);
    if (value === 'first') await first;
  }, (_, value) => completed.push(value), () => assert.fail('unexpected failure'));
  const a = write('profile', 'first');
  assert.equal(write('profile', 'first'), a);
  const b = write('profile', 'second');
  await Promise.resolve();
  assert.deepEqual(started, ['first']);
  release();
  await Promise.all([a, b]);
  assert.deepEqual(completed, ['first', 'second']);
});

test('failed writes allow retries and do not block other profiles', async () => {
  const failures = [];
  let fail = true;
  const write = createFieldWriter(async name => {
    if (name === 'a' && fail) throw Error('disk failed');
  }, () => {}, name => failures.push(name));
  assert.deepEqual(await Promise.all([write('a', 'value'), write('b', 'value')]), [false, true]);
  fail = false;
  assert.equal(await write('a', 'value'), true);
  assert.deepEqual(failures, ['a']);
});
