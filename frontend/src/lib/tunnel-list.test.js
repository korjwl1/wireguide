import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sortTunnels } from './tunnel-list.js';

const tunnels = [
  { name: 'vpn10', created_at_unix: 2, last_used_unix: 3 },
  { name: 'vpn2', created_at_unix: 2, last_used_unix: 1 },
  { name: 'Alpha', created_at_unix: 1 },
  { name: 'beta' },
];
const modes = {
  name_asc: ['Alpha', 'beta', 'vpn2', 'vpn10'],
  name_desc: ['vpn10', 'vpn2', 'beta', 'Alpha'],
  added_asc: ['beta', 'Alpha', 'vpn2', 'vpn10'],
  added_desc: ['vpn2', 'vpn10', 'Alpha', 'beta'],
  used_desc: ['vpn10', 'vpn2', 'Alpha', 'beta'],
};

test('list sorting preserves natural names, date fallbacks and the input array', () => {
  const original = [...tunnels];
  for (const [mode, expected] of Object.entries(modes)) {
    assert.deepEqual(sortTunnels(tunnels, mode, false, new Set()).map(t => t.name), expected);
  }
  assert.deepEqual(tunnels, original);
});

test('active-first sorting preserves the selected order within both groups', () => {
  const active = new Set(['vpn10', 'beta', 'missing']);
  for (const [mode, expected] of Object.entries(modes)) {
    const grouped = [...expected.filter(n => active.has(n)), ...expected.filter(n => !active.has(n))];
    assert.deepEqual(sortTunnels(tunnels, mode, true, active).map(t => t.name), grouped);
  }
});

test('equal case-insensitive names retain their original order', () => {
  const equal = [{ name: 'alpha' }, { name: 'Alpha' }, { name: 'ALPHA' }];
  assert.deepEqual(sortTunnels(equal, 'name_desc', true, new Set()), equal);
  assert.deepEqual(sortTunnels([], 'unknown', false, new Set()), []);
});

test('large active partitions preserve order without argument spreading', () => {
  const many = Array.from({ length: 150000 }, (_, i) => ({ name: String(i), created_at_unix: i }));
  const sorted = sortTunnels(many, 'added_asc', true, new Set(['149999']));
  assert.equal(sorted.length, many.length);
  assert.equal(sorted[0].name, '149999');
  assert.equal(sorted[1].name, '0');
  assert.equal(sorted.at(-1).name, '149998');
  assert.deepEqual(sortTunnels(tunnels, 'name_asc', true, new Set()), sortTunnels(tunnels, 'name_asc', false, new Set()));
});
