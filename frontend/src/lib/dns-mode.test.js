import test from 'node:test';
import assert from 'node:assert/strict';
import { parseDnsEntries, dnsChip } from './dns-mode.js';

// Echoes key + params so the tests check which i18n key was chosen.
const tr = (key, params) => (params && Object.keys(params).length ? `${key}${JSON.stringify(params)}` : key);

test('parseDnsEntries separates values for the existing detail fields', () => {
  assert.deepEqual(parseDnsEntries(['1.1.1.1', 'fd00::1', '~corp.example', 'search.example']), {
    servers: ['1.1.1.1', 'fd00::1'], match: ['corp.example'], search: ['search.example'],
  });
  assert.deepEqual(parseDnsEntries(undefined), { servers: [], match: [], search: [] });
});

test('dnsChip joins domains, hides none', () => {
  assert.deepEqual(dnsChip(tr, 'split', ['a.example', 'b.example']), {
    mode: 'split',
    text: 'tunnel.dns_chip_split{"domains":"a.example, b.example"}',
    hint: 'tunnel.dns_chip_split_hint',
  });
  assert.equal(dnsChip(tr, 'global').mode, 'global');
  assert.equal(dnsChip(tr, 'search').hint, 'tunnel.dns_chip_search_hint');
  assert.equal(dnsChip(tr, 'none'), null);
  assert.equal(dnsChip(tr, ''), null);
});
