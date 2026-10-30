import test from 'node:test';
import assert from 'node:assert/strict';
import { parseDnsEntries, dnsModeOf, dnsChip } from './dns-mode.js';

// Echoes key + params so the tests check which i18n key was chosen.
const tr = (key, params) => (params && Object.keys(params).length ? `${key}${JSON.stringify(params)}` : key);

test('dnsModeOf classifies like the backend', () => {
  assert.equal(dnsModeOf(parseDnsEntries(['10.66.66.1', '~corp.example'])), 'split');
  assert.equal(dnsModeOf(parseDnsEntries(['1.1.1.1', 'fd00::1'])), 'global');
  assert.equal(dnsModeOf(parseDnsEntries(['corp.example'])), 'search');
  assert.equal(dnsModeOf(parseDnsEntries([])), 'none');
  assert.equal(dnsModeOf(parseDnsEntries(undefined)), 'none');
  // Split wins even with search domains; search without ~ is not split.
  assert.equal(dnsModeOf(parseDnsEntries(['corp.example', '~lab.example', '10.0.0.1'])), 'split');
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
