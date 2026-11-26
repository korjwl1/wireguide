import test from 'node:test';
import assert from 'node:assert/strict';
import {
  parseDnsEntries, dnsChip, tryVia, tryFailure, diagNoteKey, domainLabel, domainState, resolveHint,
} from './dns-mode.js';

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

test('tryVia and tryFailure', () => {
  assert.equal(tryVia(tr, {}), '');
  assert.equal(tryVia(tr, { resolver: '10.66.66.1' }), 'tools.dns_try_via{"resolver":"10.66.66.1"}');
  assert.equal(tryVia(tr, { resolver: '10.66.66.1', match_domain: 'corp.example' }),
    'tools.dns_try_via_domain{"resolver":"10.66.66.1","domain":"corp.example"}');
  assert.equal(tryFailure(tr, { nxdomain: true }), 'tools.dns_try_nxdomain');
  assert.equal(tryFailure(tr, { timed_out: true }), 'tools.dns_try_timeout');
  assert.equal(tryFailure(tr, { error_code: 'invalid_name' }), 'tools.dns_try_invalid_name');
  assert.equal(tryFailure(tr, { error: 'boom' }), 'boom');
});

test('diagNoteKey is platform specific', () => {
  assert.equal(diagNoteKey('MacIntel'), 'tools.dns_leak_dig_note');
  assert.equal(diagNoteKey('Linux x86_64'), 'tools.dns_leak_linux_note');
  assert.equal(diagNoteKey('Win32'), '');
  assert.equal(diagNoteKey(undefined), '');
});

test('domain rows', () => {
  assert.equal(domainLabel({ domain: 'corp.example' }), '~corp.example');
  assert.equal(domainLabel({ domain: 'lan.example', search: true }), 'lan.example');
  assert.equal(domainState({ registered: true, resolver: '10.66.66.1' }), 'ok');
  assert.equal(domainState({ registered: false, resolver: '192.168.50.1' }), 'mismatch');
  assert.equal(domainState({ registered: false }), 'missing');
});

test('resolveHint', () => {
  assert.equal(resolveHint(['corp.example', 'x']), 'nas.corp.example');
  assert.equal(resolveHint([]), '');
  assert.equal(resolveHint(undefined), '');
});
