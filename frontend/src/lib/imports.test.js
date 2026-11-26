import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileBase64, sanitizeImportName, uniqueImportName, warningText, importedMessage, isNotConnectedError } from './imports.js';

test('oversized picker files are rejected before reading bytes', async () => {
  let reads = 0;
  const file = { size: 1025, arrayBuffer() { reads++; throw new Error('must not read'); } };
  await assert.rejects(fileBase64(file, 1024), /too large/);
  assert.equal(reads, 0);
});

test('chunked base64 preserves binary data across chunk boundaries', async () => {
  const bytes = Uint8Array.from({ length: 20000 }, (_, i) => i % 256);
  const file = { size: bytes.length, arrayBuffer: async () => bytes.buffer };
  assert.equal(await fileBase64(file, bytes.length), Buffer.from(bytes).toString('base64'));
});

test('long and Windows-reserved names remain portable on collisions', async () => {
  const base = 'a'.repeat(64);
  const name = await uniqueImportName(base, async n => n === base || n.endsWith('-1'));
  assert.equal(name, 'a'.repeat(62) + '-2');
  assert.equal(sanitizeImportName('CON'), 'tunnel-CON');
  assert.equal(sanitizeImportName(' QR (1).png '), 'QR -1-png'); // punctuation is sanitized
});

const load = (l) => JSON.parse(readFileSync(new URL(`../i18n/${l}.json`, import.meta.url), 'utf8'));
// Minimal stand-in for the i18n store: {placeholder} interpolation, raw key when missing.
const makeTr = (dict) => (key, args = {}) => {
  const v = key.split('.').reduce((o, k) => o?.[k], dict);
  if (typeof v !== 'string') return key;
  return v.replace(/\{(\w+)\}/g, (_, k) => args[k] ?? '');
};
const shared = { code: 'address_shared', message: 'shares Address 10.66.66.2/32 with home-vpn',
  args: { address: '10.66.66.2/32', tunnel: 'home-vpn' } };

test('warningText keeps only address_shared diagnostics and translates them', () => {
  const tr = makeTr(load('en'));
  assert.equal(warningText(undefined, tr), '');
  assert.equal(warningText([{ code: 'mtu_high', message: 'x' }], tr), '');
  assert.equal(warningText([shared, { code: 'mtu_high' }], tr), 'shares Address 10.66.66.2/32 with home-vpn');
  const two = [shared, { ...shared, args: { address: '10.66.66.2/32', tunnel: 'office-vpn' } }];
  assert.equal(warningText(two, tr), 'shares Address 10.66.66.2/32 with home-vpn; shares Address 10.66.66.2/32 with office-vpn');
});

test('warningText falls back to the English message without a translation', () => {
  assert.equal(warningText([shared], () => 'lint.address_shared'), shared.message);
});

test('importedMessage appends the warning only when there is one', () => {
  const tr = makeTr(load('en'));
  assert.equal(importedMessage('office-vpn', [], tr), 'Imported “office-vpn”');
  assert.equal(importedMessage('office-vpn', null, tr), 'Imported “office-vpn”');
  assert.equal(importedMessage('office-vpn', [shared], tr),
    'Imported “office-vpn” — shares Address 10.66.66.2/32 with home-vpn');
});

test('isNotConnectedError matches only the already-disconnected error', () => {
  assert.equal(isNotConnectedError('tunnel "home-vpn" is not connected'), true);
  assert.equal(isNotConnectedError('Is Not Connected'), true);
  assert.equal(isNotConnectedError('permission denied'), false);
  assert.equal(isNotConnectedError(undefined), false);
});

test('duplicate-Address strings exist in every language', () => {
  const want = [['lint', 'address_shared'], ['app', 'imported_with_warning'], ['conflict', 'address_title'],
    ['conflict', 'same_address'], ['conflict', 'address_message'], ['conflict', 'disconnect_and_connect'],
    ['conflict', 'disconnect_failed']];
  for (const l of ['en', 'ko', 'ja', 'zh']) {
    const d = load(l);
    for (const [sec, k] of want) assert.ok(typeof d[sec]?.[k] === 'string' && d[sec][k] !== '', `${l}: ${sec}.${k}`);
    assert.match(d.app.imported_with_warning, /\{name\}.*\{warning\}/, l);
  }
});
