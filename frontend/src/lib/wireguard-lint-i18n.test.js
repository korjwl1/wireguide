import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const load = (l) => JSON.parse(readFileSync(new URL(`../i18n/${l}.json`, import.meta.url), 'utf8'));
const en = load('en');

test('lint.* and editor.tpl_* keys exist in every language', () => {
  const want = [
    ...Object.keys(en.lint).map((k) => ['lint', k]),
    ['editor', 'tpl_dns_global'], ['editor', 'tpl_dns_split'],
  ];
  assert.ok(want.length > 20);
  for (const l of ['ko', 'ja', 'zh']) {
    const d = load(l);
    for (const [sec, k] of want) {
      assert.ok(typeof d[sec]?.[k] === 'string' && d[sec][k] !== '', `${l}: ${sec}.${k}`);
    }
  }
});

test('every diagnostic code emitted by the Go linter has a translation', () => {
  const codes = ['dns_global_outside', 'dns_global_outside_adapter', 'dns_mdns', 'dns_split_windows',
    'dns_split_linux', 'mtu_high', 'dns_lan_none', 'dns_no_reverse', 'fix_remove_dns', 'fix_append_dns'];
  for (const l of ['en', 'ko', 'ja', 'zh']) {
    for (const c of codes) assert.ok(load(l).lint[c], `${l}: lint.${c}`);
  }
});
