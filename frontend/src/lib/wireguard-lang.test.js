import { test } from 'node:test';
import assert from 'node:assert/strict';
import { EditorState } from '@codemirror/state';
import { CompletionContext } from '@codemirror/autocomplete';
import { createWireguardCompletion } from './wireguard-lang.js';

const tr = (key) => key;
const complete = createWireguardCompletion(tr);

function run(doc, explicit = false) {
  const state = EditorState.create({ doc });
  return complete(new CompletionContext(state, doc.length, explicit));
}

const DOC = '[Interface]\nAddress = 10.0.0.2/32\nDNS = ';
const PEER = '\n[Peer]\nAllowedIPs = 192.168.1.0/24, 10.9.0.0/24\n';

test('DNS value completion fires with nothing typed and lists ~, gateway, zones, template', () => {
  const doc = DOC + PEER;
  const state = EditorState.create({ doc });
  const pos = doc.indexOf('DNS = ') + 6;
  const res = complete(new CompletionContext(state, pos, false));
  assert.notEqual(res, null);
  assert.equal(res.from, pos);
  const labels = res.options.map((o) => o.label);
  assert.ok(labels.includes('~'));
  assert.ok(labels.includes('192.168.1.1'));
  assert.ok(labels.includes('~1.168.192.in-addr.arpa'));
  assert.ok(labels.includes('~0.9.10.in-addr.arpa'));
  assert.equal(labels.some((l) => l.includes(', ~corp.lan, ')), true);
  assert.equal(res.options.find((o) => o.label === '~').info, 'lint.cmp_tilde_info');
});

test('DNS completion after a comma replaces only the current token', () => {
  const doc = '[Interface]\nDNS = 1.1.1.1, ~co';
  const res = run(doc);
  assert.equal(res.from, doc.length - 3);
  assert.equal(res.options.some((o) => o.kind === 'line'), false);
});

test('non-DNS lines keep the key completion', () => {
  const res = run('[Interface]\nAdd', true);
  assert.ok(res.options.map((o) => o.label).includes('Address = '));
});
