import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fieldLines, mapDiagnostics } from './wireguard-lint.js';

test('indexed diagnostics preserve CRLF offsets, duplicate fields and header fallbacks', () => {
  const text = '  preamble\r\n[Interface]\r\n  DNS = 1.1.1.1\r\nDNS = 8.8.8.8\r\n[Peer]\r\nPublicKey = one\r\n[Peer]\r\n PublicKey = two\r\n';
  const fields = ['Interface.DNS', 'peer.publickey', 'PEER[01].PUBLICKEY', 'Peer[1].Endpoint', 'Peer[99].Endpoint', 'unknown'];
  const starts = ['DNS = 1.1.1.1', 'PublicKey = one', 'PublicKey = two', '[Peer]', 'preamble', '[Interface]'];
  const result = mapDiagnostics(text, fields.map(field => ({ field, message: field, severity: 'warning' })));
  for (let i = 0; i < fields.length; i++) {
    const from = i === 3 ? text.lastIndexOf(starts[i]) : text.indexOf(starts[i]);
    assert.equal(result[i].from, from, fields[i]);
    assert.equal(result[i].to, from + starts[i].length, fields[i]);
  }
  assert.equal(fieldLines(text, 'Interface.DNS').length, 2);
});

test('many distinct peer diagnostics map to their own keys without losing duplicates', () => {
  let text = '[Interface]\nPrivateKey = x\n';
  const expected = [];
  const diagnostics = [];
  for (let i = 0; i < 3000; i++) {
    text += '[Peer]\n';
    expected.push(text.length + 2);
    text += `  PublicKey = key${i}\n`;
    diagnostics.push({ field: `Peer[${i}].PublicKey`, message: `peer ${i}` });
  }
  const result = mapDiagnostics(text, [...diagnostics, diagnostics[0], null]);
  assert.equal(result.length, 3001);
  for (let i = 0; i < diagnostics.length; i++) assert.equal(result[i].from, expected[i]);
  assert.deepEqual(result.at(-1), result[0]);
});

test('empty documents and absent diagnostics remain valid', () => {
  assert.deepEqual(mapDiagnostics('', []), []);
  assert.deepEqual(mapDiagnostics('', [{ message: 'missing', severity: 'invalid' }]), [
    { from: 0, to: 0, severity: 'info', message: 'missing', fix: null },
  ]);
});
