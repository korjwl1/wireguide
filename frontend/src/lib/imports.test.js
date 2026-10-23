import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileBase64, sanitizeImportName, uniqueImportName } from './imports.js';

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
