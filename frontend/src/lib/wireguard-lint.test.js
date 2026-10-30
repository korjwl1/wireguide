import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  scanSections, fieldLines, fieldRange, diagText, fixLabel, mapDiagnostics, fixChanges,
  allowedIPsFromText, gatewayCandidates, reverseZones,
  dnsValueContext, dnsCompletionOptions, dnsHoverAt, dnsHoverText,
} from './wireguard-lint.js';

// Pick the fields named in `want` from `got` so a partial match can use
// deepStrictEqual.
function pick(got, want) {
  const out = {};
  for (const k of Object.keys(want)) out[k] = got?.[k];
  return out;
}

const DOC = `[Interface]
PrivateKey = abc
Address = 10.0.0.2/32
DNS = 1.1.1.1

[Peer]
PublicKey = k1
AllowedIPs = 192.168.1.0/24

[Peer]
PublicKey = k2
AllowedIPs = 10.5.0.9/32, 10.0.0.0/16
`;

const tr = (key, params = {}) => {
  const table = {
    'lint.dns_global_outside': 'global {servers}',
    'lint.cmp_tilde': 'split domain',
    'lint.cmp_tilde_info': 'tilde info',
    'lint.cmp_gateway': 'gateway',
    'lint.cmp_zone': 'zone',
    'lint.cmp_template': 'template',
    'lint.cmp_template_info': 'template info',
    'lint.hover_match': 'match {domain}',
    'lint.fix_remove_dns': 'Remove DNS',
  };
  const s = table[key];
  return s === undefined ? key : s.replace(/\{(\w+)\}/g, (_, n) => params[n] ?? '');
};

test('scanSections tags lines with section and peer index', () => {
  const lines = scanSections(DOC);
  assert.deepEqual(pick(lines[0], { section: 'interface', header: true }), { section: 'interface', header: true });
  assert.deepEqual(pick(lines[3], { section: 'interface', header: false }), { section: 'interface', header: false });
  assert.deepEqual(pick(lines[5], { section: 'peer', peer: 0, header: true }), { section: 'peer', peer: 0, header: true });
  assert.deepEqual(pick(lines[11], { section: 'peer', peer: 1 }), { section: 'peer', peer: 1 });
});

test('fieldLines resolves Interface and indexed Peer fields', () => {
  assert.deepEqual(fieldLines(DOC, 'Interface.DNS').map((l) => l.text), ['DNS = 1.1.1.1']);
  assert.equal(fieldLines(DOC, 'Peer[0].AllowedIPs')[0].text, 'AllowedIPs = 192.168.1.0/24');
  assert.ok(fieldLines(DOC, 'Peer[1].AllowedIPs')[0].text.includes('10.5.0.9/32'));
  assert.deepEqual(fieldLines(DOC, 'Interface.MTU'), []);
  assert.deepEqual(fieldLines(DOC, 'nonsense'), []);
});

test('fieldRange anchors to the key line, else the section header, else line 1', () => {
  const dns = fieldRange(DOC, 'Interface.DNS');
  assert.equal(DOC.slice(dns.from, dns.to), 'DNS = 1.1.1.1');
  const mtu = fieldRange(DOC, 'Interface.MTU'); // key absent
  assert.equal(DOC.slice(mtu.from, mtu.to), '[Interface]');
  const peer = fieldRange(DOC, 'Peer[1].Endpoint');
  assert.equal(DOC.slice(peer.from, peer.to), '[Peer]');
  assert.equal(peer.from, DOC.lastIndexOf('[Peer]'));
  const none = fieldRange('', 'Interface.DNS');
  assert.deepEqual(none, { from: 0, to: 0 });
});

test('mapDiagnostics maps severity, translated text and fix', () => {
  const fix = { label: 'Remove DNS line', action: 'remove_dns' };
  const out = mapDiagnostics(DOC, [
    { field: 'Interface.DNS', severity: 'warning', code: 'dns_global_outside', message: 'EN', args: { servers: '1.1.1.1' }, fix },
    { field: 'Interface.MTU', severity: 'info', code: 'unknown_code', message: 'English fallback' },
    { field: 'Interface.DNS', severity: 'bogus', code: 'dns_error', message: 'validator text' },
  ], tr);
  assert.deepEqual(pick(out[0], { severity: 'warning', message: 'global 1.1.1.1', fix }), { severity: 'warning', message: 'global 1.1.1.1', fix });
  assert.equal(DOC.slice(out[0].from, out[0].to), 'DNS = 1.1.1.1');
  assert.deepEqual(pick(out[1], { severity: 'info', message: 'English fallback', fix: null }), { severity: 'info', message: 'English fallback', fix: null });
  assert.equal(out[2].severity, 'info');
  assert.equal(out[2].message, 'validator text');
});

test('diagText and fixLabel fall back to English', () => {
  assert.equal(diagText({ code: 'x', message: 'm' }, tr), 'm');
  assert.equal(diagText({ message: 'm' }), 'm');
  assert.equal(fixLabel({ action: 'remove_dns', label: 'L' }, tr), 'Remove DNS');
  assert.equal(fixLabel({ action: 'append_dns', label: 'Add reverse zones' }, tr), 'Add reverse zones');
});

test('fixChanges removes DNS lines', () => {
  const ch = fixChanges(DOC, { action: 'remove_dns' });
  assert.equal(ch.length, 1);
  const next = DOC.slice(0, ch[0].from) + ch[0].insert + DOC.slice(ch[0].to);
  assert.ok(!next.includes('DNS ='));
  assert.ok(next.includes('Address = 10.0.0.2/32\n\n[Peer]'));
  assert.equal(fixChanges('[Interface]\nAddress = 1.2.3.4/32\n', { action: 'remove_dns' }), null);
  assert.equal(fixChanges(DOC, null), null);
});

test('fixChanges appends reverse zones to the DNS line', () => {
  const doc = '[Interface]\nDNS = 192.168.1.1, ~corp.lan  \nMTU = 1380\n';
  const ch = fixChanges(doc, { action: 'append_dns', value: '~1.168.192.in-addr.arpa' });
  const next = doc.slice(0, ch[0].from) + ch[0].insert + doc.slice(ch[0].to);
  assert.equal(next, '[Interface]\nDNS = 192.168.1.1, ~corp.lan, ~1.168.192.in-addr.arpa  \nMTU = 1380\n');
  assert.equal(fixChanges(doc, { action: 'append_dns', value: '' }), null);
});

test('allowedIPsFromText collects entries from every peer', () => {
  assert.deepEqual(allowedIPsFromText(DOC), ['192.168.1.0/24', '10.5.0.9/32', '10.0.0.0/16']);
  assert.deepEqual(allowedIPsFromText('[Interface]\nDNS = 1.1.1.1\n'), []);
});

test('gatewayCandidates mirrors the Go helper', () => {
  assert.deepEqual(gatewayCandidates(['192.168.1.0/24', '10.5.0.9/32', '10.0.0.0/16', '0.0.0.0/0', '::/0', 'junk']), ['192.168.1.1', '10.5.0.1', '10.0.0.1']);
});

test('reverseZones mirrors the Go helper', () => {
  assert.deepEqual(reverseZones(['192.168.1.0/24', '10.0.0.0/16', '10.0.0.0/8', '0.0.0.0/0', '10.5.0.9/32']), ['1.168.192.in-addr.arpa', '0.10.in-addr.arpa', '10.in-addr.arpa']);
});

test('dnsValueContext finds the token after DNS =', () => {
  assert.deepEqual(pick(dnsValueContext('DNS = '), { valueStart: 6, tokenStart: 6, token: '', valueEmpty: true }), { valueStart: 6, tokenStart: 6, token: '', valueEmpty: true });
  assert.deepEqual(pick(dnsValueContext('DNS = 1.1.1.1, ~co'), { tokenStart: 15, token: '~co', valueEmpty: false }), { tokenStart: 15, token: '~co', valueEmpty: false });
  assert.deepEqual(pick(dnsValueContext('dns='), { valueStart: 4, tokenStart: 4, valueEmpty: true }), { valueStart: 4, tokenStart: 4, valueEmpty: true });
  assert.equal(dnsValueContext('Address = 10.0.0.2/32'), null);
  assert.equal(dnsValueContext('# DNS = 1'), null);
});

test('dnsCompletionOptions offers ~, gateway, zones and a template line', () => {
  const opts = dnsCompletionOptions(DOC, tr);
  const labels = opts.map((o) => o.label);
  assert.ok(labels.includes('~'));
  assert.deepEqual(pick(opts.find((o) => o.label === '~'), { kind: 'tilde', info: 'tilde info' }), { kind: 'tilde', info: 'tilde info' });
  assert.ok(labels.includes('192.168.1.1'));
  assert.ok(labels.includes('~1.168.192.in-addr.arpa'));
  const line = opts.find((o) => o.kind === 'line');
  assert.equal(line.insert, '192.168.1.1, ~corp.lan, ~1.168.192.in-addr.arpa');
});

test('dnsCompletionOptions: template only for an empty value, defaults without AllowedIPs', () => {
  assert.equal(dnsCompletionOptions(DOC, tr, { valueEmpty: false }).some((o) => o.kind === 'line'), false);
  const bare = dnsCompletionOptions('[Interface]\nDNS = ', tr);
  assert.equal(bare.find((o) => o.kind === 'line').insert, '192.168.1.1, ~corp.lan, ~1.168.192.in-addr.arpa');
  assert.deepEqual(bare.map((o) => o.label), ['~', bare[1].label]);
});

test('dnsHoverAt locates the DNS key and ~tokens', () => {
  const line = 'DNS = 192.168.1.1, ~corp.lan';
  assert.deepEqual(dnsHoverAt(line, 1), { kind: 'key', from: 0, to: 3 });
  const hit = dnsHoverAt(line, line.indexOf('~corp') + 2);
  assert.deepEqual(pick(hit, { kind: 'match', domain: 'corp.lan', from: 19, to: 28 }), { kind: 'match', domain: 'corp.lan', from: 19, to: 28 });
  assert.equal(dnsHoverAt(line, 8), null); // on the IP
  assert.equal(dnsHoverAt('Address = 1.2.3.4/32', 2), null);
  assert.deepEqual(pick(dnsHoverAt('  dns = 1.1.1.1', 3), { kind: 'key', from: 2, to: 5 }), { kind: 'key', from: 2, to: 5 });
});

test('dnsHoverText covers Global/Split/None plus the caveats', () => {
  const key = dnsHoverText({ kind: 'key' }, tr).map((p) => p.strong || p.text);
  assert.deepEqual(key, [
    'lint.hover_global_title', 'lint.hover_split_title', 'lint.hover_none_title',
    'lint.hover_nxdomain', 'lint.hover_dig',
  ]);
  const match = dnsHoverText({ kind: 'match', domain: 'corp.lan' }, tr);
  assert.equal(match[0].text, 'match corp.lan');
  assert.equal(match.length, 3);
});

test('reverseZones never covers more than the route', () => {
  assert.deepEqual(reverseZones(['172.16.0.0/12', '100.64.0.0/10']), []);
  assert.deepEqual(reverseZones(['10.1.0.0/22']), [
    '0.1.10.in-addr.arpa', '1.1.10.in-addr.arpa', '2.1.10.in-addr.arpa', '3.1.10.in-addr.arpa',
  ]);
});

test('reverseZones gives nothing for prefixes longer than /24', () => {
  assert.deepEqual(reverseZones(['10.0.0.5/32', '10.0.0.128/25', '10.0.0.252/30']), []);
});

test('dnsCompletionOptions is prefix-only and never fuzzy-matches typed servers', () => {
  const doc = '[Interface]\nDNS = \n[Peer]\nAllowedIPs = 192.168.1.0/24\n';
  const tr = (k) => k;
  assert.deepEqual(dnsCompletionOptions(doc, tr, { valueEmpty: false, token: '1.1.1.1' }), []);
  assert.deepEqual(dnsCompletionOptions(doc, tr, { valueEmpty: false, token: '192.168.1.2' }), []);
  assert.deepEqual(dnsCompletionOptions(doc, tr, { valueEmpty: false, token: '192.168' }).map((o) => o.label), ['192.168.1.1']);
  assert.deepEqual(dnsCompletionOptions(doc, tr, { valueEmpty: false, token: '~1.' }).map((o) => o.label), ['~1.168.192.in-addr.arpa']);
});

test('IPv4-mapped and invalid entries are skipped by the derived helpers', () => {
  assert.deepEqual(gatewayCandidates(['::ffff:10.0.0.0/16', '10.0.0.0/33']), []);
  assert.deepEqual(reverseZones(['::ffff:10.0.0.0/16', '10.0.0.0/33']), []);
});

test('dnsCompletionOptions never offers the typed token back to itself', () => {
  const doc = '[Interface]\nDNS = \n[Peer]\nAllowedIPs = 192.168.1.0/24\n';
  assert.deepEqual(dnsCompletionOptions(doc, tr, { valueEmpty: false, token: '192.168.1.1' }), []);
});

test('hover text is platform-neutral about the dig caveat', () => {
  const hits = [{ kind: 'key' }, { kind: 'match', domain: 'corp.lan' }];
  for (const hit of hits) {
    const texts = dnsHoverText(hit, (k) => k).map((p) => p.text);
    assert.ok(texts.includes('lint.hover_dig'));
  }
});
