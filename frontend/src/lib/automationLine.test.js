import { test } from 'node:test';
import assert from 'node:assert/strict';
import { conditionText, verdictText, verdictTone, networkLines, verdictFor } from './automationLine.js';

// Echo translator: renders "key|k=v,..." so assertions stay readable.
const tr = (key, params = {}) => {
  const p = Object.entries(params).map(([k, v]) => `${k}=${v}`).join(',');
  return p ? `${key}|${p}` : key;
};

test('condition text covers negation and none_match', () => {
  assert.equal(conditionText(tr, { rule_type: 'ssid', rule_value: 'Home' }), 'automation.why.cond_ssid_is|value=Home');
  assert.equal(conditionText(tr, { rule_type: 'subnet', rule_negate: true, rule_value: '10.0.0.0/24' }), 'automation.why.cond_subnet_not|value=10.0.0.0/24');
  assert.equal(conditionText(tr, { rule_type: 'none_match' }), 'automation.why.cond_none');
  assert.equal(conditionText(tr, {}), '');
});

test('verdict lines per state', () => {
  const base = { rule_index: 2, rule_type: 'ssid', rule_value: 'X' };
  assert.match(verdictText(tr, { ...base, verdict: 'connect', active: false }), /^automation\.why\.v_connect\|rule=automation\.why\.rule\|n=2/);
  assert.match(verdictText(tr, { ...base, verdict: 'connect', active: true }), /^automation\.why\.v_connected/);
  assert.match(verdictText(tr, { ...base, verdict: 'disconnect', active: false }), /^automation\.why\.v_stays_off/);
  assert.equal(verdictText(tr, { verdict: 'paused', active: true }), 'automation.why.v_paused_connected');
  assert.equal(verdictText(tr, { verdict: 'paused', active: false }), 'automation.why.v_paused_disconnected');
  assert.equal(verdictText(tr, { verdict: 'overlap', overlap_cidr: '192.168.1.0/24' }), 'automation.why.v_overlap|cidr=192.168.1.0/24');
  assert.equal(verdictText(tr, { verdict: 'blocked', active: false }), 'automation.why.v_blocked');
  assert.equal(verdictText(tr, { verdict: 'no_match' }), '');
  assert.equal(verdictText(tr, null), '');
});

test('tone flags the silent do-nothing states', () => {
  for (const v of ['held', 'paused', 'overlap', 'blocked']) assert.equal(verdictTone({ verdict: v }), 'warn');
  assert.equal(verdictTone({ verdict: 'connect' }), 'info');
});

test('network lines: ssid, unknown, ethernet, settling', () => {
  assert.equal(networkLines(tr, { available: true, ssid: 'Home', settled: true }).network, 'automation.why.net_ssid|ssid=Home');
  assert.equal(networkLines(tr, { available: true, ssid_unknown: true }).network, 'automation.why.net_unknown');
  assert.equal(networkLines(tr, { available: true }).network, 'automation.why.net_no_wifi');
  assert.equal(networkLines(tr, { available: true, settled: false, has_negated_rules: true, settle_remaining_sec: 9 }).settle, 'automation.why.settling|n=9');
  assert.equal(networkLines(tr, { available: true, settled: true, has_negated_rules: true }).settle, 'automation.why.settled');
  assert.equal(networkLines(tr, { available: true, settled: false }).settle, '');
  assert.deepEqual(networkLines(tr, { available: false }), { network: '', settle: '' });
});

test('network lines: offline and unknown interface never blame Location Services', () => {
  assert.equal(networkLines(tr, { available: true, online: false, ssid_unknown: false }).network, 'automation.why.net_offline');
  assert.equal(networkLines(tr, { available: true, online: true, primary_known: false }).network, 'automation.why.net_type_unknown');
  assert.equal(networkLines(tr, { available: true, online: true, primary_known: true }).network, 'automation.why.net_no_wifi');
});

test('verdictFor finds by name', () => {
  assert.equal(verdictFor({ tunnels: [{ name: 'a' }, { name: 'b', verdict: 'x' }] }, 'b').verdict, 'x');
  assert.equal(verdictFor(null, 'a'), null);
});

test('unreadable Wi-Fi name says why, by Location Services state', () => {
  const p = { available: true, online: true, ssid_unknown: true };
  assert.equal(networkLines(tr, p, 'denied').network, 'automation.why.net_unknown_denied');
  assert.equal(networkLines(tr, p).network, 'automation.why.net_unknown');
  assert.equal(networkLines(tr, { ...p, ssid_unknown: false, ssid: 'Home' }, 'denied').network, 'automation.why.net_ssid|ssid=Home');
});
