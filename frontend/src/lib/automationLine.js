// Pure formatting for the Automation "why" strip and the per-tunnel chips.
// Takes the translator `tr(key, params)` as an argument (instead of
// importing the i18n store) so it stays testable under plain node.

// "ssid is CafeWiFi" / "subnet is not 10.0.0.0/24" / "otherwise".
export function conditionText(tr, v) {
  if (v.rule_type === 'none_match') return tr('automation.why.cond_none');
  if (!v.rule_type) return '';
  const kind = ['ssid', 'subnet', 'network'].includes(v.rule_type) ? v.rule_type : 'network';
  const neg = v.rule_negate ? '_not' : '_is';
  return tr(`automation.why.cond_${kind}${neg}`, { value: v.rule_value || '?' });
}

function ruleSuffix(tr, v) {
  if (!v.rule_index) return '';
  return tr('automation.why.rule', { n: v.rule_index, cond: conditionText(tr, v) });
}

// One tunnel's verdict as a single line, or '' when nothing worth saying
// (no rule matches / preview unavailable).
export function verdictText(tr, v) {
  return rawVerdictText(tr, v).trim();
}

function rawVerdictText(tr, v) {
  if (!v) return '';
  switch (v.verdict) {
    case 'connect':
      return tr(v.active ? 'automation.why.v_connected' : 'automation.why.v_connect', { rule: ruleSuffix(tr, v) });
    case 'disconnect':
      return tr(v.active ? 'automation.why.v_disconnect' : 'automation.why.v_stays_off', { rule: ruleSuffix(tr, v) });
    case 'held':
      return tr('automation.why.v_held');
    case 'paused':
      return tr(v.active ? 'automation.why.v_paused_connected' : 'automation.why.v_paused_disconnected');
    case 'overlap':
      return tr('automation.why.v_overlap', { cidr: v.overlap_cidr || '' });
    case 'blocked':
      return tr('automation.why.v_blocked');
    default:
      return '';
  }
}

// Severity for chip colouring: 'warn' when automation is NOT doing what
// the rules say (held / paused / overlap / blocked), 'info' otherwise.
export function verdictTone(v) {
  return v && ['held', 'paused', 'overlap', 'blocked'].includes(v.verdict) ? 'warn' : 'info';
}

// Why the Wi-Fi name is unreadable. When the GUI knows Location Services
// is denied the line says so instead of guessing.
export function unknownSSIDText(tr, locAuth) {
  if (locAuth === 'denied') return tr('automation.why.net_unknown_denied');
  return tr('automation.why.net_unknown');
}

// The network context line(s): { network, settle } — settle is '' when no
// "is not" rule exists (nothing is being held back, so don't mention it).
export function networkLines(tr, p, locAuth = 'unknown') {
  if (!p || !p.available) return { network: '', settle: '' };
  let network;
  if (p.online === false) network = tr('automation.why.net_offline');
  else if (p.ssid) network = tr('automation.why.net_ssid', { ssid: p.ssid });
  else if (p.ssid_unknown) network = unknownSSIDText(tr, locAuth);
  else if (p.primary_known === false) network = tr('automation.why.net_type_unknown');
  else network = tr('automation.why.net_no_wifi');
  let settle = '';
  if (p.has_negated_rules) {
    settle = p.settled
      ? tr('automation.why.settled')
      : tr('automation.why.settling', { n: p.settle_remaining_sec || 0 });
  }
  return { network, settle };
}

export function verdictFor(preview, name) {
  return (preview?.tunnels || []).find((t) => t.name === name) || null;
}
