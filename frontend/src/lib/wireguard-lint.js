// Pure helpers behind the config editor's lint, hover and DNS completion.
// Nothing here touches CodeMirror or the DOM so it is unit-testable; the
// CodeMirror glue lives in wireguard-lang.js.

// ---- document scanning -------------------------------------------------

/** Split text into lines with absolute offsets: [{ from, to, text }]. */
export function scanLines(text) {
  const out = [];
  let from = 0;
  for (const raw of text.split('\n')) {
    const text1 = raw.endsWith('\r') ? raw.slice(0, -1) : raw;
    out.push({ from, to: from + text1.length, text: text1 });
    from += raw.length + 1;
  }
  return out;
}

function sectionOf(line) {
  const t = line.text.trim().toLowerCase();
  if (t === '[interface]') return 'interface';
  if (t === '[peer]') return 'peer';
  return null;
}

/**
 * Tag every line with its section and peer index:
 * [{ from, to, text, section: 'interface'|'peer'|null, peer: number }].
 * Header lines carry their own section.
 */
export function scanSections(text) {
  let section = null;
  let peer = -1;
  return scanLines(text).map((l) => {
    const s = sectionOf(l);
    if (s) {
      section = s;
      if (s === 'peer') peer += 1;
    }
    return { ...l, section, peer: section === 'peer' ? peer : -1, header: !!s };
  });
}

function keyOf(lineText) {
  const m = /^\s*([A-Za-z]+)\s*=/.exec(lineText);
  return m ? m[1].toLowerCase() : null;
}

/** All lines for a validator-style field ("Interface.DNS", "Peer[1].AllowedIPs"). */
export function fieldLines(text, field) {
  const m = /^(Interface|Peer(?:\[(\d+)\])?)\.(\w+)$/i.exec(field || '');
  if (!m) return [];
  const isPeer = m[1].toLowerCase().startsWith('peer');
  const peerIdx = m[2] === undefined ? 0 : Number(m[2]);
  const key = m[3].toLowerCase();
  return scanSections(text).filter((l) => {
    if (l.header || keyOf(l.text) !== key) return false;
    return isPeer ? l.section === 'peer' && l.peer === peerIdx : l.section === 'interface';
  });
}

/** Header line of a field's section, used when the key itself is absent. */
function sectionHeader(text, field) {
  const isPeer = /^peer/i.test(field || '');
  const m = /\[(\d+)\]/.exec(field || '');
  const peerIdx = m ? Number(m[1]) : 0;
  return scanSections(text).find((l) =>
    l.header && (isPeer ? l.section === 'peer' && l.peer === peerIdx : l.section === 'interface'));
}

/** Absolute range ({ from, to }) a diagnostic's Field should be anchored to. */
export function fieldRange(text, field) {
  const lines = fieldLines(text, field);
  const target = lines[0] || sectionHeader(text, field) || scanLines(text)[0];
  const lead = target.text.length - target.text.trimStart().length;
  const from = target.from + lead;
  const to = Math.max(from, target.from + target.text.trimEnd().length);
  return { from, to };
}

// ---- diagnostics -------------------------------------------------------

const SEVERITIES = new Set(['error', 'warning', 'info']);

/** Translate a Go Diagnostic; falls back to its English Message. */
export function diagText(d, tr) {
  if (tr && d.code) {
    const key = 'lint.' + d.code;
    const txt = tr(key, d.args || {});
    if (txt && txt !== key) return txt;
  }
  return d.message || '';
}

/** Translate a Fix label; falls back to its English label. */
export function fixLabel(fix, tr) {
  if (tr && fix.action) {
    const key = 'lint.fix_' + fix.action;
    const txt = tr(key, { value: fix.value || '' });
    if (txt && txt !== key) return txt;
  }
  return fix.label || fix.action;
}

/**
 * Map Go diagnostics to editor ranges:
 * [{ from, to, severity, message, fix }].
 */
export function mapDiagnostics(text, diagnostics, tr) {
  const out = [];
  for (const d of diagnostics || []) {
    if (!d) continue;
    const { from, to } = fieldRange(text, d.field);
    out.push({
      from,
      to,
      severity: SEVERITIES.has(d.severity) ? d.severity : 'info',
      message: diagText(d, tr),
      fix: d.fix || null,
    });
  }
  return out;
}

/**
 * Compute the text changes for a quick-fix: [{ from, to, insert }] with
 * non-overlapping ascending ranges, or null if the fix does not apply.
 */
export function fixChanges(text, fix) {
  if (!fix) return null;
  const dns = fieldLines(text, 'Interface.DNS');
  if (dns.length === 0) return null;
  if (fix.action === 'remove_dns') {
    return dns.map((l) => ({
      from: l.from,
      to: Math.min(text.length, l.to + (text[l.to] === '\r' ? 2 : 1)),
      insert: '',
    }));
  }
  if (fix.action === 'append_dns' && fix.value) {
    const last = dns[dns.length - 1];
    const end = last.from + last.text.trimEnd().length;
    const afterEq = last.text.slice(last.text.indexOf('=') + 1).trim();
    return [{ from: end, to: end, insert: (afterEq ? ', ' : ' ') + fix.value }];
  }
  return null;
}

// ---- derived values (mirror internal/config/lint.go) -------------------

const CIDR4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/;

function parseCidr4(s) {
  const m = CIDR4.exec(s.trim());
  if (!m) return null;
  const o = m.slice(1, 5).map(Number);
  const ones = Number(m[5]);
  if (o.some((n) => n > 255) || ones > 32) return null;
  return { o, ones };
}

/** AllowedIPs entries (all peers) from raw config text. */
export function allowedIPsFromText(text) {
  const out = [];
  for (const l of scanSections(text)) {
    if (l.section !== 'peer' || l.header || keyOf(l.text) !== 'allowedips') continue;
    for (const part of l.text.slice(l.text.indexOf('=') + 1).split(',')) {
      const p = part.trim();
      if (p) out.push(p);
    }
  }
  return out;
}

/** x.x.x.1 gateway candidates from IPv4 AllowedIPs (max 4, de-duplicated). */
export function gatewayCandidates(allowed) {
  const out = [];
  for (const c of allowed) {
    const p = parseCidr4(c);
    if (!p || p.ones === 0) continue;
    // Network address of the entry.
    const mask = p.ones === 0 ? 0 : (0xffffffff << (32 - p.ones)) >>> 0;
    const ip = (((p.o[0] << 24) | (p.o[1] << 16) | (p.o[2] << 8) | p.o[3]) >>> 0);
    const net = (ip & mask) >>> 0;
    const b = [net >>> 24, (net >>> 16) & 255, (net >>> 8) & 255, net & 255];
    const gw = p.ones >= 24 ? `${p.o[0]}.${p.o[1]}.${p.o[2]}.1` : `${b[0]}.${b[1]}.${b[2]}.${b[3] + 1}`;
    if (!out.includes(gw)) out.push(gw);
    if (out.length >= 4) break;
  }
  return out;
}

/**
 * in-addr.arpa zones from IPv4 AllowedIPs (max 8, de-duplicated). Mirrors
 * config.ReverseZones: a zone never covers more space than the route. A /24
 * gives its own zone; /8 and /16 the whole-octet zone; other prefixes of /9 to
 * /23 give their covered next-octet sub-zones only when there are at most 8
 * (so 172.16.0.0/12 yields none). Prefixes longer than /24 give nothing.
 */
export function reverseZones(allowed) {
  const out = [];
  for (const c of allowed) {
    const p = parseCidr4(c);
    if (!p || p.ones < 8 || p.ones > 24) continue;
    const octets = Math.min(3, Math.ceil(p.ones / 8));
    const count = p.ones < 24 ? 2 ** (octets * 8 - p.ones) : 1;
    if (count > 8) continue;
    let base = p.o;
    if (p.ones < 24) {
      const mask = (0xffffffff << (32 - p.ones)) >>> 0;
      const ip = (((p.o[0] << 24) | (p.o[1] << 16) | (p.o[2] << 8) | p.o[3]) >>> 0);
      const net = (ip & mask) >>> 0;
      base = [net >>> 24, (net >>> 16) & 255, (net >>> 8) & 255, net & 255];
    }
    for (let k = 0; k < count; k++) {
      const parts = base.slice(0, octets);
      parts[octets - 1] += k;
      const zone = parts.reverse().join('.') + '.in-addr.arpa';
      if (!out.includes(zone)) out.push(zone);
    }
    if (out.length >= 8) { out.length = 8; break; }
  }
  return out;
}

// ---- DNS value completion ---------------------------------------------

const DNS_VALUE = /^(\s*DNS\s*=\s*)(.*)$/i;

/**
 * If lineBefore (the line text up to the cursor) is inside a `DNS =` value,
 * return { valueStart, tokenStart, token, valueEmpty } (columns); else null.
 */
export function dnsValueContext(lineBefore) {
  const m = DNS_VALUE.exec(lineBefore);
  if (!m) return null;
  const valueStart = m[1].length;
  const value = m[2];
  const comma = value.lastIndexOf(',');
  const rest = value.slice(comma + 1);
  const tokenStart = valueStart + comma + 1 + (rest.length - rest.trimStart().length);
  const token = lineBefore.slice(tokenStart);
  return { valueStart, tokenStart, token, valueEmpty: value.trim() === '' };
}

/**
 * Completion candidates for a `DNS =` value:
 * [{ label, kind: 'tilde'|'token'|'line', insert, detail, info }].
 * `kind: 'line'` replaces the whole value; 'tilde' inserts a snippet.
 */
export function dnsCompletionOptions(docText, tr, { valueEmpty = true, token = '' } = {}) {
  const allowed = allowedIPsFromText(docText);
  const gateways = gatewayCandidates(allowed);
  const zones = reverseZones(allowed);
  const opts = [];

  opts.push({
    label: '~',
    kind: 'tilde',
    insert: '~${corp.lan}',
    detail: tr('lint.cmp_tilde'),
    info: tr('lint.cmp_tilde_info'),
  });
  for (const gw of gateways) {
    opts.push({ label: gw, kind: 'token', insert: gw, detail: tr('lint.cmp_gateway'), info: '' });
  }
  for (const z of zones) {
    opts.push({ label: '~' + z, kind: 'token', insert: '~' + z, detail: tr('lint.cmp_zone'), info: '' });
  }
  if (valueEmpty && token === '') {
    const line = `${gateways[0] || '192.168.1.1'}, ~corp.lan, ~${zones[0] || '1.168.192.in-addr.arpa'}`;
    opts.push({ label: line, kind: 'line', insert: line, detail: tr('lint.cmp_template'), info: tr('lint.cmp_template_info') });
  }
  // Prefix-only matching: a typed server such as 1.1.1.1 must never be
  // fuzzy-matched onto an unrelated candidate (Enter would rewrite it).
  return opts.filter((o) => o.kind === 'line' || (o.label.startsWith(token) && (o.label === '~' || o.label !== token)));
}

// ---- hover -------------------------------------------------------------

/**
 * Locate a hover target on a line: the `DNS` key or a `~domain` token.
 * Returns { kind: 'key'|'match', from, to, domain? } (columns) or null.
 */
export function dnsHoverAt(lineText, col) {
  const m = /^(\s*)(DNS)(\s*=\s*)(.*)$/i.exec(lineText);
  if (!m) return null;
  const keyFrom = m[1].length;
  const keyTo = keyFrom + m[2].length;
  if (col >= keyFrom && col <= keyTo) return { kind: 'key', from: keyFrom, to: keyTo };
  const valueStart = keyTo + m[3].length;
  let pos = valueStart;
  for (const part of m[4].split(',')) {
    const lead = part.length - part.trimStart().length;
    const tok = part.trim();
    const from = pos + lead;
    const to = from + tok.length;
    if (tok.startsWith('~') && col >= from && col <= to) {
      return { kind: 'match', from, to, domain: tok.slice(1) };
    }
    pos += part.length + 1;
  }
  return null;
}

/** Hover content as [{ strong?: string, text: string }] paragraphs. */
export function dnsHoverText(hit, tr) {
  if (hit.kind === 'match') {
    return [
      { text: tr('lint.hover_match', { domain: hit.domain || '' }) },
      { text: tr('lint.hover_nxdomain') },
      { text: tr('lint.hover_dig') },
    ];
  }
  return [
    { strong: tr('lint.hover_global_title'), text: tr('lint.hover_global') },
    { strong: tr('lint.hover_split_title'), text: tr('lint.hover_split') },
    { strong: tr('lint.hover_none_title'), text: tr('lint.hover_none') },
    { text: tr('lint.hover_nxdomain') },
    { text: tr('lint.hover_dig') },
  ];
}
