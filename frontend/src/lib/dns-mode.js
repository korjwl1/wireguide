// Pure helpers for the DNS-mode chips and the DNS leak test's per-domain
// rows and "Try a name" box. Strings are never built here except through the
// translator `tr` ($t), so every locale goes through i18n keys.

// Splits an [Interface] DNS= list into servers, search domains and
// "~domain" split-DNS (routing-only) domains, mirroring domain.ParseDNSEntries.
export function parseDnsEntries(list) {
  const out = { servers: [], search: [], match: [] };
  for (const raw of list || []) {
    const tok = String(raw).trim();
    if (!tok) continue;
    if (tok.startsWith('~')) out.match.push(tok.slice(1));
    else if (tok.includes(':') || /^[0-9.]+$/.test(tok)) out.servers.push(tok);
    else out.search.push(tok);
  }
  return out;
}

// dnsModeOf classifies parsed entries the way diag.DNSModeOf does:
// split (any ~domain) > global (servers) > search (search domains only) > none.

// dnsChip returns { mode, text, hint } for the hero / list chip, or null when
// there is nothing worth saying (no DNS settings at all).
export function dnsChip(tr, mode, domains = []) {
  if (mode !== 'global' && mode !== 'split' && mode !== 'search') return null;
  return {
    mode,
    text: tr('tunnel.dns_chip_' + mode, { domains: domains.join(', ') }),
    hint: tr('tunnel.dns_chip_' + mode + '_hint'),
  };
}

// tryVia: "via 10.66.66.1 (~corp.example)" for a ResolveHost result.
export function tryVia(tr, r) {
  if (!r?.resolver) return '';
  return r.match_domain
    ? tr('tools.dns_try_via_domain', { resolver: r.resolver, domain: r.match_domain })
    : tr('tools.dns_try_via', { resolver: r.resolver });
}

// tryFailure: localised reason a ResolveHost lookup failed.
export function tryFailure(tr, r) {
  if (r.nxdomain) return tr('tools.dns_try_nxdomain');
  if (r.timed_out) return tr('tools.dns_try_timeout');
  if (r.error_code === 'invalid_name') return tr('tools.dns_try_invalid_name');
  return r.error;
}

// diagNoteKey picks the terminal caveat: dig/nslookup bypass supplemental
// resolvers only on macOS (dscacheutil is its alternative); Linux gets the
// resolvectl equivalent; Windows has neither.
export function diagNoteKey(platform) {
  if (/Mac/i.test(platform || '')) return 'tools.dns_leak_dig_note';
  if (/Linux|X11/i.test(platform || '')) return 'tools.dns_leak_linux_note';
  return '';
}

// domainLabel: match domains are shown with their "~", search domains bare.
export function domainLabel(d) {
  return d.search ? d.domain : '~' + d.domain;
}

// domainState: 'ok' (tunnel resolver owns it), 'mismatch' (another resolver
// owns it) or 'missing' (no supplemental resolver at all).
export function domainState(d) {
  if (d.registered) return 'ok';
  return d.resolver ? 'mismatch' : 'missing';
}

// resolveHint: placeholder example built from the first ~domain, if any.
export function resolveHint(domains) {
  return domains && domains[0] ? 'nas.' + domains[0] : '';
}
