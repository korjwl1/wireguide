// Pure helpers for the DNS-mode chips. Strings are never built here except
// through the translator `tr` ($t), so every locale goes through i18n keys.

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
export function dnsModeOf(parsed) {
  if (!parsed) return 'none';
  if (parsed.match.length) return 'split';
  if (parsed.servers.length) return 'global';
  if (parsed.search.length) return 'search';
  return 'none';
}

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
