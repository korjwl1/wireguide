const nameCollator = new Intl.Collator(undefined, { sensitivity: 'base', numeric: true });
const compareNames = nameCollator.compare;

export function sortTunnels(tunnels, sort, activeOnTop, activeNames) {
  let compare;
  switch (sort) {
    case 'name_desc': compare = (a, b) => -compareNames(a.name, b.name); break;
    case 'added_desc': compare = (a, b) => (b.created_at_unix || 0) - (a.created_at_unix || 0) || compareNames(a.name, b.name); break;
    case 'added_asc': compare = (a, b) => (a.created_at_unix || 0) - (b.created_at_unix || 0) || compareNames(a.name, b.name); break;
    case 'used_desc': compare = (a, b) => (b.last_used_unix || 0) - (a.last_used_unix || 0) || compareNames(a.name, b.name); break;
    default: compare = (a, b) => compareNames(a.name, b.name);
  }
  if (!activeOnTop) return [...tunnels].sort(compare);
  const active = [], inactive = [];
  for (const tunnel of tunnels) (activeNames.has(tunnel.name) ? active : inactive).push(tunnel);
  if (active.length === 0) return inactive.sort(compare);
  if (inactive.length === 0) return active.sort(compare);
  return active.sort(compare).concat(inactive.sort(compare));
}
