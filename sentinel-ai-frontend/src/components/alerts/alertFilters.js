import { severityRank } from '../../lib/format';

export function applyFilters(list, { severity, status, type, entityType, q } = {}) {
  const s = (q ?? '').trim().toLowerCase();
  return list.filter((a) => {
    if (severity && severity.size && !severity.has(a.severity)) return false;
    if (status && status.size && !status.has(a.status)) return false;
    if (type && type.size && !type.has(a.threat_type)) return false;
    if (entityType && entityType.size && !entityType.has(a.entity?.type)) return false;
    if (s) {
      const hay = `${a.threat_type} ${a.entity?.key ?? ''} ${(a.signals ?? []).join(' ')} ${(a.mitre ?? []).join(' ')}`.toLowerCase();
      if (!hay.includes(s)) return false;
    }
    return true;
  });
}

const KEY = {
  severity: (a) => severityRank(a.severity),
  risk: (a) => a.risk ?? 0,
  count: (a) => a.count ?? 0,
  last_seen: (a) => Date.parse(a.last_seen ?? 0),
  threat_type: (a) => a.threat_type ?? ''
};

export function sortAlerts(list, key, dir = 'desc') {
  const fn = KEY[key];
  if (!fn) return list;
  const mul = dir === 'asc' ? 1 : -1;
  // severity: rank 0 = most severe, so "desc" should show most-severe first → invert
  const sevMul = key === 'severity' ? -mul : mul;
  return [...list].sort((a, b) => {
    const va = fn(a);
    const vb = fn(b);
    if (va < vb) return -1 * sevMul;
    if (va > vb) return 1 * sevMul;
    return 0;
  });
}
