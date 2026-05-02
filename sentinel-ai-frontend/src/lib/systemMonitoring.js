



export const SYSTEM_IDS = ['api', 'auth', 'database'];




export const SYSTEMS = {
  api: {
    id: 'api',
    name: 'API Server',
    threatTypes: ['ddos'],
    accent: 'cyan'
  },
  auth: {
    id: 'auth',
    name: 'Auth Server',
    threatTypes: ['brute_force'],
    accent: 'orange'
  },
  database: {
    id: 'database',
    name: 'Database',
    threatTypes: ['sql_injection'],
    accent: 'violet'
  }
};


export const BASE_PROCESSES = {
  api: [
  { pid: 'nginx', label: 'nginx', role: 'edge' },
  { pid: 'uvicorn', label: 'uvicorn', role: 'app' },
  { pid: 'celery', label: 'celery-worker', role: 'worker' },
  { pid: 'redis-sidecar', label: 'redis-sidecar', role: 'cache' }],

  auth: [
  { pid: 'keycloak', label: 'keycloak', role: 'idp' },
  { pid: 'oauth-proxy', label: 'oauth-proxy', role: 'proxy' },
  { pid: 'session-cache', label: 'session-cache', role: 'cache' }],

  database: [
  { pid: 'postgresql', label: 'postgresql', role: 'db' },
  { pid: 'pgbouncer', label: 'pgbouncer', role: 'pool' },
  { pid: 'wal-archiver', label: 'wal-archiver', role: 'archive' },
  { pid: 'backup-agent', label: 'backup-agent', role: 'backup' }]

};


const ANOMALY_PROCESS_BY_THREAT = {
  ddos: { systemId: 'api', pid: 'uvicorn' },
  brute_force: { systemId: 'auth', pid: 'keycloak' },
  sql_injection: { systemId: 'database', pid: 'postgresql' }
};





export function resolveSystemForThreat(threat) {
  if (!threat?.threat_type) return 'api';
  const mapped = ANOMALY_PROCESS_BY_THREAT[threat.threat_type];
  if (mapped) return mapped.systemId;
  const id = String(threat.id ?? threat.threat_type ?? '');
  let h = 0;
  for (let i = 0; i < id.length; i++) h = h * 31 + id.charCodeAt(i) >>> 0;
  return SYSTEM_IDS[h % SYSTEM_IDS.length];
}

export function resolveAnomalyProcess(threat) {
  if (!threat?.threat_type) return null;
  const mapped = ANOMALY_PROCESS_BY_THREAT[threat.threat_type];
  if (mapped) return mapped;
  const sys = resolveSystemForThreat(threat);
  const procs = BASE_PROCESSES[sys] ?? [];
  const pick = procs[0];
  return pick ? { systemId: sys, pid: pick.pid } : null;
}

export function formatAnomalyMessage(threat, event) {
  if (event?.message) {
    const m = event.message;
    return m.length > 120 ? `${m.slice(0, 118)}…` : m;
  }
  if (threat?.correlation) {
    return `Correlation: ${String(threat.correlation).replace(/_/g, ' ')}`;
  }
  if (threat?.signals?.length) {
    return `Signals: ${threat.signals.slice(0, 3).join(', ')}`;
  }
  return `Threat ${String(threat.threat_type ?? 'unknown').replace(/_/g, ' ')} — elevated risk ${threat.risk_score != null ? threat.risk_score.toFixed(1) : '—'}`;
}