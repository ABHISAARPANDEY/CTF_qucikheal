






const BACKEND_TO_UI = {
  api_server: 'api',
  auth_server: 'auth',
  database: 'database'
};

export function mapBackendSystem(system) {
  if (!system || typeof system !== 'string') return null;
  return BACKEND_TO_UI[system] ?? null;
}

function summarizeAnomaly(data) {
  if (!data || typeof data !== 'object') return 'Anomaly detected';
  const kind = data.kind ?? 'unknown';
  if (kind === 'high_cpu') {
    const pct = data.cpu_percent ?? '?';
    return `High CPU (${pct}%) — ${data.process ?? 'system'}`;
  }
  if (kind === 'unknown_process') return `Unknown process: ${data.process ?? '?'}`;
  if (kind === 'suspicious_script' || data.process?.includes?.('suspicious'))
  return `Malicious script: ${data.process ?? 'unknown'}`;
  if (kind === 'abnormal_db_queries')
  return `Abnormal DB query — ${data.rows_examined ?? '?'} rows scanned`;
  return `${kind.replace(/_/g, ' ')}`;
}

function summarizeRecovery(data) {
  if (!data || typeof data !== 'object') return 'Recovery event';
  const a = data.action ?? '';
  const t = data.target ?? '';
  const s = data.status ?? '';
  return `${a.replace(/_/g, ' ')} · ${t} → ${s}`;
}

function summarizeProcessLog(data) {
  if (!data || typeof data !== 'object') return 'Process log';
  const proc = data.process ?? '?';
  const msg = data.message ?? '';
  const lv = data.level ?? 'info';
  return `[${lv}] ${proc}: ${msg.slice(0, 72)}${msg.length > 72 ? '…' : ''}`;
}




export function buildTelemetryEntry(payload) {
  const kind = payload.type;
  const systemId = mapBackendSystem(payload.system);
  const data = payload.data ?? {};

  const summary =
  kind === 'anomaly' ?
  summarizeAnomaly(data) :
  kind === 'recovery' ?
  summarizeRecovery(data) :
  kind === 'process_log' ?
  summarizeProcessLog(data) :
  JSON.stringify(payload).slice(0, 120);

  const id = `${Date.now()}-${Math.random().toString(36).slice(2, 11)}`;

  return {
    id,
    at: Date.now(),
    kind,
    systemId,
    summary,
    payload
  };
}

export function isSideChannelPayload(payload) {
  const t = payload?.type;
  return t === 'anomaly' || t === 'process_log' || t === 'recovery';
}