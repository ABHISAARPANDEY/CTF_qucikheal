








const API_PREFIX = '/api/v1';
const DEFAULT_WS_PATH = '/ws/live';

function trimTrailingSlash(value) {
  return value ? value.replace(/\/+$/, '') : '';
}

function getApiBaseUrl() {
  const configured = trimTrailingSlash(import.meta.env.VITE_API_BASE_URL ?? '');
  if (configured) return configured;
  if (typeof window === 'undefined') return '';
  return `${window.location.protocol}//${window.location.host}`;
}

function withApiBase(path) {
  const base = getApiBaseUrl();
  return `${base}${path}`;
}

export function wsUrl(path = DEFAULT_WS_PATH) {
  const configured = trimTrailingSlash(import.meta.env.VITE_WS_BASE_URL ?? '');
  if (configured) return `${configured}${path}`;

  const apiBase = getApiBaseUrl();
  if (apiBase) {
    const wsBase = apiBase.replace(/^http/i, 'ws');
    return `${wsBase}${path}`;
  }

  return path;
}


export async function health() {
  const res = await fetch(withApiBase(`${API_PREFIX}/health`));
  if (!res.ok) throw new Error(`health ${res.status}`);
  return res.json();
}








export async function triggerAttackKind(attack) {
  // Traffic-generator sessions (new behavioural vectors).
  const kind = typeof attack === 'string' ? attack : attack?.trafficKind;
  if (kind) {
    const speed = kind === 'low_slow_brute_force' ? 15 : kind === 'port_scan' ? 3 : 3;
    return trafficAttack({ kind, duration_s: 22, speed });
  }
  return null;
}

export async function triggerAttack(attackType) {
  const scenarioTypes = new Set([
    'ddos',
    'brute_force',
    'sql_injection',
    'insider',
    'multi_stage'
  ]);
  if (attackType && scenarioTypes.has(attackType)) {
    const res = await fetch(withApiBase('/attack'), {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ type: attackType })
    });
    if (!res.ok) {
      const detail = await res.text().catch(() => '');
      throw new Error(`/attack ${res.status}: ${detail}`);
    }
    return res.json();
  }
  const url = attackType ?
  withApiBase(`${API_PREFIX}/pipeline/run?attack_type=${encodeURIComponent(attackType)}`) :
  withApiBase(`${API_PREFIX}/pipeline/run`);
  const res = await fetch(url, { method: 'POST' });
  if (!res.ok) {
    const detail = await res.text().catch(() => '');
    throw new Error(`pipeline/run ${res.status}: ${detail}`);
  }
  return res.json();
}












export async function triggerScenario(type) {
  const res = await fetch(withApiBase('/attack'), {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ type })
  });
  if (!res.ok) {
    const detail = await res.text().catch(() => '');
    throw new Error(`/attack ${res.status}: ${detail}`);
  }
  return res.json();
}


export async function cancelAllScenarios() {
  const res = await fetch(withApiBase('/attack'), { method: 'DELETE' });
  if (!res.ok) {
    const detail = await res.text().catch(() => '');
    throw new Error(`DELETE /attack ${res.status}: ${detail}`);
  }
  return res.json();
}

export async function copilotChat(prompt) {
  const res = await fetch(withApiBase(`${API_PREFIX}/copilot/chat`), {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ prompt })
  });
  if (!res.ok) {
    const detail = await res.text().catch(() => '');
    throw new Error(`copilot/chat ${res.status}: ${detail}`);
  }
  return res.json();
}

export async function resetDemoState() {
  const res = await fetch(withApiBase(`${API_PREFIX}/demo/reset`), { method: 'POST' });
  if (!res.ok) {
    const detail = await res.text().catch(() => '');
    throw new Error(`demo/reset ${res.status}: ${detail}`);
  }
  return res.json();
}

// ---------------------------------------------------------------------------
// Detection / alerts / thresholds / traffic / reports
// ---------------------------------------------------------------------------

async function request(path, { method = 'GET', body, headers = {}, text = false } = {}) {
  const res = await fetch(withApiBase(`${API_PREFIX}${path}`), {
    method,
    headers: body != null ? { 'content-type': 'application/json', ...headers } : headers,
    body: body != null ? JSON.stringify(body) : undefined
  });
  if (!res.ok) {
    const detail = await res.text().catch(() => '');
    throw new Error(`${method} ${path} ${res.status}: ${detail}`);
  }
  if (res.status === 204) return null;
  return text ? res.text() : res.json();
}

const qs = (params) => {
  const u = new URLSearchParams();
  for (const [k, v] of Object.entries(params ?? {})) {
    if (v != null && v !== '') u.set(k, String(v));
  }
  const str = u.toString();
  return str ? `?${str}` : '';
};

export const getThresholds = () => request('/config/thresholds');
export const putThresholds = (patch) => request('/config/thresholds', { method: 'PUT', body: patch });
export const resetThresholds = () => request('/config/thresholds/reset', { method: 'POST' });

export const listAlerts = (params) => request(`/alerts${qs(params)}`);
export const getAlert = (id) => request(`/alerts/${encodeURIComponent(id)}`);
export const patchAlert = (id, patch) => request(`/alerts/${encodeURIComponent(id)}`, { method: 'PATCH', body: patch });
export const alertsSummary = () => request('/alerts/summary');

export const trafficAttack = ({ kind, duration_s = 20, speed = 1, seed } = {}) =>
  request('/traffic/attack', { method: 'POST', body: { kind, duration_s, speed, seed } });
export const trafficStop = () => request('/traffic/attack', { method: 'DELETE' });
export const trafficStats = () => request('/traffic/stats');
export const trafficConfig = (cfg) => request('/traffic/config', { method: 'PUT', body: cfg });

export const detectionStatus = () => request('/detection/status');
export const detectionCampaigns = () => request('/detection/campaigns');
export const detectionEntity = (type, key) =>
  request(`/detection/entity/${encodeURIComponent(type)}/${encodeURIComponent(key)}`);
export const detectionRetrain = () => request('/detection/retrain', { method: 'POST' });

export const incidentReport = (since) => request(`/reports/incident${qs({ since })}`);
export const incidentReportMarkdown = (since) =>
  request(`/reports/incident${qs({ since })}`, { headers: { accept: 'text/markdown' }, text: true });

export const SESSION_KINDS = [
  'port_scan',
  'credential_stuffing',
  'low_slow_brute_force',
  'brute_force',
  'ddos',
  'sql_injection'
];
