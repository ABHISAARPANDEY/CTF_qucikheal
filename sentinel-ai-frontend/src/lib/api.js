








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