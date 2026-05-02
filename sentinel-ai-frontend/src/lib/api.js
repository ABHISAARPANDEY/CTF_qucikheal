








const API_PREFIX = '/api/v1';


export function wsUrl(path = '/ws/live') {
  if (typeof window === 'undefined') return path;
  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  return `${proto}//${window.location.host}${path}`;
}


export async function health() {
  const res = await fetch(`${API_PREFIX}/health`);
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
    const res = await fetch('/attack', {
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
  `${API_PREFIX}/pipeline/run?attack_type=${encodeURIComponent(attackType)}` :
  `${API_PREFIX}/pipeline/run`;
  const res = await fetch(url, { method: 'POST' });
  if (!res.ok) {
    const detail = await res.text().catch(() => '');
    throw new Error(`pipeline/run ${res.status}: ${detail}`);
  }
  return res.json();
}












export async function triggerScenario(type) {
  const res = await fetch(`/attack`, {
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
  const res = await fetch(`/attack`, { method: 'DELETE' });
  if (!res.ok) {
    const detail = await res.text().catch(() => '');
    throw new Error(`DELETE /attack ${res.status}: ${detail}`);
  }
  return res.json();
}

export async function copilotChat(prompt) {
  const res = await fetch(`${API_PREFIX}/copilot/chat`, {
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