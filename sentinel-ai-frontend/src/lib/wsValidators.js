function isObject(value) {
  return value != null && typeof value === 'object' && !Array.isArray(value);
}

function isString(value) {
  return typeof value === 'string';
}

function isNumber(value) {
  return typeof value === 'number' && Number.isFinite(value);
}

export function isValidScenarioEvent(payload) {
  if (!isObject(payload) || payload.type !== 'scenario_event') return false;
  return (
    isString(payload.scenario) &&
    isString(payload.run_id) &&
    Number.isInteger(payload.stage) &&
    Number.isInteger(payload.total_stages) &&
    isString(payload.severity) &&
    isString(payload.ts)
  );
}

export function isValidSystemUpdate(payload) {
  if (!isObject(payload) || payload.type !== 'system_update') return false;
  if (!isString(payload.system) || !isObject(payload.data)) return false;
  const data = payload.data;
  return (
    isNumber(data.cpu) &&
    Number.isInteger(data.requests) &&
    Number.isInteger(data.latency_ms) &&
    isNumber(data.error_rate) &&
    isString(data.status) &&
    Array.isArray(data.anomalies) &&
    Array.isArray(data.processes) &&
    isString(data.ts)
  );
}

export function isValidHoneypotActivity(payload) {
  if (!isObject(payload) || payload.type !== 'honeypot_activity') return false;
  return (
    isString(payload.run_id) &&
    isString(payload.attack_type) &&
    Number.isInteger(payload.step) &&
    Number.isInteger(payload.total_steps) &&
    isString(payload.ts) &&
    isObject(payload.data) &&
    isString(payload.data.action)
  );
}

export function isValidHoneypotAnalysis(payload) {
  if (!isObject(payload) || payload.type !== 'honeypot_analysis') return false;
  return (
    isString(payload.run_id) &&
    isString(payload.attack_type) &&
    Number.isInteger(payload.step) &&
    Number.isInteger(payload.total_steps) &&
    isString(payload.ts) &&
    isObject(payload.data) &&
    isString(payload.data.pattern) &&
    isString(payload.data.risk)
  );
}

export function isValidPipelinePayload(payload) {
  if (!isObject(payload)) return false;
  return payload.event != null || payload.threat != null || payload.actions != null;
}
