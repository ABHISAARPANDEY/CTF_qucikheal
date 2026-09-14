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

export function isValidAlertFrame(payload) {
  if (!isObject(payload)) return false;
  if (payload.type !== 'alert_new' && payload.type !== 'alert_update') return false;
  const a = payload.alert;
  return (
    isObject(a) &&
    isString(a.id) &&
    isString(a.threat_type) &&
    isString(a.severity) &&
    isNumber(a.risk) &&
    isObject(a.entity)
  );
}

export function isValidStatsFrame(payload) {
  if (!isObject(payload) || payload.type !== 'stats') return false;
  return isObject(payload.data) && isNumber(payload.data.events_ingested);
}

export function isValidConfigFrame(payload) {
  if (!isObject(payload) || payload.type !== 'config_update') return false;
  return isObject(payload.thresholds);
}
