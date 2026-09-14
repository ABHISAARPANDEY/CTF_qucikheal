


















export const selectEvents = (s) => s.events;
export const selectThreat = (s) => s.threat;
export const selectRiskScore = (s) => s.riskScore;
export const selectActions = (s) => s.actions;
export const selectExplanation = (s) => s.explanation;
export const selectTelemetryLogs = (s) => s.telemetryLogs ?? [];
export const selectScenarioEvents = (s) => s.scenarioEvents ?? [];
export const selectSystemUpdates = (s) => s.systemUpdates ?? {};
export const selectHoneypotActivities = (s) => s.honeypotActivities ?? [];
export const selectHoneypotAnalyses = (s) => s.honeypotAnalyses ?? [];
export const selectStatus = (s) => s.status;


export const selectNewestEvent = (s) => s.events[0] ?? null;

export const selectEventsMeta = (s) => s.eventsMeta ?? {};
export const selectAlerts = (s) => s.alerts ?? {};
export const selectStats = (s) => s.stats;
export const selectStatsHistory = (s) => s.statsHistory ?? [];
export const selectConfig = (s) => s.config;

let _alertListCache = { src: null, list: [] };
export const selectAlertList = (s) => {
  const src = s.alerts ?? {};
  if (_alertListCache.src === src) return _alertListCache.list;
  const list = Object.values(src).sort((a, b) => Date.parse(b.last_seen ?? 0) - Date.parse(a.last_seen ?? 0));
  _alertListCache = { src, list };
  return list;
};
