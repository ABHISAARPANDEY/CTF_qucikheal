


















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