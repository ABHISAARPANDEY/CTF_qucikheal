import { useEffect, useRef, useState } from 'react';
import { buildTelemetryEntry, isSideChannelPayload } from './telemetry';
import {
  isValidAlertFrame,
  isValidConfigFrame,
  isValidHoneypotActivity,
  isValidHoneypotAnalysis,
  isValidPipelinePayload,
  isValidScenarioEvent,
  isValidStatsFrame,
  isValidSystemUpdate
} from './wsValidators';
import { getThresholds, listAlerts } from './api';

const MAX_ALERTS = 1000;
const MAX_STATS_HISTORY = 90;
const MAX_META = 2000;

export function mergeAlert(alerts, alert) {
  const next = { ...alerts, [alert.id]: alert };
  const keys = Object.keys(next);
  if (keys.length > MAX_ALERTS) {
    keys
      .sort((a, b) => Date.parse(next[a].first_seen ?? 0) - Date.parse(next[b].first_seen ?? 0))
      .slice(0, keys.length - MAX_ALERTS)
      .forEach((k) => delete next[k]);
  }
  return next;
}
































export function useRealtimeEvents({
  url = 'ws://localhost:8000/ws/live',
  maxEvents = 500
} = {}) {
  const [data, setData] = useState(() => ({
    events: [],
    eventsMeta: {},
    currentThreat: null,
    riskScore: null,
    actions: [],
    explanation: null,
    telemetryLogs: [],
    scenarioEvents: [],
    systemUpdates: {},
    honeypotActivities: [],
    honeypotAnalyses: [],
    alerts: {},
    stats: null,
    statsHistory: [],
    config: null
  }));
  const [status, setStatus] = useState('reconnecting');


  const wsRef = useRef(null);
  const retryTimerRef = useRef(null);
  const attemptsRef = useRef(0);
  const cancelledRef = useRef(false);

  useEffect(() => {
    cancelledRef.current = false;


    const teardown = () => {
      cancelledRef.current = true;
      if (retryTimerRef.current) {
        clearTimeout(retryTimerRef.current);
        retryTimerRef.current = null;
      }
      if (wsRef.current) {
        try {
          wsRef.current.close();
        } catch {
          void 0;
        }
        wsRef.current = null;
      }
    };


    const scheduleReconnect = () => {
      if (cancelledRef.current) return;
      const n = attemptsRef.current++;
      const delay = Math.min(500 * Math.pow(1.6, n), 10_000);
      retryTimerRef.current = setTimeout(connect, delay);
    };


    const connect = () => {
      if (cancelledRef.current) return;

      let ws;
      try {
        ws = new WebSocket(url);
      } catch (err) {

        console.warn('useRealtimeEvents: WebSocket constructor failed', err);
        setStatus('error');
        scheduleReconnect();
        return;
      }
      wsRef.current = ws;



      let erroredThisAttempt = false;

      ws.onopen = () => {
        attemptsRef.current = 0;
        setStatus('connected');
        // Hydrate slices that have REST sources so a fresh tab isn't empty.
        listAlerts({ limit: 500 })
          .then((res) => {
            if (cancelledRef.current) return;
            setData((prev) => {
              let alerts = prev.alerts;
              for (const a of res.items ?? []) alerts = mergeAlert(alerts, a);
              return { ...prev, alerts };
            });
          })
          .catch(() => void 0);
        getThresholds()
          .then((cfg) => {
            if (!cancelledRef.current) setData((prev) => ({ ...prev, config: cfg }));
          })
          .catch(() => void 0);
      };

      ws.onmessage = (event) => {
        let payload;
        try {
          payload = JSON.parse(event.data);
        } catch (err) {

          console.warn('useRealtimeEvents: failed to parse message', err);
          return;
        }
        if (!payload || typeof payload !== 'object') return;

        setData((prev) => {
          if (isValidAlertFrame(payload)) {
            return { ...prev, alerts: mergeAlert(prev.alerts, payload.alert) };
          }
          if (isValidStatsFrame(payload)) {
            const statsHistory = [...prev.statsHistory, { t: Date.now(), eps: payload.data.events_per_sec ?? 0 }]
              .slice(-MAX_STATS_HISTORY);
            return { ...prev, stats: payload.data, statsHistory };
          }
          if (isValidConfigFrame(payload)) {
            return { ...prev, config: payload.thresholds };
          }

          const isPipeline = isValidPipelinePayload(payload);
          const isSide = isSideChannelPayload(payload);
          const isScenario = isValidScenarioEvent(payload);
          const isSystemUpdate = isValidSystemUpdate(payload);
          const isHoneypotActivity = isValidHoneypotActivity(payload);
          const isHoneypotAnalysis = isValidHoneypotAnalysis(payload);

          let telemetryLogs = prev.telemetryLogs ?? [];
          if (isSide) {
            const entry = buildTelemetryEntry(payload);
            telemetryLogs = [entry, ...telemetryLogs].slice(0, 100);
          }

          let scenarioEvents = prev.scenarioEvents ?? [];
          if (isScenario) {
            scenarioEvents = prependUnique(
              scenarioEvents,
              payload,
              scenarioEventKey,
              80
            );
          }

          let systemUpdates = prev.systemUpdates ?? {};
          if (isSystemUpdate) {

            systemUpdates = {
              ...systemUpdates,
              [payload.system]: payload
            };
          }

          let honeypotActivities = prev.honeypotActivities ?? [];
          if (isHoneypotActivity) {
            honeypotActivities = prependUnique(
              honeypotActivities,
              payload,
              honeypotActivityKey,
              140
            );
          }

          let honeypotAnalyses = prev.honeypotAnalyses ?? [];
          if (isHoneypotAnalysis) {
            honeypotAnalyses = prependUnique(
              honeypotAnalyses,
              payload,
              honeypotAnalysisKey,
              140
            );
          }

          if (
          !isPipeline &&
          !isSide &&
          !isScenario &&
          !isSystemUpdate &&
          !isHoneypotActivity &&
          !isHoneypotAnalysis)
          {
            return prev;
          }

          if (!isPipeline) {
            return {
              ...prev,
              telemetryLogs,
              scenarioEvents,
              systemUpdates,
              honeypotActivities,
              honeypotAnalyses
            };
          }

          const incomingEvent = payload.event ?? null;
          const updatedEvents = incomingEvent ?
          [incomingEvent, ...prev.events].slice(0, maxEvents) :
          prev.events;

          let eventsMeta = prev.eventsMeta;
          if (incomingEvent?.id && payload.threat) {
            eventsMeta = {
              ...eventsMeta,
              [incomingEvent.id]: {
                threat_type: payload.threat.threat_type,
                risk_score: payload.threat.risk_score,
                severity: payload.threat.severity,
                signals: payload.threat.signals ?? [],
                alert_id: payload.alert_id ?? null,
                label: incomingEvent.label ?? null,
                ts: incomingEvent.timestamp
              }
            };
            const keys = Object.keys(eventsMeta);
            if (keys.length > MAX_META) {
              for (const k of keys.slice(0, keys.length - MAX_META)) delete eventsMeta[k];
            }
          }

          return {
            ...prev,
            events: updatedEvents,
            eventsMeta,
            currentThreat: payload.threat ?? prev.currentThreat,
            riskScore:
            typeof payload.threat?.risk_score === 'number' ?
            payload.threat.risk_score :
            prev.riskScore,
            actions: Array.isArray(payload.actions) ?
            payload.actions :
            prev.actions,
            explanation: payload.explanation ?? prev.explanation,
            telemetryLogs,
            scenarioEvents,
            systemUpdates,
            honeypotActivities,
            honeypotAnalyses
          };
        });
      };

      ws.onerror = () => {



        erroredThisAttempt = true;
        if (!cancelledRef.current) setStatus('error');
      };

      ws.onclose = () => {
        wsRef.current = null;
        if (cancelledRef.current) return;

        if (!erroredThisAttempt) setStatus('reconnecting');
        scheduleReconnect();
      };
    };

    connect();
    return teardown;
  }, [url, maxEvents]);

  return { data, status };
}

export function prependUnique(items, incoming, keyOf, maxSize) {
  const key = keyOf(incoming);
  if (!key) return [incoming, ...items].slice(0, maxSize);
  if (items.some((it) => keyOf(it) === key)) return items;
  return [incoming, ...items].slice(0, maxSize);
}

export function scenarioEventKey(evt) {
  if (!evt) return '';
  return [
  evt.run_id ?? '',
  evt.stage ?? '',
  evt.total_stages ?? '',
  evt.system ?? '',
  evt.severity ?? '',
  evt.label ?? '',
  evt.ts ?? ''].
  join('|');
}

export function honeypotActivityKey(evt) {
  if (!evt) return '';
  return [
  evt.run_id ?? '',
  evt.step ?? '',
  evt.total_steps ?? '',
  evt.data?.action ?? '',
  evt.ts ?? ''].
  join('|');
}

export function honeypotAnalysisKey(evt) {
  if (!evt) return '';
  return [
  evt.run_id ?? '',
  evt.step ?? '',
  evt.total_steps ?? '',
  evt.data?.pattern ?? '',
  evt.data?.risk ?? '',
  evt.ts ?? ''].
  join('|');
}