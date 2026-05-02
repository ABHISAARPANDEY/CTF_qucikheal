import { useEffect, useRef, useState } from 'react';
import { buildTelemetryEntry, isSideChannelPayload } from './telemetry';
import {
  isValidHoneypotActivity,
  isValidHoneypotAnalysis,
  isValidPipelinePayload,
  isValidScenarioEvent,
  isValidSystemUpdate
} from './wsValidators';
































export function useRealtimeEvents({
  url = 'ws://localhost:8000/ws/live',
  maxEvents = 50
} = {}) {
  const [data, setData] = useState(() => ({
    events: [],
    currentThreat: null,
    riskScore: null,
    actions: [],
    explanation: null,
    telemetryLogs: [],
    scenarioEvents: [],
    systemUpdates: {},
    honeypotActivities: [],
    honeypotAnalyses: []
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

          return {
            events: updatedEvents,
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