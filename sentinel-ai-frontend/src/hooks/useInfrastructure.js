import { useEffect, useMemo, useState } from 'react';
import { useRealtime } from '../lib/useRealtime';
import { selectNewestEvent, selectSystemUpdates, selectThreat } from '../lib/selectors';
import {
  SYSTEMS,
  SYSTEM_IDS,
  describeAnomaly,
  lateralSystems,
  resolveTargetSystem } from
'../lib/infrastructure';

const TICK_MS = 1200;



const PHASE_OFFSETS = Object.fromEntries(
  SYSTEM_IDS.map((id) => [id, Math.random() * Math.PI * 2])
);





















export function useInfrastructure() {
  const threat = useRealtime(selectThreat);
  const newestEvent = useRealtime(selectNewestEvent);
  const systemUpdates = useRealtime(selectSystemUpdates);

  const [tick, setTick] = useState(0);
  useEffect(() => {
    const id = setInterval(() => setTick((n) => n + 1), TICK_MS);
    return () => clearInterval(id);
  }, []);

  const target = resolveTargetSystem(threat);

  return useMemo(() => {
    const targetId = target;
    const lateral = targetId ? new Set(lateralSystems(targetId)) : new Set();

    const severity = threat?.severity ?? null;
    const risk = threat?.risk_score ?? 0;
    const isCritical =
    threat && (
    severity === 'critical' || risk >= 8);
    const isHigh =
    threat && (
    severity === 'high' || risk >= 5);

    const systems = {};
    let critical = 0;
    let warning = 0;
    let normal = 0;

    for (const id of SYSTEM_IDS) {
      const def = SYSTEMS[id];
      const phase = PHASE_OFFSETS[id];

      const wobble =
      Math.sin(tick * 0.55 + phase) * 5 +
      Math.cos(tick * 0.21 + phase * 1.7) * 3;

      const isPrimary = id === targetId;
      const isLateral = lateral.has(id);

      const live = systemUpdates[id];
      const liveData = live?.data ?? null;
      const liveFresh = Boolean(liveData);



      let status = 'normal';
      if (liveFresh && typeof liveData.status === 'string') {
        status =
        liveData.status === 'critical' ?
        'critical' :
        liveData.status === 'warning' ?
        'warning' :
        'normal';
      } else {
        if (isPrimary && isCritical) status = 'critical';else
        if (isPrimary && (isHigh || threat)) status = 'warning';else
        if (isLateral && (isCritical || isHigh)) status = 'warning';
      }


      let cpuBoost = 0;
      let rpsBoost = 0;
      if (isPrimary) {
        cpuBoost = 22 + Math.min(38, risk * 4);
        rpsBoost = 0.85 + Math.min(2.4, risk * 0.32);
      } else if (isLateral && (isCritical || isHigh)) {
        cpuBoost = 10 + Math.min(14, risk * 1.6);
        rpsBoost = 0.25;
      }

      const fallbackCpu = clamp(def.baseCpu + wobble + cpuBoost, 4, 98);
      const fallbackRps = Math.max(
        12,
        Math.round(def.baseRps * (1 + rpsBoost) + wobble * 14)
      );

      const cpu = liveFresh && typeof liveData.cpu === 'number' ?
      clamp(liveData.cpu, 0, 100) :
      fallbackCpu;
      const rps = liveFresh && typeof liveData.requests === 'number' ?
      Math.max(0, Math.round(liveData.requests)) :
      fallbackRps;

      const fallbackLatency =
      Math.round(
        (status === 'critical' ? 320 : status === 'warning' ? 80 : 22) +
        Math.abs(wobble) * (status === 'normal' ? 0.6 : 4)
      );
      const latency = liveFresh && typeof liveData.latency_ms === 'number' ?
      Math.max(0, Math.round(liveData.latency_ms)) :
      fallbackLatency;



      const noise = pseudoNoise(`${id}:${Math.floor(tick / 4)}`);
      const fallbackErrorRate =
      status === 'critical' ?
      +(2.4 + noise * 1.6).toFixed(2) :
      status === 'warning' ?
      +(0.6 + noise * 0.6).toFixed(2) :
      +(0.01 + noise * 0.04).toFixed(2);
      const errorRate = liveFresh && typeof liveData.error_rate === 'number' ?
      +liveData.error_rate.toFixed(2) :
      fallbackErrorRate;

      const hasAnomaly =
      liveFresh && Array.isArray(liveData.anomalies) && liveData.anomalies.length > 0 ||
      isPrimary ||
      isLateral && (isCritical || isHigh);
      const message = hasAnomaly ?
      liveFresh && Array.isArray(liveData.anomalies) && liveData.anomalies.length ?
      `${def.name}: ${liveData.anomalies.join(', ').replace(/_/g, ' ')}` :
      describeAnomaly(threat, isPrimary ? newestEvent : null, id) :
      null;



      const baseProcs = def.processes.map((p) => ({ ...p, anomaly: false }));
      const processes = liveFresh && Array.isArray(liveData.processes) ?
      liveData.processes.map((p, idx) => ({
        pid: String(
          p.malicious ?
          `mal-${p.name ?? p.pid ?? idx}` :
          p.pid ?? p.name ?? `${id}-${idx}`
        ),
        label: p.name ?? p.label ?? `proc-${idx}`,
        role: p.role ?? 'service',
        anomaly: Boolean(p.malicious || p.status === 'malicious'),
        summary: p.summary ?? null
      })) :
      isPrimary && (isCritical || isHigh) ?
      [
      ...baseProcs,
      {
        ...def.malicious,
        anomaly: true,
        summary: message ?? def.malicious.summary
      }] :

      baseProcs;

      const snap = {
        id,
        name: def.name,
        kind: def.kind,
        accent: def.accent,
        cluster: def.cluster,
        icon: def.icon,
        regions: def.regions,
        cpu: round1(cpu),
        rps,
        latency,
        errorRate,
        uptime: 99.92 - (status === 'critical' ? 0.4 : status === 'warning' ? 0.08 : 0),
        status,
        hasAnomaly,
        underAttack: status === 'critical',
        anomalyMessage: message,
        processes,
        threatType: threat?.threat_type ?? null
      };

      systems[id] = snap;
      if (status === 'critical') critical++;else
      if (status === 'warning') warning++;else
      normal++;
    }

    return {
      systems,
      summary: { critical, warning, normal, total: SYSTEM_IDS.length },
      activeThreatId: threat?.id ?? null
    };
  }, [tick, threat, newestEvent, target, systemUpdates]);
}



function clamp(v, lo, hi) {
  return Math.max(lo, Math.min(hi, v));
}

function round1(n) {
  return Math.round(n * 10) / 10;
}


function pseudoNoise(seed) {
  let h = 2166136261;
  for (let i = 0; i < seed.length; i++) {
    h ^= seed.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return (h >>> 0) % 1000 / 1000;
}