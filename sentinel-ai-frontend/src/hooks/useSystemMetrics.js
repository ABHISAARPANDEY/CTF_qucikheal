import { useEffect, useMemo, useState } from 'react';
import {
  BASE_PROCESSES,
  SYSTEM_IDS,
  SYSTEMS,
  formatAnomalyMessage,
  resolveAnomalyProcess } from
'../lib/systemMonitoring';

const WS_WINDOW_MS = 120_000;
const RECOVERY_GLOW_MS = 3_200;
const PHASE_OFFSETS = Object.fromEntries(
  SYSTEM_IDS.map((id) => [id, Math.random() * 10])
);




function logsForSystem(telemetryLogs, systemId, now) {
  return (telemetryLogs ?? []).filter(
    (e) => e.systemId === systemId && now - e.at < WS_WINDOW_MS
  );
}

function collectTerminatedPids(recoveries, mergedRows) {
  const terminated = new Set();
  for (const rec of recoveries) {
    const data = rec.payload?.data ?? {};
    const blob = `${data.target ?? ''} ${data.detail ?? ''} ${data.action ?? ''}`.toLowerCase();
    if (!blob.trim()) continue;
    for (const p of mergedRows) {
      const lab = (p.label ?? '').toLowerCase();
      const pid = (p.pid ?? '').toLowerCase();
      if (lab && blob.includes(lab)) terminated.add(p.pid);
      if (pid && blob.includes(pid)) terminated.add(p.pid);
    }
  }
  return terminated;
}




export function useSystemMetrics(threat, newestEvent, telemetryLogs = []) {
  const [tick, setTick] = useState(0);
  const [nowMs, setNowMs] = useState(0);

  useEffect(() => {
    const prime = setTimeout(() => setNowMs(Date.now()), 0);
    const id = setInterval(() => {
      setTick((n) => n + 1);
      setNowMs(Date.now());
    }, 1400);
    return () => {
      clearTimeout(prime);
      clearInterval(id);
    };
  }, []);

  return useMemo(() => {
    const now = nowMs;
    const pipelineAnomaly = resolveAnomalyProcess(threat);
    const pipelineMsg = threat ? formatAnomalyMessage(threat, newestEvent) : null;
    const pipelineTarget = pipelineAnomaly?.systemId ?? null;
    const pipelinePid = pipelineAnomaly?.pid ?? null;

    const bySystem = {};

    for (const id of SYSTEM_IDS) {
      const base = BASE_PROCESSES[id] ?? [];
      const seed = PHASE_OFFSETS[id];
      const wobble = Math.sin((tick + seed) * 0.7) * 6 + Math.cos((tick + seed) * 0.3) * 4;

      const sysTel = logsForSystem(telemetryLogs, id, now);
      const anomalies = sysTel.filter((l) => l.kind === 'anomaly');
      const recoveries = sysTel.filter((l) => l.kind === 'recovery');

      let cpuBoost = 0;
      let wsMessage = null;
      for (const a of anomalies) {
        const d = a.payload?.data ?? {};
        if (!wsMessage) wsMessage = a.summary;
        if (d.kind === 'high_cpu' && typeof d.cpu_percent === 'number') {
          cpuBoost = Math.max(cpuBoost, Math.min(55, (d.cpu_percent - 40) * 0.9));
        }
      }

      const isPipelineTarget = threat && pipelineTarget === id;
      const hasWsAnomaly = anomalies.length > 0;
      const hasAnyAnomaly = isPipelineTarget || hasWsAnomaly;

      let cpu = 18 + wobble + cpuBoost;
      if (isPipelineTarget && threat?.risk_score != null) {
        cpu += Math.min(42, threat.risk_score * 3.2);
      }
      cpu = Math.max(4, Math.min(96, cpu));

      let status = 'operational';
      if (hasAnyAnomaly) {
        const crit =
        threat?.severity === 'critical' ||
        (threat?.risk_score ?? 0) >= 8 ||
        anomalies.some((x) => x.payload?.data?.status === 'critical');
        const high =
        threat?.severity === 'high' ||
        (threat?.risk_score ?? 0) >= 5 ||
        anomalies.some((x) => x.payload?.data?.status === 'malicious');
        if (crit) status = 'critical';else
        if (high || hasWsAnomaly) status = 'degraded';else
        status = 'degraded';
      }

      const globalMsg = isPipelineTarget ? pipelineMsg : wsMessage;

      const injected = [];
      for (const a of anomalies) {
        const d = a.payload?.data ?? {};
        const proc = d.process;
        if (!proc || typeof proc !== 'string') continue;
        const exists = base.some((b) => b.pid === proc || b.label === proc);
        if (!exists) {
          const slug = proc.replace(/\W+/g, '_').slice(0, 24) || 'foreign';
          injected.push({
            pid: slug,
            label: proc,
            role: 'foreign',
            anomaly: true,
            anomalyMessage: a.summary,
            synthetic: true
          });
        }
      }

      const mergedRows = [...base.map((p) => ({ ...p })), ...injected];
      const terminated = collectTerminatedPids(recoveries, mergedRows);

      const recoveryFlash = recoveries.some((r) => now - r.at < RECOVERY_GLOW_MS);

      const processes = mergedRows.
      filter((p) => !terminated.has(p.pid)).
      map((p) => {
        const fromPipeline = isPipelineTarget && pipelinePid === p.pid;
        const nameHit = anomalies.some((an) => {
          const proc = an.payload?.data?.process;
          return proc && (p.label === proc || p.pid === proc || String(proc).includes(p.label));
        });
        const hot = Boolean(fromPipeline || nameHit || p.anomaly && p.synthetic);

        return {
          ...p,
          anomaly: hot,
          anomalyMessage: hot ?
          fromPipeline ?
          pipelineMsg :
          p.anomalyMessage ?? wsMessage :
          null
        };
      });

      bySystem[id] = {
        id,
        name: SYSTEMS[id].name,
        accent: SYSTEMS[id].accent,
        cpu: Math.round(cpu * 10) / 10,
        status,
        processes,
        hasAnomaly: hasAnyAnomaly,
        globalAnomalyMessage: hasAnyAnomaly ? globalMsg : null,
        recoveryFlash,
        wsAnomalyCount: anomalies.length
      };
    }

    return { systems: bySystem, tick, activeThreatId: threat?.id ?? null };
  }, [threat, newestEvent, telemetryLogs, tick, nowMs]);
}