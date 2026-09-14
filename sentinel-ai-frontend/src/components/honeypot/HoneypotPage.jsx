import { useEffect, useMemo, useState } from 'react';
import { motion } from 'framer-motion';
import { Bug, Play, Skull, Square } from 'lucide-react';
import { cancelAllScenarios, triggerScenario } from '../../lib/api';
import { ATTACKS } from '../scenarios/attacks';
import { useRealtime } from '../../lib/useRealtime';
import {
  selectHoneypotActivities,
  selectHoneypotAnalyses,
  selectNewestEvent,
  selectScenarioEvents } from
'../../lib/selectors';
import AnalysisPanel from './AnalysisPanel';
import AttackerInfoPanel from './AttackerInfoPanel';
import TerminalComponent from './TerminalComponent';
import TimelinePanel from './TimelinePanel';
import {
  ATTACK_META,
  ATTACK_TYPES,
  buildTimeline,
  detectPatterns,
  synthesizeAttackerIp } from
'./honeypotIntel';

export default function HoneypotPage() {
  const [attackVectorId, setAttackVectorId] = useState('multi-vector');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  const allScenarioEvents = useRealtime(selectScenarioEvents);
  const allHoneypotActivities = useRealtime(selectHoneypotActivities);
  const allHoneypotAnalyses = useRealtime(selectHoneypotAnalyses);
  const newestEvent = useRealtime(selectNewestEvent);

  const selectedVector = useMemo(
    () => ATTACKS.find((a) => a.id === attackVectorId) ?? ATTACKS[0],
    [attackVectorId]
  );
  const selectedScenarioType = selectedVector?.backendType ?? 'multi_stage';

  const latestHoneypot = allHoneypotActivities[0] ?? allHoneypotAnalyses[0] ?? null;
  const liveRunId = latestHoneypot?.run_id ?? allScenarioEvents[0]?.run_id ?? 'standby';
  const liveAttackType =
  latestHoneypot?.attack_type && ATTACK_TYPES.includes(latestHoneypot.attack_type) ?
  latestHoneypot.attack_type :
  selectedScenarioType;

  useEffect(() => {
    if (
    latestHoneypot?.attack_type &&
    ATTACK_TYPES.includes(latestHoneypot.attack_type))
    {
      const mappedVector = ATTACKS.find((a) => a.backendType === latestHoneypot.attack_type);
      if (!mappedVector || mappedVector.id === attackVectorId) return undefined;
      const t = setTimeout(() => setAttackVectorId(mappedVector.id), 0);
      return () => clearTimeout(t);
    }
    return undefined;
  }, [latestHoneypot, attackVectorId]);

  const runEvents = useMemo(() => {
    if (liveRunId === 'standby') return allScenarioEvents.slice(0, 80);
    return allScenarioEvents.filter((e) => !e.run_id || e.run_id === liveRunId).slice(0, 80);
  }, [allScenarioEvents, liveRunId]);

  const runHoneypotActivities = useMemo(() => {
    if (liveRunId === 'standby') return allHoneypotActivities.slice(0, 120);
    return allHoneypotActivities.filter((e) => !e.run_id || e.run_id === liveRunId).slice(0, 120);
  }, [allHoneypotActivities, liveRunId]);

  const runHoneypotAnalyses = useMemo(() => {
    if (liveRunId === 'standby') return allHoneypotAnalyses.slice(0, 120);
    return allHoneypotAnalyses.filter((e) => !e.run_id || e.run_id === liveRunId).slice(0, 120);
  }, [allHoneypotAnalyses, liveRunId]);

  const terminalRunId = `${liveRunId}:${liveAttackType}`;
  const trapped = Boolean(latestHoneypot);
  const startedAt = latestHoneypot?.ts ? Date.parse(latestHoneypot.ts) : null;

  const attackerIp = useMemo(() => {
    if (newestEvent?.source_ip) return newestEvent.source_ip;
    return synthesizeAttackerIp(liveAttackType, liveRunId);
  }, [liveAttackType, liveRunId, newestEvent]);

  const patterns = useMemo(
    () => detectPatterns(runEvents, runHoneypotAnalyses),
    [runEvents, runHoneypotAnalyses]
  );
  const stages = useMemo(() => buildTimeline(liveAttackType, runEvents), [liveAttackType, runEvents]);

  const onLaunch = async () => {
    if (busy) return;
    setBusy(true);
    setError(null);
    try {
      await triggerScenario(selectedScenarioType);
    } catch (err) {
      setError(err?.message ?? 'failed to dispatch attack');
    } finally {
      setTimeout(() => setBusy(false), 600);
    }
  };

  const onAbort = async () => {
    if (busy) return;
    setBusy(true);
    try {
      await cancelAllScenarios();
    } catch {
      void 0;
    } finally {
      setError(null);
      setTimeout(() => setBusy(false), 300);
    }
  };

  return (
    <div className="flex-1 min-h-0 flex flex-col p-3 gap-3 overflow-hidden">
      <PageHeader
        attackVectorId={attackVectorId}
        selectedScenarioType={selectedScenarioType}
        onAttackVectorChange={setAttackVectorId}
        onLaunch={onLaunch}
        onAbort={onAbort}
        busy={busy}
        trapped={trapped}
        error={error} />

      <div className="flex-1 min-h-0 grid gap-3 grid-cols-1 lg:grid-cols-12 lg:grid-rows-[minmax(0,3fr)_minmax(0,2fr)] overflow-hidden">
        <div className="min-h-0 lg:col-span-4 lg:row-span-1 flex flex-col">
          <AttackerInfoPanel
            attackType={liveAttackType}
            attackerIp={attackerIp}
            trapped={trapped}
            startedAt={startedAt}
            runId={liveRunId} />
        </div>

        <div className="min-h-0 lg:col-span-8 lg:row-span-2">
          <TerminalComponent
            runId={terminalRunId}
            attackType={liveAttackType}
            attackerIp={attackerIp}
            scenarioEvents={runEvents}
            honeypotActivities={runHoneypotActivities}
            honeypotAnalyses={runHoneypotAnalyses} />
        </div>

        <div className="min-h-0 lg:col-span-4 lg:row-span-1">
          <TimelinePanel stages={stages} />
        </div>

        <div className="min-h-0 lg:col-span-12 lg:row-span-1">
          <AnalysisPanel
            scenarioEvents={runEvents}
            patterns={patterns}
            honeypotAnalyses={runHoneypotAnalyses} />
        </div>
      </div>
    </div>);

}

function PageHeader({
  attackVectorId,
  selectedScenarioType,
  onAttackVectorChange,
  onLaunch,
  onAbort,
  busy,
  trapped,
  error
}) {
  return (
    <header className="shrink-0 flex flex-wrap items-start justify-between gap-3 px-1">
      <div className="flex items-start gap-3 min-w-0">
        <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-bg-2 border border-line text-sev-low">
          <Skull className="h-5 w-5" />
        </span>
        <div className="min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <h1 className="font-mono text-[11px] font-medium uppercase tracking-[0.22em] text-fg-secondary">
              Honeypot Analysis
            </h1>
            <StatusChip trapped={trapped} />
          </div>
          <p className="text-[14px] text-fg-primary leading-snug">
            {trapped ?
            'Live capture — adversary engaged in the decoy mesh.' :
            'Always-on decoy mesh — auto-engages whenever any attack hits the platform.'}
          </p>
          {error &&
          <p className="font-mono text-[11px] text-sev-critical mt-1">{error}</p>
          }
        </div>
      </div>

      <div className="flex items-center gap-2 shrink-0 flex-wrap">
        <AttackPicker
          value={attackVectorId}
          scenarioType={selectedScenarioType}
          onChange={onAttackVectorChange}
          disabled={busy}
        />

        <motion.button
          type="button"
          onClick={onLaunch}
          disabled={busy}
          whileHover={busy ? undefined : { y: -1 }}
          whileTap={busy ? undefined : { scale: 0.97 }}
          className="inline-flex items-center gap-2 rounded-md h-[34px] px-3 bg-accent text-white border border-accent hover:bg-accent-hover font-medium text-[12.5px] transition-cyber disabled:opacity-50 disabled:cursor-not-allowed">
          <Play className="h-3.5 w-3.5" />
          {busy ? 'Engaging…' : 'Simulate attack'}
        </motion.button>

        <motion.button
          type="button"
          onClick={onAbort}
          disabled={busy || !trapped}
          whileHover={busy || !trapped ? undefined : { y: -1 }}
          whileTap={busy || !trapped ? undefined : { scale: 0.97 }}
          className="inline-flex items-center gap-2 rounded-md h-[34px] px-3 border border-sev-critical/40 bg-sev-critical/10 text-sev-critical hover:bg-sev-critical/20 font-medium text-[12.5px] transition-cyber disabled:opacity-30 disabled:cursor-not-allowed">
          <Square className="h-3.5 w-3.5" />
          Release
        </motion.button>
      </div>
    </header>);

}

function StatusChip({ trapped }) {
  if (trapped) {
    return (
      <span className="inline-flex items-center gap-1.5 rounded-full border h-[22px] px-2 border-sev-critical/40 bg-sev-critical/10 text-sev-critical font-mono text-[10px] uppercase tracking-[0.06em]">
        <span className="h-1.5 w-1.5 rounded-full bg-sev-critical animate-blink" />
        Engaged
      </span>);

  }
  return (
    <span className="inline-flex items-center gap-1.5 rounded-full border h-[22px] px-2 border-sev-low/40 bg-sev-low/10 text-sev-low font-mono text-[10px] uppercase tracking-[0.06em]">
      <span className="h-1.5 w-1.5 rounded-full bg-sev-low" />
      Listening
    </span>);

}

function AttackPicker({ value, scenarioType, onChange, disabled }) {
  const selected = ATTACKS.find((a) => a.id === value) ?? ATTACKS[0];
  const meta = ATTACK_META[scenarioType] ?? ATTACK_META.multi_stage;
  return (
    <label className="inline-flex min-w-0 max-w-full items-center gap-2 rounded-md border h-[34px] px-2.5 border-line-strong bg-bg-2 text-fg-1 font-mono text-[11.5px] focus-within:border-accent/60">
      <Bug className="h-3.5 w-3.5 text-fg-3" />
      <span className="text-fg-3">vector</span>
      <select
        title={selected?.name ?? ''}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        disabled={disabled}
        className="min-w-[130px] max-w-[220px] truncate appearance-none bg-transparent outline-none font-mono text-[11.5px] text-fg-0 disabled:opacity-50 cursor-pointer">
        {ATTACKS.map((attack) =>
        <option key={attack.id} value={attack.id} className="bg-bg-1 text-fg-0">
            {attack.name}
          </option>
        )}
      </select>
      <span className="hidden xl:inline max-w-[180px] truncate text-fg-3 text-[10px]" title={selected?.desc ?? ''}>
        · {meta.banner}
      </span>
    </label>);

}
