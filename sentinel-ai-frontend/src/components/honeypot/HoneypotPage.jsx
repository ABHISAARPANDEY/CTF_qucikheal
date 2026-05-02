import { useEffect, useMemo, useState } from 'react';
import { motion } from 'framer-motion';
import { Bug, Play, Skull, Square } from 'lucide-react';
import { cancelAllScenarios, triggerScenario } from '../../lib/api';
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
  const [attackType, setAttackType] = useState('multi_stage');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  const allScenarioEvents = useRealtime(selectScenarioEvents);
  const allHoneypotActivities = useRealtime(selectHoneypotActivities);
  const allHoneypotAnalyses = useRealtime(selectHoneypotAnalyses);
  const newestEvent = useRealtime(selectNewestEvent);

  const latestHoneypot = allHoneypotActivities[0] ?? allHoneypotAnalyses[0] ?? null;
  const liveRunId = latestHoneypot?.run_id ?? allScenarioEvents[0]?.run_id ?? 'standby';
  const liveAttackType =
  latestHoneypot?.attack_type && ATTACK_TYPES.includes(latestHoneypot.attack_type) ?
  latestHoneypot.attack_type :
  attackType;

  useEffect(() => {
    if (
    latestHoneypot?.attack_type &&
    ATTACK_TYPES.includes(latestHoneypot.attack_type) &&
    latestHoneypot.attack_type !== attackType)
    {
      const t = setTimeout(() => setAttackType(latestHoneypot.attack_type), 0);
      return () => clearTimeout(t);
    }
    return undefined;
  }, [latestHoneypot, attackType]);

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
      await triggerScenario(attackType);
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
        attackType={attackType}
        onAttackTypeChange={setAttackType}
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
  attackType,
  onAttackTypeChange,
  onLaunch,
  onAbort,
  busy,
  trapped,
  error
}) {
  return (
    <header className="shrink-0 flex flex-wrap items-start justify-between gap-3 px-1">
      <div className="flex items-start gap-3 min-w-0">
        <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-bg-elevated/70 border border-neon-green/30 text-neon-green shadow-[0_0_18px_-8px_rgba(0,255,159,0.65)]">
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
          <p className="font-mono text-[10.5px] uppercase tracking-[0.22em] text-neon-red text-glow-red mt-1">
              [!] {error}
            </p>
          }
        </div>
      </div>

      <div className="flex items-center gap-2 shrink-0 flex-wrap">
        <AttackPicker value={attackType} onChange={onAttackTypeChange} disabled={busy} />

        <motion.button
          type="button"
          onClick={onLaunch}
          disabled={busy}
          whileHover={busy ? undefined : { y: -1 }}
          whileTap={busy ? undefined : { scale: 0.97 }}
          className="inline-flex items-center gap-2 rounded-lg border h-[34px] px-3 border-neon-green/45 bg-neon-green/[0.08] text-neon-green text-glow-green font-mono text-[11px] uppercase tracking-[0.22em] font-semibold shadow-[0_0_18px_-6px_rgba(0,255,159,0.55)] hover:border-neon-green/70 hover:bg-neon-green/[0.12] transition-cyber disabled:opacity-50 disabled:cursor-not-allowed">
          <Play className="h-3.5 w-3.5" />
          {busy ? 'engaging…' : 'simulate attack'}
        </motion.button>

        <motion.button
          type="button"
          onClick={onAbort}
          disabled={busy || !trapped}
          whileHover={busy || !trapped ? undefined : { y: -1 }}
          whileTap={busy || !trapped ? undefined : { scale: 0.97 }}
          className="inline-flex items-center gap-2 rounded-lg border h-[34px] px-3 border-neon-red/45 bg-neon-red/[0.08] text-neon-red font-mono text-[11px] uppercase tracking-[0.22em] font-semibold shadow-[0_0_18px_-6px_rgba(255,59,59,0.55)] hover:border-neon-red/70 hover:bg-neon-red/[0.12] transition-cyber disabled:opacity-30 disabled:cursor-not-allowed">
          <Square className="h-3.5 w-3.5" />
          release
        </motion.button>
      </div>
    </header>);

}

function StatusChip({ trapped }) {
  if (trapped) {
    return (
      <span className="inline-flex items-center gap-1.5 rounded-full border h-[22px] px-2 border-neon-red/45 bg-neon-red/[0.10] text-neon-red text-glow-red font-mono text-[9px] uppercase tracking-[0.22em]">
        <span className="h-1.5 w-1.5 rounded-full bg-neon-red shadow-[0_0_10px_rgba(255,59,59,0.85)] animate-anomaly-pulse" />
        Engaged
      </span>);

  }
  return (
    <span className="inline-flex items-center gap-1.5 rounded-full border h-[22px] px-2 border-neon-green/40 bg-neon-green/[0.10] text-neon-green font-mono text-[9px] uppercase tracking-[0.22em]">
      <span className="h-1.5 w-1.5 rounded-full bg-neon-green shadow-[0_0_10px_rgba(0,255,159,0.7)] animate-pulse" />
      Listening
    </span>);

}

function AttackPicker({ value, onChange, disabled }) {
  const meta = ATTACK_META[value] ?? ATTACK_META.ddos;
  return (
    <label className="inline-flex items-center gap-2 rounded-lg border h-[34px] px-2.5 border-neon-green/30 bg-black/60 text-neon-green/85 font-mono text-[11px] uppercase tracking-[0.22em] focus-within:border-neon-green/60">
      <Bug className="h-3.5 w-3.5 text-neon-green/70" />
      <span className="text-neon-green/55">vector</span>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        disabled={disabled}
        className="appearance-none bg-transparent outline-none font-mono text-[11px] uppercase tracking-[0.22em] text-neon-green text-glow-green disabled:opacity-50 cursor-pointer">
        {ATTACK_TYPES.map((t) =>
        <option key={t} value={t} className="bg-black text-neon-green">
            {ATTACK_META[t]?.label ?? t}
          </option>
        )}
      </select>
      <span className="hidden md:inline text-neon-green/45 text-[9.5px]">
        · {meta.banner}
      </span>
    </label>);

}
