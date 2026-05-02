import { useEffect, useMemo, useRef, useState } from 'react';
import { motion } from 'framer-motion';
import { Crosshair, Filter, Radio } from 'lucide-react';
import Terminal from './Terminal';
import {
  buildHoneypotEngagement,
  buildHoneypotPipelineFinale,
  buildPreviewHoneypotScript } from
'./honeypotScript';
import { ATTACKS, CATEGORIES } from './attacks';
import { Badge } from '../ui/badge';
import { Button } from '../ui/button';
import { triggerAttack } from '../../lib/api';
import { useRealtime } from '../../lib/useRealtime';
import {
  selectActions,
  selectExplanation,
  selectNewestEvent,
  selectThreat } from
'../../lib/selectors';



















const WIRED_COUNT = ATTACKS.filter((a) => a.active).length;

export default function AttackPanel() {

  const [selected, setSelected] = useState(null);

  const [runId, setRunId] = useState(0);


  const [script, setScript] = useState(null);
  const [busy, setBusy] = useState(false);


  const event = useRealtime(selectNewestEvent);
  const threat = useRealtime(selectThreat);
  const actions = useRealtime(selectActions);
  const explanation = useRealtime(selectExplanation);



  const consumedThreatRef = useRef(null);


  useEffect(() => {
    if (!selected?.active) return;
    if (!threat || !event || !actions) return;
    if (consumedThreatRef.current === threat.id) return;



    if (selected.backendType && threat.threat_type !== selected.backendType) return;

    consumedThreatRef.current = threat.id;
    setScript((prev) => [
    ...(prev ?? []),
    ...buildHoneypotPipelineFinale(event, threat, actions, explanation)]
    );
  }, [selected, event, threat, actions, explanation]);

  const runPreview = (attack) => {
    if (busy) return;
    setBusy(true);
    setSelected(attack);
    setRunId((n) => n + 1);
    consumedThreatRef.current = null;
    setScript(buildPreviewHoneypotScript(attack));
    setTimeout(() => setBusy(false), 320);
  };

  const launchLive = async (attack) => {
    if (!attack.active || busy) return;
    setBusy(true);
    setSelected(attack);
    setRunId((n) => n + 1);
    consumedThreatRef.current = null;
    setScript(buildHoneypotEngagement(attack));

    try {
      await triggerAttack(attack.backendType);
    } catch (err) {
      setScript((prev) => [
      ...(prev ?? []),
      '',
      `[✗] dispatch failed: ${err?.message ?? 'unknown error'}`,
      '[!] check backend connectivity and retry']
      );
    } finally {
      setTimeout(() => setBusy(false), 300);
    }
  };

  const handleTileClick = (attack) => {
    if (busy) return;
    if (attack.active) void launchLive(attack);else
    runPreview(attack);
  };


  const tilesByCategory = useMemo(() => {
    const groups = {};
    for (const a of ATTACKS) {
      ;(groups[a.category] ||= []).push(a);
    }
    return groups;
  }, []);

  return (
    <div className="flex-1 min-h-0 grid grid-cols-1 lg:grid-cols-12 gap-3 p-3 overflow-hidden">
      {}
      <section className="lg:col-span-7 min-h-0 flex flex-col rounded-2xl border border-border-subtle glass-panel overflow-hidden">
        <header className="flex items-start justify-between gap-3 px-5 pt-4 pb-3 border-b border-border-subtle">
          <div className="flex items-center gap-3 min-w-0">
            <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-bg-elevated/70 border border-neon-orange/35 text-neon-orange shadow-[0_0_18px_-6px_rgba(255,159,28,0.7)]">
              <Crosshair className="h-4 w-4" />
            </span>
            <div className="min-w-0">
              <h1 className="font-mono text-[11px] font-medium uppercase tracking-[0.22em] text-fg-secondary">
                Attack Scenarios
              </h1>
              <p className="text-[13px] text-fg-primary/95 leading-tight truncate">
                Launch and visualize cyber-attack chains in real time
              </p>
            </div>
          </div>
          <div className="shrink-0 flex items-center gap-2">
            <Badge variant="success" glow>
              <span className="font-semibold">{WIRED_COUNT}</span>
              <span className="opacity-70"> live</span>
              <span className="opacity-45 mx-1">·</span>
              <span className="opacity-70">{ATTACKS.length} scenarios</span>
            </Badge>
            <Button variant="ghost" size="icon" className="h-7 w-7" aria-label="Filter">
              <Filter className="h-3.5 w-3.5" />
            </Button>
          </div>
        </header>

        <div className="flex-1 overflow-y-auto scrollbar-cyber p-4 space-y-5">
          {Object.entries(tilesByCategory).map(([cat, list]) =>
          <CategoryGroup
            key={cat}
            category={cat}
            attacks={list}
            selectedId={selected?.id}
            onSelect={handleTileClick}
            disabled={busy} />

          )}
        </div>
      </section>

      {}
      <section className="lg:col-span-5 min-h-[420px] lg:min-h-0">
        <Terminal script={script} runId={runId} />
      </section>
    </div>);

}

function CategoryGroup({ category, attacks, selectedId, onSelect, disabled }) {
  const meta = CATEGORIES[category] ?? CATEGORIES.NETWORK;
  const liveInCat = attacks.filter((a) => a.active).length;
  return (
    <div>
      <div className="flex items-center gap-2 mb-2">
        <span
          className="h-1 w-3 rounded-full"
          style={{ background: `rgb(${meta.rgb})`, boxShadow: `0 0 8px rgba(${meta.rgb},0.7)` }} />
        
        <span
          className="font-mono text-[10.5px] uppercase tracking-[0.28em]"
          style={{ color: `rgb(${meta.rgb})` }}>
          
          {meta.label}
        </span>
        <span className="ml-auto font-mono text-[9.5px] tracking-[0.22em] text-fg-faint">
          {attacks.length} scenarios
          {liveInCat > 0 ?
          <span className="text-fg-muted"> · {liveInCat} live</span> :
          null}
        </span>
      </div>
      <div className="grid grid-cols-2 sm:grid-cols-3 xl:grid-cols-4 gap-2">
        {attacks.map((attack) =>
        <AttackTile
          key={attack.id}
          attack={attack}
          selected={attack.id === selectedId}
          onClick={onSelect}
          disabled={disabled} />

        )}
      </div>
    </div>);

}

function AttackTile({ attack, selected, onClick, disabled }) {
  const meta = CATEGORIES[attack.category] ?? CATEGORIES.NETWORK;
  const wired = attack.active;

  return (
    <motion.button
      type="button"
      onClick={() => onClick(attack)}
      disabled={disabled}
      title={wired ? 'Runs live pipeline simulation' : 'Preview — simulator not wired for this vector'}
      whileHover={disabled ? undefined : { y: -2 }}
      whileTap={disabled ? undefined : { scale: 0.97 }}
      transition={{ type: 'spring', stiffness: 380, damping: 28 }}
      style={{ '--tile-rgb': meta.rgb }}
      className={[
      'relative overflow-hidden rounded-lg p-2.5 text-left select-none transition-cyber',
      'border bg-gradient-to-br',
      wired ? '' : 'opacity-[0.92]',
      selected ?
      'border-[rgba(var(--tile-rgb),0.65)] from-[rgba(var(--tile-rgb),0.18)] to-[rgba(var(--tile-rgb),0.04)] shadow-[0_0_28px_-6px_rgba(var(--tile-rgb),0.85)]' :
      'border-[rgba(var(--tile-rgb),0.30)] from-[rgba(var(--tile-rgb),0.10)] to-[rgba(var(--tile-rgb),0.02)] shadow-[0_0_18px_-10px_rgba(var(--tile-rgb),0.7)]',
      'hover:border-[rgba(var(--tile-rgb),0.55)] hover:shadow-[0_0_26px_-6px_rgba(var(--tile-rgb),0.85)]',
      'disabled:opacity-50 disabled:cursor-not-allowed'].
      join(' ')}>
      
      <span
        aria-hidden
        className="pointer-events-none absolute -top-12 -right-12 h-24 w-24 rounded-full blur-3xl opacity-30"
        style={{ background: `rgba(var(--tile-rgb),0.7)` }} />
      
      <div className="relative flex items-center gap-1.5 mb-1.5 min-w-0">
        <span
          className="font-mono text-[9px] uppercase tracking-[0.22em] font-semibold truncate"
          style={{ color: `rgb(var(--tile-rgb))`, textShadow: `0 0 10px rgba(var(--tile-rgb),0.6)` }}>
          
          {meta.label}
        </span>
        {wired && !selected &&
        <Radio
          className="h-3 w-3 shrink-0 opacity-75"
          style={{ color: `rgb(var(--tile-rgb))` }}
          aria-hidden />

        }
        {selected &&
        <motion.span
          layoutId="attack-tile-active"
          className="ml-auto h-1.5 w-1.5 shrink-0 rounded-full"
          style={{
            background: `rgb(var(--tile-rgb))`,
            boxShadow: `0 0 8px rgba(var(--tile-rgb),0.95)`
          }}
          transition={{ type: 'spring', stiffness: 380, damping: 30 }} />

        }
      </div>
      <div className="relative text-[12.5px] font-medium text-fg-primary leading-tight truncate pr-1">
        {attack.name}
      </div>
      <div className="relative mt-1 font-mono text-[9.5px] uppercase tracking-[0.22em] text-fg-faint">
        {selected ?
        wired ?
        'launching…' :
        'preview…' :
        wired ?
        'press to run' :
        'click to preview'}
      </div>
    </motion.button>);

}