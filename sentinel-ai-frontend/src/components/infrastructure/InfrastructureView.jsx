import { useState } from 'react';
import { motion } from 'framer-motion';
import { Boxes, Network, Radio, ShieldCheck, Workflow } from 'lucide-react';
import { useInfrastructure } from '../../hooks/useInfrastructure';
import { CLUSTERS, SYSTEMS } from '../../lib/infrastructure';
import { cn } from '../../lib/utils';
import SystemCard from './SystemCard';
import SystemDetailPanel from './SystemDetailPanel';

const ACCENT_RGB = {
  cyan: '0,212,255',
  green: '0,255,159',
  orange: '255,159,28',
  violet: '167,139,250'
};

const stagger = {
  hidden: {},
  show: { transition: { staggerChildren: 0.08, delayChildren: 0.05 } }
};

const item = {
  hidden: { opacity: 0, y: 16, scale: 0.985 },
  show: {
    opacity: 1,
    y: 0,
    scale: 1,
    transition: { duration: 0.5, ease: [0.2, 0.7, 0.2, 1] }
  }
};










export default function InfrastructureView() {
  const [expandedId, setExpandedId] = useState(null);
  const { systems, summary } = useInfrastructure();
  const expanded = expandedId ? systems[expandedId] : null;

  return (
    <div className="flex-1 min-h-0 flex flex-col p-3 gap-3 overflow-hidden">
      <PageHeader summary={summary} />

      <motion.div
        variants={stagger}
        initial="hidden"
        animate="show"
        className="flex-1 min-h-0 grid grid-cols-1 xl:grid-cols-2 2xl:grid-cols-3 auto-rows-[minmax(300px,1fr)] gap-3 overflow-y-auto scrollbar-cyber pb-3">
        
        {CLUSTERS.map((cluster) =>
        <motion.div key={cluster.id} variants={item} className="min-h-0">
            <ClusterFrame
            cluster={cluster}
            systems={cluster.systemIds.map((id) => systems[id])}
            onExpand={(s) => setExpandedId(s.id)} />
          
          </motion.div>
        )}
      </motion.div>

      <SystemDetailPanel system={expanded} onClose={() => setExpandedId(null)} />
    </div>);

}



function PageHeader({ summary }) {
  return (
    <header className="shrink-0 flex flex-wrap items-start justify-between gap-3 px-1">
      <div className="flex items-start gap-3 min-w-0">
        <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-bg-elevated/70 border border-neon-cyan/25 text-neon-cyan shadow-[0_0_18px_-8px_rgba(0,212,255,0.5)]">
          <Network className="h-5 w-5" />
        </span>
        <div className="min-w-0">
          <h1 className="font-mono text-[11px] font-medium uppercase tracking-[0.22em] text-fg-secondary">
            Infrastructure View
          </h1>
          <p className="text-[14px] text-fg-primary leading-snug">
            Banking topology · live host metrics, request load and process integrity across both clusters.
          </p>
        </div>
      </div>

      <div className="flex items-center gap-2 shrink-0">
        <SummaryChip
          tone="green"
          icon={<ShieldCheck className="h-3 w-3" />}
          label="Healthy"
          value={summary.normal} />
        
        <SummaryChip
          tone="orange"
          icon={<Radio className="h-3 w-3" />}
          label="Warning"
          value={summary.warning}
          pulse={summary.warning > 0} />
        
        <SummaryChip
          tone="red"
          icon={<Boxes className="h-3 w-3" />}
          label="Critical"
          value={summary.critical}
          pulse={summary.critical > 0} />
        
      </div>
    </header>);

}

function SummaryChip({ tone, icon, label, value, pulse }) {
  const cfg =
  tone === 'red' ?
  'border-neon-red/40 bg-neon-red/[0.08] text-neon-red' :
  tone === 'orange' ?
  'border-neon-orange/40 bg-neon-orange/[0.08] text-neon-orange' :
  'border-neon-green/35 bg-neon-green/[0.08] text-neon-green';
  return (
    <span
      className={cn(
        'inline-flex items-center gap-2 rounded-lg border h-[30px] px-2.5',
        'font-mono text-[10px] uppercase tracking-[0.18em]',
        cfg,
        pulse && 'animate-pulse'
      )}>
      
      {icon}
      {label}
      <span className="font-mono text-[12px] tabular-nums font-semibold">{value}</span>
    </span>);

}








function ClusterFrame({ cluster, systems, onExpand }) {
  const accentRgb = ACCENT_RGB[cluster.accent] ?? ACCENT_RGB.cyan;
  const anyHot = systems.some((s) => s?.status !== 'normal');

  return (
    <section
      style={{ '--accent-rgb': accentRgb }}
      className={cn(
        'relative h-full min-h-0 rounded-2xl border glass-deep transition-cyber',
        'overflow-hidden flex flex-col',
        anyHot ?
        'border-[rgba(var(--accent-rgb),0.32)] shadow-[0_0_36px_-18px_rgba(var(--accent-rgb),0.5)]' :
        'border-border-subtle'
      )}>
      
      {}
      <span
        aria-hidden
        className={cn(
          'pointer-events-none absolute inset-x-0 top-0 h-px bg-[rgba(var(--accent-rgb),1)]',
          anyHot ? 'opacity-80' : 'opacity-40'
        )} />
      
      {}
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0 opacity-[0.18] bg-grid-faint"
        style={{
          maskImage: 'radial-gradient(ellipse at center, black 30%, transparent 80%)',
          WebkitMaskImage: 'radial-gradient(ellipse at center, black 30%, transparent 80%)'
        }} />
      

      {}
      <header className="relative flex items-start justify-between gap-3 px-4 pt-3.5 pb-3 border-b border-border-subtle">
        <div className="flex items-center gap-2.5 min-w-0">
          <span
            className={cn(
              'flex h-8 w-8 shrink-0 items-center justify-center rounded-lg',
              'border bg-bg-elevated/70',
              'border-[rgba(var(--accent-rgb),0.35)] text-[rgb(var(--accent-rgb))]'
            )}>
            
            <Workflow className="h-4 w-4" />
          </span>
          <div className="min-w-0">
            <div className="font-mono text-[10.5px] font-medium uppercase tracking-[0.22em] text-fg-secondary truncate">
              {cluster.name}
            </div>
            <div className="text-[11.5px] text-fg-muted leading-snug truncate">
              {cluster.blurb}
            </div>
          </div>
        </div>
        <div className="font-mono text-[9.5px] uppercase tracking-[0.22em] text-fg-faint shrink-0">
          {systems.length} hosts
        </div>
      </header>

      {}
      <div className="relative flex-1 min-h-0 p-3">
        <ClusterConnector active={anyHot} />
        <div className="relative grid grid-cols-1 md:grid-cols-2 gap-3 h-full">
          {systems.map(
            (s) =>
            s &&
            <div key={s.id} className="min-h-0 flex">
                  <div className="w-full min-h-0">
                    <SystemCard system={s} onExpand={onExpand} />
                  </div>
                </div>

          )}
        </div>
      </div>
    </section>);

}






function ClusterConnector({ active }) {
  return (
    <svg
      aria-hidden
      className="pointer-events-none absolute inset-0 hidden md:block"
      preserveAspectRatio="none"
      viewBox="0 0 100 100">
      
      <line
        x1="0"
        y1="50"
        x2="100"
        y2="50"
        stroke="rgba(var(--accent-rgb),0.22)"
        strokeWidth="0.25"
        strokeDasharray="0.8 1.4"
        vectorEffect="non-scaling-stroke" />
      
      {active &&
      <circle
        r="0.6"
        fill={`rgb(var(--accent-rgb))`}
        opacity="0.85">
        
          <animate
          attributeName="cx"
          values="2;98;2"
          dur="3.6s"
          repeatCount="indefinite" />
        
          <animate
          attributeName="cy"
          values="50;50;50"
          dur="3.6s"
          repeatCount="indefinite" />
        
          <animate
          attributeName="opacity"
          values="0;0.9;0"
          dur="3.6s"
          repeatCount="indefinite" />
        
        </circle>
      }
    </svg>);

}


export { CLUSTERS, SYSTEMS };