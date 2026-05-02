import { motion } from 'framer-motion';
import {
  Activity,
  Banknote,
  Cpu,
  Database,
  Expand,
  Globe,
  Lock,
  Maximize2,
  Signal } from
'lucide-react';
import { cn } from '../../lib/utils';
import ProcessList from './ProcessList';





const ICONS = {
  globe: Globe,
  lock: Lock,
  banknote: Banknote,
  database: Database
};

const ACCENT_RGB = {
  cyan: '0,212,255',
  green: '0,255,159',
  orange: '255,159,28',
  violet: '167,139,250',
  blue: '59,130,246'
};

const STATUS_THEME = {
  normal: {
    label: 'Normal',
    rgb: '0,255,159',
    text: 'text-neon-green',
    dot: 'bg-neon-green shadow-[0_0_10px_rgba(0,255,159,0.55)]',
    border: 'border-border-subtle',
    glow: '',
    cpuBar: 'from-neon-cyan/70 to-neon-cyan'
  },
  warning: {
    label: 'Warning',
    rgb: '255,159,28',
    text: 'text-neon-orange',
    dot: 'bg-neon-orange shadow-[0_0_12px_rgba(255,159,28,0.7)] animate-pulse',
    border: 'border-neon-orange/45',
    glow: 'shadow-[0_0_28px_-10px_rgba(255,159,28,0.55)]',
    cpuBar: 'from-neon-orange to-neon-orange/90'
  },
  critical: {
    label: 'Critical',
    rgb: '255,59,59',
    text: 'text-neon-red',
    dot: 'bg-neon-red shadow-[0_0_14px_rgba(255,59,59,0.85)] animate-anomaly-pulse',
    border: 'border-neon-red/55',
    glow: 'shadow-[0_0_38px_-10px_rgba(255,59,59,0.7)]',
    cpuBar: 'from-neon-orange to-neon-red'
  }
};











export default function SystemCard({ system, onExpand }) {
  const theme = STATUS_THEME[system.status] ?? STATUS_THEME.normal;
  const Icon = ICONS[system.icon] ?? Activity;
  const accentRgb = ACCENT_RGB[system.accent] ?? ACCENT_RGB.cyan;
  const cpuPct = Math.min(100, Math.max(0, system.cpu));

  return (
    <motion.button
      type="button"
      onClick={() => onExpand?.(system)}
      whileHover={{ y: -4 }}
      whileTap={{ scale: 0.985 }}
      style={{
        '--accent-rgb': accentRgb,
        '--status-rgb': theme.rgb
      }}
      animate={
      system.underAttack ?
      {
        boxShadow: [
        '0 0 0 0 rgba(var(--status-rgb),0)',
        '0 0 36px 4px rgba(var(--status-rgb),0.32)',
        '0 0 0 0 rgba(var(--status-rgb),0)'],

        transition: {
          duration: 1.6,
          repeat: Infinity,
          ease: 'easeInOut'
        }
      } :
      {}
      }
      className={cn(
        'group/system relative w-full text-left overflow-hidden',
        'rounded-2xl border glass-panel transition-cyber cursor-pointer',
        'p-3 flex flex-col gap-2 min-h-0 h-full',
        theme.border,
        theme.glow,
        'hover:border-[rgba(var(--status-rgb),0.65)]',
        'hover:shadow-[0_0_0_1px_rgba(var(--status-rgb),0.18),0_28px_60px_-30px_rgba(0,0,0,0.85),0_0_42px_-12px_rgba(var(--status-rgb),0.5)]',

        system.hasAnomaly && 'ring-1 ring-[rgba(var(--status-rgb),0.32)]'
      )}>
      
      {}
      <span
        aria-hidden
        className={cn(
          'pointer-events-none absolute inset-x-0 top-0 h-px',
          system.status === 'normal' ? 'opacity-30' : 'opacity-80',
          'bg-[rgba(var(--status-rgb),1)]'
        )} />
      

      {}
      <span
        aria-hidden
        className={cn(
          'pointer-events-none absolute -top-16 -right-16 h-40 w-40 rounded-full blur-3xl transition-opacity duration-500',
          system.status === 'normal' ?
          'opacity-0 group-hover/system:opacity-25' :
          'opacity-40',
          'bg-[rgba(var(--status-rgb),0.6)]'
        )} />
      

      {}
      {system.underAttack &&
      <motion.span
        aria-hidden
        initial={{ x: '-110%' }}
        animate={{ x: '120%' }}
        transition={{ duration: 1.6, repeat: Infinity, ease: 'linear' }}
        className="pointer-events-none absolute inset-y-0 w-1/3 bg-gradient-to-r from-transparent via-neon-red/15 to-transparent" />

      }

      {}
      <header className="relative flex items-start justify-between gap-2 min-w-0">
        <div className="flex items-center gap-2.5 min-w-0">
          <span
            className={cn(
              'flex h-9 w-9 shrink-0 items-center justify-center rounded-xl',
              'border bg-bg-elevated/80 transition-cyber',
              `border-[rgba(var(--accent-rgb),0.35)]`,
              `text-[rgb(var(--accent-rgb))]`,
              'group-hover/system:border-[rgba(var(--accent-rgb),0.6)]',
              'group-hover/system:shadow-[0_0_18px_-6px_rgba(var(--accent-rgb),0.7)]'
            )}>
            
            <Icon className="h-4 w-4" strokeWidth={2.1} />
          </span>
          <div className="min-w-0">
            <div className="text-[14px] font-semibold leading-tight text-fg-primary truncate">
              {system.name}
            </div>
            <div className="font-mono text-[9.5px] uppercase tracking-[0.22em] text-fg-muted truncate">
              {system.kind}
            </div>
          </div>
        </div>

        <StatusPill status={system.status} theme={theme} />
      </header>

      {}
      <div className="relative grid grid-cols-2 gap-2 pt-0.5">
        <CpuBlock cpu={cpuPct} theme={theme} />
        <RpsBlock rps={system.rps} theme={theme} />
      </div>

      {}
      <div className="relative min-h-0 flex-1 flex flex-col">
        <div className="mb-1 flex items-center justify-between">
          <span className="font-mono text-[9px] uppercase tracking-[0.22em] text-fg-muted">
            Active processes · {system.processes.length}
          </span>
          {system.hasAnomaly &&
          <span className="font-mono text-[9px] uppercase tracking-[0.2em] text-neon-red flex items-center gap-1">
              <span className="h-1 w-1 rounded-full bg-neon-red animate-pulse" />
              live alert
            </span>
          }
        </div>
        <div className="min-h-0 flex-1 overflow-hidden">
          <ProcessList processes={system.processes} dense maxVisible={3} />
        </div>
      </div>

      {}
      <div
        className={cn(
          'relative pt-1.5 border-t border-border-subtle/70',
          'flex items-center justify-between gap-2',
          'opacity-80 group-hover/system:opacity-100 transition-opacity duration-300'
        )}>
        
        <div className="flex items-center gap-2 min-w-0 font-mono text-[9.5px] text-fg-muted tabular-nums">
          <span className="flex items-center gap-1">
            <Signal className="h-3 w-3 text-fg-faint" />
            {system.latency}ms
          </span>
          <span className="flex items-center gap-1">
            <span className="h-1 w-1 rounded-full bg-fg-faint" />
            err {system.errorRate}%
          </span>
        </div>
        <span
          className={cn(
            'inline-flex items-center gap-1 font-mono text-[9px] uppercase tracking-[0.22em]',
            'text-neon-cyan'
          )}>
          
          expand
          <Expand className="h-3 w-3" />
        </span>
      </div>
    </motion.button>);

}

function StatusPill({ status, theme }) {
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded-full border px-2 h-[22px] shrink-0',
        'font-mono text-[9px] uppercase tracking-[0.22em]',
        status === 'normal' ?
        'border-neon-green/30 bg-neon-green/[0.08] text-neon-green' :
        status === 'warning' ?
        'border-neon-orange/40 bg-neon-orange/[0.10] text-neon-orange' :
        'border-neon-red/45 bg-neon-red/[0.12] text-neon-red text-glow-red'
      )}>
      
      <span className={cn('h-1.5 w-1.5 rounded-full', theme.dot)} />
      {theme.label}
    </span>);

}

function CpuBlock({ cpu, theme }) {
  return (
    <div className="rounded-lg border border-border-subtle/70 bg-bg-sunken/40 px-2.5 py-2 min-w-0">
      <div className="flex items-center justify-between mb-1.5">
        <span className="flex items-center gap-1 font-mono text-[9px] uppercase tracking-[0.2em] text-fg-muted">
          <Cpu className="h-3 w-3" />
          CPU
        </span>
        <span className={cn('font-mono text-[11px] tabular-nums font-medium', theme.text)}>
          {cpu.toFixed(0)}%
        </span>
      </div>
      <div className="h-1.5 rounded-full bg-bg-base/60 border border-border-subtle/60 overflow-hidden">
        <motion.div
          className={cn('h-full rounded-full bg-gradient-to-r', theme.cpuBar)}
          initial={false}
          animate={{ width: `${cpu}%` }}
          transition={{ type: 'spring', stiffness: 110, damping: 18 }} />
        
      </div>
    </div>);

}

function RpsBlock({ rps, theme }) {
  return (
    <div className="rounded-lg border border-border-subtle/70 bg-bg-sunken/40 px-2.5 py-2 min-w-0">
      <div className="flex items-center justify-between mb-1.5">
        <span className="flex items-center gap-1 font-mono text-[9px] uppercase tracking-[0.2em] text-fg-muted">
          <Activity className="h-3 w-3" />
          Rate
        </span>
        <span className="font-mono text-[9px] uppercase tracking-[0.2em] text-fg-faint">
          rps
        </span>
      </div>
      <div className="flex items-baseline gap-1 truncate">
        <motion.span
          key={Math.round(rps / 8)}
          initial={{ opacity: 0.55, y: 1 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.25 }}
          className={cn('font-mono text-[16px] leading-none tabular-nums font-semibold truncate', theme.text)}>
          
          {formatRps(rps)}
        </motion.span>
        <Maximize2 className="h-2.5 w-2.5 text-fg-faint shrink-0" />
      </div>
    </div>);

}

function formatRps(n) {
  if (n >= 10_000) return `${(n / 1000).toFixed(1)}k`;
  if (n >= 1000) return `${(n / 1000).toFixed(2)}k`;
  return String(n);
}