import { motion } from 'framer-motion';
import {
  Crosshair,
  History,
  Microscope,
  ShieldCheck } from
'lucide-react';

const ICONS = {
  crosshair: Crosshair,
  shield: ShieldCheck,
  microscope: Microscope
};

const STATUS = {
  pending: {
    text: 'text-neon-green/40',
    border: 'border-neon-green/15',
    bg: 'bg-neon-green/[0.02]',
    label: 'pending',
    iconClass: 'text-neon-green/30'
  },
  active: {
    text: 'text-neon-orange',
    border: 'border-neon-orange/45',
    bg: 'bg-neon-orange/[0.06]',
    label: 'in progress',
    iconClass: 'text-neon-orange'
  },
  complete: {
    text: 'text-neon-green',
    border: 'border-neon-green/55',
    bg: 'bg-neon-green/[0.08]',
    label: 'complete',
    iconClass: 'text-neon-green text-glow-green'
  }
};















export default function TimelinePanel({ stages = [] }) {
  return (
    <section
      className="
        relative h-full overflow-hidden rounded-xl
        border border-neon-green/30 bg-black
        shadow-[0_0_36px_-12px_rgba(0,255,159,0.45),0_0_0_1px_rgba(0,255,159,0.08)_inset]
        flex flex-col
      ">





      
      {}
      <header className="relative flex items-center gap-2 px-3 h-9 border-b border-neon-green/20 bg-black/70">
        <History className="h-3.5 w-3.5 text-neon-green/80" />
        <span className="font-mono text-[10.5px] uppercase tracking-[0.22em] text-neon-green/85 text-glow-green">
          timeline :: containment chain
        </span>
        <span className="ml-auto font-mono text-[9.5px] tracking-[0.22em] text-neon-green/40">
          {stages.filter((s) => s.status === 'complete').length}/{stages.length} stages
        </span>
      </header>

      {}
      <span
        aria-hidden
        className="pointer-events-none absolute inset-0 z-0 opacity-[0.06]"
        style={{
          background:
          'repeating-linear-gradient(0deg, rgba(0,255,159,0.55) 0, rgba(0,255,159,0.55) 1px, transparent 1px, transparent 3px)'
        }} />
      

      <ol className="relative z-10 flex-1 overflow-y-auto scrollbar-cyber p-4 space-y-3 list-none m-0">
        {stages.map((stage, idx) =>
        <Stage
          key={stage.id}
          stage={stage}
          index={idx + 1}
          isLast={idx === stages.length - 1} />

        )}
      </ol>
    </section>);

}

function Stage({ stage, index, isLast }) {
  const cfg = STATUS[stage.status] ?? STATUS.pending;
  const Icon = ICONS[stage.icon] ?? Crosshair;

  return (
    <li className="relative pl-9">
      {}
      {!isLast &&
      <span
        aria-hidden
        className={`
            absolute left-[14px] top-7 bottom-[-12px] w-px
            ${stage.status === 'complete' ? 'bg-neon-green/35' : 'bg-neon-green/15'}
          `} />

      }

      {}
      <span className={`absolute left-0 top-0 flex h-7 w-7 items-center justify-center rounded-md border ${cfg.border} ${cfg.bg}`}>
        {stage.status === 'active' ?
        <motion.span
          animate={{ scale: [1, 1.18, 1] }}
          transition={{ duration: 1.4, repeat: Infinity, ease: 'easeInOut' }}>
          
            <Icon className={`h-3.5 w-3.5 ${cfg.iconClass}`} />
          </motion.span> :

        <Icon className={`h-3.5 w-3.5 ${cfg.iconClass}`} />
        }
      </span>

      {}
      <motion.div
        layout
        initial={false}
        animate={
        stage.status === 'active' ?
        {
          boxShadow: [
          '0 0 0 0 rgba(255,159,28,0)',
          '0 0 24px -4px rgba(255,159,28,0.55)',
          '0 0 0 0 rgba(255,159,28,0)']

        } :
        { boxShadow: '0 0 0 0 rgba(0,0,0,0)' }
        }
        transition={{
          duration: 1.6,
          repeat: stage.status === 'active' ? Infinity : 0,
          ease: 'easeInOut'
        }}
        className={`
          rounded-md border px-3 py-2
          ${cfg.border} ${cfg.bg}
        `}>
        
        <div className="flex items-center justify-between gap-2 min-w-0">
          <div className="flex items-center gap-2 min-w-0">
            <span className="font-mono text-[9.5px] uppercase tracking-[0.24em] text-neon-green/40">
              {String(index).padStart(2, '0')}
            </span>
            <span className={`font-mono text-[12.5px] font-semibold uppercase tracking-tight ${cfg.text}`}>
              {stage.label}
            </span>
          </div>
          <span className={`font-mono text-[9px] uppercase tracking-[0.22em] ${cfg.text}`}>
            {cfg.label}
          </span>
        </div>
        <p className="mt-1 text-[11.5px] leading-snug text-neon-green/55">
          {stage.sub}
        </p>
        {stage.ts &&
        <div className="mt-1.5 font-mono text-[9.5px] tracking-[0.22em] text-neon-green/45">
            t = {formatTime(stage.ts)}
          </div>
        }
      </motion.div>
    </li>);

}

function formatTime(epoch) {
  if (!epoch) return '—';
  const d = new Date(epoch);
  return d.toLocaleTimeString('en-GB', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  });
}