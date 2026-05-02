import { AnimatePresence, motion } from 'framer-motion';
import {
  Activity,
  AlertTriangle,
  Brain,
  ChevronRight,
  Microscope } from
'lucide-react';

















export default function AnalysisPanel({
  scenarioEvents = [],
  patterns = [],
  honeypotAnalyses = []
}) {
  const sortedEvents = [...scenarioEvents].sort(
    (a, b) => (a.stage ?? 0) - (b.stage ?? 0)
  );
  const sortedHoneypotAnalyses = [...honeypotAnalyses].sort(
    (a, b) => (a.step ?? 0) - (b.step ?? 0)
  );
  const empty =
  sortedEvents.length === 0 &&
  patterns.length === 0 &&
  sortedHoneypotAnalyses.length === 0;

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
        <Microscope className="h-3.5 w-3.5 text-neon-green/80" />
        <span className="font-mono text-[10.5px] uppercase tracking-[0.22em] text-neon-green/85 text-glow-green">
          behaviour :: forensic analysis
        </span>
        <span className="ml-auto font-mono text-[9.5px] tracking-[0.22em] text-neon-green/45">
          {sortedEvents.length} actions · {patterns.length} patterns
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
      

      <div className="relative z-10 flex-1 min-h-0 grid grid-cols-1 lg:grid-cols-2 gap-px bg-neon-green/10">
        {}
        <div className="bg-black p-4 min-h-0 overflow-y-auto scrollbar-cyber">
          <SectionHeader
            icon={<Activity className="h-3.5 w-3.5" />}
            title="Detected actions"
            count={sortedEvents.length} />
          

          {empty ?
          <EmptyState
            text="No adversary actions yet — terminal will populate as the play unfolds." /> :

          sortedEvents.length === 0 ?
          <EmptyState text="Patterns identified — see right panel." /> :

          <ul className="mt-3 space-y-1.5 list-none p-0 m-0">
              <AnimatePresence initial={false} mode="popLayout">
                {sortedEvents.map((evt) =>
              <ActionRow
                key={`${evt.run_id}-${evt.stage}-${evt.system ?? 'na'}-${evt.label ?? 'evt'}-${evt.ts ?? 'ts'}`}
                evt={evt} />

              )}
              </AnimatePresence>
            </ul>
          }
        </div>

        {}
        <div className="bg-black p-4 min-h-0 overflow-y-auto scrollbar-cyber">
          <SectionHeader
            icon={<Brain className="h-3.5 w-3.5" />}
            title="Honeypot analysis"
            count={sortedHoneypotAnalyses.length} />
          

          {sortedHoneypotAnalyses.length > 0 &&
          <ul className="mt-3 space-y-1.5 list-none p-0 m-0">
              <AnimatePresence initial={false} mode="popLayout">
                {sortedHoneypotAnalyses.map((evt) =>
              <AnalysisRow key={`${evt.run_id}-${evt.step}-${evt.ts}`} evt={evt} />
              )}
              </AnimatePresence>
            </ul>
          }

          <SectionHeader
            icon={<Brain className="h-3.5 w-3.5" />}
            title="Patterns identified"
            count={patterns.length} />
          

          {patterns.length === 0 ?
          <EmptyState text="Pattern engine standing by — TTPs surface as actions accumulate." /> :

          <ul className="mt-3 grid grid-cols-1 gap-2 list-none p-0 m-0">
              <AnimatePresence initial={false} mode="popLayout">
                {patterns.map((p) =>
              <PatternRow key={p.id} pattern={p} />
              )}
              </AnimatePresence>
            </ul>
          }

          {}
          {patterns.length > 0 &&
          <KeywordCloud patterns={patterns} />
          }
        </div>
      </div>
    </section>);

}



function SectionHeader({ icon, title, count }) {
  return (
    <div className="flex items-center gap-2 font-mono text-[10px] uppercase tracking-[0.24em] text-neon-green/60">
      <span className="text-neon-green/85">{icon}</span>
      <span className="text-neon-green/85">{title}</span>
      <span className="ml-auto text-neon-green/35">[{count}]</span>
    </div>);

}

function EmptyState({ text }) {
  return (
    <div className="mt-4 rounded-md border border-dashed border-neon-green/20 px-3 py-4 text-center">
      <p className="font-mono text-[11px] text-neon-green/45">{text}</p>
    </div>);

}

const SEV = {
  info: {
    text: 'text-neon-green/80',
    border: 'border-neon-green/25',
    bg: 'bg-neon-green/[0.04]',
    dot: 'bg-neon-green/60',
    glyph: '[*]'
  },
  warning: {
    text: 'text-neon-orange',
    border: 'border-neon-orange/35',
    bg: 'bg-neon-orange/[0.06]',
    dot: 'bg-neon-orange',
    glyph: '[~]'
  },
  high: {
    text: 'text-neon-red/95',
    border: 'border-neon-red/40',
    bg: 'bg-neon-red/[0.07]',
    dot: 'bg-neon-red',
    glyph: '[!]'
  },
  critical: {
    text: 'text-neon-red text-glow-red',
    border: 'border-neon-red/55',
    bg: 'bg-neon-red/[0.10]',
    dot: 'bg-neon-red',
    glyph: '[✗]'
  }
};

function ActionRow({ evt }) {
  const sev = SEV[evt.severity] ?? SEV.info;
  return (
    <motion.li
      layout
      initial={{ opacity: 0, x: -10 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, height: 0, marginBottom: 0 }}
      transition={{ duration: 0.28, ease: [0.2, 0.7, 0.2, 1] }}
      className={`
        relative overflow-hidden rounded-md border px-2.5 py-1.5
        ${sev.border} ${sev.bg}
      `}>
      
      <div className="flex items-start gap-2 min-w-0">
        <span className={`mt-1.5 h-1.5 w-1.5 rounded-full shrink-0 ${sev.dot}`} />
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2 min-w-0">
            <span className={`font-mono text-[10px] uppercase tracking-[0.22em] ${sev.text}`}>
              {sev.glyph} stage {evt.stage}/{evt.total_stages}
            </span>
            {evt.system &&
            <span className="font-mono text-[9.5px] uppercase tracking-[0.22em] text-neon-green/40 truncate">
                · {evt.system}
              </span>
            }
            <span className={`ml-auto font-mono text-[9px] uppercase tracking-[0.24em] ${sev.text}`}>
              {evt.severity}
            </span>
          </div>
          <p className={`mt-0.5 font-mono text-[12px] leading-snug ${sev.text}`}
          style={{ textShadow: '0 0 6px rgba(0,255,159,0.18)' }}>
            {evt.label}
          </p>
        </div>
      </div>
    </motion.li>);

}

function PatternRow({ pattern }) {
  const sev = SEV[pattern.severity] ?? SEV.info;
  return (
    <motion.li
      layout
      initial={{ opacity: 0, scale: 0.96 }}
      animate={{ opacity: 1, scale: 1 }}
      exit={{ opacity: 0, scale: 0.92 }}
      transition={{ type: 'spring', stiffness: 360, damping: 26 }}
      className={`
        relative overflow-hidden rounded-md border px-3 py-2
        ${sev.border} ${sev.bg}
      `}>
      
      <div className="flex items-center gap-2 min-w-0">
        <ChevronRight className={`h-3 w-3 shrink-0 ${sev.text}`} />
        <span className={`font-mono text-[12px] font-semibold tracking-tight truncate ${sev.text}`}>
          {pattern.label}
        </span>
        <span className="ml-auto font-mono text-[9.5px] uppercase tracking-[0.22em] text-neon-green/45">
          ×{pattern.hits}
        </span>
        <span className={`font-mono text-[9px] uppercase tracking-[0.22em] ${sev.text}`}>
          {pattern.severity}
        </span>
      </div>
      {pattern.description &&
      <p className="mt-1 text-[11px] leading-snug text-neon-green/55">
          {pattern.description}
        </p>
      }
    </motion.li>);

}

function AnalysisRow({ evt }) {
  const sev = SEV[String(evt?.data?.risk ?? 'low').toLowerCase() === 'critical' ?
  'critical' :
  String(evt?.data?.risk ?? 'low').toLowerCase() === 'high' ?
  'high' :
  String(evt?.data?.risk ?? 'low').toLowerCase() === 'medium' ?
  'warning' :
  'info'];
  return (
    <motion.li
      layout
      initial={{ opacity: 0, x: -10 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, height: 0, marginBottom: 0 }}
      transition={{ duration: 0.22 }}
      className={`rounded-md border px-2.5 py-1.5 ${sev.border} ${sev.bg}`}>
      
      <div className="flex items-center gap-2">
        <span className={`h-1.5 w-1.5 rounded-full ${sev.dot}`} />
        <span className={`font-mono text-[10px] uppercase tracking-[0.22em] ${sev.text}`}>
          step {evt.step}/{evt.total_steps}
        </span>
        <span className={`ml-auto font-mono text-[9px] uppercase tracking-[0.22em] ${sev.text}`}>
          {String(evt?.data?.risk ?? 'low')}
        </span>
      </div>
      <p className={`mt-0.5 font-mono text-[12px] ${sev.text}`}>
        {evt?.data?.pattern ?? 'unknown pattern'}
      </p>
    </motion.li>);

}

function KeywordCloud({ patterns }) {
  if (!patterns.length) return null;
  return (
    <div className="mt-4 pt-3 border-t border-neon-green/15">
      <div className="font-mono text-[9.5px] uppercase tracking-[0.24em] text-neon-green/40 mb-1.5 flex items-center gap-1.5">
        <AlertTriangle className="h-3 w-3" />
        TTP fingerprint
      </div>
      <div className="flex flex-wrap gap-1.5">
        {patterns.map((p) => {
          const sev = SEV[p.severity] ?? SEV.info;
          return (
            <span
              key={p.id}
              className={`
                inline-flex items-center gap-1 rounded border ${sev.border} ${sev.bg}
                font-mono text-[9.5px] uppercase tracking-[0.22em] ${sev.text}
                px-1.5 py-0.5
              `}>
              
              <span className={`h-1 w-1 rounded-full ${sev.dot}`} />
              {p.id.replace(/_/g, ' ')}
            </span>);

        })}
      </div>
    </div>);

}