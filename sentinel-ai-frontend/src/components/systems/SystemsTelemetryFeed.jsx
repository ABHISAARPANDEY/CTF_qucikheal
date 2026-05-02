import { useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { cn } from '../../lib/utils';




export default function SystemsTelemetryFeed({ entries, className = '' }) {
  const bottomRef = useRef(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth', block: 'end' });
  }, [entries]);

  return (
    <div
      className={cn(
        'rounded-lg border border-border-subtle bg-black/35 overflow-hidden flex flex-col min-h-[72px]',
        className
      )}>
      
      <div className="px-2 py-1 border-b border-border-subtle/80 bg-bg-sunken/40">
        <span className="font-mono text-[9px] uppercase tracking-[0.22em] text-fg-faint">
          Host telemetry
        </span>
      </div>
      <div className="flex-1 min-h-0 overflow-y-auto scrollbar-cyber px-2 py-1.5 space-y-1">
        <AnimatePresence initial={false}>
          {(entries ?? []).slice(0, 24).map((e) =>
          <motion.div
            key={e.id}
            initial={{ opacity: 0, x: -8 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, height: 0 }}
            transition={{ duration: 0.22 }}
            className={cn(
              'font-mono text-[10px] leading-snug rounded px-1.5 py-0.5',
              e.kind === 'anomaly' && 'bg-neon-red/10 text-neon-red/95 border border-neon-red/25',
              e.kind === 'recovery' &&
              'bg-neon-green/10 text-neon-green/90 border border-neon-green/25 animate-recovery-line',
              e.kind === 'process_log' && 'text-fg-muted border border-transparent'
            )}>
            
              <span className="text-fg-faint opacity-70">
                {e.systemId ? `${e.systemId}` : '—'}
              </span>{' '}
              <span className="text-fg-secondary/90">{e.summary}</span>
            </motion.div>
          )}
        </AnimatePresence>
        <div ref={bottomRef} className="h-px w-full" aria-hidden />
      </div>
    </div>);

}