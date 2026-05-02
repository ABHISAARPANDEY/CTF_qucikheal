import { AnimatePresence, motion } from 'framer-motion';
import { AlertTriangle, ChevronRight } from 'lucide-react';
import { cn } from '../../lib/utils';












export default function ProcessList({ processes = [], dense = false, maxVisible }) {
  const items = maxVisible ? processes.slice(0, maxVisible) : processes;
  const hidden = processes.length - items.length;

  return (
    <ul
      className={cn(
        'relative flex flex-col list-none m-0 p-0',
        dense ? 'gap-1' : 'gap-1.5'
      )}>
      
      <AnimatePresence initial={false} mode="popLayout">
        {items.map((p, idx) =>
        <ProcessRow key={p.pid} process={p} dense={dense} delayStep={idx} />
        )}
      </AnimatePresence>

      {hidden > 0 &&
      <li className="px-2 pt-1 font-mono text-[9.5px] uppercase tracking-[0.2em] text-fg-faint">
          +{hidden} more
        </li>
      }
    </ul>);

}

function ProcessRow({ process, dense, delayStep }) {
  const malicious = !!process.anomaly;

  return (
    <motion.li
      layout
      initial={
      malicious ?
      { opacity: 0, x: -28, scale: 0.94 } :
      { opacity: 0, y: 6 }
      }
      animate={{ opacity: 1, x: 0, y: 0, scale: 1 }}
      exit={{ opacity: 0, height: 0, marginTop: 0, scale: 0.95 }}
      transition={
      malicious ?
      { type: 'spring', stiffness: 360, damping: 24 } :
      { duration: 0.32, ease: [0.2, 0.7, 0.2, 1], delay: delayStep * 0.04 }
      }
      className={cn(
        'group/row relative overflow-hidden rounded-md border transition-cyber',
        dense ? 'px-2 py-1' : 'px-2.5 py-1.5',
        malicious ?
        [
        'border-neon-red/55 bg-neon-red/[0.10]',
        'shadow-[0_0_20px_-6px_rgba(255,59,59,0.55)]',
        'animate-anomaly-pulse'] :

        'border-border-subtle/80 bg-bg-sunken/40 hover:border-border-strong/70'
      )}>
      
      {}
      {malicious &&
      <span
        aria-hidden
        className="pointer-events-none absolute inset-0 bg-gradient-to-r from-neon-red/35 via-neon-red/10 to-transparent animate-anomaly-flash" />

      }

      <div className="relative flex items-start gap-2 min-w-0">
        <span
          className={cn(
            'mt-1 h-1.5 w-1.5 rounded-full shrink-0',
            malicious ?
            'bg-neon-red shadow-[0_0_10px_rgba(255,59,59,0.85)]' :
            'bg-fg-faint'
          )} />
        
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-1.5 min-w-0">
            <span
              className={cn(
                'font-mono truncate',
                dense ? 'text-[11px]' : 'text-[12px]',
                malicious ?
                'font-medium text-neon-red text-glow-red' :
                'text-fg-primary/95'
              )}>
              
              {process.label}
            </span>
            {malicious &&
            <span
              className={cn(
                'inline-flex items-center gap-1 rounded-md border h-[16px] px-1 shrink-0',
                'border-neon-red/40 bg-neon-red/10',
                'font-mono text-[9px] uppercase tracking-[0.2em] text-neon-red',
                'shadow-[0_0_12px_-4px_rgba(255,59,59,0.6)]'
              )}>
              
                <AlertTriangle className="h-2.5 w-2.5" />
                threat
              </span>
            }
          </div>
          <div
            className={cn(
              'font-mono uppercase tracking-[0.18em] mt-0.5',
              dense ? 'text-[8.5px]' : 'text-[9px]',
              malicious ? 'text-neon-red/80' : 'text-fg-faint'
            )}>
            
            {process.role}
          </div>
          {malicious && process.summary &&
          <p className="mt-1 text-[10.5px] leading-snug text-fg-secondary/95 line-clamp-2">
              <ChevronRight className="inline-block h-2.5 w-2.5 mr-0.5 text-neon-red/80 -mt-0.5" />
              {process.summary}
            </p>
          }
        </div>
      </div>
    </motion.li>);

}