import { motion, AnimatePresence } from 'framer-motion';
import { Activity, Cpu } from 'lucide-react';
import PanelCard from '../PanelCard';
import ProcessRow from './ProcessRow';
import { cn } from '../../lib/utils';

function StatusDot({ status }) {
  const cfg =
  status === 'critical' ?
  'bg-neon-red shadow-[0_0_12px_rgba(255,59,59,0.85)] animate-anomaly-pulse' :
  status === 'degraded' ?
  'bg-neon-orange shadow-[0_0_10px_rgba(255,159,28,0.65)]' :
  'bg-neon-green shadow-[0_0_10px_rgba(0,255,159,0.55)]';

  const label =
  status === 'critical' ? 'critical' : status === 'degraded' ? 'degraded' : 'operational';

  return (
    <span className="flex items-center gap-1.5 shrink-0" title={label}>
      <span className={cn('h-2 w-2 rounded-full', cfg)} />
      <span className="font-mono text-[9px] uppercase tracking-[0.2em] text-fg-muted">{label}</span>
    </span>);

}

function CpuMeter({ value, hot }) {
  const pct = Math.min(100, Math.max(0, value));
  return (
    <div className={cn('flex items-center gap-2 min-w-0', hot && 'text-neon-orange')}>
      <Cpu className={cn('h-3.5 w-3.5 shrink-0', hot ? 'text-neon-orange' : 'text-fg-muted')} />
      <div className="flex-1 min-w-0 h-1.5 rounded-full bg-bg-sunken border border-border-subtle overflow-hidden">
        <motion.div
          className={cn(
            'h-full rounded-full',
            hot ? 'bg-gradient-to-r from-neon-orange to-neon-red' : 'bg-gradient-to-r from-neon-cyan/80 to-neon-cyan'
          )}
          initial={false}
          animate={{ width: `${pct}%` }}
          transition={{ type: 'spring', stiffness: 120, damping: 18 }} />
        
      </div>
      <span
        className={cn(
          'font-mono text-[10px] tabular-nums w-10 text-right shrink-0',
          hot ? 'text-neon-orange' : 'text-fg-secondary'
        )}>
        
        {pct.toFixed(0)}%
      </span>
    </div>);

}






export default function SystemCard({ system, density = 'default' }) {
  const compact = density === 'compact';
  const hot = system.status !== 'operational';

  return (
    <motion.div
      className="h-full min-h-0 min-w-0 w-full"
      animate={
      system.recoveryFlash ?
      {
        boxShadow: [
        '0 0 0 0 rgba(0,255,159,0)',
        '0 0 36px 8px rgba(0,255,159,0.28)',
        '0 0 0 0 rgba(0,255,159,0)']

      } :
      {}
      }
      transition={{ duration: 1.5, ease: 'easeOut' }}>
      
      <PanelCard
        title={system.name}
        subtitle={compact ? undefined : 'Live processes & resource pressure'}
        icon={<Activity className="h-4 w-4" />}
        accent={system.accent}
        tone={system.hasAnomaly ? 'primary' : 'default'}
        className={cn(
          system.hasAnomaly && 'ring-1 ring-neon-red/30',
          system.recoveryFlash && 'animate-recovery-pulse'
        )}>
        
        <div className="space-y-3">
          <div className="flex items-center justify-between gap-2">
            <StatusDot status={system.status} />
            {!compact &&
            <span className="font-mono text-[9px] text-fg-faint uppercase tracking-[0.16em]">
                {system.processes.length} procs
              </span>
            }
          </div>
          <CpuMeter value={system.cpu} hot={hot} />
          <div className={cn('space-y-1.5', compact && 'space-y-1')}>
            <AnimatePresence mode="popLayout" initial={false}>
              {system.processes.map((p) =>
              <motion.div
                key={p.pid}
                layout
                initial={{ opacity: 0, scale: 0.96 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0, height: 0, marginBottom: 0, scale: 0.92 }}
                transition={{ duration: 0.38, ease: [0.2, 0.7, 0.2, 1] }}>
                
                  <ProcessRow
                  label={p.label}
                  role={p.role}
                  anomaly={p.anomaly}
                  anomalyMessage={p.anomalyMessage}
                  compact={compact}
                  recoveryGlow={system.recoveryFlash} />
                
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </div>
      </PanelCard>
    </motion.div>);

}