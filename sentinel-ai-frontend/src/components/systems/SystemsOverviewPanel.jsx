import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import { ChevronRight, Server } from 'lucide-react';
import PanelCard from '../PanelCard';
import { useRealtime } from '../../lib/useRealtime';
import {
  selectActions,
  selectExplanation,
  selectNewestEvent,
  selectTelemetryLogs,
  selectThreat } from
'../../lib/selectors';
import { useSystemMetrics } from '../../hooks/useSystemMetrics';
import { SYSTEM_IDS } from '../../lib/systemMonitoring';
import { cn } from '../../lib/utils';
import SystemsTelemetryFeed from './SystemsTelemetryFeed';
import ResponseIntelStrip from './ResponseIntelStrip';




export default function SystemsOverviewPanel() {
  const threat = useRealtime(selectThreat);
  const newestEvent = useRealtime(selectNewestEvent);
  const telemetryLogs = useRealtime(selectTelemetryLogs);
  const actions = useRealtime(selectActions);
  const explanation = useRealtime(selectExplanation);
  const { systems } = useSystemMetrics(threat, newestEvent, telemetryLogs);

  const feedEntries = [...telemetryLogs].reverse();

  return (
    <PanelCard
      title="Systems"
      subtitle="API · Auth · Database · honeypot mesh"
      icon={<Server className="h-4 w-4" />}
      accent="cyan"
      tone="default"
      actions={
      <Link
        to="/systems"
        className="inline-flex items-center gap-0.5 font-mono text-[10px] uppercase tracking-[0.18em] text-neon-cyan hover:text-fg-primary transition-colors">
        
          expand
          <ChevronRight className="h-3.5 w-3.5" />
        </Link>
      }
      bodyClassName="p-4 pt-3 space-y-3">
      
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
        {SYSTEM_IDS.map((id) => {
          const s = systems[id];
          const dot =
          s.status === 'critical' ?
          'bg-neon-red animate-anomaly-pulse' :
          s.status === 'degraded' ?
          'bg-neon-orange' :
          'bg-neon-green';

          return (
            <motion.div
              key={id}
              layout
              className={cn(
                'rounded-lg border px-2.5 py-2 min-w-0 transition-cyber',
                s.hasAnomaly ?
                'border-neon-red/45 bg-neon-red/[0.08] shadow-[0_0_20px_-12px_rgba(255,59,59,0.5)]' :
                'border-border-subtle bg-bg-sunken/50',
                s.recoveryFlash && 'border-neon-green/35 animate-recovery-pulse'
              )}
              animate={
              s.hasAnomaly ?
              {
                boxShadow: [
                '0 0 0 0 rgba(255,59,59,0)',
                '0 0 18px 2px rgba(255,59,59,0.35)',
                '0 0 0 0 rgba(255,59,59,0)']

              } :
              s.recoveryFlash ?
              {
                boxShadow: [
                '0 0 0 0 rgba(0,255,159,0)',
                '0 0 20px 3px rgba(0,255,159,0.3)',
                '0 0 0 0 rgba(0,255,159,0)']

              } :
              {}
              }
              transition={{ duration: 1.5, repeat: s.hasAnomaly ? Infinity : 0, ease: 'easeInOut' }}>
              
              <div className="flex items-center gap-2 min-w-0">
                <span className={cn('h-1.5 w-1.5 rounded-full shrink-0', dot)} />
                <span className="text-[12px] font-medium text-fg-primary truncate">{s.name}</span>
                {s.wsAnomalyCount > 0 &&
                <span className="ml-auto font-mono text-[8px] text-neon-red/90 tabular-nums">
                    +{s.wsAnomalyCount} sig
                  </span>
                }
              </div>
              <div className="mt-1 font-mono text-[10px] text-fg-muted tabular-nums">
                CPU {s.cpu.toFixed(0)}%
              </div>
              {s.hasAnomaly && s.globalAnomalyMessage &&
              <p className="mt-1 text-[9.5px] leading-snug text-neon-red/90 line-clamp-2">
                  {s.globalAnomalyMessage}
                </p>
              }
            </motion.div>);

        })}
      </div>

      <SystemsTelemetryFeed entries={feedEntries} />

      <ResponseIntelStrip actions={actions} explanation={explanation} />
    </PanelCard>);

}