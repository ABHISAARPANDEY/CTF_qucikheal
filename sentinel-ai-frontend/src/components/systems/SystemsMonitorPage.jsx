import { motion } from 'framer-motion';
import { Server } from 'lucide-react';
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
import SystemCard from './SystemCard';
import SystemsTelemetryFeed from './SystemsTelemetryFeed';
import ResponseIntelStrip from './ResponseIntelStrip';

const container = {
  hidden: {},
  show: { transition: { staggerChildren: 0.08, delayChildren: 0.04 } }
};

const item = {
  hidden: { opacity: 0, y: 14 },
  show: {
    opacity: 1,
    y: 0,
    transition: { duration: 0.45, ease: [0.2, 0.7, 0.2, 1] }
  }
};




export default function SystemsMonitorPage() {
  const threat = useRealtime(selectThreat);
  const newestEvent = useRealtime(selectNewestEvent);
  const telemetryLogs = useRealtime(selectTelemetryLogs);
  const actions = useRealtime(selectActions);
  const explanation = useRealtime(selectExplanation);
  const { systems } = useSystemMetrics(threat, newestEvent, telemetryLogs);

  const feedEntries = [...telemetryLogs].reverse();

  return (
    <div className="flex-1 min-h-0 flex flex-col p-3 gap-3 overflow-hidden">
      <header className="shrink-0 flex items-start gap-3 px-1">
        <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-bg-elevated/70 border border-neon-cyan/25 text-neon-cyan shadow-[0_0_18px_-8px_rgba(0,212,255,0.5)]">
          <Server className="h-5 w-5" />
        </span>
        <div className="min-w-0">
          <h1 className="font-mono text-[11px] font-medium uppercase tracking-[0.22em] text-fg-secondary">
            Systems monitor
          </h1>
          <p className="text-[14px] text-fg-primary leading-snug">
            Host telemetry from the honeypot mesh, automated actions, and AI correlation — live.
          </p>
        </div>
      </header>

      <div className="flex-1 min-h-0 grid grid-cols-1 xl:grid-cols-12 gap-3 overflow-hidden">
        <motion.div
          variants={container}
          initial="hidden"
          animate="show"
          className="xl:col-span-8 min-h-0 min-w-0 grid gap-3 grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 auto-rows-min content-start overflow-y-auto scrollbar-cyber pr-1">
          
          {SYSTEM_IDS.map((id) =>
          <motion.div key={id} variants={item} className="min-h-0 min-w-0 flex">
              <SystemCard system={systems[id]} density="default" />
            </motion.div>
          )}
        </motion.div>

        <div className="xl:col-span-4 min-h-0 min-w-0 flex flex-col gap-3 overflow-hidden">
          <SystemsTelemetryFeed entries={feedEntries} className="flex-1 min-h-[180px]" />
          <ResponseIntelStrip actions={actions} explanation={explanation} />
        </div>
      </div>
    </div>);

}