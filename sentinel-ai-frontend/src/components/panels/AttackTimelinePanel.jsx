import { memo, useEffect, useMemo, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { GitBranch, Search, ShieldAlert, Send, Check } from 'lucide-react';
import PanelCard from '../PanelCard';
import { Badge } from '../ui/badge';
import { useRealtime } from '../../lib/useRealtime';
import {
  selectActions,
  selectNewestEvent,
  selectStatus,
  selectThreat } from
'../../lib/selectors';



























const STAGE_DELAYS_MS = [0, 600, 1200];

const fmtTime = (iso) =>
iso ?
new Date(iso).toLocaleTimeString('en-GB', {
  hour: '2-digit', minute: '2-digit', second: '2-digit'
}) :
'';

const fmtPct = (n) => `${Math.round(n * 100)}%`;

export default function AttackTimelinePanel() {



  const newestEvent = useRealtime(selectNewestEvent);
  const threat = useRealtime(selectThreat);
  const actions = useRealtime(selectActions);
  const status = useRealtime(selectStatus);


  const [currentStage, setCurrentStage] = useState(-1);
  const triggerId = newestEvent?.id;

  useEffect(() => {
    if (!triggerId) return;
    const t0 = setTimeout(() => setCurrentStage(0), STAGE_DELAYS_MS[0]);
    const t1 = setTimeout(() => setCurrentStage(1), STAGE_DELAYS_MS[1]);
    const t2 = setTimeout(() => setCurrentStage(2), STAGE_DELAYS_MS[2]);
    return () => {
      clearTimeout(t0);
      clearTimeout(t1);
      clearTimeout(t2);
    };
  }, [triggerId]);

  const isMultiStage = threat?.correlation === 'multi_stage_attack';
  const isSustained = threat?.correlation === 'sustained_attack';



  const stageDetails = useMemo(
    () => [
    {
      Icon: Search,
      title: 'Anomaly Detected',
      detail: newestEvent ?
      `${newestEvent.event_type.toUpperCase()} from ${newestEvent.source_ip}` :
      'Awaiting first signal',
      meta: newestEvent ? `severity: ${newestEvent.severity}` : '',
      ts: newestEvent ? fmtTime(newestEvent.timestamp) : '',
      critical: newestEvent?.severity === 'critical'
    },
    {
      Icon: ShieldAlert,
      title: isMultiStage ?
      'Multi-Stage Attack' :
      isSustained ?
      'Sustained Threat' :
      'Threat Escalated',
      detail: threat ?
      `${threat.threat_type.replace(/_/g, ' ')} · risk ${threat.risk_score.toFixed(1)}/10` :
      'No threat scored',
      meta: threat ?
      `confidence ${fmtPct(threat.confidence)}${
      threat.signals?.length ? ` · ${threat.signals.length} signals` : ''}` :

      '',
      ts: threat ? fmtTime(threat.detected_at) : '',
      critical: isMultiStage
    },
    {
      Icon: Send,
      title: 'Response Dispatched',
      detail: actions?.length ?
      `${actions.length} action${actions.length === 1 ? '' : 's'}: ${actions.
      slice(0, 2).
      map((a) => a.action_type.replace(/_/g, ' ')).
      join(', ')}${actions.length > 2 ? ', …' : ''}` :
      'No actions dispatched',
      meta: actions?.length ?
      `priorities: ${[...new Set(actions.map((a) => a.priority?.toUpperCase()))].join(', ')}` :
      '',
      ts: actions?.[0]?.executed_at ? fmtTime(actions[0].executed_at) : '',
      critical: false
    }],

    [newestEvent, threat, actions, isMultiStage, isSustained]
  );


  const progressPct = currentStage >= 0 ?
  (currentStage + 0.5) / stageDetails.length * 100 :
  0;


  const subtitle =
  status !== 'connected' && currentStage < 0 ?
  'Awaiting connection' :
  currentStage < 0 ?
  'Awaiting first signal' :
  isMultiStage ?
  'Multi-stage attack chain' :
  isSustained ?
  'Sustained attack pattern' :
  'Live attack progression';

  return (
    <PanelCard
      title="Attack Timeline"
      subtitle={subtitle}
      accent="violet"
      tone="subtle"
      icon={<GitBranch className="h-4 w-4" />}
      bodyClassName="px-5 py-4"
      actions={
      <Badge
        variant={isMultiStage ? 'destructive' : 'violet'}
        glow={isMultiStage}>
        
          <span
          className={[
          'h-1.5 w-1.5 rounded-full animate-[blink_1.4s_ease-in-out_infinite]',
          isMultiStage ?
          'bg-neon-red shadow-[0_0_8px_rgba(255,59,59,0.95)]' :
          'bg-neon-violet shadow-[0_0_8px_rgba(167,139,250,0.95)]'].
          join(' ')} />
        
          <span>{isMultiStage ? 'Chain Detected' : 'Tracking'}</span>
        </Badge>
      }>
      
      <div className="relative h-full overflow-y-auto scrollbar-cyber pr-1">
        {}
        <div className="absolute left-[15px] top-2 bottom-2 w-px bg-border-subtle" />

        {}
        <motion.div
          initial={{ height: 0 }}
          animate={{ height: `${progressPct}%` }}
          transition={{ duration: 0.8, ease: [0.2, 0.7, 0.2, 1] }}
          className={[
          'absolute left-[15px] top-2 w-px',
          isMultiStage ?
          'bg-gradient-to-b from-neon-orange via-neon-red to-neon-red/40 shadow-[0_0_8px_rgba(255,59,59,0.7)]' :
          'bg-gradient-to-b from-neon-cyan via-neon-violet to-neon-violet/40 shadow-[0_0_8px_rgba(167,139,250,0.7)]'].
          join(' ')} />
        

        <ol className="relative space-y-4">
          {stageDetails.map((stage, i) =>
          <Stage
            key={i}
            stage={stage}
            index={i}
            status={
            currentStage < 0 ?
            'pending' :
            i < currentStage ?
            'done' :
            i === currentStage ?
            'current' :
            'pending'
            } />

          )}
        </ol>
      </div>
    </PanelCard>);

}




const Stage = memo(function Stage({ stage, index, status }) {
  const { Icon, title, detail, meta, ts, critical } = stage;
  const done = status === 'done';
  const current = status === 'current';


  const ringColor = critical ? 'border-neon-red' : 'border-neon-violet';

  const dotClasses = done ?
  'bg-neon-cyan border-neon-cyan/60 text-bg-base shadow-[0_0_10px_rgba(0,212,255,0.7)]' :
  current ?
  critical ?
  'bg-bg-sunken border-neon-red text-neon-red shadow-[0_0_14px_rgba(255,59,59,0.8)]' :
  'bg-bg-sunken border-neon-violet text-neon-violet shadow-[0_0_14px_rgba(167,139,250,0.8)]' :
  'bg-bg-sunken border-border-strong text-fg-faint';

  const cardClasses = current ?
  critical ?
  'border-neon-red/40 bg-neon-red/5 shadow-[0_0_22px_-8px_rgba(255,59,59,0.7)]' :
  'border-neon-violet/35 bg-neon-violet/5 shadow-[0_0_22px_-8px_rgba(167,139,250,0.65)]' :
  'border-transparent bg-transparent';

  const labelClasses = done ?
  'text-fg-secondary' :
  current ?
  'text-fg-primary' :
  'text-fg-muted';

  return (
    <motion.li
      initial={{ opacity: 0, x: -10 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ duration: 0.4, delay: index * 0.06, ease: [0.2, 0.7, 0.2, 1] }}
      className="relative pl-9">
      
      {}
      <div className="absolute left-0 top-0.5">
        <div
          className={`relative h-[30px] w-[30px] rounded-full border flex items-center justify-center transition-cyber ${dotClasses}`}>
          
          {done ?
          <Check className="h-3.5 w-3.5" strokeWidth={2.6} /> :

          <Icon className="h-3.5 w-3.5" strokeWidth={2.2} />
          }
          {current &&
          <>
              <motion.span
              aria-hidden
              animate={{ scale: [1, 1.6], opacity: [0.6, 0] }}
              transition={{ duration: 1.6, repeat: Infinity, ease: 'easeOut' }}
              className={`absolute inset-0 rounded-full border ${ringColor}`} />
            
              <motion.span
              aria-hidden
              animate={{ scale: [1, 1.9], opacity: [0.4, 0] }}
              transition={{
                duration: 1.6,
                repeat: Infinity,
                ease: 'easeOut',
                delay: 0.4
              }}
              className={`absolute inset-0 rounded-full border ${ringColor}`} />
            
            </>
          }
        </div>
      </div>

      {}
      <div className={`rounded-lg border p-2.5 transition-cyber ${cardClasses}`}>
        <div className="flex items-baseline justify-between gap-2">
          <span className={`text-[12.5px] font-medium truncate ${labelClasses}`}>
            {title}
          </span>
          {ts &&
          <span className="font-mono text-[10px] tabular-nums text-fg-muted shrink-0">
              {ts}
            </span>
          }
        </div>

        {}
        <AnimatePresence mode="wait" initial={false}>
          <motion.p
            key={detail}
            initial={{ opacity: 0, y: 3 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -3 }}
            transition={{ duration: 0.22 }}
            className="mt-0.5 text-[11px] text-fg-muted leading-snug font-mono truncate">
            
            {detail}
          </motion.p>
        </AnimatePresence>

        {meta &&
        <p className="mt-0.5 text-[10px] text-fg-faint leading-snug font-mono truncate">
            {meta}
          </p>
        }

        {current &&
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.15 }}
          className={`mt-1.5 flex items-center gap-1 font-mono text-[10px] uppercase tracking-[0.22em] ${
          critical ? 'text-neon-red' : 'text-neon-violet'}`
          }>
          
            <span
            className={`h-1 w-1 rounded-full animate-[blink_1.4s_ease-in-out_infinite] ${
            critical ? 'bg-neon-red' : 'bg-neon-violet'}`
            } />
          
            {critical ? 'Chain detected' : 'Active stage'}
          </motion.div>
        }
      </div>
    </motion.li>);

});