import { memo, useEffect, useRef, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Activity, Ban, Bell, Eye, FileText, Gauge,
  KeyRound, Lock, Send, ShieldOff, UserX, XOctagon } from
'lucide-react';
import PanelCard from '../PanelCard';
import { Badge } from '../ui/badge';
import { useRealtime } from '../../lib/useRealtime';
import { selectActions } from '../../lib/selectors';




















const MAX_ROWS = 20;


const TONE = {
  p0: { variant: 'destructive', label: 'CRITICAL', border: 'border-l-neon-red', rail: 'bg-neon-red', glow: 'shadow-[0_0_18px_-4px_rgba(255,59,59,0.7)]', text: 'text-neon-red', rgb: '255,59,59', showGlow: true },
  p1: { variant: 'destructive', label: 'CRITICAL', border: 'border-l-neon-red', rail: 'bg-neon-red', glow: 'shadow-[0_0_14px_-4px_rgba(255,59,59,0.6)]', text: 'text-neon-red', rgb: '255,59,59', showGlow: true },
  p2: { variant: 'warning', label: 'WARNING', border: 'border-l-neon-orange', rail: 'bg-neon-orange', glow: '', text: 'text-neon-orange', rgb: '255,159,28', showGlow: false },
  p3: { variant: 'success', label: 'SUCCESS', border: 'border-l-neon-green', rail: 'bg-neon-green', glow: '', text: 'text-neon-green', rgb: '0,255,159', showGlow: false }
};


const ICON = {
  block_ip: Ban,
  rate_limit: Gauge,
  isolate_service: ShieldOff,
  restrict_access: Lock,
  monitor: Eye,
  quarantine_host: ShieldOff,
  disable_user: UserX,
  kill_process: XOctagon,
  rotate_credentials: KeyRound,
  notify: Bell,
  escalate: Send,
  log_only: FileText
};


const LABEL = {
  block_ip: 'Block IP',
  rate_limit: 'Rate Limit',
  isolate_service: 'Isolate Service',
  restrict_access: 'Restrict Access',
  monitor: 'Monitor',
  quarantine_host: 'Quarantine Host',
  disable_user: 'Disable User',
  kill_process: 'Kill Process',
  rotate_credentials: 'Rotate Credentials',
  notify: 'Notify',
  escalate: 'Escalate',
  log_only: 'Log Only'
};

const fmtTime = (iso) => {
  const d = iso ? new Date(iso) : new Date();
  return d.toLocaleTimeString('en-GB', {
    hour: '2-digit', minute: '2-digit', second: '2-digit'
  });
};

export default function SystemActions() {



  const actions = useRealtime(selectActions);
  const [history, setHistory] = useState([]);
  const listRef = useRef(null);

  useEffect(() => {
    if (!actions || actions.length === 0) return;
    const t = setTimeout(() => {
      setHistory((prev) => {
        const seen = new Set(prev.map((a) => a.id));
        const fresh = actions.filter((a) => a.id && !seen.has(a.id));
        if (fresh.length === 0) return prev;

        return [...fresh, ...prev].slice(0, MAX_ROWS);
      });
    }, 0);
    return () => clearTimeout(t);
  }, [actions]);


  const newestId = history[0]?.id;
  useEffect(() => {
    listRef.current?.scrollTo({ top: 0, behavior: 'smooth' });
  }, [newestId]);

  return (
    <PanelCard
      title="System Actions"
      subtitle="Live response stream"
      accent="green"
      icon={<Activity className="h-4 w-4" />}
      bodyClassName="p-0"
      actions={
      <Badge variant="success" glow={history.length > 0}>
          <span className="h-1.5 w-1.5 rounded-full bg-neon-green shadow-[0_0_8px_rgba(0,255,159,0.95)] animate-[blink_1.4s_ease-in-out_infinite]" />
          <span className="font-semibold">{history.length} dispatched</span>
        </Badge>
      }>
      
      <div className="relative h-full">
        {}
        <span aria-hidden className="pointer-events-none absolute inset-x-0 top-0    h-6 bg-gradient-to-b from-bg-panel/90 to-transparent z-10" />
        <span aria-hidden className="pointer-events-none absolute inset-x-0 bottom-0 h-8 bg-gradient-to-t from-bg-panel/90 to-transparent z-10" />

        {history.length === 0 ?
        <div className="h-full flex items-center justify-center px-6 py-10 text-center">
            <div className="font-mono text-[11px] uppercase tracking-[0.22em] text-fg-muted">
              No actions dispatched yet…
            </div>
          </div> :

        <ul ref={listRef} className="overflow-y-auto scrollbar-cyber max-h-full">
            <AnimatePresence initial={false}>
              {history.map((action) =>
            <ActionRow key={action.id} action={action} />
            )}
            </AnimatePresence>
          </ul>
        }
      </div>
    </PanelCard>);

}



const ActionRow = memo(function ActionRow({ action }) {
  const tone = TONE[action.priority] ?? TONE.p2;
  const Icon = ICON[action.action_type] ?? Activity;
  const label = LABEL[action.action_type] ?? action.action_type;

  return (
    <motion.li
      layout


      initial={{ opacity: 0, x: -14, height: 0 }}
      animate={{ opacity: 1, x: 0, height: 'auto' }}
      exit={{ opacity: 0, x: 14, height: 0 }}
      transition={{ duration: 0.32, ease: [0.2, 0.7, 0.2, 1] }}
      className={[
      'group relative grid grid-cols-[auto_1fr_auto] items-center gap-3 px-5 py-2.5 font-mono',
      'border-b border-border-subtle/60',
      tone.showGlow ? 'border-l-[3px]' : 'border-l-2',
      tone.border,
      'hover:bg-bg-elevated/60 transition-cyber'].
      join(' ')}
      style={tone.showGlow ? { '--row-rgb': tone.rgb } : undefined}>
      
      {}
      <span
        aria-hidden
        className={[
        'absolute left-0 top-0 bottom-0 w-[3px]',
        tone.rail,
        tone.showGlow ? 'opacity-100' : 'opacity-50 group-hover:opacity-100',
        tone.glow,
        'transition-opacity'].
        join(' ')} />
      

      {}
      <div
        className={[
        'relative flex h-8 w-8 items-center justify-center rounded-lg bg-bg-sunken/80 border',
        tone.text,
        tone.showGlow ? 'border-neon-red/40 shadow-[0_0_12px_-3px_rgba(255,59,59,0.55)]' : 'border-border-subtle'].
        join(' ')}>
        
        <Icon className="h-4 w-4" strokeWidth={2} />
      </div>

      {}
      <div className="relative min-w-0">
        <div className="flex items-center gap-2">
          <span
            className={`text-[13px] truncate ${
            tone.showGlow ? 'font-semibold text-fg-primary text-glow-red' : 'font-medium text-fg-primary'}`
            }>
            
            {label}
          </span>
          <Badge
            variant={tone.variant}
            glow={tone.showGlow}
            className="h-[16px] px-1.5 text-[9.5px] tracking-[0.18em] rounded-sm">
            
            EXECUTED
          </Badge>
          {action.priority &&
          <Badge variant="outline" className="h-[16px] px-1.5 text-[9.5px] rounded-sm uppercase">
              {action.priority}
            </Badge>
          }
        </div>
        <div className="text-[11px] text-fg-muted truncate">
          <span className="text-fg-secondary">{action.target}</span>
          {action.reason &&
          <>
              <span className="mx-1.5 text-fg-faint">·</span>
              <span className="truncate">{action.reason}</span>
            </>
          }
        </div>
      </div>

      {}
      <div className="relative text-right">
        <div className="text-[11px] tabular-nums text-fg-secondary">
          {fmtTime(action.executed_at)}
        </div>
        <div className="text-[9.5px] uppercase tracking-[0.18em] text-fg-faint">
          {tone.label}
        </div>
      </div>
    </motion.li>);

});