import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Crosshair, Zap, KeyRound, Bug } from 'lucide-react';
import PanelCard from '../PanelCard';
import { Badge } from '../ui/badge';
import { bus, EVENTS } from '../../lib/eventBus';
import { triggerAttack } from '../../lib/api';







const SIMULATIONS = [
{
  id: 'ddos',
  backendType: 'ddos',
  label: 'Simulate DDoS',
  short: 'DDoS Flood',
  desc: 'Saturate edge gateway with synthetic packet flood',
  Icon: Zap,
  tone: 'red',
  rgb: '255,59,59'
},
{
  id: 'brute',
  backendType: 'brute_force',
  label: 'Simulate Brute Force',
  short: 'Brute Force',
  desc: 'Hammer SSH on bastion-02 with credential pairs',
  Icon: KeyRound,
  tone: 'orange',
  rgb: '255,159,28'
},
{
  id: 'sqli',
  backendType: 'sql_injection',
  label: 'Simulate SQL Injection',
  short: 'SQL Injection',
  desc: 'Probe web endpoints with classic SQLi payloads',
  Icon: Bug,
  tone: 'violet',
  rgb: '167,139,250'
}];


const fmtTime = () =>
new Date().toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });

export default function AttackControlPanel() {
  const [activity, setActivity] = useState([]);
  const [busy, setBusy] = useState(null);

  const launch = async (sim) => {
    if (busy) return;
    setBusy(sim.id);

    const runId = `${sim.id}-${Date.now()}`;
    setActivity((a) =>
    [{ id: runId, label: sim.short, tone: sim.tone, ts: fmtTime(), status: 'running' }, ...a].slice(0, 6)
    );



    bus.emit(EVENTS.SIMULATE_REQUEST, sim);

    try {
      await triggerAttack(sim.backendType);
      setActivity((a) =>
      a.map((row) => row.id === runId ? { ...row, status: 'dispatched' } : row)
      );
    } catch (err) {

      console.warn('triggerAttack failed:', err);
      setActivity((a) =>
      a.map((row) => row.id === runId ? { ...row, status: 'failed' } : row)
      );
    } finally {
      setBusy(null);
    }
  };

  return (
    <PanelCard
      title="Attack Control"
      subtitle="Trigger live simulations on the backend"
      accent="orange"
      icon={<Crosshair className="h-4 w-4" />}>
      
      <div className="relative h-full flex flex-col gap-4">
        <div
          aria-hidden
          className="absolute inset-0 bg-grid-faint pointer-events-none -z-0"
          style={{ maskImage: 'radial-gradient(ellipse at center, black 55%, transparent 95%)' }} />
        

        <div className="relative grid gap-3 sm:grid-cols-3">
          {SIMULATIONS.map((s) =>
          <SimButton
            key={s.id}
            sim={s}
            onLaunch={launch}
            disabled={busy !== null && busy !== s.id}
            loading={busy === s.id} />

          )}
        </div>

        <div className="relative flex-1 min-h-0 flex flex-col">
          <div className="flex items-center justify-between mb-2">
            <span className="font-mono text-[10px] uppercase tracking-[0.22em] text-fg-faint">
              Recent activity
            </span>
            <span className="font-mono text-[10px] uppercase tracking-[0.22em] text-fg-faint">
              {activity.length} runs
            </span>
          </div>
          <ul className="flex-1 min-h-0 overflow-y-auto scrollbar-cyber space-y-1.5 pr-1">
            <AnimatePresence initial={false}>
              {activity.length === 0 ?
              <li className="px-2 py-3 text-center font-mono text-[10px] uppercase tracking-[0.22em] text-fg-faint">
                  No simulations launched yet
                </li> :

              activity.map((a) => <ActivityRow key={a.id} item={a} />)
              }
            </AnimatePresence>
          </ul>
        </div>
      </div>
    </PanelCard>);

}

function SimButton({ sim, onLaunch, disabled, loading }) {
  const { Icon, label, desc, rgb } = sim;

  return (
    <motion.button
      whileHover={disabled ? undefined : { y: -2 }}
      whileTap={disabled ? undefined : { scale: 0.97 }}
      transition={{ type: 'spring', stiffness: 380, damping: 28 }}
      onClick={() => onLaunch(sim)}
      disabled={disabled}
      style={{ '--btn-rgb': rgb }}
      className="relative group overflow-hidden rounded-xl p-3 text-left
                 border border-[rgba(var(--btn-rgb),0.22)]
                 bg-gradient-to-br from-[rgba(var(--btn-rgb),0.08)] to-[rgba(var(--btn-rgb),0.015)]
                 shadow-[0_1px_0_0_rgba(255,255,255,0.04)_inset]
                 hover:border-[rgba(var(--btn-rgb),0.5)]
                 hover:shadow-[0_0_28px_-8px_rgba(var(--btn-rgb),0.8),0_1px_0_0_rgba(255,255,255,0.05)_inset]
                 disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:shadow-none
                 transition-cyber">







      
      <span
        aria-hidden
        className="pointer-events-none absolute -top-12 -right-12 h-32 w-32 rounded-full blur-3xl opacity-30 group-hover:opacity-70 transition-opacity duration-500"
        style={{ background: `rgba(var(--btn-rgb),0.7)` }} />
      
      <span
        aria-hidden
        className="pointer-events-none absolute inset-0 -translate-x-full group-hover:translate-x-full transition-transform duration-700"
        style={{
          background:
          'linear-gradient(105deg, transparent 30%, rgba(255,255,255,0.18) 50%, transparent 70%)'
        }} />
      

      <div className="relative flex items-center gap-2 mb-2">
        <span
          className="flex h-7 w-7 items-center justify-center rounded-md border"
          style={{
            background: `rgba(var(--btn-rgb),0.18)`,
            borderColor: `rgba(var(--btn-rgb),0.45)`,
            color: `rgb(var(--btn-rgb))`,
            boxShadow: `0 0 12px rgba(var(--btn-rgb),0.55)`
          }}>
          
          <Icon className="h-3.5 w-3.5" strokeWidth={2.2} />
        </span>
        <span
          className="font-mono text-[10.5px] uppercase tracking-[0.22em]"
          style={{ color: `rgb(var(--btn-rgb))`, textShadow: `0 0 10px rgba(var(--btn-rgb),0.6)` }}>
          
          {label}
        </span>
      </div>
      <p className="relative text-[11.5px] text-fg-secondary leading-snug">{desc}</p>

      <div className="relative mt-2 flex items-center justify-between">
        <span className="font-mono text-[9.5px] uppercase tracking-[0.22em] text-fg-faint">
          {loading ? 'Dispatching…' : 'Press to launch'}
        </span>
        <span
          aria-hidden
          className="font-mono text-[12px] opacity-60 group-hover:opacity-100 transition-opacity"
          style={{ color: `rgb(var(--btn-rgb))` }}>
          
          {loading ? '…' : '▶'}
        </span>
      </div>
    </motion.button>);

}



const STATUS_TONE = {
  running: { variant: 'cyan', glow: true, dot: 'bg-neon-cyan animate-[blink_1.4s_ease-in-out_infinite]' },
  dispatched: { variant: 'success', glow: false, dot: 'bg-neon-green' },
  failed: { variant: 'destructive', glow: true, dot: 'bg-neon-red animate-[blink_1.4s_ease-in-out_infinite]' }
};

function ActivityRow({ item }) {
  const s = STATUS_TONE[item.status] ?? STATUS_TONE.running;
  return (
    <motion.li
      layout
      initial={{ opacity: 0, x: -10 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: 10 }}
      transition={{ duration: 0.32, ease: [0.2, 0.7, 0.2, 1] }}
      className="flex items-center gap-3 px-2.5 py-1.5 rounded-md border border-border-subtle/70 bg-bg-elevated/40 hover:bg-bg-elevated/70 transition-cyber">
      
      <span className={`h-1.5 w-1.5 rounded-full ${s.dot}`} />
      <span className="text-[12px] text-fg-primary truncate flex-1">{item.label}</span>
      <Badge variant={s.variant} glow={s.glow} className="h-[18px] text-[9.5px] tracking-[0.22em]">
        {item.status}
      </Badge>
      <span className="font-mono text-[10px] tabular-nums text-fg-muted w-10 text-right">{item.ts}</span>
    </motion.li>);

}