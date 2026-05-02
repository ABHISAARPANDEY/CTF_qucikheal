import { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import { Activity, Bell, Search, Bot, UserCog, RotateCcw } from 'lucide-react';
import { Button } from './ui/button';
import { Badge } from './ui/badge';
import { cn } from '../lib/utils';
import { useRealtime } from '../lib/useRealtime';
import { selectStatus } from '../lib/selectors';
import { resetDemoState } from '../lib/api';

function useClock() {
  const [now, setNow] = useState(() => new Date());
  useEffect(() => {
    const id = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(id);
  }, []);
  return now;
}

const fmtTime = (d) =>
d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' });

const fmtDate = (d) =>
d.toLocaleDateString('en-US', { weekday: 'short', day: '2-digit', month: 'short' });

export default function Topbar({ mode, onModeChange }) {
  const now = useClock();
  const [resetting, setResetting] = useState(false);

  const wsStatus = useRealtime(selectStatus);
  const handleReset = async () => {
    if (resetting) return;
    setResetting(true);
    try {
      await resetDemoState();
    } catch {
      void 0;
    } finally {
      setResetting(false);
    }
  };

  return (
    <header className="relative z-10 flex h-16 shrink-0 items-center gap-4 border-b border-border-subtle glass-deep px-6">
      {}
      <span
        aria-hidden
        className="pointer-events-none absolute inset-x-0 bottom-0 h-px bg-gradient-to-r from-transparent via-neon-cyan/25 to-transparent" />
      

      {}
      <div className="relative flex-1 max-w-md">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-fg-muted" />
        <input
          type="text"
          placeholder="Search threats, hosts, CVEs…"
          className="w-full h-9 rounded-lg bg-bg-elevated/60 border border-border-subtle pl-9 pr-3
                     text-[13px] text-fg-primary placeholder:text-fg-muted
                     focus:outline-none focus:border-neon-cyan/40 focus:ring-1 focus:ring-neon-cyan/30
                     transition-cyber" />



        
      </div>

      {}
      <LiveSystemPill status={wsStatus} />

      {}
      <ModeToggle mode={mode} onChange={onModeChange} />

      <Button
        type="button"
        variant="outline"
        onClick={handleReset}
        disabled={resetting}
        className="h-9 rounded-lg border-neon-violet/35 text-neon-violet hover:border-neon-violet/65 hover:bg-neon-violet/[0.08] font-mono text-[10px] uppercase tracking-[0.2em]"
      >
        <RotateCcw className="h-3.5 w-3.5 mr-1.5" />
        {resetting ? 'resetting...' : 'demo reset'}
      </Button>

      {}
      <Button
        variant="outline"
        size="icon"
        className="relative h-9 w-9 rounded-lg hover:border-neon-orange/40"
        aria-label="Notifications">
        
        <Bell className="h-4 w-4" />
        <span className="absolute top-1.5 right-1.5 h-1.5 w-1.5 rounded-full bg-neon-orange shadow-[0_0_8px_rgba(255,159,28,0.95)] animate-[blink_1.4s_ease-in-out_infinite]" />
      </Button>

      {}
      <div className="text-right leading-tight">
        <div className="font-mono text-[14px] tabular-nums text-fg-primary">{fmtTime(now)}</div>
        <div className="font-mono text-[10px] uppercase tracking-[0.18em] text-fg-muted">
          {fmtDate(now)}
        </div>
      </div>
    </header>);

}

const STATUS_TONE = {
  connected: { variant: 'success', dot: 'bg-neon-green shadow-[0_0_10px_rgba(0,255,159,0.95)]', ping: 'bg-neon-green opacity-70 animate-ping', label: 'Live System', secondary: 'Secure' },
  connecting: { variant: 'warning', dot: 'bg-neon-orange shadow-[0_0_10px_rgba(255,159,28,0.95)] animate-[blink_1.4s_ease-in-out_infinite]', ping: 'bg-neon-orange opacity-60 animate-ping', label: 'Connecting', secondary: 'Backend' },
  disconnected: { variant: 'destructive', dot: 'bg-neon-red shadow-[0_0_10px_rgba(255,59,59,0.95)]', ping: 'bg-neon-red opacity-60 animate-ping', label: 'Offline', secondary: 'Backend' }
};

function LiveSystemPill({ status = 'connecting' }) {
  const tone = STATUS_TONE[status] ?? STATUS_TONE.connecting;

  const isLive = status === 'connected';
  return (
    <Badge
      variant={tone.variant}
      glow={isLive}
      className={cn(
        'hidden md:inline-flex h-9 px-3 gap-2 rounded-lg',
        'text-[11px]'
      )}>
      
      <span className="relative flex h-2 w-2">
        <span className={cn('absolute inline-flex h-full w-full rounded-full', tone.ping)} />
        <span className={cn('relative inline-flex h-2 w-2 rounded-full', tone.dot)} />
      </span>
      <span className={isLive ? 'font-semibold' : 'font-medium'}>{tone.label}</span>
      <span className="h-3 w-px bg-current/30 mx-0.5 opacity-30" />
      <Activity className="h-3.5 w-3.5" />
      <span>{tone.secondary}</span>
    </Badge>);

}

function ModeToggle({ mode, onChange }) {
  const isAuto = mode === 'autonomous';
  return (
    <div
      role="tablist"
      aria-label="Operation mode"
      className="relative hidden sm:flex h-9 items-center rounded-lg border border-border-subtle bg-bg-elevated/60 p-1 shadow-[0_0_24px_-12px_rgba(0,212,255,0.4)]">
      
      {}
      <motion.span
        layout
        transition={{ type: 'spring', stiffness: 480, damping: 36 }}
        className={[
        'absolute inset-y-1 w-[calc(50%-0.25rem)] rounded-md',
        isAuto ?
        'left-1 bg-gradient-to-r from-neon-cyan/20 to-neon-cyan/5 border border-neon-cyan/30 shadow-[0_0_18px_-4px_rgba(0,212,255,0.7)]' :
        'left-[calc(50%+0rem)] bg-gradient-to-r from-neon-violet/20 to-neon-violet/5 border border-neon-violet/30 shadow-[0_0_18px_-4px_rgba(167,139,250,0.7)]'].
        join(' ')} />
      
      <motion.button
        whileTap={{ scale: 0.96 }}
        role="tab"
        aria-selected={isAuto}
        onClick={() => onChange?.('autonomous')}
        className={[
        'relative z-10 flex items-center gap-1.5 px-3 h-7 rounded-md font-mono text-[11px] uppercase tracking-[0.2em] transition-cyber',
        isAuto ? 'text-neon-cyan text-glow-cyan' : 'text-fg-muted hover:text-fg-secondary'].
        join(' ')}>
        
        <Bot className="h-3.5 w-3.5" />
        Autonomous
      </motion.button>
      <motion.button
        whileTap={{ scale: 0.96 }}
        role="tab"
        aria-selected={!isAuto}
        onClick={() => onChange?.('assisted')}
        className={[
        'relative z-10 flex items-center gap-1.5 px-3 h-7 rounded-md font-mono text-[11px] uppercase tracking-[0.2em] transition-cyber',
        !isAuto ? 'text-neon-violet' : 'text-fg-muted hover:text-fg-secondary'].
        join(' ')}>
        
        <UserCog className="h-3.5 w-3.5" />
        Assisted
      </motion.button>
    </div>);

}