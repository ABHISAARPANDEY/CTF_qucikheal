import { useEffect, useMemo, useState } from 'react';
import { useLocation } from 'react-router-dom';
import { Bot, Command, Moon, RotateCcw, Sun, UserCog } from 'lucide-react';
import { Button } from './ui/button';
import { Kbd } from './ui/kbd';
import { cn } from '../lib/utils';
import { useRealtime } from '../lib/useRealtime';
import { selectAlertList, selectStats, selectStatus } from '../lib/selectors';
import { resetDemoState } from '../lib/api';
import { fmtNum, fmtPct } from '../lib/format';
import { bus, EVENTS } from '../lib/eventBus';
import { getTheme, setTheme } from '../lib/theme';

const TITLES = {
  '/': ['Overview', 'Live detection posture'],
  '/alerts': ['Alerts', 'Triage queue'],
  '/scenarios': ['Scenarios', 'Attack simulation & detection lab'],
  '/systems': ['Systems', 'Service telemetry'],
  '/infrastructure': ['Infrastructure', 'Host & process view'],
  '/honeypot': ['Honeypot', 'Adversary interaction'],
  '/reports': ['Reports', 'Incident summary & exports'],
  '/settings': ['Settings', 'Detection thresholds & traffic']
};

function useClock() {
  const [now, setNow] = useState(() => new Date());
  useEffect(() => {
    const id = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(id);
  }, []);
  return now;
}

const OPEN = new Set(['new', 'acknowledged', 'investigating']);

export default function Topbar({ mode, onModeChange }) {
  const now = useClock();
  const location = useLocation();
  const [resetting, setResetting] = useState(false);
  const [theme, setThemeState] = useState(getTheme);
  const toggleTheme = () => {
    const next = theme === 'light' ? 'dark' : 'light';
    setTheme(next);
    setThemeState(next);
  };
  const wsStatus = useRealtime(selectStatus);
  const stats = useRealtime(selectStats);
  const alerts = useRealtime(selectAlertList);

  const [title, subtitle] = useMemo(() => {
    if (location.pathname.startsWith('/entities/')) {
      const [, , type, ...rest] = location.pathname.split('/');
      return ['Entity', `${type} · ${decodeURIComponent(rest.join('/'))}`];
    }
    return TITLES[location.pathname] ?? ['SentinelAI', ''];
  }, [location.pathname]);

  const open = useMemo(() => {
    const c = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const a of alerts) if (OPEN.has(a.status) && a.severity in c) c[a.severity] += 1;
    return c;
  }, [alerts]);
  const openTotal = open.critical + open.high + open.medium + open.low;

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
    <header className="relative z-10 flex h-14 shrink-0 items-center gap-4 border-b border-line bg-bg-1 px-4">
      <div className="min-w-0 w-56">
        <div className="text-[14px] font-semibold text-fg-0 truncate">{title}</div>
        <div className="text-[11.5px] text-fg-2 truncate">{subtitle}</div>
      </div>

      <div className="hidden lg:flex items-center gap-1 rounded-md border border-line bg-bg-0 px-1 h-9">
        <Metric label="ev/s" value={stats ? fmtNum(Math.round(stats.events_per_sec ?? 0)) : '—'} />
        <Sep />
        <div className="flex items-center gap-2 px-2.5">
          <span className="text-[10.5px] uppercase tracking-[0.06em] text-fg-3">open</span>
          <span className="font-mono tabular text-[12.5px] text-fg-0">{openTotal}</span>
          <span className="flex items-center gap-1.5">
            <Dot n={open.critical} cls="bg-sev-critical" />
            <Dot n={open.high} cls="bg-sev-high" />
            <Dot n={open.medium} cls="bg-sev-medium" />
            <Dot n={open.low} cls="bg-sev-low" />
          </span>
        </div>
        <Sep />
        <Metric label="suppressed" value={stats ? fmtPct(stats.suppression_ratio ?? 0) : '—'} />
        <Sep />
        <Metric label="ingested" value={stats ? fmtNum(stats.events_ingested ?? 0) : '—'} />
        <Sep />
        <div className="flex items-center gap-1.5 px-2.5">
          <span
            className={cn(
              'h-1.5 w-1.5 rounded-full',
              wsStatus === 'connected' ? 'bg-ok' : wsStatus === 'connecting' || wsStatus === 'reconnecting' ? 'bg-warn animate-blink' : 'bg-bad'
            )}
          />
          <span className="text-[11.5px] text-fg-2">{wsStatus === 'connected' ? 'live' : wsStatus}</span>
        </div>
      </div>

      <div className="flex-1" />

      <Button variant="outline" size="icon" onClick={toggleTheme} aria-label="Toggle theme" className="text-fg-2">
        {theme === 'light' ? <Moon className="h-4 w-4" /> : <Sun className="h-4 w-4" />}
      </Button>

      <Button variant="outline" size="sm" onClick={() => bus.emit(EVENTS.OPEN_PALETTE)} className="gap-2 text-fg-2">
        <Command className="h-3.5 w-3.5" />
        <span className="hidden md:inline">Command</span>
        <Kbd>⌘K</Kbd>
      </Button>

      <ModeToggle mode={mode} onChange={onModeChange} />

      <Button variant="outline" size="sm" onClick={handleReset} disabled={resetting} className="text-fg-2">
        <RotateCcw className="h-3.5 w-3.5" />
        {resetting ? 'Resetting…' : 'Reset demo'}
      </Button>

      <div className="text-right leading-tight hidden sm:block">
        <div className="font-mono tabular text-[13px] text-fg-0">
          {now.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
        </div>
        <div className="text-[10.5px] text-fg-3">
          {now.toLocaleDateString('en-US', { weekday: 'short', day: '2-digit', month: 'short' })}
        </div>
      </div>
    </header>
  );
}

function Metric({ label, value }) {
  return (
    <div className="flex items-baseline gap-1.5 px-2.5">
      <span className="text-[10.5px] uppercase tracking-[0.06em] text-fg-3">{label}</span>
      <span className="font-mono tabular text-[12.5px] text-fg-0">{value}</span>
    </div>
  );
}

function Sep() {
  return <span className="h-4 w-px bg-line-strong" />;
}

function Dot({ n, cls }) {
  return (
    <span className="flex items-center gap-0.5">
      <span className={cn('h-1.5 w-1.5 rounded-full', n ? cls : 'bg-bg-3')} />
      <span className="font-mono tabular text-[10.5px] text-fg-2">{n}</span>
    </span>
  );
}

function ModeToggle({ mode, onChange }) {
  const isAuto = mode === 'autonomous';
  return (
    <div role="tablist" aria-label="Operation mode" className="hidden sm:flex h-8 items-center rounded-md border border-line bg-bg-0 p-0.5">
      {[
        ['autonomous', Bot, 'Auto'],
        ['assisted', UserCog, 'Assisted']
      ].map(([val, Icon, label]) => {
        const active = (val === 'autonomous') === isAuto;
        return (
          <button
            key={val}
            role="tab"
            aria-selected={active}
            onClick={() => onChange?.(val)}
            className={cn(
              'flex items-center gap-1.5 h-7 px-2.5 rounded text-[12px] transition-cyber focus-ring',
              active ? 'bg-bg-2 text-fg-0' : 'text-fg-2 hover:text-fg-1'
            )}
          >
            <Icon className="h-3.5 w-3.5" />
            {label}
          </button>
        );
      })}
    </div>
  );
}
