import { useEffect, useMemo, useState } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import {
  Activity,
  AlertOctagon,
  Banknote,
  Cpu,
  Database,
  Globe,
  Lock,
  Signal,
  X } from
'lucide-react';
import { cn } from '../../lib/utils';
import ProcessList from './ProcessList';
import { triggerScenario } from '../../lib/api';

const ICONS = { globe: Globe, lock: Lock, banknote: Banknote, database: Database };

const STATUS_RGB = {
  normal: '0,255,159',
  warning: '255,159,28',
  critical: '255,59,59'
};








export default function SystemDetailPanel({ system, onClose }) {

  useEffect(() => {
    if (!system) return;
    const onKey = (e) => {
      if (e.key === 'Escape') onClose?.();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [system, onClose]);




  const [samples, setSamples] = useState([]);
  const cpu = system?.cpu;
  const id = system?.id;
  useEffect(() => {
    if (id == null) {
      const handle = setTimeout(() => setSamples([]), 0);
      return () => clearTimeout(handle);
    }

    let primed = false;
    const handle = setInterval(() => {
      setSamples((prev) => {
        if (!primed) {
          primed = true;
          return Array.from({ length: 24 }, () => cpu ?? 0);
        }
        return [...prev.slice(-23), cpu ?? 0];
      });
    }, 800);
    return () => clearInterval(handle);
  }, [id, cpu]);

  const sparkPath = useMemo(
    () => system ? buildSparkPath(samples, 280, 60) : '',
    [samples, system]
  );

  return (
    <AnimatePresence>
      {system &&
      <motion.div
        key="overlay"
        className="fixed inset-0 z-50 flex items-center justify-center p-4 sm:p-8"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        transition={{ duration: 0.2 }}>
        
          {}
          <button
          type="button"
          aria-label="Close panel"
          onClick={onClose}
          className="absolute inset-0 bg-bg-base/80 backdrop-blur-md cursor-default" />
        

          <DetailCard system={system} onClose={onClose} sparkPath={sparkPath} />
        </motion.div>
      }
    </AnimatePresence>);

}

function DetailCard({ system, onClose, sparkPath }) {
  const Icon = ICONS[system.icon] ?? Activity;
  const statusRgb = STATUS_RGB[system.status] ?? STATUS_RGB.normal;
  const malicious = system.processes.filter((p) => p.anomaly);
  const normal = system.processes.filter((p) => !p.anomaly);
  const [cmd, setCmd] = useState('');
  const [busyCmd, setBusyCmd] = useState(false);
  const [logs, setLogs] = useState(() => [
  '[*] terminal ready',
  '[*] try: run bank_update.exe',
  '[*] try: nmap --top-ports 1000 10.0.0.15',
  '[*] try: sqlmap -u /accounts?id=1']);

  const runCommand = async () => {
    const text = cmd.trim();
    if (!text || busyCmd) return;
    setBusyCmd(true);
    setLogs((prev) => [...prev.slice(-12), `> ${text}`]);
    setCmd('');
    const lower = text.toLowerCase();
    let scenario = null;
    if (lower.includes('bank_update.exe') || lower.includes('.exe')) scenario = 'insider';
    else if (lower.includes('nmap') || lower.includes('masscan') || lower.includes('flood')) scenario = 'ddos';
    else if (lower.includes('sqlmap') || lower.includes('union select') || lower.includes('sqli')) scenario = 'sql_injection';
    else if (lower.includes('hydra') || lower.includes('brute') || lower.includes('password')) scenario = 'brute_force';
    else if (lower.includes('killchain') || lower.includes('apt') || lower.includes('lateral')) scenario = 'multi_stage';
    try {
      if (scenario) {
        const res = await triggerScenario(scenario);
        setLogs((prev) => [...prev.slice(-12), `[+] launched ${scenario} · run ${res.run_id}`]);
      } else {
        setLogs((prev) => [...prev.slice(-12), '[~] command executed in sandbox (no mapped scenario)']);
      }
    } catch (err) {
      setLogs((prev) => [...prev.slice(-12), `[!] command failed: ${err?.message ?? 'unknown error'}`]);
    } finally {
      setBusyCmd(false);
    }
  };

  return (
    <motion.div
      role="dialog"
      aria-modal="true"
      aria-label={`${system.name} detail`}
      initial={{ opacity: 0, y: 18, scale: 0.97 }}
      animate={{ opacity: 1, y: 0, scale: 1 }}
      exit={{ opacity: 0, y: 16, scale: 0.97, transition: { duration: 0.18 } }}
      transition={{ type: 'spring', stiffness: 260, damping: 26 }}
      style={{ '--status-rgb': statusRgb }}
      className={cn(
        'relative z-10 w-full max-w-[820px] max-h-[88vh] overflow-y-auto scrollbar-cyber',
        'rounded-2xl border glass-deep shadow-elevated',
        'border-[rgba(var(--status-rgb),0.45)]',
        'shadow-[0_0_0_1px_rgba(var(--status-rgb),0.2),0_40px_80px_-30px_rgba(0,0,0,0.9),0_0_60px_-12px_rgba(var(--status-rgb),0.55)]'
      )}>
      
      {}
      <span
        aria-hidden
        className="pointer-events-none absolute inset-x-0 top-0 h-px bg-[rgba(var(--status-rgb),1)]" />
      
      {}
      <header className="relative flex items-start justify-between gap-3 px-6 pt-5 pb-4 border-b border-border-subtle">
        <div className="flex items-center gap-3 min-w-0">
          <span
            className={cn(
              'flex h-11 w-11 shrink-0 items-center justify-center rounded-xl',
              'border bg-bg-elevated/80',
              'border-[rgba(var(--status-rgb),0.45)] text-[rgb(var(--status-rgb))]',
              'shadow-[0_0_22px_-6px_rgba(var(--status-rgb),0.7)]'
            )}>
            
            <Icon className="h-5 w-5" />
          </span>
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <h2 className="text-[16px] font-semibold text-fg-primary truncate">
                {system.name}
              </h2>
              <StatusChip status={system.status} />
            </div>
            <div className="font-mono text-[10px] uppercase tracking-[0.22em] text-fg-muted truncate">
              {system.kind} · {system.regions.join(' · ')}
            </div>
          </div>
        </div>
        <button
          type="button"
          onClick={onClose}
          className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border border-border-subtle text-fg-muted hover:border-neon-cyan/40 hover:text-neon-cyan transition-cyber"
          aria-label="Close">
          
          <X className="h-4 w-4" />
        </button>
      </header>

      <div className="px-6 py-5 space-y-5">
        {}
        {system.hasAnomaly && system.anomalyMessage &&
        <motion.div
          initial={{ opacity: 0, y: -6 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3 }}
          className={cn(
            'flex items-start gap-2.5 rounded-xl border px-3 py-2.5',
            'border-[rgba(var(--status-rgb),0.45)] bg-[rgba(var(--status-rgb),0.08)]'
          )}>
          
            <AlertOctagon className="h-4 w-4 mt-0.5 shrink-0 text-[rgb(var(--status-rgb))]" />
            <div className="min-w-0">
              <div className="font-mono text-[10px] uppercase tracking-[0.22em] text-[rgb(var(--status-rgb))]">
                Active incident
                {system.threatType &&
              <> · {String(system.threatType).replace(/_/g, ' ')}</>
              }
              </div>
              <p className="text-[12.5px] text-fg-primary leading-snug mt-0.5">
                {system.anomalyMessage}
              </p>
            </div>
          </motion.div>
        }

        {}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
          <Metric icon={Cpu} label="CPU" value={`${system.cpu.toFixed(0)}%`} status={system.status} />
          <Metric icon={Activity} label="RPS" value={formatRps(system.rps)} status={system.status} />
          <Metric icon={Signal} label="Latency" value={`${system.latency}ms`} status={system.status} />
          <Metric icon={AlertOctagon} label="Errors" value={`${system.errorRate}%`} status={system.status} />
        </div>

        {}
        <div className="rounded-xl border border-border-subtle bg-bg-sunken/40 p-3">
          <div className="flex items-center justify-between mb-1">
            <span className="font-mono text-[10px] uppercase tracking-[0.22em] text-fg-muted">
              CPU · last 30s
            </span>
            <span className="font-mono text-[10px] tabular-nums text-fg-secondary">
              {system.cpu.toFixed(0)}%
            </span>
          </div>
          <svg viewBox="0 0 280 60" className="w-full h-[60px]">
            <defs>
              <linearGradient id="sparkFill" x1="0" x2="0" y1="0" y2="1">
                <stop offset="0%" stopColor={`rgb(${STATUS_RGB[system.status]})`} stopOpacity="0.45" />
                <stop offset="100%" stopColor={`rgb(${STATUS_RGB[system.status]})`} stopOpacity="0" />
              </linearGradient>
            </defs>
            <path d={`${sparkPath} L 280 60 L 0 60 Z`} fill="url(#sparkFill)" />
            <path d={sparkPath} stroke={`rgb(${STATUS_RGB[system.status]})`} strokeWidth="1.4" fill="none" />
          </svg>
        </div>

        {}
        <div className="grid grid-cols-1 lg:grid-cols-5 gap-4">
          <div className="lg:col-span-3 min-w-0">
            <SectionTitle>Active processes</SectionTitle>
            <ProcessList processes={normal} />
          </div>
          <div className="lg:col-span-2 min-w-0">
            <SectionTitle tone="red">Hostile activity</SectionTitle>
            {malicious.length > 0 ?
            <ProcessList processes={malicious} /> :

            <div className="rounded-md border border-border-subtle/70 bg-bg-sunken/40 px-3 py-4 text-center">
                <div className="font-mono text-[10px] uppercase tracking-[0.22em] text-neon-green">
                  All clear
                </div>
                <p className="text-[11px] text-fg-muted mt-1">
                  No foreign processes detected on this host.
                </p>
              </div>
            }
          </div>
        </div>

        <div className="rounded-xl border border-neon-cyan/25 bg-black/70 p-3">
          <div className="font-mono text-[10px] uppercase tracking-[0.22em] text-neon-cyan mb-2">
            Sim terminal
          </div>
          <div className="h-32 overflow-y-auto scrollbar-cyber rounded-md border border-border-subtle bg-bg-sunken/50 px-2 py-1.5 font-mono text-[11px] text-neon-green/90 space-y-0.5">
            {logs.map((l, idx) =>
            <div key={`${idx}-${l.slice(0, 16)}`}>{l}</div>
            )}
          </div>
          <div className="mt-2 flex items-center gap-2">
            <input
              value={cmd}
              onChange={(e) => setCmd(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') {
                  e.preventDefault();
                  void runCommand();
                }
              }}
              placeholder="run bank_update.exe"
              className="flex-1 h-8 rounded-md border border-border-subtle bg-bg-sunken/60 px-2 font-mono text-[11px] text-fg-primary outline-none focus:border-neon-cyan/45"
            />
            <button
              type="button"
              onClick={() => {
                void runCommand();
              }}
              disabled={busyCmd}
              className="h-8 px-2.5 rounded-md border border-neon-cyan/35 text-neon-cyan font-mono text-[10px] uppercase tracking-[0.2em] disabled:opacity-50"
            >
              run
            </button>
          </div>
        </div>
      </div>
    </motion.div>);

}

function Metric({ icon: Icon, label, value, status }) {
  const hot = status !== 'normal';
  return (
    <div
      className={cn(
        'rounded-lg border bg-bg-sunken/40 px-3 py-2.5 min-w-0',
        hot ? 'border-[rgba(var(--status-rgb),0.4)]' : 'border-border-subtle'
      )}>
      
      <div className="flex items-center gap-1.5 font-mono text-[9.5px] uppercase tracking-[0.22em] text-fg-muted">
        <Icon className="h-3 w-3" />
        {label}
      </div>
      <div
        className={cn(
          'mt-1 font-mono text-[18px] leading-none tabular-nums font-semibold',
          hot ? 'text-[rgb(var(--status-rgb))]' : 'text-fg-primary'
        )}>
        
        {value}
      </div>
    </div>);

}

function StatusChip({ status }) {
  const txt =
  status === 'critical' ?
  'Critical' :
  status === 'warning' ?
  'Warning' :
  'Normal';
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded-full border h-[22px] px-2',
        'font-mono text-[9px] uppercase tracking-[0.22em]',
        status === 'critical' ?
        'border-neon-red/45 bg-neon-red/[0.12] text-neon-red text-glow-red' :
        status === 'warning' ?
        'border-neon-orange/45 bg-neon-orange/[0.10] text-neon-orange' :
        'border-neon-green/35 bg-neon-green/[0.10] text-neon-green'
      )}>
      
      <span
        className={cn(
          'h-1.5 w-1.5 rounded-full',
          status === 'critical' ?
          'bg-neon-red shadow-[0_0_10px_rgba(255,59,59,0.85)] animate-anomaly-pulse' :
          status === 'warning' ?
          'bg-neon-orange shadow-[0_0_10px_rgba(255,159,28,0.65)]' :
          'bg-neon-green'
        )} />
      
      {txt}
    </span>);

}

function SectionTitle({ children, tone }) {
  return (
    <h3
      className={cn(
        'mb-2 font-mono text-[10px] uppercase tracking-[0.22em]',
        tone === 'red' ? 'text-neon-red' : 'text-fg-muted'
      )}>
      
      {children}
    </h3>);

}

function buildSparkPath(values, width, height) {
  if (!values.length) return '';
  const min = 0;
  const max = 100;
  const stepX = width / (values.length - 1 || 1);
  return values.
  map((v, i) => {
    const x = i * stepX;
    const y = height - (v - min) / (max - min) * height;
    return `${i === 0 ? 'M' : 'L'} ${x.toFixed(1)} ${y.toFixed(1)}`;
  }).
  join(' ');
}

function formatRps(n) {
  if (n >= 10_000) return `${(n / 1000).toFixed(1)}k`;
  if (n >= 1000) return `${(n / 1000).toFixed(2)}k`;
  return String(n);
}