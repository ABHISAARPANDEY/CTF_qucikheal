import { memo, useEffect, useMemo, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Radar, Filter, ShieldAlert, ShieldX, ShieldCheck, ShieldQuestion } from 'lucide-react';
import PanelCard from '../PanelCard';
import { Badge } from '../ui/badge';
import { Button } from '../ui/button';
import { useRealtime } from '../../lib/useRealtime';
import { selectEvents } from '../../lib/selectors';













const SEVERITY = {
  critical: {
    color: 'text-neon-red',
    border: 'border-l-neon-red',
    dot: 'bg-neon-red',
    glow: 'shadow-[0_0_18px_-2px_rgba(255,59,59,0.7)]',
    badgeVariant: 'destructive',
    label: 'CRITICAL',
    Icon: ShieldX,
    rowBg: 'bg-neon-red/[0.05]',
    rgb: '255,59,59',
    showGlow: true
  },
  high: {
    color: 'text-neon-red',
    border: 'border-l-neon-red',
    dot: 'bg-neon-red',
    glow: 'shadow-[0_0_14px_-2px_rgba(255,59,59,0.6)]',
    badgeVariant: 'destructive',
    label: 'HIGH',
    Icon: ShieldAlert,
    rowBg: 'bg-neon-red/[0.03]',
    rgb: '255,59,59',
    showGlow: true
  },
  medium: {
    color: 'text-neon-orange',
    border: 'border-l-neon-orange',
    dot: 'bg-neon-orange',
    glow: '',
    badgeVariant: 'warning',
    label: 'MEDIUM',
    Icon: ShieldAlert,
    rowBg: '',
    rgb: '255,159,28',
    showGlow: false
  },
  low: {
    color: 'text-neon-green',
    border: 'border-l-neon-green',
    dot: 'bg-neon-green',
    glow: '',
    badgeVariant: 'success',
    label: 'LOW',
    Icon: ShieldCheck,
    rowBg: '',
    rgb: '0,255,159',
    showGlow: false
  },
  info: {
    color: 'text-fg-muted',
    border: 'border-l-border-strong',
    dot: 'bg-fg-muted',
    glow: '',
    badgeVariant: 'outline',
    label: 'INFO',
    Icon: ShieldQuestion,
    rowBg: '',
    rgb: '148,163,184',
    showGlow: false
  }
};






const KIND_PATTERNS = [
[/sql.?injection|sqli/i, 'SQL Injection'],
[/ddos|flood|amplification/i, 'DDoS Flood'],
[/brute.?force|failed.?(login|auth)/i, 'Brute Force'],
[/port.?scan|nmap|syn.?scan/i, 'Port Scan'],
[/malware|trojan|ransomware|virus/i, 'Malware'],
[/phish/i, 'Phishing'],
[/exfil|outbound\s+transfer/i, 'Data Exfiltration'],
[/privilege.?escalation|sudo.?abuse|uid=0/i, 'Privilege Escalation'],
[/lateral|psexec|smb.?relay/i, 'Lateral Movement']];


function deriveKind(event) {
  const msg = event?.message || '';
  for (const [re, label] of KIND_PATTERNS) {
    if (re.test(msg)) return label;
  }
  const t = event?.event_type || '';
  return t ? t.charAt(0).toUpperCase() + t.slice(1) : 'Unknown';
}

const fmtTime = (iso) => {
  const d = iso ? new Date(iso) : new Date();
  return d.toLocaleTimeString('en-GB', {
    hour: '2-digit', minute: '2-digit', second: '2-digit'
  });
};

export default function ThreatFeedPanel() {



  const events = useRealtime(selectEvents);
  const listRef = useRef(null);



  const newestId = events[0]?.id;
  useEffect(() => {
    listRef.current?.scrollTo({ top: 0, behavior: 'smooth' });
  }, [newestId]);


  const counters = useMemo(() => {
    const c = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const e of events) {
      const sev = e.severity in SEVERITY ? e.severity : 'info';
      c[sev] += 1;
    }
    return c;
  }, [events]);

  return (
    <PanelCard
      title="Threat Feed"
      subtitle="Real-time signal stream"
      accent="red"
      tone="primary"
      icon={<Radar className="h-4 w-4" />}
      bodyClassName="p-0"
      actions={
      <>
          <Badge variant="destructive" glow className="hidden sm:inline-flex">
            <span className="h-1.5 w-1.5 rounded-full bg-neon-red shadow-[0_0_8px_rgba(255,59,59,0.95)] animate-[blink_1.4s_ease-in-out_infinite]" />
            <span className="font-semibold">Live</span>
          </Badge>
          <Button variant="ghost" size="icon" className="h-7 w-7" aria-label="Filter threats">
            <Filter className="h-3.5 w-3.5" />
          </Button>
        </>
      }>
      
      {}
      <div className="grid grid-cols-4 gap-px bg-border-subtle border-b border-border-subtle">
        <Stat label="Critical" value={counters.critical} tone="text-neon-red" />
        <Stat label="High" value={counters.high} tone="text-neon-red" />
        <Stat label="Medium" value={counters.medium} tone="text-neon-orange" />
        <Stat label="Low/Info" value={counters.low + counters.info} tone="text-neon-green" />
      </div>

      {}
      <div className="relative h-full">
        <span aria-hidden className="pointer-events-none absolute inset-x-0 top-0 h-6 bg-gradient-to-b from-bg-panel/90 to-transparent z-10" />
        <span aria-hidden className="pointer-events-none absolute inset-x-0 bottom-0 h-8 bg-gradient-to-t from-bg-panel/90 to-transparent z-10" />

        {events.length === 0 ?
        <div className="h-full flex items-center justify-center px-6 py-10 text-center">
            <div className="font-mono text-[11px] uppercase tracking-[0.22em] text-fg-muted">
              Waiting for live signals from backend…
            </div>
          </div> :

        <ul ref={listRef} className="overflow-y-auto scrollbar-cyber max-h-full">
            <AnimatePresence initial={false}>
              {events.map((event) =>
            <ThreatRow key={event.id} event={event} />
            )}
            </AnimatePresence>
          </ul>
        }
      </div>
    </PanelCard>);

}




const ThreatRow = memo(function ThreatRow({ event }) {
  const sev = event.severity in SEVERITY ? event.severity : 'info';
  const s = SEVERITY[sev];
  const Icon = s.Icon;
  const isCritical = sev === 'critical';
  const kind = deriveKind(event);

  return (
    <motion.li
      layout

      initial={{ opacity: 0, y: -16, height: 0 }}
      animate={{ opacity: 1, y: 0, height: 'auto' }}
      exit={{ opacity: 0, y: 16, height: 0 }}
      transition={{ duration: 0.32, ease: [0.2, 0.7, 0.2, 1] }}
      className={[
      'group relative grid grid-cols-[auto_1fr_auto] items-center gap-3 px-5 py-3 font-mono',
      'border-b border-border-subtle/60',
      s.showGlow ? 'border-l-[3px]' : 'border-l-2',
      s.border,
      s.rowBg,

      'hover:bg-bg-elevated/60 transition-cyber'].
      join(' ')}
      style={s.showGlow ? { '--row-rgb': s.rgb } : undefined}>
      
      {}
      {isCritical &&
      <motion.span
        aria-hidden
        animate={{ opacity: [0.0, 0.18, 0.0] }}
        transition={{ duration: 2.4, repeat: Infinity, ease: 'easeInOut' }}
        className="pointer-events-none absolute inset-0"
        style={{ background: `linear-gradient(90deg, rgba(var(--row-rgb),0.25), transparent 70%)` }} />

      }

      {}
      <span
        aria-hidden
        className={`absolute left-0 top-0 bottom-0 w-[3px] ${s.dot} ${
        s.showGlow ? 'opacity-100' : 'opacity-50 group-hover:opacity-100'} ${
        s.glow} ${
        isCritical ? 'animate-[pulse-glow_2.2s_ease-in-out_infinite]' : ''} transition-opacity`
        }
        style={s.showGlow ? { color: `rgb(${s.rgb})` } : undefined} />
      

      {}
      <div
        className={`relative flex h-8 w-8 items-center justify-center rounded-lg bg-bg-sunken/80 border ${s.color} ${
        s.showGlow ? 'border-neon-red/40 shadow-[0_0_14px_-3px_rgba(255,59,59,0.55)]' : 'border-border-subtle'}`
        }>
        
        <Icon className="h-4 w-4" strokeWidth={2} />
      </div>

      {}
      <div className="relative min-w-0">
        <div className="flex items-center gap-2">
          <span
            className={`text-[13px] truncate ${
            s.showGlow ? 'font-semibold text-fg-primary text-glow-red' : 'font-medium text-fg-primary'}`
            }>
            
            {kind}
          </span>
          <Badge
            variant={s.badgeVariant}
            glow={isCritical}
            className="h-[16px] px-1.5 text-[9.5px] tracking-[0.18em] rounded-sm">
            
            {s.label}
          </Badge>
        </div>
        <div className="text-[11px] text-fg-muted truncate">
          <span className="text-fg-secondary">{event.source_ip}</span>
          <span className="mx-1.5 text-fg-faint">·</span>
          <span className="uppercase tracking-[0.14em] text-fg-faint">{event.event_type}</span>
          <span className="mx-1.5 text-fg-faint">·</span>
          <span className="truncate">{event.message}</span>
        </div>
      </div>

      {}
      <div className="relative text-right">
        <div className="text-[11px] tabular-nums text-fg-secondary">{fmtTime(event.timestamp)}</div>
        <div className="text-[9.5px] uppercase tracking-[0.18em] text-fg-faint">UTC</div>
      </div>
    </motion.li>);

});

function Stat({ label, value, tone }) {
  return (
    <div className="bg-bg-panel/60 px-4 py-3">
      <div className={`font-mono text-[20px] font-semibold tabular-nums leading-none ${tone}`}>
        {value}
      </div>
      <div className="mt-1.5 font-mono text-[10px] uppercase tracking-[0.18em] text-fg-muted">
        {label}
      </div>
    </div>);

}