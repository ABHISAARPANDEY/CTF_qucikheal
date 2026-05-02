import { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import {
  Globe2,
  MapPin,
  ShieldAlert,
  Target,
  UserX,
  Zap } from
'lucide-react';
import { ATTACK_META } from './honeypotIntel';














export default function AttackerInfoPanel({
  attackType,
  attackerIp,
  trapped,
  startedAt,
  runId,
  geo
}) {
  const meta = ATTACK_META[attackType] ?? ATTACK_META.ddos;
  const now = useTickingNow(trapped ? 1000 : null);
  const elapsed = startedAt && now ? formatElapsed(now - startedAt) : '—';
  const fakeGeo = geo ?? mockGeo(attackerIp);

  return (
    <section
      className="
        relative h-full overflow-hidden rounded-xl
        border border-neon-green/30 bg-black
        shadow-[0_0_36px_-12px_rgba(0,255,159,0.45),0_0_0_1px_rgba(0,255,159,0.08)_inset]
        flex flex-col
      ">





      
      {}
      <header className="relative flex items-center gap-2 px-3 h-9 border-b border-neon-green/20 bg-black/70">
        <UserX className="h-3.5 w-3.5 text-neon-green/80" />
        <span className="font-mono text-[10.5px] uppercase tracking-[0.22em] text-neon-green/85 text-glow-green">
          adversary :: profile
        </span>
        <span className="ml-auto font-mono text-[9px] uppercase tracking-[0.24em] text-neon-green/40">
          {runId ? runId.slice(0, 12) : 'idle'}
        </span>
      </header>

      {}
      <span
        aria-hidden
        className="pointer-events-none absolute inset-0 z-0 opacity-[0.06]"
        style={{
          background:
          'repeating-linear-gradient(0deg, rgba(0,255,159,0.55) 0, rgba(0,255,159,0.55) 1px, transparent 1px, transparent 3px)'
        }} />
      

      <div className="relative z-10 flex-1 overflow-y-auto scrollbar-cyber p-4 space-y-4">
        {}
        <div>
          <FieldLabel icon={<Globe2 className="h-3 w-3" />}>source IP</FieldLabel>
          <div className="mt-1 flex items-baseline gap-2">
            <code
              className="font-mono text-[22px] font-semibold text-neon-green tracking-tight"
              style={{ textShadow: '0 0 14px rgba(0,255,159,0.65)' }}>
              
              {attackerIp ?? '—.—.—.—'}
            </code>
            <span className="font-mono text-[10px] text-neon-green/55 uppercase tracking-[0.22em]">
              ipv4
            </span>
          </div>
          <div className="mt-1 flex flex-wrap items-center gap-2 font-mono text-[10px] text-neon-green/60">
            <MapPin className="h-3 w-3" />
            <span>{fakeGeo.country}</span>
            <span className="opacity-50">·</span>
            <span className="text-neon-green/45">ASN {fakeGeo.asn}</span>
          </div>
        </div>

        <Divider />

        {}
        <div>
          <FieldLabel icon={<Target className="h-3 w-3" />}>attack vector</FieldLabel>
          <div className="mt-1 flex items-center gap-2">
            <span
              className="font-mono text-[10px] uppercase tracking-[0.22em] px-1.5 py-0.5 rounded border border-neon-green/35 text-neon-green/85 bg-neon-green/[0.06]">
              
              {meta.short}
            </span>
            <span className="font-mono text-[12.5px] text-neon-green/95">
              {meta.label}
            </span>
          </div>
          <p className="mt-1 text-[11.5px] text-neon-green/55 leading-snug">
            {meta.blurb}
          </p>
        </div>

        <Divider />

        {}
        <div>
          <FieldLabel icon={<ShieldAlert className="h-3 w-3" />}>status</FieldLabel>
          <div className="mt-1.5 flex items-center gap-2">
            <TrappedChip trapped={trapped} />
          </div>
          <p className="mt-1.5 text-[11px] text-neon-green/55 leading-snug">
            {trapped ?
            'Adversary session pinned to sinkhole. Egress drops at observation plane.' :
            'Standing by. Trigger an attack to engage the honeypot mesh.'}
          </p>
        </div>

        <Divider />

        {}
        <dl className="grid grid-cols-2 gap-x-4 gap-y-2 font-mono text-[10.5px]">
          <Stat label="ingress" value={startedAt ? formatTime(startedAt) : '—'} />
          <Stat label="elapsed" value={elapsed} />
          <Stat label="frame src" value="decoy mesh" />
          <Stat label="egress" value="sinkhole" />
        </dl>
      </div>

      {}
      <footer
        className="relative z-10 px-3 h-7 border-t border-neon-green/20 bg-black/70 flex items-center overflow-hidden">
        
        <motion.span
          className="font-mono text-[10px] tracking-[0.24em] uppercase text-neon-green/65 text-glow-green whitespace-nowrap"
          animate={trapped ? { opacity: [0.55, 1, 0.55] } : { opacity: 0.55 }}
          transition={{ duration: 1.6, repeat: Infinity, ease: 'easeInOut' }}>
          
          {trapped ?
          'observation plane :: recording' :
          'observation plane :: idle'}
        </motion.span>
        <span className="ml-auto font-mono text-[9.5px] tracking-[0.22em] text-neon-green/35">
          ttyHoney0
        </span>
      </footer>
    </section>);

}



function FieldLabel({ icon, children }) {
  return (
    <div className="flex items-center gap-1.5 font-mono text-[9.5px] uppercase tracking-[0.24em] text-neon-green/55">
      {icon}
      {children}
    </div>);

}

function Divider() {
  return (
    <span
      aria-hidden
      className="block h-px w-full bg-gradient-to-r from-transparent via-neon-green/25 to-transparent" />);


}

function Stat({ label, value }) {
  return (
    <div className="flex flex-col">
      <span className="text-neon-green/45 uppercase tracking-[0.22em] text-[9px]">
        {label}
      </span>
      <span className="text-neon-green/90 truncate">{value}</span>
    </div>);

}

function TrappedChip({ trapped }) {
  if (!trapped) {
    return (
      <span className="inline-flex items-center gap-1.5 rounded-md border border-neon-green/25 bg-neon-green/[0.04] px-2 h-[26px] font-mono text-[11px] uppercase tracking-[0.22em] text-neon-green/60">
        <span className="h-2 w-2 rounded-full bg-neon-green/40" />
        standby
      </span>);

  }
  return (
    <motion.span
      initial={{ scale: 0.92, opacity: 0 }}
      animate={{ scale: 1, opacity: 1 }}
      transition={{ type: 'spring', stiffness: 360, damping: 22 }}
      className="
        relative inline-flex items-center gap-2 rounded-md border border-neon-red/55 bg-neon-red/[0.10]
        px-2.5 h-[28px] font-mono text-[11.5px] font-semibold uppercase tracking-[0.26em]
        text-neon-red text-glow-red
        shadow-[0_0_18px_-4px_rgba(255,59,59,0.65)]
        animate-anomaly-pulse
      ">






      
      <span className="relative flex h-2 w-2">
        <span className="absolute inline-flex h-full w-full rounded-full bg-neon-red opacity-65 animate-ping" />
        <span className="relative inline-flex h-2 w-2 rounded-full bg-neon-red shadow-[0_0_10px_rgba(255,59,59,0.95)]" />
      </span>
      trapped
      <Zap className="h-3 w-3 text-neon-red" />
    </motion.span>);

}

function mockGeo(ip) {
  if (!ip) return { country: '— · unknown', asn: '——' };
  if (ip.startsWith('10.')) return { country: 'INTERNAL · vpn', asn: 'AS-INT' };
  const oct = parseInt(ip.split('.')[0] ?? '0', 10);
  if (oct < 50) return { country: 'BR · São Paulo', asn: '262907' };
  if (oct < 100) return { country: 'NL · Amsterdam', asn: '60781' };
  if (oct < 150) return { country: 'CN · Shanghai', asn: '4837' };
  if (oct < 200) return { country: 'RU · Moscow', asn: '24940' };
  return { country: 'IR · Tehran', asn: '58224' };
}

function formatElapsed(ms) {
  if (ms == null || ms < 0) return '—';
  const s = Math.floor(ms / 1000);
  if (s < 60) return `${s}s`;
  return `${Math.floor(s / 60)}m ${s % 60}s`;
}

function formatTime(epoch) {
  const d = new Date(epoch);
  return d.toLocaleTimeString('en-GB', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  });
}








function useTickingNow(intervalMs) {
  const [now, setNow] = useState(null);
  useEffect(() => {
    if (intervalMs == null) {
      const off = setTimeout(() => setNow(null), 0);
      return () => clearTimeout(off);
    }


    const seed = setTimeout(() => setNow(Date.now()), 0);
    const handle = setInterval(() => setNow(Date.now()), intervalMs);
    return () => {
      clearTimeout(seed);
      clearInterval(handle);
    };
  }, [intervalMs]);
  return now;
}