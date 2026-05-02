import { motion } from 'framer-motion';
import {
  Crosshair, Server, FileText, Settings, LifeBuoy, Construction } from
'lucide-react';









const SECTIONS = {
  scenarios: {
    Icon: Crosshair,
    label: 'Attack Scenarios',
    blurb: 'Curated multi-stage exercises that walk the kill chain end to end.',
    accent: 'orange',
    rgb: '255,159,28'
  },
  systems: {
    Icon: Server,
    label: 'Systems',
    blurb: 'Inventory of monitored hosts, services, and their posture.',
    accent: 'cyan',
    rgb: '0,212,255'
  },
  reports: {
    Icon: FileText,
    label: 'Reports',
    blurb: 'Exportable incident summaries, audit logs, and compliance digests.',
    accent: 'violet',
    rgb: '167,139,250'
  },
  settings: {
    Icon: Settings,
    label: 'Settings',
    blurb: 'Detection thresholds, action policies, and integration credentials.',
    accent: 'green',
    rgb: '0,255,159'
  },
  support: {
    Icon: LifeBuoy,
    label: 'Support',
    blurb: 'Runbooks, troubleshooting guides, and engineer handoff.',
    accent: 'cyan',
    rgb: '0,212,255'
  }
};

export default function ComingSoon({ section }) {
  const meta = SECTIONS[section] ?? {
    Icon: Construction,
    label: section,
    blurb: 'This section is under construction.',
    accent: 'cyan',
    rgb: '0,212,255'
  };
  const { Icon, label, blurb, rgb } = meta;

  return (
    <motion.section
      key={section}
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.45, ease: [0.2, 0.7, 0.2, 1] }}
      className="relative flex-1 min-h-0 p-3"
      style={{ '--accent-rgb': rgb }}>
      
      <div
        className="relative h-full w-full overflow-hidden rounded-2xl border border-border-subtle glass-panel
                   shadow-[0_18px_44px_-28px_rgba(0,0,0,0.8)] flex items-center justify-center">

        
        {}
        <span
          aria-hidden
          className="pointer-events-none absolute -top-32 -right-32 h-80 w-80 rounded-full blur-3xl opacity-25"
          style={{ background: `rgb(${rgb})` }} />
        
        <span
          aria-hidden
          className="pointer-events-none absolute -bottom-32 -left-32 h-80 w-80 rounded-full blur-3xl opacity-15"
          style={{ background: `rgb(${rgb})` }} />
        

        {}
        <div
          aria-hidden
          className="absolute inset-0 bg-grid-faint pointer-events-none opacity-60"
          style={{ maskImage: 'radial-gradient(ellipse at center, black 45%, transparent 90%)' }} />
        

        <div className="relative flex max-w-md flex-col items-center px-8 py-12 text-center">
          {}
          <motion.div
            initial={{ scale: 0.85, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            transition={{ duration: 0.5, ease: [0.2, 0.7, 0.2, 1] }}
            className="relative flex h-20 w-20 items-center justify-center rounded-2xl border bg-bg-elevated/70"
            style={{
              borderColor: `rgba(${rgb},0.45)`,
              boxShadow: `0 0 28px -6px rgba(${rgb},0.55)`,
              color: `rgb(${rgb})`
            }}>
            
            <Icon className="h-9 w-9" strokeWidth={1.8} />
            <motion.span
              aria-hidden
              animate={{ scale: [1, 1.3], opacity: [0.45, 0] }}
              transition={{ duration: 2, repeat: Infinity, ease: 'easeOut' }}
              className="absolute inset-0 rounded-2xl border"
              style={{ borderColor: `rgba(${rgb},0.6)` }} />
            
          </motion.div>

          <div className="mt-6 font-mono text-[10px] uppercase tracking-[0.3em] text-fg-faint">
            SentinelAI · Section
          </div>
          <h1 className="mt-1.5 text-[28px] font-semibold tracking-tight text-fg-primary">
            {label}
          </h1>
          <p className="mt-3 text-[13.5px] leading-relaxed text-fg-secondary">
            {blurb}
          </p>

          <div className="mt-7 inline-flex items-center gap-2 rounded-full border border-border-subtle bg-bg-sunken/70 px-3 py-1.5">
            <Construction className="h-3.5 w-3.5 text-fg-muted" />
            <span className="font-mono text-[10.5px] uppercase tracking-[0.22em] text-fg-muted">
              Under construction
            </span>
          </div>
        </div>
      </div>
    </motion.section>);

}