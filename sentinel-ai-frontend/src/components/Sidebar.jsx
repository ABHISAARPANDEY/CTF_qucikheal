import { motion } from 'framer-motion';
import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  Crosshair,
  Server,
  Network,
  Skull,
  FileText,
  ShieldCheck,
  Settings,
  LifeBuoy } from
'lucide-react';

const NAV = [
{ id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard, to: '/' },
{ id: 'scenarios', label: 'Attack Scenarios', icon: Crosshair, to: '/scenarios' },
{ id: 'systems', label: 'Systems', icon: Server, to: '/systems' },
{ id: 'infrastructure', label: 'Infrastructure', icon: Network, to: '/infrastructure' },
{ id: 'honeypot', label: 'Honeypot', icon: Skull, to: '/honeypot' },
{ id: 'reports', label: 'Reports', icon: FileText, to: '/reports' }];


const SECONDARY = [
{ id: 'settings', label: 'Settings', icon: Settings, to: '/settings' },
{ id: 'support', label: 'Support', icon: LifeBuoy, to: '/support' }];


export default function Sidebar() {
  return (
    <aside className="relative z-10 flex h-full w-[248px] shrink-0 flex-col border-r border-border-subtle glass-deep">
      {}
      <span
        aria-hidden
        className="pointer-events-none absolute top-0 bottom-0 right-0 w-px bg-gradient-to-b from-transparent via-neon-cyan/20 to-transparent" />
      

      {}
      <div className="relative flex items-center gap-3 px-5 h-16 border-b border-border-subtle">
        <motion.div
          whileHover={{ rotate: -6, scale: 1.05 }}
          transition={{ type: 'spring', stiffness: 360, damping: 20 }}
          className="relative flex h-9 w-9 items-center justify-center rounded-xl bg-bg-elevated border border-neon-cyan/25 ring-glow-cyan">
          
          <ShieldCheck className="h-5 w-5 text-neon-cyan text-glow-cyan" strokeWidth={2.25} />
          <motion.span
            aria-hidden
            animate={{ opacity: [0.4, 0.9, 0.4] }}
            transition={{ duration: 2.4, repeat: Infinity, ease: 'easeInOut' }}
            className="absolute inset-0 rounded-xl ring-1 ring-neon-cyan/40" />
          
        </motion.div>
        <div className="leading-tight">
          <div className="text-[15px] font-semibold tracking-tight text-fg-primary">
            Sentinel<span className="text-neon-cyan text-glow-cyan">AI</span>
          </div>
          <div className="font-mono text-[10px] uppercase tracking-[0.22em] text-fg-muted">
            Cyber Defense
          </div>
        </div>
      </div>

      {}
      <nav className="flex-1 overflow-y-auto scrollbar-cyber px-3 py-5">
        <p className="px-3 mb-2 font-mono text-[10px] uppercase tracking-[0.2em] text-fg-faint">
          Operations
        </p>
        <ul className="space-y-1">
          {NAV.map((item) =>
          <NavItem key={item.id} item={item} />
          )}
        </ul>

        <p className="mt-8 px-3 mb-2 font-mono text-[10px] uppercase tracking-[0.2em] text-fg-faint">
          Workspace
        </p>
        <ul className="space-y-1">
          {SECONDARY.map((item) =>
          <NavItem key={item.id} item={item} />
          )}
        </ul>
      </nav>

      {}
      <motion.div
        whileHover={{ scale: 1.015 }}
        className="relative m-3 rounded-xl border border-border-subtle bg-bg-elevated/60 p-3 overflow-hidden transition-cyber hover:border-neon-green/30">
        
        <span
          aria-hidden
          className="pointer-events-none absolute -top-12 -right-12 h-32 w-32 rounded-full blur-3xl bg-neon-green/15" />
        
        <div className="relative flex items-center gap-2 mb-1.5">
          <span className="relative flex h-2 w-2">
            <span className="absolute inline-flex h-full w-full rounded-full bg-neon-green opacity-60 animate-ping" />
            <span className="relative inline-flex h-2 w-2 rounded-full bg-neon-green shadow-[0_0_8px_rgba(0,255,159,0.9)]" />
          </span>
          <span className="font-mono text-[10px] uppercase tracking-[0.18em] text-fg-secondary">
            Agent online
          </span>
        </div>
        <div className="relative text-[12px] text-fg-secondary leading-snug">
          24 nodes monitored · 0 anomalies
        </div>
      </motion.div>
    </aside>);

}

function NavItem({ item }) {
  const Icon = item.icon;
  const end = item.to === '/';

  return (
    <li>
      <NavLink
        to={item.to}
        end={end}
        className={({ isActive }) =>
        [
        'group relative flex w-full items-center gap-3 rounded-lg px-3 py-2 text-left overflow-hidden',
        'text-[13.5px] transition-cyber',
        isActive ? 'text-fg-primary' : 'text-fg-secondary hover:text-fg-primary'].
        join(' ')
        }>
        
        {({ isActive }) =>
        <>
            {isActive &&
          <motion.span
            layoutId="sidebar-active-bg"
            transition={{ type: 'spring', stiffness: 360, damping: 30 }}
            className="absolute inset-0 rounded-lg bg-gradient-to-r from-neon-cyan/15 via-neon-cyan/5 to-transparent border border-neon-cyan/20 shadow-[0_0_24px_-8px_rgba(0,212,255,0.55)]" />

          }

            {!isActive &&
          <span
            aria-hidden
            className="pointer-events-none absolute inset-0 rounded-lg opacity-0 group-hover:opacity-100 transition-opacity duration-300 bg-gradient-to-r from-white/[0.04] to-transparent" />

          }

            {isActive &&
          <motion.span
            layoutId="sidebar-active-rail"
            transition={{ type: 'spring', stiffness: 380, damping: 32 }}
            className="absolute left-0 top-1.5 bottom-1.5 w-0.5 rounded-full bg-neon-cyan shadow-[0_0_10px_2px_rgba(0,212,255,0.7)]" />

          }

            <Icon
            className={[
            'relative h-4 w-4 shrink-0 transition-colors',
            isActive ? 'text-neon-cyan text-glow-cyan' : 'text-fg-muted group-hover:text-neon-cyan/80'].
            join(' ')}
            strokeWidth={2} />
          
            <span className="relative truncate">{item.label}</span>
          </>
        }
      </NavLink>
    </li>);

}