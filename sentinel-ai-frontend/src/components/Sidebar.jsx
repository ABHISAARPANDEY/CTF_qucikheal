/* eslint-disable react-refresh/only-export-components */
import { useEffect, useState } from 'react';
import { NavLink } from 'react-router-dom';
import {
  Activity,
  BellRing,
  Crosshair,
  FileText,
  Network,
  PanelLeftClose,
  PanelLeftOpen,
  Server,
  Settings,
  ShieldCheck,
  Skull
} from 'lucide-react';
import { cn } from '../lib/utils';
import { useRealtime } from '../lib/useRealtime';
import { selectAlertList } from '../lib/selectors';

const PREFETCH = {
  '/systems': () => import('./systems/SystemsMonitorPage'),
  '/infrastructure': () => import('./infrastructure/InfrastructureView'),
  '/honeypot': () => import('./honeypot/HoneypotPage'),
  '/reports': () => import('./reports/ReportsPage'),
  '/alerts': () => import('./alerts/AlertsPage'),
  '/settings': () => import('./settings/SettingsPage')
};

export const NAV_GROUPS = [
  {
    label: 'Detect',
    items: [
      { id: 'overview', label: 'Overview', icon: Activity, to: '/' },
      { id: 'alerts', label: 'Alerts', icon: BellRing, to: '/alerts', badge: 'open' }
    ]
  },
  {
    label: 'Simulate',
    items: [
      { id: 'scenarios', label: 'Scenarios', icon: Crosshair, to: '/scenarios' },
      { id: 'systems', label: 'Systems', icon: Server, to: '/systems' },
      { id: 'infrastructure', label: 'Infrastructure', icon: Network, to: '/infrastructure' },
      { id: 'honeypot', label: 'Honeypot', icon: Skull, to: '/honeypot' }
    ]
  },
  {
    label: 'Operate',
    items: [
      { id: 'reports', label: 'Reports', icon: FileText, to: '/reports' },
      { id: 'settings', label: 'Settings', icon: Settings, to: '/settings' }
    ]
  }
];

const PIN_KEY = 'sentinel.sidebar.pinned';

export default function Sidebar() {
  const [pinned, setPinned] = useState(() => {
    try {
      return localStorage.getItem(PIN_KEY) === '1';
    } catch {
      return false;
    }
  });
  const [hover, setHover] = useState(false);
  const expanded = pinned || hover;
  const alerts = useRealtime(selectAlertList);
  const openCount = alerts.filter((a) => ['new', 'acknowledged', 'investigating'].includes(a.status)).length;

  useEffect(() => {
    try {
      localStorage.setItem(PIN_KEY, pinned ? '1' : '0');
    } catch {
      void 0;
    }
  }, [pinned]);

  return (
    <aside
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      style={{ width: expanded ? 208 : 56 }}
      className="relative z-20 flex h-full shrink-0 flex-col border-r border-line bg-bg-1 transition-[width] duration-150 ease-out overflow-hidden"
    >
      <div className="flex h-14 items-center gap-3 px-3.5 border-b border-line">
        <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md bg-accent-soft text-accent-hover">
          <ShieldCheck className="h-4 w-4" strokeWidth={2.25} />
        </span>
        <div className={cn('leading-tight whitespace-nowrap transition-opacity', expanded ? 'opacity-100' : 'opacity-0')}>
          <div className="text-[13.5px] font-semibold tracking-tight text-fg-0">SentinelAI</div>
          <div className="text-[10.5px] text-fg-2">SOC console</div>
        </div>
      </div>

      <nav className="flex-1 overflow-y-auto overflow-x-hidden scrollbar-cyber px-2 py-3">
        {NAV_GROUPS.map((g) => (
          <div key={g.label} className="mb-4">
            <p
              className={cn(
                'px-2 mb-1 text-[10px] uppercase tracking-[0.1em] text-fg-3 whitespace-nowrap transition-opacity',
                expanded ? 'opacity-100' : 'opacity-0'
              )}
            >
              {g.label}
            </p>
            <ul className="space-y-0.5">
              {g.items.map((item) => (
                <NavItem key={item.id} item={item} expanded={expanded} count={item.badge === 'open' ? openCount : 0} />
              ))}
            </ul>
          </div>
        ))}
      </nav>

      <button
        type="button"
        onClick={() => setPinned((p) => !p)}
        className="flex h-10 items-center gap-3 px-4 border-t border-line text-fg-3 hover:text-fg-1 transition-cyber"
        aria-label={pinned ? 'Collapse sidebar' : 'Pin sidebar open'}
      >
        {pinned ? <PanelLeftClose className="h-4 w-4 shrink-0" /> : <PanelLeftOpen className="h-4 w-4 shrink-0" />}
        <span className={cn('text-[12px] whitespace-nowrap transition-opacity', expanded ? 'opacity-100' : 'opacity-0')}>
          {pinned ? 'Collapse' : 'Keep open'}
        </span>
      </button>
    </aside>
  );
}

function NavItem({ item, expanded, count }) {
  const Icon = item.icon;
  const prefetch = () => {
    const p = PREFETCH[item.to];
    if (p) void p();
  };
  return (
    <li>
      <NavLink
        to={item.to}
        end={item.to === '/'}
        onMouseEnter={prefetch}
        onFocus={prefetch}
        title={expanded ? undefined : item.label}
        className={({ isActive }) =>
          cn(
            'group relative flex h-8 w-full items-center gap-3 rounded-md px-2.5 text-[13px] transition-cyber focus-ring',
            isActive ? 'bg-bg-2 text-fg-0' : 'text-fg-2 hover:text-fg-0 hover:bg-bg-2/60'
          )
        }
      >
        {({ isActive }) => (
          <>
            {isActive && <span className="absolute left-0 top-1.5 bottom-1.5 w-0.5 rounded-full bg-accent" />}
            <Icon className={cn('h-4 w-4 shrink-0', isActive ? 'text-accent-hover' : 'text-fg-2 group-hover:text-fg-1')} strokeWidth={2} />
            <span className={cn('flex-1 truncate transition-opacity', expanded ? 'opacity-100' : 'opacity-0')}>{item.label}</span>
            {count > 0 && (
              <span
                className={cn(
                  'font-mono tabular text-[10.5px] rounded px-1 min-w-5 text-center bg-sev-critical/15 text-sev-critical',
                  expanded ? 'opacity-100' : 'absolute -top-0.5 right-0.5 opacity-100 scale-90'
                )}
              >
                {count > 99 ? '99+' : count}
              </span>
            )}
          </>
        )}
      </NavLink>
    </li>
  );
}
