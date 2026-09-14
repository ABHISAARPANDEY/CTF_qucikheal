import { useEffect, useMemo, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { useNavigate } from 'react-router-dom';
import { ArrowRight, BellRing, Crosshair, RotateCcw, Search, Settings } from 'lucide-react';
import { NAV_GROUPS } from './Sidebar';
import { Kbd } from './ui/kbd';
import { cn } from '../lib/utils';
import { bus, EVENTS } from '../lib/eventBus';
import { patchAlert, resetDemoState, SESSION_KINDS, trafficAttack } from '../lib/api';
import { useRealtime } from '../lib/useRealtime';
import { selectAlertList } from '../lib/selectors';
import { titleCase } from '../lib/format';

const SPEED = { low_slow_brute_force: 15, port_scan: 3, credential_stuffing: 3, brute_force: 2, ddos: 2, sql_injection: 2 };

function score(q, text) {
  if (!q) return 1;
  const t = text.toLowerCase();
  const s = q.toLowerCase();
  if (t.startsWith(s)) return 3;
  if (t.includes(s)) return 2;
  let i = 0;
  for (const ch of t) if (ch === s[i]) i += 1;
  return i === s.length ? 1 : 0;
}

export default function CommandPalette() {
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState('');
  const [idx, setIdx] = useState(0);
  const inputRef = useRef(null);
  const navigate = useNavigate();
  const alerts = useRealtime(selectAlertList);

  useEffect(() => {
    const onKey = (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setOpen((o) => !o);
      }
    };
    window.addEventListener('keydown', onKey);
    const off = bus.on(EVENTS.OPEN_PALETTE, () => setOpen(true));
    return () => {
      window.removeEventListener('keydown', onKey);
      off();
    };
  }, []);

  useEffect(() => {
    if (open) {
      setQ('');
      setIdx(0);
      setTimeout(() => inputRef.current?.focus(), 0);
    }
  }, [open]);

  const actions = useMemo(() => {
    const out = [];
    for (const g of NAV_GROUPS) {
      for (const it of g.items) {
        out.push({ id: `nav:${it.to}`, group: 'Go to', label: it.label, icon: it.icon, run: () => navigate(it.to) });
      }
    }
    for (const kind of SESSION_KINDS) {
      out.push({
        id: `launch:${kind}`,
        group: 'Launch attack',
        label: titleCase(kind),
        icon: Crosshair,
        run: () => trafficAttack({ kind, duration_s: 20, speed: SPEED[kind] ?? 2 }).catch(() => void 0)
      });
    }
    for (const a of alerts.filter((x) => x.status === 'new').slice(0, 8)) {
      out.push({
        id: `ack:${a.id}`,
        group: 'Acknowledge',
        label: `${titleCase(a.threat_type)} · ${a.entity?.key ?? ''} · ${a.id.slice(0, 8)}`,
        icon: BellRing,
        run: () => patchAlert(a.id, { status: 'acknowledged' }).catch(() => void 0)
      });
    }
    out.push({ id: 'settings', group: 'Configure', label: 'Detection thresholds', icon: Settings, run: () => navigate('/settings') });
    out.push({ id: 'reset', group: 'Demo', label: 'Reset demo state', icon: RotateCcw, run: () => resetDemoState().catch(() => void 0) });
    return out;
  }, [alerts, navigate]);

  const results = useMemo(() => {
    const scored = actions
      .map((a) => ({ a, s: score(q, `${a.group} ${a.label}`) }))
      .filter((x) => x.s > 0)
      .sort((x, y) => y.s - x.s);
    return scored.slice(0, 14).map((x) => x.a);
  }, [actions, q]);

  useEffect(() => setIdx(0), [q]);

  const run = (a) => {
    setOpen(false);
    a?.run();
  };

  if (!open) return null;
  return createPortal(
    <div className="fixed inset-0 z-50 flex items-start justify-center pt-[12vh] bg-black/50" onClick={() => setOpen(false)}>
      <div
        role="dialog"
        aria-label="Command palette"
        onClick={(e) => e.stopPropagation()}
        className="w-[560px] max-w-[calc(100vw-2rem)] rounded-lg border border-line-strong bg-bg-1 overflow-hidden"
      >
        <div className="flex items-center gap-2 px-3 h-11 border-b border-line">
          <Search className="h-4 w-4 text-fg-3" />
          <input
            ref={inputRef}
            value={q}
            onChange={(e) => setQ(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'ArrowDown') { e.preventDefault(); setIdx((i) => Math.min(results.length - 1, i + 1)); }
              if (e.key === 'ArrowUp') { e.preventDefault(); setIdx((i) => Math.max(0, i - 1)); }
              if (e.key === 'Enter') { e.preventDefault(); run(results[idx]); }
              if (e.key === 'Escape') setOpen(false);
            }}
            placeholder="Jump to a page, launch an attack, acknowledge an alert…"
            className="flex-1 bg-transparent text-[13.5px] text-fg-0 placeholder:text-fg-3 outline-none"
          />
          <Kbd>esc</Kbd>
        </div>
        <ul className="max-h-[52vh] overflow-y-auto scrollbar-cyber py-1">
          {results.length === 0 && <li className="px-3 py-6 text-center text-[12.5px] text-fg-3">No matches</li>}
          {results.map((a, i) => {
            const Icon = a.icon ?? ArrowRight;
            return (
              <li key={a.id}>
                <button
                  type="button"
                  onMouseEnter={() => setIdx(i)}
                  onClick={() => run(a)}
                  className={cn(
                    'flex w-full items-center gap-3 px-3 h-9 text-left text-[13px]',
                    i === idx ? 'bg-bg-2 text-fg-0' : 'text-fg-1'
                  )}
                >
                  <Icon className="h-4 w-4 text-fg-3" />
                  <span className="text-[11px] uppercase tracking-[0.06em] text-fg-3 w-28 shrink-0">{a.group}</span>
                  <span className="truncate">{a.label}</span>
                  {i === idx && <Kbd className="ml-auto">↵</Kbd>}
                </button>
              </li>
            );
          })}
        </ul>
      </div>
    </div>,
    document.body
  );
}
