import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { BellRing } from 'lucide-react';
import { Badge } from '../ui/badge';
import { Table, TBody, TD, TH, THead, TR, useSort, useVirtualRows } from '../ui/table';
import { Empty } from '../ui/empty';
import { Kbd } from '../ui/kbd';
import AlertDrawer from './AlertDrawer';
import { applyFilters, sortAlerts } from './alertFilters';
import { useRealtime } from '../../lib/useRealtime';
import { selectAlertList } from '../../lib/selectors';
import { getAlert, patchAlert } from '../../lib/api';
import { cn } from '../../lib/utils';
import { fmtAgo, SEVERITY_ORDER, titleCase } from '../../lib/format';

const ROW = 40;
const STATUSES = ['new', 'acknowledged', 'investigating', 'resolved', 'false_positive'];
const ENTITY_TYPES = ['ip', 'user', 'subnet', 'campaign'];

function facetToggle(setter) {
  return (val) =>
    setter((prev) => {
      const n = new Set(prev);
      if (n.has(val)) n.delete(val);
      else n.add(val);
      return n;
    });
}

export default function AlertsPage() {
  const alerts = useRealtime(selectAlertList);
  const [sev, setSev] = useState(new Set());
  const [status, setStatus] = useState(new Set(['new', 'acknowledged', 'investigating']));
  const [type, setType] = useState(new Set());
  const [entityType, setEntityType] = useState(new Set());
  const [q, setQ] = useState('');
  const [sort, onSort] = useSort({ key: 'severity', dir: 'desc' });
  const [cursor, setCursor] = useState(0);
  const [params, setParams] = useSearchParams();
  const bodyRef = useRef(null);

  const types = useMemo(() => Array.from(new Set(alerts.map((a) => a.threat_type))).sort(), [alerts]);

  const rows = useMemo(
    () => sortAlerts(applyFilters(alerts, { severity: sev, status, type, entityType, q }), sort.key, sort.dir),
    [alerts, sev, status, type, entityType, q, sort]
  );

  const openId = params.get('alert');
  const selected = useMemo(() => alerts.find((a) => a.id === openId) ?? null, [alerts, openId]);

  const openAlert = useCallback(
    (id) => {
      setParams((p) => {
        const n = new URLSearchParams(p);
        n.set('alert', id);
        return n;
      });
    },
    [setParams]
  );
  const closeAlert = useCallback(() => {
    setParams((p) => {
      const n = new URLSearchParams(p);
      n.delete('alert');
      return n;
    });
  }, [setParams]);

  // Refresh the opened alert's full record (drawer needs breakdown/zscores).
  const [full, setFull] = useState(null);
  useEffect(() => {
    if (!openId) return void setFull(null);
    getAlert(openId).then(setFull).catch(() => setFull(selected));
  }, [openId]); // eslint-disable-line react-hooks/exhaustive-deps

  const act = useCallback(
    async (id, patch) => {
      try {
        await patchAlert(id, patch);
      } catch {
        void 0;
      }
    },
    []
  );

  const onKeyDown = useCallback(
    (e) => {
      if (['INPUT', 'TEXTAREA'].includes(e.target.tagName)) return;
      if (e.key === 'j') setCursor((c) => Math.min(rows.length - 1, c + 1));
      else if (e.key === 'k') setCursor((c) => Math.max(0, c - 1));
      else if (e.key === 'Enter' && rows[cursor]) openAlert(rows[cursor].id);
      else if (e.key === 'a' && rows[cursor]) act(rows[cursor].id, { status: 'acknowledged' });
      else if (e.key === 'r' && rows[cursor]) act(rows[cursor].id, { status: 'resolved' });
      else if (e.key === 'f' && rows[cursor]) act(rows[cursor].id, { status: 'false_positive' });
    },
    [rows, cursor, openAlert, act]
  );

  useEffect(() => {
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [onKeyDown]);

  const v = useVirtualRows({ count: rows.length, rowHeight: ROW, viewportHeight: (bodyRef.current?.clientHeight ?? 600) });

  return (
    <div className="flex-1 min-h-0 flex flex-col p-3 gap-2">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2 px-1">
        <Facets label="Severity" values={SEVERITY_ORDER} active={sev} onToggle={facetToggle(setSev)} tone />
        <Facets label="Status" values={STATUSES} active={status} onToggle={facetToggle(setStatus)} />
        <Facets label="Entity" values={ENTITY_TYPES} active={entityType} onToggle={facetToggle(setEntityType)} />
        {types.length > 1 && <Facets label="Type" values={types} active={type} onToggle={facetToggle(setType)} />}
        <div className="flex items-center gap-2 ml-auto">
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="search type, entity, signal, MITRE"
            className="h-7 w-64 rounded-md border border-line bg-bg-0 px-2.5 text-[12px] text-fg-0 placeholder:text-fg-3 focus-ring"
          />
          <span className="font-mono tabular text-[11.5px] text-fg-3">{rows.length}</span>
          <span className="hidden md:flex items-center gap-1 text-[11px] text-fg-3">
            <Kbd>j</Kbd><Kbd>k</Kbd> move <Kbd>a</Kbd> ack <Kbd>r</Kbd> resolve
          </span>
        </div>
      </div>

      <div className="flex-1 min-h-0 rounded-lg border border-line bg-bg-1 overflow-hidden">
        {rows.length === 0 ? (
          <Empty icon={BellRing} title="No alerts match" hint="Adjust the facets, or launch an attack from Scenarios / the ⌘K palette." />
        ) : (
          <div ref={bodyRef} onScroll={v.onScroll} className="h-full overflow-auto scrollbar-cyber">
            <Table>
              <THead>
                <tr>
                  <TH className="w-24" sortKey="severity" sort={sort} onSort={onSort}>Sev</TH>
                  <TH sortKey="threat_type" sort={sort} onSort={onSort}>Type</TH>
                  <TH>Entity</TH>
                  <TH className="w-24" align="right" sortKey="risk" sort={sort} onSort={onSort}>Risk</TH>
                  <TH className="w-16" align="right" sortKey="count" sort={sort} onSort={onSort}>×</TH>
                  <TH className="w-16" align="right" sortKey="last_seen" sort={sort} onSort={onSort}>Age</TH>
                  <TH className="w-28">Status</TH>
                  <TH className="w-24">MITRE</TH>
                </tr>
              </THead>
              <TBody>
                {v.padTop > 0 && <tr style={{ height: v.padTop }} />}
                {rows.slice(v.start, v.end).map((a, i) => {
                  const idx = v.start + i;
                  return (
                    <TR
                      key={a.id}
                      clickable
                      active={a.id === openId || idx === cursor}
                      onClick={() => {
                        setCursor(idx);
                        openAlert(a.id);
                      }}
                      style={{ height: ROW }}
                    >
                      <TD><Badge variant={a.severity}>{a.severity}</Badge></TD>
                      <TD className="text-fg-0">{titleCase(a.threat_type)}</TD>
                      <TD mono className="text-fg-1">
                        <span className="text-fg-3">{a.entity?.type}:</span> {a.entity?.key}
                      </TD>
                      <TD align="right">
                        <span className="inline-flex items-center gap-1.5">
                          <span className="w-10 h-1.5 rounded-full bg-bg-3 overflow-hidden">
                            <span className="block h-full bg-accent" style={{ width: `${(a.risk / 10) * 100}%` }} />
                          </span>
                          <span className="font-mono tabular text-fg-0">{a.risk?.toFixed(1)}</span>
                        </span>
                      </TD>
                      <TD mono align="right" className="text-fg-1">{a.count}</TD>
                      <TD mono align="right" className="text-fg-3">{fmtAgo(a.last_seen)}</TD>
                      <TD><span className={cn('text-[11.5px]', a.status === 'new' ? 'text-fg-0' : 'text-fg-2')}>{a.status.replace('_', ' ')}</span></TD>
                      <TD mono className="text-fg-3 text-[11px]">{(a.mitre ?? [])[0] ?? '—'}</TD>
                    </TR>
                  );
                })}
                {v.padBottom > 0 && <tr style={{ height: v.padBottom }} />}
              </TBody>
            </Table>
          </div>
        )}
      </div>

      <AlertDrawer alert={full ?? selected} open={Boolean(openId)} onClose={closeAlert} onChange={setFull} />
    </div>
  );
}

function Facets({ label, values, active, onToggle, tone }) {
  return (
    <div className="flex items-center gap-1.5">
      <span className="text-[10.5px] uppercase tracking-[0.06em] text-fg-3">{label}</span>
      {values.map((val) => {
        const on = active.has(val);
        return (
          <button
            key={val}
            type="button"
            onClick={() => onToggle(val)}
            className={cn(
              'h-6 px-2 rounded-md border text-[11px] transition-cyber',
              on ? 'border-line-strong bg-bg-2 text-fg-0' : 'border-line text-fg-3 hover:text-fg-1',
              tone && on && `text-sev-${val}`
            )}
          >
            {val.replace('_', ' ')}
          </button>
        );
      })}
    </div>
  );
}
