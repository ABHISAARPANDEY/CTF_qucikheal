import { useMemo, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Search, Zap } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '../ui/card';
import { Badge } from '../ui/badge';
import { Table, TBody, TD, TH, THead, TR, useVirtualRows } from '../ui/table';
import { Empty } from '../ui/empty';
import { useRealtime } from '../../lib/useRealtime';
import { selectEvents, selectEventsMeta } from '../../lib/selectors';
import { cn } from '../../lib/utils';
import { fmtTime, SEVERITY_ORDER, titleCase } from '../../lib/format';

const ROW = 36;

export default function EventStream({ height = 420 }) {
  const events = useRealtime(selectEvents);
  const meta = useRealtime(selectEventsMeta);
  const navigate = useNavigate();
  const [sev, setSev] = useState(() => new Set(SEVERITY_ORDER));
  const [type, setType] = useState('all');
  const [q, setQ] = useState('');
  const [hideBenign, setHideBenign] = useState(false);
  const bodyRef = useRef(null);

  const types = useMemo(() => Array.from(new Set(events.map((e) => e.event_type))).sort(), [events]);

  const rows = useMemo(() => {
    const s = q.trim().toLowerCase();
    return events.filter((e) => {
      const m = meta[e.id];
      const effSev = m?.severity ?? e.severity;
      if (!sev.has(effSev)) return false;
      if (type !== 'all' && e.event_type !== type) return false;
      if (hideBenign && (m?.threat_type ?? 'benign') === 'benign') return false;
      if (s && !`${e.message} ${e.source_ip} ${e.username ?? ''} ${m?.threat_type ?? ''}`.toLowerCase().includes(s)) return false;
      return true;
    });
  }, [events, meta, sev, type, q, hideBenign]);

  const v = useVirtualRows({ count: rows.length, rowHeight: ROW, viewportHeight: height - 96 });

  const toggleSev = (s) =>
    setSev((prev) => {
      const n = new Set(prev);
      if (n.has(s)) n.delete(s);
      else n.add(s);
      return n;
    });

  return (
    <Card className="h-full min-h-0 flex flex-col">
      <CardHeader className="flex-wrap gap-y-2">
        <CardTitle>Live event stream</CardTitle>
        <div className="flex items-center gap-1.5 flex-wrap">
          {SEVERITY_ORDER.map((s) => (
            <button
              key={s}
              type="button"
              onClick={() => toggleSev(s)}
              className={cn(
                'h-6 px-2 rounded-md border text-[11px] uppercase tracking-[0.06em] transition-cyber',
                sev.has(s) ? `border-line-strong text-fg-0 bg-bg-2` : 'border-line text-fg-3'
              )}
            >
              {s}
            </button>
          ))}
          <select value={type} onChange={(e) => setType(e.target.value)} className="h-6 rounded-md border border-line bg-bg-0 px-1.5 text-[11.5px] text-fg-1 focus-ring">
            <option value="all">all types</option>
            {types.map((t) => (
              <option key={t} value={t}>{t}</option>
            ))}
          </select>
          <label className="flex items-center gap-1.5 text-[11.5px] text-fg-2 cursor-pointer select-none">
            <input type="checkbox" checked={hideBenign} onChange={(e) => setHideBenign(e.target.checked)} className="accent-[color:var(--color-accent)]" />
            hide benign
          </label>
          <div className="relative">
            <Search className="absolute left-2 top-1/2 -translate-y-1/2 h-3 w-3 text-fg-3" />
            <input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="filter"
              className="h-6 w-36 rounded-md border border-line bg-bg-0 pl-6 pr-2 text-[11.5px] text-fg-0 placeholder:text-fg-3 focus-ring"
            />
          </div>
          <span className="font-mono tabular text-[11px] text-fg-3">{rows.length}/{events.length}</span>
        </div>
      </CardHeader>
      <CardContent className="p-0 flex-1 min-h-0">
        {rows.length === 0 ? (
          <Empty title="No events match" hint="Loosen the filters or launch a scenario." />
        ) : (
          <div ref={bodyRef} onScroll={v.onScroll} className="h-full overflow-auto scrollbar-cyber">
            <Table>
              <THead>
                <tr>
                  <TH className="w-20">Time</TH>
                  <TH className="w-24">Verdict</TH>
                  <TH className="w-16" align="right">Risk</TH>
                  <TH className="w-32">Source</TH>
                  <TH>Message</TH>
                </tr>
              </THead>
              <TBody>
                {v.padTop > 0 && <tr style={{ height: v.padTop }} />}
                {rows.slice(v.start, v.end).map((e) => {
                  const m = meta[e.id];
                  const tt = m?.threat_type ?? 'benign';
                  const effSev = m?.severity ?? e.severity;
                  const benign = tt === 'benign';
                  return (
                    <TR key={e.id} clickable onClick={() => navigate(`/entities/ip/${encodeURIComponent(String(e.source_ip))}`)} style={{ height: ROW }}>
                      <TD mono className="text-fg-3">{fmtTime(e.timestamp)}</TD>
                      <TD>
                        <span className="inline-flex items-center gap-1.5">
                          <Badge variant={benign ? 'outline' : effSev}>{benign ? 'benign' : titleCase(tt)}</Badge>
                          {m?.matched_by_signature && <Zap className="h-3 w-3 text-accent-hover" aria-label="signature match" />}
                        </span>
                      </TD>
                      <TD mono align="right" className={cn(benign ? 'text-fg-3' : 'text-fg-0')}>{(m?.risk_score ?? 0).toFixed(1)}</TD>
                      <TD mono className="text-fg-1">{String(e.source_ip)}</TD>
                      <TD className={cn('truncate max-w-[520px]', benign ? 'text-fg-3' : 'text-fg-1')} title={e.message}>{e.message}</TD>
                    </TR>
                  );
                })}
                {v.padBottom > 0 && <tr style={{ height: v.padBottom }} />}
              </TBody>
            </Table>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
