import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { FileJson, FileText, Printer, RefreshCw, Table2 } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '../ui/card';
import { Badge } from '../ui/badge';
import { Button } from '../ui/button';
import { Stat } from '../ui/stat';
import { Table, TBody, TD, TH, THead, TR } from '../ui/table';
import { Empty } from '../ui/empty';
import { incidentReport, incidentReportMarkdown } from '../../lib/api';
import { fmtNum, fmtPct, SEV_COLOR, titleCase } from '../../lib/format';

function download(name, content, type) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export default function ReportsPage() {
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(() => {
    setLoading(true);
    incidentReport()
      .then(setReport)
      .catch(() => setReport(null))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  if (loading && !report) return <div className="p-6 text-[13px] text-fg-3">Building incident report…</div>;
  if (!report) return <div className="p-6"><Empty title="No report" hint="Backend unreachable." /></div>;

  const m = report.metrics;
  const csv = () => {
    const rows = [['timestamp', 'type', 'severity', 'entity', 'risk', 'count', 'status']];
    for (const t of report.timeline) rows.push([t.ts, t.type, t.severity, t.entity?.key ?? '', t.risk, t.count, t.status]);
    download('incident_timeline.csv', rows.map((r) => r.map((v) => `"${String(v ?? '').replaceAll('"', '""')}"`).join(',')).join('\n'), 'text/csv');
  };

  return (
    <div className="print-report flex-1 min-h-0 overflow-y-auto scrollbar-cyber p-3 space-y-3">
      <div className="no-print flex items-center justify-between gap-3 px-1">
        <div>
          <h1 className="text-[15px] font-semibold text-fg-0">Incident report</h1>
          <p className="text-[12px] text-fg-2">Generated {new Date(report.generated_at).toLocaleString()}</p>
        </div>
        <div className="flex items-center gap-1.5">
          <Button variant="outline" size="sm" onClick={load}><RefreshCw className="h-3.5 w-3.5" /> Refresh</Button>
          <Button variant="outline" size="sm" onClick={() => download('incident.json', JSON.stringify(report, null, 2), 'application/json')}><FileJson className="h-3.5 w-3.5" /> JSON</Button>
          <Button variant="outline" size="sm" onClick={csv}><Table2 className="h-3.5 w-3.5" /> CSV</Button>
          <Button variant="outline" size="sm" onClick={() => incidentReportMarkdown().then((md) => download('incident.md', md, 'text/markdown')).catch(() => void 0)}><FileText className="h-3.5 w-3.5" /> Markdown</Button>
          <Button variant="default" size="sm" onClick={() => window.print()}><Printer className="h-3.5 w-3.5" /> Print / PDF</Button>
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-2">
        <Stat label="Events ingested" value={fmtNum(m.events_ingested)} hint={`${m.events_per_sec} ev/s`} />
        <Stat label="Alerts raised" value={fmtNum(m.alerts_raised)} hint={`${m.alerts_open} open`} tone={m.alerts_open ? 'warn' : 'neutral'} />
        <Stat label="Suppression" value={fmtPct(m.suppression_ratio)} tone="ok" />
        <Stat label="Deduplicated" value={fmtNum(m.deduped)} />
        <Stat label="Below threshold" value={fmtNum(m.suppressed)} />
        <Stat label="MTTD" value={m.mttd_s == null ? '—' : `${m.mttd_s.toFixed(1)}s`} />
      </div>

      <div className="grid gap-2 lg:grid-cols-3">
        <BarCard title="By severity" data={report.alerts_by_severity} colorFor={(k) => SEV_COLOR[k]} />
        <BarCard title="By type" data={report.alerts_by_type} />
        <Card>
          <CardHeader><CardTitle>MITRE ATT&CK coverage</CardTitle></CardHeader>
          <CardContent className="p-3">
            {report.mitre_coverage.length === 0 ? <Empty title="None" className="py-4" /> : (
              <ul className="space-y-1">
                {report.mitre_coverage.map((x) => (
                  <li key={x.technique} className="flex items-center justify-between text-[12.5px]">
                    <span className="font-mono text-accent-hover">{x.technique}</span>
                    <span className="font-mono tabular text-fg-2">{x.count}</span>
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-2 lg:grid-cols-2">
        <RankCard title="Top attackers" rows={report.top_attackers} render={(r) => (
          <>
            <TD mono><Link to={`/entities/ip/${encodeURIComponent(r.ip)}`} className="text-accent-hover hover:underline">{r.ip}</Link></TD>
            <TD align="right" mono>{r.events}</TD>
            <TD align="right" mono className="text-fg-0">{r.risk_max?.toFixed(1)}</TD>
            <TD className="text-fg-2 truncate max-w-[200px]">{(r.types ?? []).map(titleCase).join(', ')}</TD>
          </>
        )} head={<><TH>IP</TH><TH align="right">Events</TH><TH align="right">Max risk</TH><TH>Types</TH></>} />
        <RankCard title="Top targeted accounts" rows={report.top_targets} render={(r) => (
          <>
            <TD mono><Link to={`/entities/user/${encodeURIComponent(r.user)}`} className="text-accent-hover hover:underline">{r.user}</Link></TD>
            <TD align="right" mono>{r.events}</TD>
            <TD align="right" mono className="text-fg-0">{r.risk_max?.toFixed(1)}</TD>
          </>
        )} head={<><TH>User</TH><TH align="right">Events</TH><TH align="right">Max risk</TH></>} />
      </div>

      <Card>
        <CardHeader><CardTitle>Timeline</CardTitle><span className="font-mono text-[11px] text-fg-3">{report.timeline.length}</span></CardHeader>
        <CardContent className="p-0 max-h-[360px] overflow-y-auto scrollbar-cyber">
          {report.timeline.length === 0 ? <Empty title="No alerts yet" className="py-6" /> : (
            <Table>
              <THead><tr><TH className="w-40">Time</TH><TH>Type</TH><TH>Entity</TH><TH align="right">Risk</TH><TH align="right">×</TH><TH>Status</TH></tr></THead>
              <TBody>
                {report.timeline.map((t) => (
                  <TR key={t.alert_id}>
                    <TD mono className="text-fg-3">{new Date(t.ts).toLocaleTimeString('en-GB')}</TD>
                    <TD><Badge variant={t.severity}>{titleCase(t.type)}</Badge></TD>
                    <TD mono className="text-fg-1">{t.entity?.key}</TD>
                    <TD mono align="right" className="text-fg-0">{t.risk?.toFixed(1)}</TD>
                    <TD mono align="right" className="text-fg-2">{t.count}</TD>
                    <TD className="text-fg-2">{t.status.replace('_', ' ')}</TD>
                  </TR>
                ))}
              </TBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function BarCard({ title, data, colorFor }) {
  const entries = Object.entries(data ?? {}).sort((a, b) => b[1] - a[1]);
  const max = Math.max(1, ...entries.map(([, v]) => v));
  return (
    <Card>
      <CardHeader><CardTitle>{title}</CardTitle></CardHeader>
      <CardContent className="p-3 space-y-1.5">
        {entries.length === 0 ? <Empty title="None" className="py-4" /> : entries.map(([k, v]) => (
          <div key={k} className="flex items-center gap-2 text-[12px]">
            <span className="w-32 shrink-0 text-fg-2 truncate">{titleCase(k)}</span>
            <div className="flex-1 h-2 rounded-full bg-bg-3 overflow-hidden">
              <div className="h-full rounded-full" style={{ width: `${(v / max) * 100}%`, background: colorFor?.(k) ?? 'var(--color-accent)' }} />
            </div>
            <span className="w-8 text-right font-mono tabular text-fg-1">{v}</span>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}

function RankCard({ title, rows, render, head }) {
  return (
    <Card>
      <CardHeader><CardTitle>{title}</CardTitle></CardHeader>
      <CardContent className="p-0">
        {(rows ?? []).length === 0 ? <Empty title="None" className="py-6" /> : (
          <Table>
            <THead><tr>{head}</tr></THead>
            <TBody>{rows.map((r, i) => <TR key={i}>{render(r)}</TR>)}</TBody>
          </Table>
        )}
      </CardContent>
    </Card>
  );
}
