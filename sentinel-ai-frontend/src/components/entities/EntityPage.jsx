import { useEffect, useRef, useState } from 'react';
import { useParams } from 'react-router-dom';
import { ArrowLeft } from 'lucide-react';
import { Link } from 'react-router-dom';
import { Card, CardContent, CardHeader, CardTitle } from '../ui/card';
import { Badge } from '../ui/badge';
import { Table, TBody, TD, TH, THead, TR } from '../ui/table';
import { Sparkline } from '../ui/sparkline';
import { Empty } from '../ui/empty';
import { detectionEntity } from '../../lib/api';
import { fmtTime, titleCase } from '../../lib/format';

export default function EntityPage() {
  const { type, key } = useParams();
  const [data, setData] = useState(null);
  const [err, setErr] = useState(false);
  const history = useRef({});

  useEffect(() => {
    let alive = true;
    setData(null);
    setErr(false);
    history.current = {};
    const tick = () =>
      detectionEntity(type, key)
        .then((d) => {
          if (!alive) return;
          setData(d);
          for (const [f, v] of Object.entries(d.features ?? {})) {
            (history.current[f] ??= []).push({ v });
            if (history.current[f].length > 60) history.current[f].shift();
          }
        })
        .catch(() => alive && setErr(true));
    tick();
    const id = setInterval(tick, 5000);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, [type, key]);

  if (err) return <div className="p-6"><Empty title="Entity not found" hint="It may have aged out of the detection window." /></div>;
  if (!data) return <div className="p-6 text-[13px] text-fg-3">Loading entity…</div>;

  const features = Object.entries(data.features ?? {});
  const baseline = data.baseline ?? {};
  const z = data.zscores ?? {};

  return (
    <div className="flex-1 min-h-0 overflow-y-auto scrollbar-cyber p-3 space-y-2">
      <div className="flex items-center gap-2 px-1">
        <Link to="/alerts" className="text-fg-3 hover:text-fg-1"><ArrowLeft className="h-4 w-4" /></Link>
        <Badge variant="neutral">{type}</Badge>
        <span className="font-mono text-[14px] text-fg-0">{key}</span>
      </div>

      {type === 'campaign' && data.campaign && (
        <Card>
          <CardHeader><CardTitle>Campaign fingerprint</CardTitle></CardHeader>
          <CardContent className="grid grid-cols-2 md:grid-cols-4 gap-3 text-[13px]">
            <KV label="User agent" value={data.campaign.user_agent} mono />
            <KV label="Endpoint" value={data.campaign.endpoint} mono />
            <KV label="Distinct IPs" value={data.campaign.distinct_ips} />
            <KV label="Distinct /24s" value={data.campaign.distinct_subnets} />
            <KV label="Distinct users" value={data.campaign.distinct_users} />
            <KV label="Fail ratio" value={`${(data.campaign.fail_ratio * 100).toFixed(0)}%`} />
            <KV label="Events" value={data.campaign.events} />
          </CardContent>
        </Card>
      )}

      <div className="grid gap-2 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
        <Card>
          <CardHeader><CardTitle>Behavioural features</CardTitle><span className="text-[11px] text-fg-3">vs population baseline</span></CardHeader>
          <CardContent className="p-0">
            {features.length === 0 ? (
              <Empty title="No feature history" className="py-6" />
            ) : (
              <Table>
                <THead>
                  <tr><TH>Feature</TH><TH align="right">Value</TH><TH align="right">Mean±σ</TH><TH align="right">z</TH><TH className="w-28">Trend</TH></tr>
                </THead>
                <TBody>
                  {features.map(([f, v]) => {
                    const b = baseline[f];
                    const zz = z[f] ?? z[`user.${f}`];
                    const outlier = zz != null && Math.abs(zz) >= 2;
                    return (
                      <TR key={f}>
                        <TD className="text-fg-1">{titleCase(f)}</TD>
                        <TD mono align="right" className="text-fg-0">{Number(v).toFixed(2)}</TD>
                        <TD mono align="right" className="text-fg-3">{b ? `${b.mean.toFixed(1)}±${b.std.toFixed(1)}` : '—'}</TD>
                        <TD mono align="right" className={outlier ? 'text-sev-high' : 'text-fg-2'}>{zz != null ? `${zz > 0 ? '+' : ''}${zz.toFixed(1)}` : '—'}</TD>
                        <TD><Sparkline data={history.current[f] ?? []} width={100} height={20} /></TD>
                      </TR>
                    );
                  })}
                </TBody>
              </Table>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader><CardTitle>Related alerts</CardTitle><span className="font-mono text-[11px] text-fg-3">{data.alerts?.length ?? 0}</span></CardHeader>
          <CardContent className="p-0 max-h-[420px] overflow-y-auto scrollbar-cyber">
            {(data.alerts ?? []).length === 0 ? (
              <Empty title="No alerts for this entity" className="py-6" />
            ) : (
              <Table>
                <THead><tr><TH>Sev</TH><TH>Type</TH><TH align="right">Risk</TH><TH align="right">×</TH></tr></THead>
                <TBody>
                  {data.alerts.map((a) => (
                    <TR key={a.id}>
                      <TD><Badge variant={a.severity}>{a.severity}</Badge></TD>
                      <TD className="text-fg-1">{titleCase(a.threat_type)}</TD>
                      <TD mono align="right" className="text-fg-0">{a.risk?.toFixed(1)}</TD>
                      <TD mono align="right" className="text-fg-2">{a.count}</TD>
                    </TR>
                  ))}
                </TBody>
              </Table>
            )}
          </CardContent>
        </Card>
      </div>

      {(data.events ?? []).length > 0 && (
        <Card>
          <CardHeader><CardTitle>Recent events</CardTitle><span className="font-mono text-[11px] text-fg-3">{data.events.length}</span></CardHeader>
          <CardContent className="p-0 max-h-[300px] overflow-y-auto scrollbar-cyber">
            <Table>
              <THead><tr><TH className="w-20">Time</TH><TH className="w-28">Type</TH><TH>Message</TH></tr></THead>
              <TBody>
                {data.events.slice().reverse().map((e) => (
                  <TR key={e.id}>
                    <TD mono className="text-fg-3">{fmtTime(e.timestamp)}</TD>
                    <TD className="text-fg-2">{e.event_type}</TD>
                    <TD className="text-fg-1 truncate max-w-[640px]" title={e.message}>{e.message}</TD>
                  </TR>
                ))}
              </TBody>
            </Table>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

function KV({ label, value, mono }) {
  return (
    <div>
      <div className="text-[10.5px] uppercase tracking-[0.06em] text-fg-3">{label}</div>
      <div className={`mt-0.5 text-fg-0 ${mono ? 'font-mono text-[12px] break-all' : ''}`}>{value}</div>
    </div>
  );
}
