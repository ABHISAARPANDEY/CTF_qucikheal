import { useEffect, useMemo, useRef, useState } from 'react';
import { Beaker, Play } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '../ui/card';
import { Button } from '../ui/button';
import { Badge } from '../ui/badge';
import { Sparkline } from '../ui/sparkline';
import { Empty } from '../ui/empty';
import { SESSION_KINDS, trafficAttack } from '../../lib/api';
import { useRealtime } from '../../lib/useRealtime';
import { selectEventsMeta, selectStats } from '../../lib/selectors';
import { titleCase } from '../../lib/format';

const EXPECTED = {
  port_scan: 'port_scan',
  credential_stuffing: 'credential_stuffing',
  low_slow_brute_force: 'low_slow_brute',
  brute_force: 'lexical / ip_repetition',
  ddos: 'distributed_sources',
  sql_injection: 'lexical'
};
const SPEED = { low_slow_brute_force: 15, port_scan: 3, credential_stuffing: 3, brute_force: 2, ddos: 2, sql_injection: 2 };

export default function DetectionLab() {
  const [kind, setKind] = useState('credential_stuffing');
  const [run, setRun] = useState(null); // {kind, startedAt}
  const stats = useRealtime(selectStats);
  const meta = useRealtime(selectEventsMeta);
  const traj = useRef([]);

  const launch = async () => {
    traj.current = [];
    const startedAt = Date.now();
    setRun({ kind, startedAt, firstAlert: null, signals: new Set() });
    try {
      await trafficAttack({ kind, duration_s: 22, speed: SPEED[kind] ?? 2 });
    } catch {
      void 0;
    }
  };

  // Watch pipeline metadata for events of this run's label.
  useEffect(() => {
    if (!run) return;
    let latest = null;
    for (const m of Object.values(meta)) {
      if (m.label !== run.kind || !m.ts) continue;
      if (Date.parse(m.ts) < run.startedAt - 1000) continue;
      latest = m;
      for (const s of m.signals ?? []) run.signals.add(s);
      if (m.alert_id && run.firstAlert == null) run.firstAlert = ((Date.now() - run.startedAt) / 1000).toFixed(1);
    }
    if (latest) {
      traj.current = [...traj.current, { v: latest.risk_score }].slice(-40);
      setRun((r) => ({ ...r })); // nudge re-render
    }
  }, [meta]); // eslint-disable-line react-hooks/exhaustive-deps

  const session = useMemo(
    () => (stats?.active_sessions ?? []).find((s) => s.kind === run?.kind),
    [stats, run?.kind]
  );

  return (
    <div className="flex-1 min-h-0 grid gap-3 p-3 lg:grid-cols-[320px_minmax(0,1fr)]">
      <Card className="h-fit">
        <CardHeader><CardTitle>Detection lab</CardTitle></CardHeader>
        <CardContent className="space-y-3">
          <p className="text-[12.5px] text-fg-2">Launch a live attack campaign and watch which detection signals fire and how fast an alert is raised.</p>
          <div className="space-y-1.5">
            {SESSION_KINDS.map((k) => (
              <button
                key={k}
                onClick={() => setKind(k)}
                className={`flex w-full items-center justify-between gap-2 rounded-md border px-3 h-9 text-left text-[13px] transition-cyber ${
                  kind === k ? 'border-accent/50 bg-accent-soft text-fg-0' : 'border-line text-fg-1 hover:bg-bg-2'
                }`}
              >
                <span>{titleCase(k)}</span>
                <span className="font-mono text-[10.5px] text-fg-3">{EXPECTED[k]}</span>
              </button>
            ))}
          </div>
          <Button variant="default" className="w-full" onClick={launch}>
            <Play className="h-3.5 w-3.5" /> Launch {titleCase(kind)}
          </Button>
        </CardContent>
      </Card>

      <Card className="min-h-0">
        <CardHeader><CardTitle>Live scoreboard</CardTitle>{run && <Badge variant="accent">{titleCase(run.kind)}</Badge>}</CardHeader>
        <CardContent>
          {!run ? (
            <Empty icon={Beaker} title="Nothing running" hint="Pick a vector and launch to see detection in action." />
          ) : (
            <div className="space-y-5">
              <div className="grid grid-cols-3 gap-2">
                <Metric label="Events emitted" value={session?.emitted ?? 0} />
                <Metric label="Time to first alert" value={run.firstAlert ? `${run.firstAlert}s` : '—'} tone={run.firstAlert ? 'ok' : 'muted'} />
                <Metric label="Remaining" value={session ? `${session.remaining_s}s` : 'done'} />
              </div>
              <div>
                <h4 className="text-[11px] uppercase tracking-[0.06em] text-fg-3 mb-2">Risk trajectory</h4>
                <div className="rounded-md border border-line bg-bg-0 p-3">
                  <Sparkline data={traj.current} width={640} height={60} color="var(--color-accent-hover)" />
                </div>
              </div>
              <div>
                <h4 className="text-[11px] uppercase tracking-[0.06em] text-fg-3 mb-2">Signals fired</h4>
                <div className="flex flex-wrap gap-1.5">
                  {[...(run.signals ?? [])].length ? (
                    [...run.signals].map((s) => <Badge key={s} variant={s === EXPECTED[run.kind] ? 'accent' : 'neutral'}>{s}</Badge>)
                  ) : (
                    <span className="text-[12px] text-fg-3">waiting for events…</span>
                  )}
                </div>
                <p className="mt-2 text-[11.5px] text-fg-3">Expected primary detector: <span className="font-mono text-fg-1">{EXPECTED[run.kind]}</span></p>
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function Metric({ label, value, tone }) {
  return (
    <div className="rounded-md border border-line bg-bg-0 px-3 py-2.5">
      <div className="text-[10.5px] uppercase tracking-[0.06em] text-fg-3">{label}</div>
      <div className={`mt-1 font-mono tabular text-[20px] ${tone === 'ok' ? 'text-sev-low' : tone === 'muted' ? 'text-fg-3' : 'text-fg-0'}`}>{value}</div>
    </div>
  );
}
