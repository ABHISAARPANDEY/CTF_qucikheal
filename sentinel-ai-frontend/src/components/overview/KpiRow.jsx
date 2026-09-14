import { useEffect, useMemo, useState } from 'react';
import { Stat } from '../ui/stat';
import { Sparkline } from '../ui/sparkline';
import { useRealtime } from '../../lib/useRealtime';
import { selectAlertList, selectStats, selectStatsHistory } from '../../lib/selectors';
import { incidentReport } from '../../lib/api';
import { fmtNum, fmtPct } from '../../lib/format';

const OPEN = new Set(['new', 'acknowledged', 'investigating']);

export default function KpiRow() {
  const stats = useRealtime(selectStats);
  const history = useRealtime(selectStatsHistory);
  const alerts = useRealtime(selectAlertList);
  const [mttd, setMttd] = useState(null);

  useEffect(() => {
    let alive = true;
    const tick = () =>
      incidentReport()
        .then((r) => alive && setMttd(r?.metrics?.mttd_s ?? null))
        .catch(() => void 0);
    tick();
    const id = setInterval(tick, 10_000);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, []);

  const open = useMemo(() => {
    const c = { critical: 0, high: 0, medium: 0, low: 0, total: 0 };
    for (const a of alerts) {
      if (!OPEN.has(a.status)) continue;
      c.total += 1;
      if (a.severity in c) c[a.severity] += 1;
    }
    return c;
  }, [alerts]);

  const spark = useMemo(() => history.map((h) => ({ v: h.eps })), [history]);
  const sessions = stats?.active_sessions ?? [];

  return (
    <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-2">
      <Stat label="Events ingested" value={fmtNum(stats?.events_ingested ?? 0)} hint={`target ${stats?.target_eps ?? '—'} ev/s`} />
      <Stat
        label="Throughput"
        value={`${Math.round(stats?.events_per_sec ?? 0)} ev/s`}
        right={<Sparkline data={spark} color="var(--color-accent-hover)" />}
        hint={stats?.paused ? 'paused' : 'benign ratio ' + fmtPct(stats?.benign_ratio ?? 0)}
      />
      <Stat
        label="Open alerts"
        value={open.total}
        tone={open.critical ? 'bad' : open.high ? 'warn' : 'neutral'}
        hint={
          <span className="flex gap-2">
            <span className="text-sev-critical">{open.critical} crit</span>
            <span className="text-sev-high">{open.high} high</span>
            <span className="text-sev-medium">{open.medium} med</span>
            <span className="text-sev-low">{open.low} low</span>
          </span>
        }
      />
      <Stat
        label="Suppression"
        value={fmtPct(stats?.suppression_ratio ?? 0)}
        tone="ok"
        hint={`${fmtNum(stats?.alerts_deduped ?? 0)} deduped · ${fmtNum(stats?.alerts_suppressed ?? 0)} below threshold`}
      />
      <Stat
        label="Active campaigns"
        value={sessions.length}
        tone={sessions.length ? 'warn' : 'neutral'}
        hint={sessions.length ? sessions.map((s) => s.kind.replace(/_/g, ' ')).join(', ') : 'no simulated attacks running'}
      />
      <Stat label="MTTD" value={mttd == null ? '—' : `${mttd.toFixed(1)}s`} hint="mean time to detect (campaign start → alert)" />
    </div>
  );
}
