import { useMemo } from 'react';
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { Card, CardContent, CardHeader, CardTitle } from '../ui/card';
import { useRealtime } from '../../lib/useRealtime';
import { selectAlertList } from '../../lib/selectors';
import { SEV_COLOR } from '../../lib/format';

const MINUTES = 15;
const SEVS = ['low', 'medium', 'high', 'critical'];

export default function AlertsChart() {
  const alerts = useRealtime(selectAlertList);

  const data = useMemo(() => {
    const now = Date.now();
    const start = now - MINUTES * 60_000;
    const buckets = Array.from({ length: MINUTES }, (_, i) => {
      const t = start + i * 60_000;
      return { t, label: new Date(t).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' }), low: 0, medium: 0, high: 0, critical: 0 };
    });
    for (const a of alerts) {
      const ts = Date.parse(a.first_seen);
      if (Number.isNaN(ts) || ts < start) continue;
      const i = Math.min(MINUTES - 1, Math.floor((ts - start) / 60_000));
      if (a.severity in buckets[i]) buckets[i][a.severity] += 1;
    }
    return buckets;
  }, [alerts]);

  return (
    <Card className="h-full">
      <CardHeader>
        <CardTitle>Alerts raised · last {MINUTES} min</CardTitle>
        <div className="flex items-center gap-3 text-[11px] text-fg-2">
          {SEVS.slice().reverse().map((s) => (
            <span key={s} className="flex items-center gap-1">
              <span className="h-2 w-2 rounded-sm" style={{ background: SEV_COLOR[s] }} />
              {s}
            </span>
          ))}
        </div>
      </CardHeader>
      <CardContent className="p-2 h-[190px]">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data} margin={{ top: 8, right: 8, bottom: 0, left: -18 }}>
            <CartesianGrid stroke="var(--color-line)" vertical={false} />
            <XAxis dataKey="label" tick={{ fill: 'var(--color-fg-3)', fontSize: 10 }} axisLine={false} tickLine={false} interval={4} />
            <YAxis allowDecimals={false} tick={{ fill: 'var(--color-fg-3)', fontSize: 10 }} axisLine={false} tickLine={false} />
            <Tooltip
              cursor={{ stroke: 'var(--color-line-strong)' }}
              contentStyle={{ background: 'var(--color-bg-2)', border: '1px solid var(--color-line-strong)', borderRadius: 6, fontSize: 12 }}
              labelStyle={{ color: 'var(--color-fg-1)' }}
            />
            {SEVS.map((s) => (
              <Area key={s} type="monotone" stackId="1" dataKey={s} stroke={SEV_COLOR[s]} fill={SEV_COLOR[s]} fillOpacity={0.35} strokeWidth={1.25} isAnimationActive={false} />
            ))}
          </AreaChart>
        </ResponsiveContainer>
      </CardContent>
    </Card>
  );
}
