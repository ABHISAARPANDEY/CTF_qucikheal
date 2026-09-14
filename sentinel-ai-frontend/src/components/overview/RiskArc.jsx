import { useEffect, useState } from 'react';
import { animate, useMotionValue } from 'framer-motion';
import { useRealtime } from '../../lib/useRealtime';
import { selectConfig, selectRiskScore, selectThreat } from '../../lib/selectors';
import { Card, CardContent, CardHeader, CardTitle } from '../ui/card';
import { titleCase } from '../../lib/format';

function toneFor(score, cfg) {
  const c = cfg ?? {};
  if (score >= (c.sev_critical ?? 8.5)) return ['var(--color-sev-critical)', 'Critical'];
  if (score >= (c.sev_high ?? 6.5)) return ['var(--color-sev-high)', 'High'];
  if (score >= (c.sev_medium ?? 4.0)) return ['var(--color-sev-medium)', 'Elevated'];
  if (score >= (c.sev_low ?? 2.0)) return ['var(--color-sev-low)', 'Low'];
  return ['var(--color-fg-2)', 'Nominal'];
}

export default function RiskArc() {
  const score = useRealtime(selectRiskScore) ?? 0;
  const threat = useRealtime(selectThreat);
  const cfg = useRealtime(selectConfig);
  const mv = useMotionValue(0);
  const [shown, setShown] = useState(0);

  useEffect(() => {
    const ctl = animate(mv, score, { duration: 0.4, ease: 'easeOut' });
    return () => ctl.stop();
  }, [score, mv]);
  useEffect(() => mv.on('change', (v) => setShown(v)), [mv]);

  const [color, label] = toneFor(score, cfg);
  const r = 64;
  const c = Math.PI * r;
  const pct = Math.max(0, Math.min(1, shown / 10));
  const alertMin = cfg?.alert_min_risk ?? 4;
  const marker = Math.PI - (alertMin / 10) * Math.PI;

  return (
    <Card className="h-full">
      <CardHeader>
        <CardTitle>Latest event risk</CardTitle>
        <span className="text-[11px] text-fg-3">alert threshold {alertMin.toFixed(1)}</span>
      </CardHeader>
      <CardContent className="flex flex-col items-center justify-center gap-2 py-3">
        <svg viewBox="0 0 160 92" className="w-full max-w-[220px]">
          <path d="M 16 84 A 64 64 0 0 1 144 84" fill="none" stroke="var(--color-bg-3)" strokeWidth="10" strokeLinecap="round" />
          <path
            d="M 16 84 A 64 64 0 0 1 144 84"
            fill="none"
            stroke={color}
            strokeWidth="10"
            strokeLinecap="round"
            strokeDasharray={`${pct * c} ${c}`}
          />
          <line
            x1={80 + Math.cos(marker) * 54}
            y1={84 - Math.sin(marker) * 54}
            x2={80 + Math.cos(marker) * 74}
            y2={84 - Math.sin(marker) * 74}
            stroke="var(--color-fg-3)"
            strokeWidth="1.5"
          />
          <text x="80" y="76" textAnchor="middle" fill="var(--color-fg-0)" fontSize="30" fontFamily="var(--font-mono)" fontWeight="500">
            {shown.toFixed(1)}
          </text>
        </svg>
        <div className="text-[12px] font-medium" style={{ color }}>
          {label}
        </div>
        <div className="text-[11.5px] text-fg-2 text-center truncate max-w-full">
          {threat ? `${titleCase(threat.threat_type)} · confidence ${(threat.confidence * 100).toFixed(0)}%` : 'awaiting events'}
        </div>
      </CardContent>
    </Card>
  );
}
