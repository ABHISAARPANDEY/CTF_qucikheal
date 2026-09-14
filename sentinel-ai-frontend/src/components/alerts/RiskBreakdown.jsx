import { titleCase } from '../../lib/format';

// Mirror of backend RISK_BUDGET (engine/detection.py) — max points per factor.
const BUDGET = {
  severity: 1.5,
  frequency: 1.0,
  repetition: 1.0,
  vector: 2.0,
  behavioral_zscore: 2.0,
  isolation_forest: 1.5,
  distributed_campaign: 1.0
};

const LABEL = {
  behavioral_zscore: 'Behavioural z-score',
  isolation_forest: 'Isolation forest',
  distributed_campaign: 'Distributed campaign',
  vector: 'Vector detector'
};

export default function RiskBreakdown({ breakdown, risk }) {
  const entries = Object.entries(BUDGET);
  return (
    <div className="space-y-1.5">
      <div className="flex items-baseline justify-between">
        <span className="text-[12px] text-fg-2">Risk contribution</span>
        <span className="font-mono tabular text-[13px] text-fg-0">{(risk ?? 0).toFixed(2)} / 10</span>
      </div>
      {entries.map(([k, max]) => {
        const v = breakdown?.[k] ?? 0;
        const pct = max > 0 ? Math.min(100, (v / max) * 100) : 0;
        return (
          <div key={k} className="flex items-center gap-2">
            <span className="w-36 shrink-0 text-[11.5px] text-fg-2 truncate">{LABEL[k] ?? titleCase(k)}</span>
            <div className="flex-1 h-2 rounded-full bg-bg-3 overflow-hidden">
              <div className="h-full rounded-full bg-accent" style={{ width: `${pct}%` }} />
            </div>
            <span className="w-16 text-right font-mono tabular text-[11px] text-fg-1">{v.toFixed(2)}<span className="text-fg-3">/{max}</span></span>
          </div>
        );
      })}
    </div>
  );
}
