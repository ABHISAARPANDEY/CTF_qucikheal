import { titleCase } from '../../lib/format';

export default function ZScoreBars({ zscores, features }) {
  const entries = Object.entries(zscores ?? {}).filter(([, v]) => Math.abs(v) > 0.01);
  if (!entries.length) return <div className="text-[12px] text-fg-3">Baseline still warming up for this entity.</div>;
  entries.sort((a, b) => Math.abs(b[1]) - Math.abs(a[1]));
  return (
    <div className="space-y-1.5">
      {entries.map(([k, z]) => {
        const clamped = Math.max(-4, Math.min(4, z));
        const pct = (Math.abs(clamped) / 4) * 50;
        const outlier = Math.abs(z) >= 2;
        const name = k.replace(/^user\./, '');
        const featVal = features?.[name];
        return (
          <div key={k} className="flex items-center gap-2">
            <span className="w-36 shrink-0 text-[11.5px] text-fg-2 truncate" title={featVal != null ? `value ${featVal}` : undefined}>
              {titleCase(name)}
            </span>
            <div className="flex-1 h-3 relative rounded bg-bg-3">
              <span className="absolute inset-y-0 left-1/2 w-px bg-line-strong" />
              <span
                className="absolute inset-y-0 rounded"
                style={{
                  left: z < 0 ? `${50 - pct}%` : '50%',
                  width: `${pct}%`,
                  background: outlier ? 'var(--color-sev-high)' : 'var(--color-accent)'
                }}
              />
            </div>
            <span className={`w-12 text-right font-mono tabular text-[11px] ${outlier ? 'text-sev-high' : 'text-fg-2'}`}>
              {z > 0 ? '+' : ''}{z.toFixed(1)}σ
            </span>
          </div>
        );
      })}
    </div>
  );
}
