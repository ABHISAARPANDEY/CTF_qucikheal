import { cn } from '../../lib/utils';

const TONE = {
  neutral: 'text-fg-0',
  ok: 'text-sev-low',
  warn: 'text-sev-medium',
  bad: 'text-sev-critical',
  accent: 'text-accent-hover'
};

export function Stat({ label, value, hint, tone = 'neutral', right, className, children }) {
  return (
    <div className={cn('rounded-lg border border-line bg-bg-1 px-3.5 py-3 min-w-0', className)}>
      <div className="flex items-center justify-between gap-2">
        <span className="text-[11px] uppercase tracking-[0.06em] text-fg-2 truncate">{label}</span>
        {right}
      </div>
      <div className={cn('mt-1 font-mono tabular text-[22px] leading-none font-medium truncate', TONE[tone] ?? TONE.neutral)}>
        {value}
      </div>
      {(hint || children) && <div className="mt-1.5 text-[11.5px] text-fg-2 truncate">{hint}{children}</div>}
    </div>
  );
}
