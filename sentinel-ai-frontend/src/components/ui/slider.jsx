import { cn } from '../../lib/utils';

export function Slider({ label, hint, value, min = 0, max = 10, step = 0.1, onChange, className, dirty }) {
  const pct = max > min ? ((value - min) / (max - min)) * 100 : 0;
  return (
    <label className={cn('block', className)}>
      <div className="flex items-baseline justify-between gap-3 mb-1">
        <span className={cn('text-[12.5px]', dirty ? 'text-accent-hover' : 'text-fg-1')}>{label}</span>
        <input
          type="number"
          value={value}
          min={min}
          max={max}
          step={step}
          onChange={(e) => onChange(Number(e.target.value))}
          className="w-20 h-6 rounded border border-line-strong bg-bg-0 px-1.5 text-right font-mono tabular text-[12px] text-fg-0 focus-ring"
        />
      </div>
      <input
        type="range"
        value={value}
        min={min}
        max={max}
        step={step}
        onChange={(e) => onChange(Number(e.target.value))}
        className="w-full h-1.5 appearance-none rounded-full bg-bg-3 accent-[color:var(--color-accent)] cursor-pointer"
        style={{ background: `linear-gradient(to right, var(--color-accent) ${pct}%, var(--color-bg-3) ${pct}%)` }}
      />
      {hint && <div className="mt-1 text-[11px] text-fg-3">{hint}</div>}
    </label>
  );
}
