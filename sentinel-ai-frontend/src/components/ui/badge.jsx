import { forwardRef } from 'react';
import { cva } from 'class-variance-authority';
import { cn } from '../../lib/utils';

const badgeVariants = cva(
  [
    'inline-flex items-center gap-1 rounded-md',
    'px-1.5 h-5',
    'border font-mono text-[10.5px] uppercase tracking-[0.08em]',
    'whitespace-nowrap select-none'
  ].join(' '),
  {
    variants: {
      variant: {
        critical: 'bg-sev-critical/10 text-sev-critical border-sev-critical/30',
        high: 'bg-sev-high/10 text-sev-high border-sev-high/30',
        medium: 'bg-sev-medium/10 text-sev-medium border-sev-medium/30',
        low: 'bg-sev-low/10 text-sev-low border-sev-low/30',
        info: 'bg-bg-2 text-fg-2 border-line-strong',
        accent: 'bg-accent-soft text-accent-hover border-accent/30',
        neutral: 'bg-bg-2 text-fg-1 border-line',
        outline: 'bg-transparent text-fg-2 border-line-strong',
        // legacy aliases
        default: 'bg-accent-soft text-accent-hover border-accent/30',
        secondary: 'bg-bg-2 text-fg-1 border-line',
        destructive: 'bg-sev-critical/10 text-sev-critical border-sev-critical/30',
        success: 'bg-sev-low/10 text-sev-low border-sev-low/30',
        warning: 'bg-sev-high/10 text-sev-high border-sev-high/30',
        cyan: 'bg-accent-soft text-accent-hover border-accent/30',
        violet: 'bg-bg-2 text-fg-1 border-line'
      },
      glow: { true: '', false: '' }
    },
    defaultVariants: { variant: 'neutral', glow: false }
  }
);

const Badge = forwardRef(function Badge({ className, variant, glow, ...props }, ref) {
  return <span ref={ref} className={cn(badgeVariants({ variant, glow }), className)} {...props} />;
});

export { Badge };
