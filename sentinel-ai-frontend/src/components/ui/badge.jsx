import { forwardRef } from 'react';
import { cva } from 'class-variance-authority';
import { cn } from '../../lib/utils';










const badgeVariants = cva(
  [
  'inline-flex items-center gap-1 rounded-md',
  'px-2 h-[22px]',
  'border font-mono text-[10px] uppercase tracking-[0.22em]',
  'whitespace-nowrap select-none',
  'transition-cyber'].
  join(' '),
  {
    variants: {
      variant: {
        default: 'bg-neon-cyan/10 text-neon-cyan border-neon-cyan/30',
        secondary: 'bg-bg-elevated/60 text-fg-secondary border-border-subtle',
        outline: 'bg-transparent text-fg-muted border-border-strong',
        destructive: 'bg-neon-red/10 text-neon-red border-neon-red/30',
        success: 'bg-neon-green/10 text-neon-green border-neon-green/30',
        warning: 'bg-neon-orange/10 text-neon-orange border-neon-orange/30',
        info: 'bg-neon-blue/10 text-neon-blue border-neon-blue/30',
        cyan: 'bg-neon-cyan/10 text-neon-cyan border-neon-cyan/30',
        violet: 'bg-neon-violet/10 text-neon-violet border-neon-violet/25'
      },
      glow: {
        true: '',
        false: ''
      }
    },
    compoundVariants: [

    { variant: 'destructive', glow: true, className: 'shadow-[0_0_18px_-6px_rgba(255,59,59,0.7)] text-glow-red' },
    { variant: 'success', glow: true, className: 'shadow-[0_0_18px_-6px_rgba(0,255,159,0.7)] text-glow-green' },
    { variant: 'warning', glow: true, className: 'shadow-[0_0_18px_-6px_rgba(255,159,28,0.7)]' },
    { variant: 'info', glow: true, className: 'shadow-[0_0_18px_-6px_rgba(59,130,246,0.7)]' },
    { variant: 'cyan', glow: true, className: 'shadow-[0_0_18px_-6px_rgba(0,212,255,0.7)] text-glow-cyan' },
    { variant: 'violet', glow: true, className: 'shadow-[0_0_18px_-6px_rgba(167,139,250,0.7)]' },
    { variant: 'default', glow: true, className: 'shadow-[0_0_18px_-6px_rgba(0,212,255,0.7)] text-glow-cyan' }],

    defaultVariants: {
      variant: 'secondary',
      glow: false
    }
  }
);

const Badge = forwardRef(function Badge({ className, variant, glow, ...props }, ref) {
  return (
    <span
      ref={ref}
      className={cn(badgeVariants({ variant, glow }), className)}
      {...props} />);


});

export { Badge };