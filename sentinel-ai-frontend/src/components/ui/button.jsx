import { forwardRef } from 'react';
import { cva } from 'class-variance-authority';
import { cn } from '../../lib/utils';


















const buttonVariants = cva(
  [
  'inline-flex items-center justify-center gap-1.5 rounded-md',
  'font-medium select-none whitespace-nowrap',
  'transition-cyber',
  'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-neon-cyan/40',
  'disabled:pointer-events-none disabled:opacity-50'].
  join(' '),
  {
    variants: {
      variant: {
        default:
        'bg-neon-cyan/15 text-neon-cyan border border-neon-cyan/30 hover:bg-neon-cyan/25 hover:border-neon-cyan/45 hover:shadow-[0_0_18px_-6px_rgba(0,212,255,0.7)]',
        secondary:
        'bg-bg-elevated/70 text-fg-primary border border-border-subtle hover:bg-bg-elevated hover:border-border-strong',
        outline:
        'bg-transparent text-fg-secondary border border-border-subtle hover:text-fg-primary hover:border-border-strong hover:bg-bg-elevated/40',
        ghost:
        'bg-transparent text-fg-muted hover:text-fg-primary hover:bg-bg-elevated/60',
        destructive:
        'bg-neon-red/12 text-neon-red border border-neon-red/30 hover:bg-neon-red/20 hover:shadow-[0_0_18px_-6px_rgba(255,59,59,0.7)]',
        link:
        'bg-transparent text-neon-cyan hover:text-glow-cyan underline-offset-4 hover:underline'
      },
      size: {
        sm: 'h-7 px-2.5 text-[11.5px]',
        default: 'h-9 px-3.5 text-[13px]',
        lg: 'h-10 px-5 text-[13.5px]',
        icon: 'h-8 w-8 p-0'
      }
    },
    defaultVariants: {
      variant: 'secondary',
      size: 'default'
    }
  }
);

const Button = forwardRef(function Button(
{ className, variant, size, type = 'button', ...props },
ref)
{
  return (
    <button
      ref={ref}
      type={type}
      className={cn(buttonVariants({ variant, size }), className)}
      {...props} />);


});

export { Button };