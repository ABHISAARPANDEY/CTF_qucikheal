/* eslint-disable react-refresh/only-export-components */
import { forwardRef } from 'react';
import { cva } from 'class-variance-authority';
import { cn } from '../../lib/utils';

const buttonVariants = cva(
  [
    'inline-flex items-center justify-center gap-1.5 rounded-md',
    'font-medium select-none whitespace-nowrap',
    'transition-cyber focus-ring',
    'disabled:pointer-events-none disabled:opacity-50'
  ].join(' '),
  {
    variants: {
      variant: {
        default: 'bg-accent text-white border border-accent hover:bg-accent-hover hover:border-accent-hover',
        secondary: 'bg-bg-2 text-fg-0 border border-line-strong hover:bg-bg-3',
        outline: 'bg-transparent text-fg-1 border border-line-strong hover:text-fg-0 hover:bg-bg-2',
        ghost: 'bg-transparent text-fg-2 hover:text-fg-0 hover:bg-bg-2',
        destructive: 'bg-sev-critical/10 text-sev-critical border border-sev-critical/30 hover:bg-sev-critical/20',
        link: 'bg-transparent text-accent-hover underline-offset-4 hover:underline'
      },
      size: {
        xs: 'h-6 px-2 text-[11px]',
        sm: 'h-7 px-2.5 text-[12px]',
        default: 'h-8 px-3 text-[13px]',
        lg: 'h-9 px-4 text-[13px]',
        icon: 'h-8 w-8 p-0'
      }
    },
    defaultVariants: { variant: 'secondary', size: 'default' }
  }
);

const Button = forwardRef(function Button({ className, variant, size, type = 'button', ...props }, ref) {
  return <button ref={ref} type={type} className={cn(buttonVariants({ variant, size }), className)} {...props} />;
});

export { Button, buttonVariants };
