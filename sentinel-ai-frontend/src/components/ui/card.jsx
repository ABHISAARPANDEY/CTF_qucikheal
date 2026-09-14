import { forwardRef } from 'react';
import { cn } from '../../lib/utils';

const Card = forwardRef(function Card({ className, ...props }, ref) {
  return (
    <div
      ref={ref}
      className={cn('relative flex flex-col rounded-lg border border-line bg-bg-1 text-fg-0', className)}
      {...props}
    />
  );
});

const CardHeader = forwardRef(function CardHeader({ className, ...props }, ref) {
  return (
    <div
      ref={ref}
      className={cn('flex items-start justify-between gap-3 px-4 pt-3 pb-2.5 border-b border-line', className)}
      {...props}
    />
  );
});

const CardTitle = forwardRef(function CardTitle({ className, ...props }, ref) {
  return <h3 ref={ref} className={cn('text-[12px] font-medium tracking-tight text-fg-1', className)} {...props} />;
});

const CardDescription = forwardRef(function CardDescription({ className, ...props }, ref) {
  return <p ref={ref} className={cn('text-[12px] text-fg-2 leading-tight', className)} {...props} />;
});

const CardContent = forwardRef(function CardContent({ className, ...props }, ref) {
  return <div ref={ref} className={cn('relative flex-1 min-h-0 p-4', className)} {...props} />;
});

const CardFooter = forwardRef(function CardFooter({ className, ...props }, ref) {
  return <div ref={ref} className={cn('flex items-center gap-2 px-4 py-2.5 border-t border-line', className)} {...props} />;
});

export { Card, CardHeader, CardTitle, CardDescription, CardContent, CardFooter };
