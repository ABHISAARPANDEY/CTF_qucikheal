import { forwardRef } from 'react';
import { cn } from '../../lib/utils';

















const Card = forwardRef(function Card({ className, ...props }, ref) {
  return (
    <div
      ref={ref}
      className={cn(
        'relative flex flex-col rounded-2xl border border-border-subtle glass-panel text-fg-primary',
        className
      )}
      {...props} />);


});

const CardHeader = forwardRef(function CardHeader({ className, ...props }, ref) {
  return (
    <div
      ref={ref}
      className={cn(
        'flex items-start justify-between gap-3 px-5 pt-4 pb-3 border-b border-border-subtle',
        className
      )}
      {...props} />);


});

const CardTitle = forwardRef(function CardTitle({ className, ...props }, ref) {
  return (
    <h3
      ref={ref}
      className={cn(
        'font-mono text-[11px] font-medium uppercase tracking-[0.22em] text-fg-secondary',
        className
      )}
      {...props} />);


});

const CardDescription = forwardRef(function CardDescription({ className, ...props }, ref) {
  return (
    <p
      ref={ref}
      className={cn('text-[13px] text-fg-primary/95 leading-tight', className)}
      {...props} />);


});

const CardContent = forwardRef(function CardContent({ className, ...props }, ref) {
  return (
    <div
      ref={ref}
      className={cn('relative flex-1 min-h-0 p-5', className)}
      {...props} />);


});

const CardFooter = forwardRef(function CardFooter({ className, ...props }, ref) {
  return (
    <div
      ref={ref}
      className={cn(
        'flex items-center gap-2 px-5 py-3 border-t border-border-subtle',
        className
      )}
      {...props} />);


});

export { Card, CardHeader, CardTitle, CardDescription, CardContent, CardFooter };