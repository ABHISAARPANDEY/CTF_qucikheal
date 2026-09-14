import { cn } from '../../lib/utils';

export function Kbd({ children, className }) {
  return (
    <kbd
      className={cn(
        'inline-flex h-5 min-w-5 items-center justify-center rounded border border-line-strong bg-bg-2 px-1 font-mono text-[10.5px] text-fg-2',
        className
      )}
    >
      {children}
    </kbd>
  );
}
