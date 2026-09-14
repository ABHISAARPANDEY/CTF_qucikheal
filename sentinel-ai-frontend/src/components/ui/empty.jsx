import { cn } from '../../lib/utils';

export function Empty({ icon: Icon, title, hint, className, action }) {
  return (
    <div className={cn('flex flex-col items-center justify-center gap-2 py-10 text-center', className)}>
      {Icon && <Icon className="h-5 w-5 text-fg-3" />}
      <div className="text-[13px] text-fg-1">{title}</div>
      {hint && <div className="text-[12px] text-fg-3 max-w-xs">{hint}</div>}
      {action}
    </div>
  );
}
