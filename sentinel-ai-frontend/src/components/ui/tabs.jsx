import { createContext, useContext, useId, useState } from 'react';
import { cn } from '../../lib/utils';

const Ctx = createContext(null);

export function Tabs({ value, defaultValue, onChange, children, className }) {
  const [internal, setInternal] = useState(defaultValue);
  const current = value ?? internal;
  const id = useId();
  const set = (v) => {
    setInternal(v);
    onChange?.(v);
  };
  return (
    <Ctx.Provider value={{ current, set, id }}>
      <div className={cn('flex flex-col min-h-0', className)}>{children}</div>
    </Ctx.Provider>
  );
}

export function TabList({ children, className }) {
  return (
    <div role="tablist" className={cn('flex items-center gap-1 border-b border-line', className)}>
      {children}
    </div>
  );
}

export function Tab({ value, children, className }) {
  const { current, set, id } = useContext(Ctx);
  const active = current === value;
  return (
    <button
      role="tab"
      id={`${id}-tab-${value}`}
      aria-selected={active}
      aria-controls={`${id}-panel-${value}`}
      tabIndex={active ? 0 : -1}
      onClick={() => set(value)}
      className={cn(
        'relative h-9 px-3 text-[13px] font-medium transition-cyber focus-ring rounded-t-md',
        active ? 'text-fg-0' : 'text-fg-2 hover:text-fg-1',
        className
      )}
    >
      {children}
      {active && <span className="absolute inset-x-2 -bottom-px h-0.5 bg-accent rounded-full" />}
    </button>
  );
}

export function TabPanel({ value, children, className }) {
  const { current, id } = useContext(Ctx);
  if (current !== value) return null;
  return (
    <div
      role="tabpanel"
      id={`${id}-panel-${value}`}
      aria-labelledby={`${id}-tab-${value}`}
      className={cn('flex-1 min-h-0 flex flex-col', className)}
    >
      {children}
    </div>
  );
}
