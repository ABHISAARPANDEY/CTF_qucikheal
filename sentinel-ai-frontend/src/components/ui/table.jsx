/* eslint-disable react-refresh/only-export-components */
import { forwardRef, useCallback, useState } from 'react';
import { ChevronDown, ChevronUp, ChevronsUpDown } from 'lucide-react';
import { cn } from '../../lib/utils';

export const Table = forwardRef(function Table({ className, ...props }, ref) {
  return <table ref={ref} className={cn('w-full border-collapse text-[12.5px] leading-tight', className)} {...props} />;
});

export function THead({ className, ...props }) {
  return <thead className={cn('sticky top-0 z-10 bg-bg-1', className)} {...props} />;
}

export function TBody(props) {
  return <tbody {...props} />;
}

export function TR({ className, active, clickable, ...props }) {
  return (
    <tr
      className={cn(
        'border-b border-line',
        clickable && 'cursor-pointer hover:bg-bg-2/70',
        active && 'bg-accent-soft hover:bg-accent-soft',
        className
      )}
      {...props}
    />
  );
}

export function TH({ className, sortKey, sort, onSort, align = 'left', children, ...props }) {
  const sortable = Boolean(sortKey && onSort);
  const isActive = sortable && sort?.key === sortKey;
  const Icon = !isActive ? ChevronsUpDown : sort.dir === 'asc' ? ChevronUp : ChevronDown;
  return (
    <th
      className={cn(
        'h-8 px-2.5 font-medium text-[11px] uppercase tracking-[0.06em] text-fg-2 border-b border-line-strong whitespace-nowrap',
        align === 'right' ? 'text-right' : 'text-left',
        sortable && 'cursor-pointer select-none hover:text-fg-0',
        className
      )}
      onClick={sortable ? () => onSort(sortKey) : undefined}
      aria-sort={isActive ? (sort.dir === 'asc' ? 'ascending' : 'descending') : undefined}
      {...props}
    >
      <span className={cn('inline-flex items-center gap-1', align === 'right' && 'flex-row-reverse')}>
        {children}
        {sortable && <Icon className={cn('h-3 w-3', isActive ? 'text-fg-0' : 'text-fg-3')} />}
      </span>
    </th>
  );
}

export function TD({ className, align = 'left', mono, ...props }) {
  return (
    <td
      className={cn(
        'h-9 px-2.5 align-middle text-fg-1 whitespace-nowrap',
        align === 'right' && 'text-right',
        mono && 'font-mono tabular',
        className
      )}
      {...props}
    />
  );
}

/** Tiny windowing hook: renders only rows visible in a scroll container. */
export function useVirtualRows({ count, rowHeight, viewportHeight, overscan = 8 }) {
  const [scrollTop, setScrollTop] = useState(0);
  const onScroll = useCallback((e) => setScrollTop(e.currentTarget.scrollTop), []);
  const visible = Math.ceil((viewportHeight || 600) / rowHeight);
  const start = Math.max(0, Math.floor(scrollTop / rowHeight) - overscan);
  const end = Math.min(count, start + visible + overscan * 2);
  return {
    start,
    end,
    padTop: start * rowHeight,
    padBottom: Math.max(0, (count - end) * rowHeight),
    onScroll
  };
}

export function useSort(initial = { key: null, dir: 'desc' }) {
  const [sort, setSort] = useState(initial);
  const onSort = useCallback(
    (key) => setSort((s) => (s.key === key ? { key, dir: s.dir === 'asc' ? 'desc' : 'asc' } : { key, dir: 'desc' })),
    []
  );
  return [sort, onSort];
}
