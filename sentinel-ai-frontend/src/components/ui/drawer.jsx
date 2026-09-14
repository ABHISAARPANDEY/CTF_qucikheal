import { useEffect, useRef } from 'react';
import { createPortal } from 'react-dom';
import { AnimatePresence, motion } from 'framer-motion';
import { X } from 'lucide-react';
import { Button } from './button';
import { cn } from '../../lib/utils';

export function Drawer({ open, onClose, title, subtitle, width = 560, children, footer, className }) {
  const panelRef = useRef(null);

  useEffect(() => {
    if (!open) return undefined;
    const onKey = (e) => {
      if (e.key === 'Escape') onClose?.();
    };
    window.addEventListener('keydown', onKey);
    const first = panelRef.current?.querySelector('button, [href], input, textarea, select, [tabindex]');
    first?.focus?.();
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  return createPortal(
    <AnimatePresence>
      {open && (
        <>
          <motion.div
            key="backdrop"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.15 }}
            className="fixed inset-0 z-40 bg-black/50"
            onClick={onClose}
          />
          <motion.aside
            key="panel"
            ref={panelRef}
            role="dialog"
            aria-modal="true"
            aria-label={typeof title === 'string' ? title : 'Details'}
            initial={{ x: 24, opacity: 0 }}
            animate={{ x: 0, opacity: 1 }}
            exit={{ x: 24, opacity: 0 }}
            transition={{ duration: 0.16, ease: 'easeOut' }}
            style={{ width, maxWidth: '100vw' }}
            className={cn('fixed inset-y-0 right-0 z-50 flex flex-col bg-bg-1 border-l border-line-strong', className)}
          >
            <header className="flex items-start justify-between gap-3 px-5 py-4 border-b border-line">
              <div className="min-w-0">
                <div className="text-[14px] font-semibold text-fg-0 truncate">{title}</div>
                {subtitle && <div className="text-[12px] text-fg-2 mt-0.5">{subtitle}</div>}
              </div>
              <Button variant="ghost" size="icon" onClick={onClose} aria-label="Close">
                <X className="h-4 w-4" />
              </Button>
            </header>
            <div className="flex-1 min-h-0 overflow-y-auto scrollbar-cyber px-5 py-4">{children}</div>
            {footer && <footer className="border-t border-line px-5 py-3">{footer}</footer>}
          </motion.aside>
        </>
      )}
    </AnimatePresence>,
    document.body
  );
}
