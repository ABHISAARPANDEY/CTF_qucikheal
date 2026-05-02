import { motion } from 'framer-motion';
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from './ui/card';
import { cn } from '../lib/utils';
















const ACCENT = {
  green: { rgb: '0,255,159', text: 'text-neon-green', dot: 'bg-neon-green' },
  red: { rgb: '255,59,59', text: 'text-neon-red', dot: 'bg-neon-red' },
  orange: { rgb: '255,159,28', text: 'text-neon-orange', dot: 'bg-neon-orange' },
  blue: { rgb: '59,130,246', text: 'text-neon-blue', dot: 'bg-neon-blue' },
  cyan: { rgb: '0,212,255', text: 'text-neon-cyan', dot: 'bg-neon-cyan' },
  violet: { rgb: '167,139,250', text: 'text-neon-violet', dot: 'bg-neon-violet' }
};


const TONE = {
  primary: {
    border: 'border-[rgba(var(--accent-rgb),0.22)]',
    shadow: 'shadow-[0_1px_0_0_rgba(255,255,255,0.04)_inset,0_24px_60px_-30px_rgba(0,0,0,0.85)]',
    headerPad: 'px-5 pt-[18px] pb-3',
    bodyPad: 'p-5',
    accentLine: 'opacity-50',
    titleClass: 'text-fg-primary'
  },
  default: {
    border: 'border-border-subtle',
    shadow: 'shadow-[0_18px_44px_-28px_rgba(0,0,0,0.8)]',
    headerPad: 'px-5 pt-4 pb-3',
    bodyPad: 'p-5',
    accentLine: 'opacity-0',
    titleClass: 'text-fg-secondary'
  },
  subtle: {
    border: 'border-border-subtle',
    shadow: 'shadow-[0_14px_36px_-28px_rgba(0,0,0,0.7)]',
    headerPad: 'px-5 pt-3.5 pb-2.5',
    bodyPad: 'px-5 py-4',
    accentLine: 'opacity-0',
    titleClass: 'text-fg-muted'
  }
};

const MotionCard = motion.create(Card);

export default function PanelCard({
  title,
  subtitle,
  icon,
  accent = 'cyan',
  actions,
  tone = 'default',
  className = '',
  bodyClassName = '',
  children
}) {
  const a = ACCENT[accent] ?? ACCENT.cyan;
  const t = TONE[tone] ?? TONE.default;
  const isPrimary = tone === 'primary';

  return (
    <MotionCard
      whileHover={{ y: -3 }}
      transition={{ type: 'spring', stiffness: 320, damping: 26 }}
      style={{ '--accent-rgb': a.rgb }}
      className={cn(
        'group h-full overflow-hidden transition-cyber',
        t.border,
        t.shadow,

        'hover:border-[rgba(var(--accent-rgb),0.32)]',
        'hover:shadow-[0_1px_0_0_rgba(255,255,255,0.04)_inset,0_0_0_1px_rgba(var(--accent-rgb),0.16),0_28px_60px_-30px_rgba(0,0,0,0.85)]',
        className
      )}>
      
      {}
      <span
        aria-hidden
        className={cn(
          'absolute inset-x-0 top-0 h-px transition-opacity duration-300',
          a.dot,
          t.accentLine,
          'group-hover:opacity-0'
        )} />
      
      <span
        aria-hidden
        className={cn(
          'absolute inset-x-0 top-0 h-px opacity-0 transition-opacity duration-300',
          'group-hover:opacity-100',
          a.text,
          'shimmer-line'
        )} />
      

      {}
      <span
        aria-hidden
        className={cn(
          'pointer-events-none absolute -top-20 -right-20 h-44 w-44 rounded-full blur-3xl',
          'opacity-0 group-hover:opacity-30 transition-opacity duration-500',
          a.dot
        )} />
      

      <CardHeader className={cn(t.headerPad)}>
        <div className="flex items-center gap-3 min-w-0">
          {icon ?
          <span
            className={cn(
              'flex h-8 w-8 shrink-0 items-center justify-center rounded-lg',
              'bg-bg-elevated/70 border border-border-subtle',
              a.text,
              'group-hover:border-[rgba(var(--accent-rgb),0.4)] transition-cyber'
            )}>
            
              {icon}
            </span> :

          <span className={cn('h-2 w-2 shrink-0 rounded-full', a.dot)} />
          }
          <div className="min-w-0">
            <CardTitle className={cn(t.titleClass, 'truncate')}>
              {title}
            </CardTitle>
            {subtitle &&
            <CardDescription className={cn('truncate', isPrimary ? 'mt-0.5' : '')}>
                {subtitle}
              </CardDescription>
            }
          </div>
        </div>
        {actions && <div className="shrink-0 flex items-center gap-2">{actions}</div>}
      </CardHeader>

      <CardContent className={cn(t.bodyPad, bodyClassName)}>
        {children}
      </CardContent>
    </MotionCard>);

}