import { motion } from 'framer-motion';
import { AlertTriangle } from 'lucide-react';
import { Badge } from '../ui/badge';
import { cn } from '../../lib/utils';




export default function ProcessRow({
  label,
  role,
  anomaly,
  anomalyMessage,
  compact,
  recoveryGlow = false
}) {
  return (
    <motion.div
      layout
      className={cn(
        'relative rounded-md border px-2.5 py-1.5 transition-cyber overflow-hidden',
        compact ? 'text-[11px]' : 'text-[12px]',
        anomaly ?
        [
        'border-neon-red/55 bg-neon-red/[0.12]',
        'shadow-[0_0_20px_-8px_rgba(255,59,59,0.55)]',
        'animate-anomaly-pulse'] :

        recoveryGlow ?
        'border-neon-green/40 bg-neon-green/[0.07]' :
        'border-border-subtle/80 bg-bg-sunken/40'
      )}>
      
      {anomaly &&
      <span
        aria-hidden
        className="pointer-events-none absolute inset-0 bg-gradient-to-r from-neon-red/30 via-neon-red/10 to-transparent animate-anomaly-flash" />

      }
      {recoveryGlow && !anomaly &&
      <span
        aria-hidden
        className="pointer-events-none absolute inset-0 bg-gradient-to-r from-neon-green/25 via-transparent to-neon-cyan/10 animate-recovery-line" />

      }
      <div className="relative flex items-start gap-2 min-w-0">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2 min-w-0">
            <span
              className={cn(
                'font-mono font-medium truncate',
                anomaly ? 'text-neon-red text-glow-red' : 'text-fg-primary'
              )}>
              
              {label}
            </span>
            {anomaly &&
            <Badge variant="destructive" glow className="h-[18px] px-1.5 shrink-0">
                <AlertTriangle className="h-3 w-3" aria-hidden />
                alert
              </Badge>
            }
          </div>
          {!compact &&
          <div className="font-mono text-[9px] uppercase tracking-[0.18em] text-fg-faint mt-0.5">
              {role}
            </div>
          }
          {anomaly && anomalyMessage &&
          <p className="mt-1 text-[10.5px] leading-snug text-fg-secondary line-clamp-2">
              {anomalyMessage}
            </p>
          }
        </div>
      </div>
    </motion.div>);

}