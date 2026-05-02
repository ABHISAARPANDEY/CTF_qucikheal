import { Sparkles, Zap } from 'lucide-react';
import { Badge } from '../ui/badge';
import { cn } from '../../lib/utils';




export default function ResponseIntelStrip({ actions, explanation, className = '' }) {
  const summary = explanation?.summary ?? null;
  const provider = explanation?.provider ?? '';

  return (
    <div className={cn('grid gap-2 sm:grid-cols-2 min-w-0', className)}>
      <div className="rounded-lg border border-border-subtle bg-bg-sunken/45 px-2.5 py-2 min-w-0">
        <div className="flex items-center gap-1.5 mb-1.5">
          <Zap className="h-3.5 w-3.5 text-neon-orange shrink-0" />
          <span className="font-mono text-[9px] uppercase tracking-[0.22em] text-fg-faint">
            Actions taken
          </span>
        </div>
        {!actions?.length ?
        <p className="text-[11px] text-fg-muted">Awaiting pipeline dispatch…</p> :

        <ul className="flex flex-wrap gap-1">
            {actions.slice(0, 8).map((a) =>
          <li key={a.id ?? `${a.action_type}-${a.target}`}>
                <Badge variant="cyan" className="h-auto py-0.5 max-w-[180px] truncate">
                  {a.action_type?.replace(/_/g, ' ') ?? 'action'} → {a.target}
                </Badge>
              </li>
          )}
          </ul>
        }
      </div>

      <div className="rounded-lg border border-neon-violet/25 bg-neon-violet/[0.06] px-2.5 py-2 min-w-0 relative overflow-hidden">
        <span
          aria-hidden
          className="pointer-events-none absolute inset-0 opacity-[0.07] bg-[radial-gradient(circle_at_20%_50%,rgba(167,139,250,0.5),transparent_65%)]" />
        
        <div className="relative flex items-start gap-1.5 mb-1">
          <Sparkles className="h-3.5 w-3.5 text-neon-violet shrink-0 mt-0.5" />
          <span className="font-mono text-[9px] uppercase tracking-[0.22em] text-neon-violet/90">
            AI explanation
          </span>
          {provider ?
          <span className="ml-auto font-mono text-[8px] text-fg-faint truncate">{provider}</span> :
          null}
        </div>
        {!summary ?
        <p className="relative text-[11px] text-fg-muted leading-snug">
            Copilot narrative arrives with the next pipeline broadcast.
          </p> :

        <p className="relative text-[11.5px] text-fg-primary/95 leading-snug line-clamp-4">{summary}</p>
        }
      </div>
    </div>);

}