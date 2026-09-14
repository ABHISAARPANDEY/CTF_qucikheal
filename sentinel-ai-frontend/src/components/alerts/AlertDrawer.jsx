import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Drawer } from '../ui/drawer';
import { Badge } from '../ui/badge';
import { Button } from '../ui/button';
import RiskBreakdown from './RiskBreakdown';
import ZScoreBars from './ZScoreBars';
import { patchAlert } from '../../lib/api';
import { fmtTime, titleCase } from '../../lib/format';

const STATUSES = [
  ['acknowledged', 'Acknowledge'],
  ['investigating', 'Investigate'],
  ['resolved', 'Resolve'],
  ['false_positive', 'False positive']
];

export default function AlertDrawer({ alert, open, onClose, onChange }) {
  const [notes, setNotes] = useState('');
  const [saving, setSaving] = useState(null);

  useEffect(() => setNotes(alert?.notes ?? ''), [alert?.id, alert?.notes]);

  if (!alert) return null;

  const set = async (patch, tag) => {
    setSaving(tag);
    try {
      const updated = await patchAlert(alert.id, patch);
      onChange?.(updated);
    } catch {
      void 0;
    } finally {
      setSaving(null);
    }
  };

  const entityLink =
    alert.entity?.type && alert.entity?.key
      ? `/entities/${alert.entity.type}/${encodeURIComponent(alert.entity.key)}`
      : null;

  return (
    <Drawer
      open={open}
      onClose={onClose}
      title={
        <span className="flex items-center gap-2">
          <Badge variant={alert.severity}>{alert.severity}</Badge>
          {titleCase(alert.threat_type)}
        </span>
      }
      subtitle={`${alert.entity?.type} · ${alert.entity?.key} · seen ×${alert.count}`}
      footer={
        <div className="flex flex-wrap gap-1.5">
          {STATUSES.map(([val, label]) => (
            <Button
              key={val}
              size="sm"
              variant={alert.status === val ? 'default' : 'outline'}
              disabled={saving === val}
              onClick={() => set({ status: val }, val)}
            >
              {label}
            </Button>
          ))}
        </div>
      }
    >
      <div className="space-y-5">
        <div className="grid grid-cols-2 gap-2 text-[12px]">
          <Field label="Status"><Badge variant="neutral">{alert.status.replace('_', ' ')}</Badge></Field>
          <Field label="Risk"><span className="font-mono tabular text-fg-0">{alert.risk?.toFixed(2)}</span></Field>
          <Field label="Confidence"><span className="font-mono tabular">{((alert.confidence ?? 0) * 100).toFixed(0)}%</span></Field>
          <Field label="Assignee">{alert.assignee || '—'}</Field>
          <Field label="First seen">{fmtTime(alert.first_seen)}</Field>
          <Field label="Last seen">{fmtTime(alert.last_seen)}</Field>
        </div>

        {alert.mitre?.length > 0 && (
          <div className="flex flex-wrap gap-1.5">
            {alert.mitre.map((m) => (
              <Badge key={m} variant="accent">{m}</Badge>
            ))}
          </div>
        )}

        {entityLink && (
          <Link to={entityLink} onClick={onClose} className="inline-block text-[12.5px] text-accent-hover hover:underline">
            Inspect entity → {alert.entity.key}
          </Link>
        )}

        <Section title="Risk breakdown">
          <RiskBreakdown breakdown={alert.risk_breakdown} risk={alert.risk} />
        </Section>

        <Section title="Signals fired">
          <div className="flex flex-wrap gap-1.5">
            {(alert.signals ?? []).length ? (
              alert.signals.map((s) => <Badge key={s} variant="neutral">{s}</Badge>)
            ) : (
              <span className="text-[12px] text-fg-3">none</span>
            )}
          </div>
        </Section>

        <Section title="Behaviour vs. population baseline">
          <ZScoreBars zscores={alert.zscores} features={alert.features} />
        </Section>

        {alert.actions?.length > 0 && (
          <Section title="Recommended response">
            <ul className="space-y-1.5">
              {alert.actions.map((a, i) => (
                <li key={i} className="rounded-md border border-line bg-bg-2 px-3 py-2">
                  <div className="flex items-center gap-2">
                    <Badge variant={a.priority === 'p0' ? 'critical' : a.priority === 'p1' ? 'high' : 'neutral'}>{a.priority}</Badge>
                    <span className="text-[12.5px] font-medium text-fg-0">{titleCase(a.action_type)}</span>
                    <span className="font-mono text-[11px] text-fg-3 ml-auto truncate">{a.target}</span>
                  </div>
                  <p className="mt-1 text-[11.5px] text-fg-2">{a.reason}</p>
                </li>
              ))}
            </ul>
          </Section>
        )}

        <Section title="Analyst notes">
          <textarea
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            onBlur={() => notes !== (alert.notes ?? '') && set({ notes }, 'notes')}
            placeholder="Add triage notes…"
            rows={3}
            className="w-full rounded-md border border-line bg-bg-0 px-2.5 py-2 text-[12.5px] text-fg-0 placeholder:text-fg-3 focus-ring resize-y"
          />
        </Section>

        {alert.sample_message && (
          <Section title="Sample event">
            <code className="block rounded-md border border-line bg-bg-0 px-2.5 py-2 font-mono text-[11.5px] text-fg-1 break-all">
              {alert.sample_message}
            </code>
          </Section>
        )}
      </div>
    </Drawer>
  );
}

function Field({ label, children }) {
  return (
    <div>
      <div className="text-[10.5px] uppercase tracking-[0.06em] text-fg-3">{label}</div>
      <div className="mt-0.5 text-fg-1">{children}</div>
    </div>
  );
}

function Section({ title, children }) {
  return (
    <section>
      <h4 className="text-[11px] uppercase tracking-[0.06em] text-fg-3 mb-2">{title}</h4>
      {children}
    </section>
  );
}
