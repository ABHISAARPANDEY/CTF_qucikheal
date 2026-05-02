import { useMemo } from 'react';
import { Download, FileText } from 'lucide-react';
import { useRealtime } from '../../lib/useRealtime';
import {
  selectActions,
  selectEvents,
  selectHoneypotActivities,
  selectHoneypotAnalyses,
  selectScenarioEvents,
  selectSystemUpdates,
  selectThreat
} from '../../lib/selectors';

function downloadJson(name, data) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function downloadCsv(name, rows) {
  const csv = rows.map((r) => r.map((v) => `"${String(v ?? '').replaceAll('"', '""')}"`).join(',')).join('\n');
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export default function ReportsPage() {
  const events = useRealtime(selectEvents);
  const threat = useRealtime(selectThreat);
  const actions = useRealtime(selectActions);
  const scenarioEvents = useRealtime(selectScenarioEvents);
  const honeypotActivities = useRealtime(selectHoneypotActivities);
  const honeypotAnalyses = useRealtime(selectHoneypotAnalyses);
  const systemUpdates = useRealtime(selectSystemUpdates);

  const summary = useMemo(() => {
    const systems = Object.values(systemUpdates ?? {});
    const criticalSystems = systems.filter((s) => s?.data?.status === 'critical').length;
    const warningSystems = systems.filter((s) => s?.data?.status === 'warning').length;
    return {
      events: events.length,
      actions: actions.length,
      scenarioEvents: scenarioEvents.length,
      honeypotActivities: honeypotActivities.length,
      honeypotAnalyses: honeypotAnalyses.length,
      criticalSystems,
      warningSystems
    };
  }, [events, actions, scenarioEvents, honeypotActivities, honeypotAnalyses, systemUpdates]);

  const incident = useMemo(
    () => ({
      generated_at: new Date().toISOString(),
      threat,
      summary,
      timeline: [...scenarioEvents].reverse(),
      systems: systemUpdates,
      actions,
      honeypot: {
        activity: [...honeypotActivities].reverse(),
        analysis: [...honeypotAnalyses].reverse()
      }
    }),
    [threat, summary, scenarioEvents, systemUpdates, actions, honeypotActivities, honeypotAnalyses]
  );

  const csvRows = useMemo(() => {
    const header = ['timestamp', 'kind', 'severity', 'label', 'system', 'risk'];
    const body = [...scenarioEvents]
      .reverse()
      .map((e) => [e.ts ?? '', 'scenario_event', e.severity ?? '', e.label ?? '', e.system ?? '', '']);
    const hp = [...honeypotAnalyses]
      .reverse()
      .map((e) => [e.ts ?? '', 'honeypot_analysis', e.data?.risk ?? '', e.data?.pattern ?? '', '', e.data?.risk ?? '']);
    return [header, ...body, ...hp];
  }, [scenarioEvents, honeypotAnalyses]);

  return (
    <div className="flex-1 min-h-0 flex flex-col p-3 gap-3 overflow-hidden">
      <header className="shrink-0 flex items-start justify-between gap-3 px-1">
        <div className="flex items-center gap-3 min-w-0">
          <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-bg-elevated/70 border border-neon-violet/25 text-neon-violet shadow-[0_0_18px_-8px_rgba(167,139,250,0.5)]">
            <FileText className="h-5 w-5" />
          </span>
          <div className="min-w-0">
            <h1 className="font-mono text-[11px] font-medium uppercase tracking-[0.22em] text-fg-secondary">Reports</h1>
            <p className="text-[14px] text-fg-primary leading-snug">Live incident summary, timeline and exports.</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => downloadJson(`incident-${Date.now()}.json`, incident)}
            className="inline-flex items-center gap-2 rounded-lg border h-[34px] px-3 border-neon-cyan/40 bg-neon-cyan/[0.08] text-neon-cyan font-mono text-[11px] uppercase tracking-[0.22em]"
          >
            <Download className="h-3.5 w-3.5" />
            export json
          </button>
          <button
            type="button"
            onClick={() => downloadCsv(`timeline-${Date.now()}.csv`, csvRows)}
            className="inline-flex items-center gap-2 rounded-lg border h-[34px] px-3 border-neon-green/40 bg-neon-green/[0.08] text-neon-green font-mono text-[11px] uppercase tracking-[0.22em]"
          >
            <Download className="h-3.5 w-3.5" />
            export csv
          </button>
        </div>
      </header>

      <section className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <Metric label="events" value={summary.events} tone="cyan" />
        <Metric label="actions" value={summary.actions} tone="green" />
        <Metric label="critical systems" value={summary.criticalSystems} tone="red" />
        <Metric label="honeypot findings" value={summary.honeypotAnalyses} tone="violet" />
      </section>

      <section className="flex-1 min-h-0 rounded-2xl border border-border-subtle glass-panel p-3 overflow-y-auto scrollbar-cyber">
        <h2 className="font-mono text-[10px] uppercase tracking-[0.22em] text-fg-faint mb-2">incident timeline</h2>
        <ul className="space-y-1.5">
          {[...scenarioEvents].reverse().slice(-80).map((evt, idx) => (
            <li key={`${evt.run_id}-${evt.stage}-${evt.ts}-${idx}`} className="rounded-md border border-border-subtle bg-bg-sunken/40 px-2.5 py-1.5">
              <div className="flex items-center gap-2 text-[11px]">
                <span className="font-mono text-fg-faint">{evt.ts ?? '—'}</span>
                <span className="font-mono uppercase tracking-[0.2em] text-fg-secondary">{evt.severity}</span>
                <span className="text-fg-primary">{evt.label}</span>
              </div>
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}

function Metric({ label, value, tone }) {
  const cls =
    tone === 'red'
      ? 'border-neon-red/35 text-neon-red bg-neon-red/[0.07]'
      : tone === 'green'
      ? 'border-neon-green/35 text-neon-green bg-neon-green/[0.07]'
      : tone === 'violet'
      ? 'border-neon-violet/35 text-neon-violet bg-neon-violet/[0.07]'
      : 'border-neon-cyan/35 text-neon-cyan bg-neon-cyan/[0.07]';
  return (
    <div className={`rounded-xl border px-3 py-2 ${cls}`}>
      <div className="font-mono text-[9px] uppercase tracking-[0.22em] opacity-80">{label}</div>
      <div className="font-mono text-[22px] leading-none mt-1">{value}</div>
    </div>
  );
}
