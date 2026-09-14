import { useEffect, useMemo, useState } from 'react';
import { RotateCcw, Save, Trash2, Zap } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '../ui/card';
import { Button } from '../ui/button';
import { Slider } from '../ui/slider';
import { getThresholds, putThresholds, resetThresholds, detectionRetrain, trafficConfig, listSignatures, clearSignatures } from '../../lib/api';
import { titleCase } from '../../lib/format';
import { useRealtime } from '../../lib/useRealtime';
import { selectEventsMeta, selectStats } from '../../lib/selectors';

const GROUPS = [
  { title: 'Alerting', fields: [
    ['alert_min_risk', 0, 10, 0.1, 'Minimum risk to raise an alert'],
    ['dedupe_window_s', 1, 600, 1, 'Dedup window (s) — same entity+type collapses']
  ]},
  { title: 'Severity cut points (risk → severity)', fields: [
    ['sev_critical', 0, 10, 0.1], ['sev_high', 0, 10, 0.1], ['sev_medium', 0, 10, 0.1], ['sev_low', 0, 10, 0.1]
  ]},
  { title: 'Decision tiers', fields: [
    ['high_risk', 0, 10, 0.1], ['low_risk', 0, 10, 0.1], ['high_confidence', 0, 1, 0.05], ['low_confidence', 0, 1, 0.05]
  ]},
  { title: 'Port scan', fields: [['port_scan_min_ports', 2, 200, 1], ['port_scan_seq', 0, 1, 0.05]] },
  { title: 'Credential stuffing', fields: [['stuffing_min_users', 2, 100, 1], ['stuffing_fail_ratio', 0, 1, 0.05]] },
  { title: 'Low & slow brute force', fields: [['lowslow_min_ips', 2, 100, 1], ['lowslow_fail_ratio', 0, 1, 0.05], ['lowslow_min_gap_s', 0, 120, 1]] },
  { title: 'Behavioural baseline', fields: [['zscore_fire', 0, 10, 0.1], ['zscore_max', 0.1, 12, 0.1], ['baseline_warmup', 1, 500, 1]] },
  { title: 'Distributed campaign', fields: [['campaign_min_ips', 2, 100, 1], ['campaign_min_subnets', 1, 50, 1], ['campaign_min_fail_ratio', 0, 1, 0.05]] },
  { title: 'Isolation forest', fields: [['if_contamination', 0.01, 0.5, 0.01], ['if_retrain_s', 10, 3600, 10]] }
];

const LABELS = {
  alert_min_risk: 'Alert threshold', dedupe_window_s: 'Dedup window',
  sev_critical: 'Critical ≥', sev_high: 'High ≥', sev_medium: 'Medium ≥', sev_low: 'Low ≥',
  high_risk: 'High-tier risk', low_risk: 'Low-tier risk', high_confidence: 'High confidence', low_confidence: 'Low confidence',
  port_scan_min_ports: 'Min distinct ports', port_scan_seq: 'Sequential ratio',
  stuffing_min_users: 'Min distinct users', stuffing_fail_ratio: 'Min fail ratio',
  lowslow_min_ips: 'Min distinct IPs', lowslow_fail_ratio: 'Min fail ratio', lowslow_min_gap_s: 'Min mean gap (s)',
  zscore_fire: 'Fire at |z| ≥', zscore_max: 'Saturate at |z|', baseline_warmup: 'Warm-up samples',
  campaign_min_ips: 'Min IPs', campaign_min_subnets: 'Min /24s', campaign_min_fail_ratio: 'Min fail ratio',
  if_contamination: 'Contamination', if_retrain_s: 'Retrain interval (s)'
};

export default function SettingsPage() {
  const [base, setBase] = useState(null);
  const [draft, setDraft] = useState(null);
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState('');
  const stats = useRealtime(selectStats);
  const meta = useRealtime(selectEventsMeta);
  const [signatures, setSignatures] = useState({ count: 0, signatures: [] });

  const loadSignatures = () => listSignatures().then(setSignatures).catch(() => void 0);
  useEffect(() => {
    loadSignatures();
    const id = setInterval(loadSignatures, 5000);
    return () => clearInterval(id);
  }, []);

  useEffect(() => {
    getThresholds().then((t) => {
      setBase(t);
      setDraft(t);
    }).catch(() => void 0);
  }, []);

  const dirtyKeys = useMemo(() => {
    if (!base || !draft) return new Set();
    return new Set(Object.keys(draft).filter((k) => draft[k] !== base[k]));
  }, [base, draft]);

  const preview = useMemo(() => {
    if (!draft) return null;
    const risks = Object.values(meta).map((m) => m.risk_score).filter((r) => typeof r === 'number');
    if (!risks.length) return null;
    const would = risks.filter((r) => r >= draft.alert_min_risk).length;
    return { would, total: risks.length };
  }, [draft, meta]);

  if (!draft) return <div className="p-6 text-[13px] text-fg-3">Loading thresholds…</div>;

  const set = (k, v) => setDraft((d) => ({ ...d, [k]: v }));

  const apply = async () => {
    setSaving(true);
    setMsg('');
    try {
      const patch = Object.fromEntries([...dirtyKeys].map((k) => [k, draft[k]]));
      const updated = await putThresholds(patch);
      setBase(updated);
      setDraft(updated);
      setMsg('Applied and broadcast to all clients.');
    } catch (e) {
      setMsg(`Rejected: ${e.message}`);
    } finally {
      setSaving(false);
    }
  };

  const reset = async () => {
    const t = await resetThresholds();
    setBase(t);
    setDraft(t);
    setMsg('Reset to defaults.');
  };

  return (
    <div className="flex-1 min-h-0 overflow-y-auto scrollbar-cyber p-3 space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-3 px-1">
        <div>
          <h1 className="text-[15px] font-semibold text-fg-0">Detection thresholds</h1>
          <p className="text-[12px] text-fg-2">Tune the engine at runtime. Changes hot-reload and broadcast to every connected client.</p>
        </div>
        <div className="flex items-center gap-2">
          {preview && (
            <span className="text-[12px] text-fg-2">
              At <span className="font-mono text-fg-0">{draft.alert_min_risk.toFixed(1)}</span>: <span className="font-mono text-accent-hover">{preview.would}</span>/{preview.total} recent events would alert
            </span>
          )}
          <Button variant="outline" size="sm" onClick={() => detectionRetrain().then(() => setMsg('Isolation forest retrained.')).catch(() => void 0)}><Zap className="h-3.5 w-3.5" /> Retrain forest</Button>
          <Button variant="outline" size="sm" onClick={reset}><RotateCcw className="h-3.5 w-3.5" /> Reset</Button>
          <Button variant="default" size="sm" onClick={apply} disabled={saving || dirtyKeys.size === 0}><Save className="h-3.5 w-3.5" /> Apply {dirtyKeys.size ? `(${dirtyKeys.size})` : ''}</Button>
        </div>
      </div>
      {msg && <div className="mx-1 rounded-md border border-line bg-bg-2 px-3 py-1.5 text-[12px] text-fg-1">{msg}</div>}

      <Card>
        <CardHeader>
          <CardTitle>Learned attack signatures</CardTitle>
          <div className="flex items-center gap-2">
            <span className="font-mono text-[11px] text-fg-3">{signatures.count}</span>
            <Button variant="outline" size="xs" onClick={() => clearSignatures().then(loadSignatures).catch(() => void 0)} disabled={!signatures.count}>
              <Trash2 className="h-3 w-3" /> Clear
            </Button>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          {signatures.signatures.length === 0 ? (
            <div className="px-4 py-6 text-center text-[12.5px] text-fg-3">
              No signatures yet — run an attack scenario. Each confirmed detection is distilled into a
              signature so the next occurrence is caught instantly.
            </div>
          ) : (
            <div className="max-h-[280px] overflow-y-auto scrollbar-cyber">
              <table className="w-full text-[12px]">
                <thead className="sticky top-0 bg-bg-1">
                  <tr className="text-fg-3 text-[10.5px] uppercase tracking-[0.06em]">
                    <th className="text-left font-medium px-4 h-8">Threat</th>
                    <th className="text-left font-medium px-2">Indicator</th>
                    <th className="text-right font-medium px-2">Risk</th>
                    <th className="text-right font-medium px-4">Hits</th>
                  </tr>
                </thead>
                <tbody>
                  {signatures.signatures.map((sig) => (
                    <tr key={sig.id} className="border-t border-line">
                      <td className="px-4 h-9 text-fg-0 flex items-center gap-1.5"><Zap className="h-3 w-3 text-accent-hover" />{titleCase(sig.threat_type)}</td>
                      <td className="px-2 font-mono text-fg-1 truncate max-w-[320px]" title={sig.indicator}>{sig.indicator}</td>
                      <td className="px-2 text-right font-mono text-fg-0">{sig.risk?.toFixed(1)}</td>
                      <td className="px-4 text-right font-mono text-fg-2">{sig.hits}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      {stats && (
        <Card>
          <CardHeader><CardTitle>Traffic generator</CardTitle></CardHeader>
          <CardContent className="grid md:grid-cols-3 gap-4">
            <Slider label="Rate (ev/s)" value={stats.target_eps ?? 12} min={1} max={200} step={1} onChange={(v) => trafficConfig({ rate_eps: v }).catch(() => void 0)} />
            <Slider label="Benign ratio" value={stats.benign_ratio ?? 0.9} min={0} max={1} step={0.05} onChange={(v) => trafficConfig({ benign_ratio: v }).catch(() => void 0)} />
            <label className="flex items-center gap-2 text-[13px] text-fg-1 self-end">
              <input type="checkbox" checked={Boolean(stats.paused)} onChange={(e) => trafficConfig({ paused: e.target.checked }).catch(() => void 0)} className="accent-[color:var(--color-accent)]" />
              Pause background traffic
            </label>
          </CardContent>
        </Card>
      )}

      <div className="grid gap-2 md:grid-cols-2 xl:grid-cols-3">
        {GROUPS.map((g) => (
          <Card key={g.title}>
            <CardHeader><CardTitle>{g.title}</CardTitle></CardHeader>
            <CardContent className="space-y-3">
              {g.fields.map(([k, min, max, step]) => (
                <Slider
                  key={k}
                  label={LABELS[k] ?? k}
                  value={draft[k]}
                  min={min}
                  max={max}
                  step={step}
                  dirty={dirtyKeys.has(k)}
                  onChange={(v) => set(k, v)}
                />
              ))}
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}
