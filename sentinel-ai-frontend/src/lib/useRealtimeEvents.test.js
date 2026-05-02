import { describe, expect, it } from 'vitest';
import {
  honeypotActivityKey,
  honeypotAnalysisKey,
  prependUnique,
  scenarioEventKey } from
'./useRealtimeEvents';

describe('realtime event dedupe helpers', () => {
  it('deduplicates scenario events by stable key', () => {
    const evt = {
      type: 'scenario_event',
      run_id: 'run-1',
      stage: 2,
      total_stages: 5,
      system: 'api_gateway',
      severity: 'high',
      label: 'Lateral movement',
      ts: '2026-05-02T10:00:00.000Z'
    };
    const keyOf = scenarioEventKey;

    const once = prependUnique([], evt, keyOf, 10);
    const twice = prependUnique(once, { ...evt }, keyOf, 10);

    expect(once).toHaveLength(1);
    expect(twice).toHaveLength(1);
  });

  it('keeps newest-first order while deduplicating honeypot activities', () => {
    const a1 = {
      run_id: 'run-x',
      step: 1,
      total_steps: 3,
      ts: '2026-05-02T10:00:00.000Z',
      data: { action: 'scanning' }
    };
    const a2 = {
      run_id: 'run-x',
      step: 2,
      total_steps: 3,
      ts: '2026-05-02T10:00:01.000Z',
      data: { action: 'credential_dump' }
    };

    const first = prependUnique([], a1, honeypotActivityKey, 10);
    const second = prependUnique(first, a2, honeypotActivityKey, 10);
    const duplicateSecond = prependUnique(second, { ...a2 }, honeypotActivityKey, 10);

    expect(second.map((x) => x.step)).toEqual([2, 1]);
    expect(duplicateSecond.map((x) => x.step)).toEqual([2, 1]);
  });

  it('enforces buffer cap for honeypot analyses', () => {
    const entries = Array.from({ length: 5 }, (_, i) => ({
      run_id: 'run-buf',
      step: i + 1,
      total_steps: 5,
      ts: `2026-05-02T10:00:0${i}.000Z`,
      data: { pattern: `pattern-${i + 1}`, risk: 'low' }
    }));

    let out = [];
    for (const e of entries) {
      out = prependUnique(out, e, honeypotAnalysisKey, 3);
    }

    expect(out).toHaveLength(3);
    expect(out[0].step).toBe(5);
    expect(out[2].step).toBe(3);
  });
});