import { describe, expect, it } from 'vitest';
import {
  isValidHoneypotActivity,
  isValidHoneypotAnalysis,
  isValidPipelinePayload,
  isValidScenarioEvent,
  isValidSystemUpdate
} from './wsValidators';

describe('wsValidators', () => {
  it('accepts valid scenario event payload', () => {
    expect(
      isValidScenarioEvent({
        type: 'scenario_event',
        scenario: 'ddos',
        run_id: 'ddos-123',
        stage: 1,
        total_stages: 5,
        severity: 'warning',
        ts: '2026-05-02T00:00:00Z'
      })
    ).toBe(true);
  });

  it('rejects malformed system update payload', () => {
    expect(
      isValidSystemUpdate({
        type: 'system_update',
        system: 'api_gateway',
        data: { cpu: '90' }
      })
    ).toBe(false);
  });

  it('accepts honeypot activity and analysis contracts', () => {
    expect(
      isValidHoneypotActivity({
        type: 'honeypot_activity',
        run_id: 'run-1',
        attack_type: 'multi_stage',
        step: 1,
        total_steps: 4,
        ts: '2026-05-02T00:00:00Z',
        data: { action: 'scanning' }
      })
    ).toBe(true);
    expect(
      isValidHoneypotAnalysis({
        type: 'honeypot_analysis',
        run_id: 'run-1',
        attack_type: 'multi_stage',
        step: 1,
        total_steps: 4,
        ts: '2026-05-02T00:00:00Z',
        data: { pattern: 'surface mapping', risk: 'low' }
      })
    ).toBe(true);
  });

  it('recognizes pipeline payload marker fields', () => {
    expect(isValidPipelinePayload({ threat: { id: 'x' } })).toBe(true);
    expect(isValidPipelinePayload({ type: 'scenario_event' })).toBe(false);
  });
});

import { isValidAlertFrame, isValidConfigFrame, isValidStatsFrame } from './wsValidators';

describe('new frame validators', () => {
  it('accepts alert frames and rejects malformed ones', () => {
    const good = { type: 'alert_new', alert: { id: 'a', threat_type: 'port_scan', severity: 'high', risk: 6.1, entity: { type: 'ip', key: '1.1.1.1' } } };
    expect(isValidAlertFrame(good)).toBe(true);
    expect(isValidAlertFrame({ ...good, type: 'alert_update' })).toBe(true);
    expect(isValidAlertFrame({ type: 'alert_new', alert: { id: 'a' } })).toBe(false);
    expect(isValidAlertFrame({ type: 'stats' })).toBe(false);
  });
  it('accepts stats and config frames', () => {
    expect(isValidStatsFrame({ type: 'stats', data: { events_ingested: 3 } })).toBe(true);
    expect(isValidStatsFrame({ type: 'stats', data: {} })).toBe(false);
    expect(isValidConfigFrame({ type: 'config_update', thresholds: { alert_min_risk: 4 } })).toBe(true);
    expect(isValidConfigFrame({ type: 'config_update' })).toBe(false);
  });
});
