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
