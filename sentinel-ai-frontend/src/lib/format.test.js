import { describe, expect, it } from 'vitest';
import { fmtAgo, fmtNum, fmtPct, severityRank, titleCase } from './format';

describe('format', () => {
  it('buckets fmtAgo', () => {
    const now = Date.parse('2026-01-01T00:10:00Z');
    expect(fmtAgo('2026-01-01T00:09:50Z', now)).toBe('10s');
    expect(fmtAgo('2026-01-01T00:05:00Z', now)).toBe('5m');
    expect(fmtAgo('2025-12-31T22:10:00Z', now)).toBe('2h');
    expect(fmtAgo('2025-12-30T00:10:00Z', now)).toBe('2d');
    expect(fmtAgo(null, now)).toBe('');
  });
  it('ranks severities critical first', () => {
    expect(severityRank('critical')).toBeLessThan(severityRank('high'));
    expect(severityRank('low')).toBeLessThan(severityRank('info'));
    expect(severityRank('bogus')).toBe(5);
  });
  it('formats numbers and percents', () => {
    expect(fmtNum(999)).toBe('999');
    expect(fmtNum(1500)).toBe('1.5k');
    expect(fmtNum(2_000_000)).toBe('2.0M');
    expect(fmtNum(null)).toBe('—');
    expect(fmtPct(0.5)).toBe('50%');
    expect(fmtPct(0.997)).toBe('99.7%');
  });
  it('title-cases snake case', () => {
    expect(titleCase('credential_stuffing')).toBe('Credential Stuffing');
  });
});
