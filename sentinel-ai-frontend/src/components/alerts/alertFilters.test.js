import { describe, expect, it } from 'vitest';
import { applyFilters, sortAlerts } from './alertFilters';

const A = [
  { id: '1', severity: 'high', status: 'new', threat_type: 'port_scan', entity: { type: 'ip', key: '1.1.1.1' }, risk: 6, count: 2, last_seen: '2026-01-01T00:00:02Z', signals: ['port_scan'], mitre: ['T1046'] },
  { id: '2', severity: 'critical', status: 'acknowledged', threat_type: 'credential_stuffing', entity: { type: 'campaign', key: 'c1' }, risk: 9, count: 40, last_seen: '2026-01-01T00:00:05Z', signals: [], mitre: ['T1110.004'] },
  { id: '3', severity: 'medium', status: 'new', threat_type: 'brute_force', entity: { type: 'user', key: 'cfo@bank' }, risk: 5, count: 4, last_seen: '2026-01-01T00:00:01Z', signals: ['low_slow_brute'], mitre: [] }
];

describe('alertFilters', () => {
  it('filters by severity set', () => {
    expect(applyFilters(A, { severity: new Set(['critical']) }).map((a) => a.id)).toEqual(['2']);
  });
  it('filters by status and entity type', () => {
    expect(applyFilters(A, { status: new Set(['new']) }).map((a) => a.id)).toEqual(['1', '3']);
    expect(applyFilters(A, { entityType: new Set(['campaign']) }).map((a) => a.id)).toEqual(['2']);
  });
  it('free-text searches type, entity, signals, mitre', () => {
    expect(applyFilters(A, { q: 'T1046' }).map((a) => a.id)).toEqual(['1']);
    expect(applyFilters(A, { q: 'cfo' }).map((a) => a.id)).toEqual(['3']);
  });
  it('empty filters pass everything', () => {
    expect(applyFilters(A, {}).length).toBe(3);
  });
  it('sorts severity most-severe first on desc', () => {
    expect(sortAlerts(A, 'severity', 'desc').map((a) => a.id)).toEqual(['2', '1', '3']);
  });
  it('sorts risk and count', () => {
    expect(sortAlerts(A, 'risk', 'desc')[0].id).toBe('2');
    expect(sortAlerts(A, 'count', 'asc')[0].id).toBe('1');
  });
});
