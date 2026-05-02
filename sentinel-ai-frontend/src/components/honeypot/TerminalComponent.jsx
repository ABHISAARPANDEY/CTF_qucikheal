import { useMemo } from 'react';
import Terminal from '../scenarios/Terminal';
import { buildHoneypotScript } from './honeypotIntel';



















export default function TerminalComponent({
  runId,
  attackType,
  attackerIp,
  scenarioEvents = [],
  honeypotActivities = [],
  honeypotAnalyses = []
}) {
  const script = useMemo(
    () =>
    buildHoneypotScript(
      attackType,
      attackerIp,
      scenarioEvents,
      honeypotActivities,
      honeypotAnalyses
    ),
    [attackType, attackerIp, scenarioEvents, honeypotActivities, honeypotAnalyses]
  );

  return <Terminal script={script} runId={runId} />;
}