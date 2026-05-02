import { useEffect, useRef, useState } from 'react';
import { useRealtime } from './useRealtime';
import { selectThreat } from './selectors';

































const SEVERITY_INTENSITY = {
  critical: 1.00,
  high: 0.75,
  medium: 0.40,
  low: 0.15,
  info: 0.00
};


const SEVERITY_TONE = {
  critical: '#ff3b3b',
  high: '#ff3b3b',
  medium: '#ff9f1c',
  low: '#00ff9f',
  info: null
};


const FLASH_SEVERITIES = new Set(['critical', 'high', 'medium']);


const PULSE_SEVERITIES = new Set(['critical', 'high']);





const FLASH_THROTTLE_MS = 1500;

export function useThreatReaction() {
  const threat = useRealtime(selectThreat);
  const severity = threat?.severity ?? null;




  const [flashKey, setFlashKey] = useState(-1);


  const lastFlashTimeRef = useRef(0);
  const lastTriggeredIdRef = useRef(null);

  useEffect(() => {
    if (!threat) return;
    if (threat.id === lastTriggeredIdRef.current) return;
    lastTriggeredIdRef.current = threat.id;

    if (!FLASH_SEVERITIES.has(severity)) return;

    const now = Date.now();
    if (now - lastFlashTimeRef.current < FLASH_THROTTLE_MS) return;
    lastFlashTimeRef.current = now;

    setFlashKey((k) => k < 0 ? 0 : k + 1);
  }, [threat, severity]);

  const intensity = SEVERITY_INTENSITY[severity] ?? 0;

  return {
    severity,
    intensity,
    glowMultiplier: 1 + intensity * 0.5,
    isPulsing: PULSE_SEVERITIES.has(severity),
    flashKey,
    flashTone: SEVERITY_TONE[severity] ?? null
  };
}