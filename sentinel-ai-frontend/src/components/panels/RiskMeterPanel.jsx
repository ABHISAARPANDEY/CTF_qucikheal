import { useEffect, useRef, useState } from 'react';
import { motion, useMotionValue, animate } from 'framer-motion';
import { Gauge, TrendingDown, TrendingUp } from 'lucide-react';
import PanelCard from '../PanelCard';
import { Badge } from '../ui/badge';
import { useRealtime } from '../../lib/useRealtime';
import { selectRiskScore } from '../../lib/selectors';





















const ACCENT_HEX = {
  green: '#00ff9f',
  blue: '#3b82f6',
  orange: '#ff9f1c',
  red: '#ff3b3b'
};

const PULSE_THRESHOLD = 7;


function toneFor(score) {
  if (score >= PULSE_THRESHOLD) return { hex: ACCENT_HEX.red, label: 'CRITICAL', accent: 'red' };
  if (score >= 5) return { hex: ACCENT_HEX.orange, label: 'ELEVATED', accent: 'orange' };
  if (score >= 2.5) return { hex: ACCENT_HEX.blue, label: 'MODERATE', accent: 'blue' };
  return { hex: ACCENT_HEX.green, label: 'NOMINAL', accent: 'green' };
}

export default function RiskMeterPanel() {

  const score = useRealtime(selectRiskScore) ?? 0;




  const prevRef = useRef(0);
  const [delta, setDelta] = useState(0);




  const motionValue = useMotionValue(0);
  const [shown, setShown] = useState(0);

  useEffect(() => {
    const prev = prevRef.current;
    setDelta(score - prev);
    prevRef.current = score;

    const isDropping = score < prev;
    const controls = animate(motionValue, score, {

      duration: isDropping ? 1.2 : 0.55,
      ease: isDropping ? [0.4, 0.0, 0.2, 1] : [0.2, 0.7, 0.2, 1]
    });
    return () => controls.stop();
  }, [score, motionValue]);

  useEffect(() => motionValue.on('change', (v) => setShown(v)), [motionValue]);

  const tone = toneFor(score);
  const pct = Math.max(0, Math.min(1, score / 10));
  const isCritical = score >= PULSE_THRESHOLD;


  const radius = 92;
  const stroke = 14;
  const circ = Math.PI * radius;
  const dash = pct * circ;


  const trendActive = Math.abs(delta) >= 0.5;
  const trendUp = delta > 0;
  const TrendIcon = trendUp ? TrendingUp : TrendingDown;
  const trendVariant = trendUp ? 'warning' : 'success';

  return (
    <PanelCard
      title="System Risk Level"
      subtitle={isCritical ? 'Threshold exceeded' : 'Live aggregate score'}
      accent={tone.accent}
      icon={<Gauge className="h-4 w-4" />}
      actions={
      <Badge variant={trendVariant} glow={trendActive}>
          <TrendIcon className="h-3 w-3" />
          <span className={trendActive ? 'font-semibold' : 'font-medium'}>
            {delta >= 0 ? '+' : ''}{delta.toFixed(1)} pts
          </span>
        </Badge>
      }>
      
      <div className="flex h-full flex-col items-center justify-center">
        <div className="relative w-full max-w-[300px]">
          {}
          {isCritical &&
          <>
              <motion.span
              aria-hidden
              animate={{ opacity: [0.35, 0.7, 0.35], scale: [1, 1.12, 1] }}
              transition={{ duration: 1.6, repeat: Infinity, ease: 'easeInOut' }}
              className="absolute inset-0 rounded-full blur-3xl pointer-events-none"
              style={{ backgroundColor: tone.hex }} />
            
              <motion.span
              aria-hidden
              animate={{ scale: [1, 1.35], opacity: [0.45, 0] }}
              transition={{ duration: 1.6, repeat: Infinity, ease: 'easeOut' }}
              className="absolute top-2 left-1/2 -translate-x-1/2 h-32 w-56 rounded-[100%] pointer-events-none"
              style={{ boxShadow: `0 0 0 2px ${tone.hex}55` }} />
            
            </>
          }

          {}
          {!isCritical &&
          <motion.span
            aria-hidden
            animate={{ opacity: [0.18, 0.32, 0.18] }}
            transition={{ duration: 2.6, repeat: Infinity, ease: 'easeInOut' }}
            className="absolute top-2 left-1/2 -translate-x-1/2 h-32 w-56 rounded-[100%] blur-3xl pointer-events-none"
            style={{ backgroundColor: tone.hex }} />

          }

          {}
          <svg
            viewBox="0 0 220 130"
            className="relative w-full"
            role="img"
            aria-label={`System risk level ${score.toFixed(1)} of 10`}>
            
            <defs>
              <linearGradient id="risk-grad" x1="0" x2="1">
                <stop offset="0%" stopColor={ACCENT_HEX.green} />
                <stop offset="50%" stopColor={ACCENT_HEX.orange} />
                <stop offset="100%" stopColor={ACCENT_HEX.red} />
              </linearGradient>
              <filter id="risk-glow" x="-20%" y="-20%" width="140%" height="140%">
                <feGaussianBlur stdDeviation={isCritical ? 4 : 2} result="b" />
                <feMerge>
                  <feMergeNode in="b" />
                  <feMergeNode in="SourceGraphic" />
                </feMerge>
              </filter>
            </defs>

            {}
            <path
              d="M18 110 A92 92 0 0 1 202 110"
              fill="none"
              stroke="rgba(255,255,255,0.06)"
              strokeWidth={stroke}
              strokeLinecap="round" />
            

            {}
            {Array.from({ length: 11 }).map((_, i) => {
              const angle = Math.PI - i / 10 * Math.PI;
              const x1 = 110 + Math.cos(angle) * (radius + 12);
              const y1 = 110 - Math.sin(angle) * (radius + 12);
              const x2 = 110 + Math.cos(angle) * (radius + 4);
              const y2 = 110 - Math.sin(angle) * (radius + 4);
              return (
                <line
                  key={i}
                  x1={x1} y1={y1} x2={x2} y2={y2}
                  stroke="rgba(255,255,255,0.18)"
                  strokeWidth={i % 5 === 0 ? 1.5 : 1} />);


            })}

            {
            }
            <motion.path
              d="M18 110 A92 92 0 0 1 202 110"
              fill="none"
              stroke="url(#risk-grad)"
              strokeWidth={stroke}
              strokeLinecap="round"
              strokeDasharray={circ}
              animate={{ strokeDashoffset: circ - dash }}
              transition={{
                duration: delta < 0 ? 1.0 : 0.55,
                ease: [0.2, 0.7, 0.2, 1]
              }}
              filter="url(#risk-glow)" />
            
          </svg>

          {}
          <div className="absolute inset-x-0 top-9 flex flex-col items-center pointer-events-none">
            <motion.div
              className="font-mono text-[44px] leading-none tabular-nums font-semibold"
              style={{
                color: tone.hex,
                textShadow: isCritical ?
                `0 0 28px ${tone.hex}, 0 0 8px ${tone.hex}` :
                `0 0 16px ${tone.hex}88`
              }}
              animate={isCritical ? { scale: [1, 1.05, 1] } : { scale: 1 }}
              transition={{
                duration: 1.6,
                repeat: isCritical ? Infinity : 0,
                ease: 'easeInOut'
              }}>
              
              {shown.toFixed(1)}
            </motion.div>
            <div
              className="mt-1.5 font-mono text-[10.5px] uppercase tracking-[0.28em] font-medium"
              style={{ color: tone.hex }}>
              
              {tone.label}
            </div>
            <div className="mt-0.5 font-mono text-[9px] uppercase tracking-[0.22em] text-fg-faint">
              of 10.0
            </div>
          </div>
        </div>
      </div>
    </PanelCard>);

}