import { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';













const CHAR_DELAY_MS = 14;
const LINE_DELAY_MS = 200;

const DEFAULT_IDLE = [
'[*] sentinel-cli  v0.4.2 · honey mesh standby',
'[*] adversary shell idle — select a scenario to engage decoys',
'[*] all egress paths terminate in observation plane'];


function normalizeEntry(entry) {
  if (entry != null && typeof entry === 'object' && 'text' in entry) {
    return {
      text: entry.text,
      pauseAfter: entry.pauseAfter ?? LINE_DELAY_MS,
      charDelay: entry.charDelay ?? CHAR_DELAY_MS,
      glitch: !!entry.glitch
    };
  }
  const s = entry ?? '';
  return {
    text: s,
    pauseAfter: LINE_DELAY_MS,
    charDelay: CHAR_DELAY_MS,
    glitch: false
  };
}

export default function Terminal({ script, runId = 'idle', idle = DEFAULT_IDLE }) {
  const active = script && script.length > 0 ? script : idle;
  const normalized = useMemo(() => active.map(normalizeEntry), [active]);

  const [committed, setCommitted] = useState([]);
  const [currentLine, setCurrentLine] = useState(0);
  const [currentChar, setCurrentChar] = useState(0);
  const [glitchPulse, setGlitchPulse] = useState(false);
  const [resetEpoch, setResetEpoch] = useState(0);
  const endRef = useRef(null);

  useEffect(() => {
    const t = setTimeout(() => {
      setCommitted([]);
      setCurrentLine(0);
      setCurrentChar(0);
      setGlitchPulse(false);
      setResetEpoch((n) => n + 1);
    }, 0);
    return () => clearTimeout(t);
  }, [runId]);

  useEffect(() => {
    if (!normalized.length || currentLine >= normalized.length) return;
    const row = normalized[currentLine];
    const line = row.text;

    if (currentChar < line.length) {
      const t = setTimeout(() => setCurrentChar((c) => c + 1), row.charDelay);
      return () => clearTimeout(t);
    }

    const t = setTimeout(() => {
      if (row.glitch) {
        setGlitchPulse(true);
        window.setTimeout(() => setGlitchPulse(false), 520);
      }
      setCommitted((c) => [...c, line]);
      setCurrentLine((l) => l + 1);
      setCurrentChar(0);
    }, row.pauseAfter);
    return () => clearTimeout(t);
  }, [normalized, currentLine, currentChar, resetEpoch]);

  useLayoutEffect(() => {
    endRef.current?.scrollIntoView({ behavior: 'smooth', block: 'end' });
  }, [committed, currentChar, currentLine]);

  const isTyping = normalized.length > 0 && currentLine < normalized.length;
  const partial = isTyping ? (normalized[currentLine]?.text ?? '').slice(0, currentChar) : '';

  return (
    <motion.div
      className="
        relative h-full w-full overflow-hidden rounded-xl
        border border-neon-green/30 bg-black
        shadow-[0_0_44px_-12px_rgba(0,255,159,0.55),0_0_0_1px_rgba(0,255,159,0.08)_inset]
      "




      animate={
      glitchPulse ?
      {
        x: [0, -5, 6, -4, 3, 0],
        rotate: [0, -0.35, 0.4, -0.2, 0]
      } :
      { x: 0, rotate: 0 }
      }
      transition={{ duration: 0.42, ease: 'easeOut' }}>
      
      <AnimatePresence>
        {glitchPulse &&
        <motion.div
          key="chromatic"
          initial={{ opacity: 0 }}
          animate={{ opacity: [0, 0.14, 0.06, 0] }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.45 }}
          className="pointer-events-none absolute inset-0 z-20 mix-blend-screen"
          style={{
            background:
            'linear-gradient(90deg, rgba(255,0,80,0.25) 0%, transparent 35%, transparent 65%, rgba(0,200,255,0.2) 100%)'
          }} />

        }
      </AnimatePresence>

      {}
      <div className="relative flex items-center gap-2 px-4 h-9 border-b border-neon-green/20 bg-black/70">
        <span className="h-2.5 w-2.5 rounded-full bg-red-500/55" />
        <span className="h-2.5 w-2.5 rounded-full bg-yellow-500/55" />
        <span className="h-2.5 w-2.5 rounded-full bg-neon-green/55" />
        <span className="ml-3 font-mono text-[10.5px] uppercase tracking-[0.22em] text-neon-green/70 text-glow-green">
          sentinel:
        </span>
        <span className="hidden sm:inline font-mono text-[9px] uppercase tracking-[0.28em] text-neon-violet/70 ml-2 px-1.5 py-0.5 rounded border border-neon-violet/25 bg-neon-violet/10">
          decoy PoV
        </span>
        <span className="ml-auto font-mono text-[9.5px] tracking-[0.22em] text-neon-green/40">
          ttyHoney0
        </span>
      </div>

      {}
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0 z-10 opacity-[0.065]"
        style={{
          background:
          'repeating-linear-gradient(0deg, rgba(0,255,159,0.55) 0, rgba(0,255,159,0.55) 1px, transparent 1px, transparent 3px)'
        }} />
      

      <motion.div
        aria-hidden
        className="pointer-events-none absolute inset-0 z-10 bg-neon-green/[0.04]"
        animate={
        glitchPulse ?
        { opacity: [0.05, 0.14, 0.06, 0.09] } :
        { opacity: [0.04, 0.065, 0.048, 0.055] }
        }
        transition={
        glitchPulse ? { duration: 0.35 } : { duration: 2.4, repeat: Infinity, ease: 'easeInOut' }
        } />
      

      <div
        aria-hidden
        className="pointer-events-none absolute inset-0 z-10"
        style={{
          background:
          'radial-gradient(ellipse at center, transparent 45%, rgba(0,0,0,0.58) 100%)'
        }} />
      

      {}
      <div className="relative z-0 h-[calc(100%-2.25rem)] overflow-y-auto scrollbar-cyber px-5 py-4 scroll-smooth">
        {committed.map((line, i) =>
        <Line key={`${i}-${line.slice(0, 12)}`} text={line} />
        )}

        {isTyping ?
        <Line text={partial} cursor /> :

        <Line text="" cursor />
        }
        <div ref={endRef} className="h-px w-full shrink-0" aria-hidden />
      </div>
    </motion.div>);

}

function Line({ text, cursor = false }) {
  const tone = lineTone(text);
  const empty = text === '';

  return (
    <div
      className={`font-mono text-[12.5px] leading-[1.58] whitespace-pre-wrap break-words ${tone}`}
      style={{ textShadow: '0 0 6px rgba(0,255,159,0.32)' }}>
      
      {empty ? <span className="opacity-0">.</span> : text}
      {cursor &&
      <span
        aria-hidden
        className="
            inline-block w-[0.55em] h-[1.05em] ml-[2px] align-text-bottom
            bg-neon-green
            shadow-[0_0_10px_rgba(0,255,159,0.88)]
            animate-[blink_1.05s_step-end_infinite]
          " />






      }
    </div>);

}

function lineTone(line) {
  if (!line) return 'text-neon-green/85';
  if (line.startsWith('>>>')) return 'text-neon-cyan font-semibold text-glow-cyan';
  if (line.startsWith('[+]')) return 'text-neon-green text-glow-green';
  if (line.startsWith('[✓]')) return 'text-neon-green text-glow-green';
  if (line.startsWith('[*]')) return 'text-neon-cyan/85';
  if (line.startsWith('[~]')) return 'text-neon-orange/90';
  if (line.startsWith('[!]')) return 'text-neon-red text-glow-red';
  if (line.startsWith('[✗]')) return 'text-neon-red text-glow-red';
  if (line.startsWith('[⚡]')) return 'text-neon-violet';
  if (line.startsWith('[i]')) return 'text-fg-muted';
  return 'text-neon-green/85';
}