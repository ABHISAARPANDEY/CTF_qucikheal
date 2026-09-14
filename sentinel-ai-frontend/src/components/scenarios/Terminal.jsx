import { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';













const CHAR_DELAY_MS = 14;
const LINE_DELAY_MS = 200;

const DEFAULT_IDLE = [
'# tail -f /var/log/honeypot/session.log',
'sentinel-honeypot: decoy mesh armed, 14 sensors reporting',
'sentinel-honeypot: no active session — launch a scenario to engage decoys',
'sentinel-honeypot: all egress routed to observation plane (0.0.0.0/0 -> sinkhole)'];


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
      className="relative h-full w-full overflow-hidden rounded-lg border border-line bg-bg-sunken"




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
      <div className="relative flex items-center gap-2 px-4 h-9 border-b border-line bg-bg-2">
        <span className="h-2.5 w-2.5 rounded-full bg-sev-critical/70" />
        <span className="h-2.5 w-2.5 rounded-full bg-sev-medium/70" />
        <span className="h-2.5 w-2.5 rounded-full bg-sev-low/70" />
        <span className="ml-3 font-mono text-[11px] text-fg-2">soc@sentinel</span>
        <span className="hidden sm:inline font-mono text-[10px] text-fg-3 ml-2 px-1.5 py-0.5 rounded border border-line">
          decoy capture
        </span>
        <span className="ml-auto font-mono text-[10px] text-fg-3">/var/log/honeypot</span>
      </div>

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
    <div className={`font-mono text-[12px] leading-[1.6] whitespace-pre-wrap break-words ${tone}`}>

      {empty ? <span className="opacity-0">.</span> : text}
      {cursor &&
      <span
        aria-hidden
        className="inline-block w-[0.5em] h-[1.05em] ml-[2px] align-text-bottom bg-accent animate-[blink_1.05s_step-end_infinite]" />






      }
    </div>);

}

function lineTone(line) {
  if (!line) return 'text-fg-1';
  // section headers and comments
  if (line.startsWith('#') || line.startsWith('>>>')) return 'text-fg-3';
  // the attacker's own shell input:  root@edge-gw-02:~# cmd   or   $ cmd
  if (/^\S+@\S+[:~][^ ]*[#$]/.test(line) || line.startsWith('$ ')) return 'text-accent-hover font-medium';
  // syslog severity keywords
  if (/\b(CRIT|CRITICAL|ALERT|FATAL|EMERG)\b/.test(line)) return 'text-sev-critical font-medium';
  if (/\b(ERR|ERROR|FAIL|FAILED|DENIED|REFUSED)\b/.test(line)) return 'text-sev-critical';
  if (/\b(WARN|WARNING)\b/.test(line)) return 'text-sev-high';
  if (/\b(NOTICE|ACCEPTED|CONTAINED|RESOLVED|BLOCKED|OK)\b/.test(line)) return 'text-sev-low';
  if (/\b(INFO|DEBUG)\b/.test(line)) return 'text-fg-2';
  // legacy bracket prefixes still supported
  if (line.startsWith('[+]') || line.startsWith('[✓]')) return 'text-sev-low';
  if (line.startsWith('[!]') || line.startsWith('[✗]')) return 'text-sev-critical';
  if (line.startsWith('[~]')) return 'text-sev-high';
  if (line.startsWith('[*]')) return 'text-fg-2';
  return 'text-fg-1';
}