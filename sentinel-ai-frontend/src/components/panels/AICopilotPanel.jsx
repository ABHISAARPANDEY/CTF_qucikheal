import { useEffect, useRef, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Bot, Send, Sparkles } from 'lucide-react';
import { Card } from '../ui/card';
import { Button } from '../ui/button';
import { bus, EVENTS } from '../../lib/eventBus';
import { copilotChat } from '../../lib/api';
import { useRealtime } from '../../lib/useRealtime';
import { selectExplanation } from '../../lib/selectors';

const SEED = [
  {
    id: 1,
    role: 'ai',
    text:
      'SentinelAI online. Streaming live pipeline events — I summarize each ' +
      'detection as it arrives and propose response actions.',
    reasoning: 'WebSocket /ws/live attached. Awaiting first detection.',
    ts: '—'
  }
];

const SUGGESTIONS = [
  'Summarize the last 5 critical alerts',
  'What action would you take on the latest threat?',
  'Draft an incident report'
];

const TYPING_MS = 900;
const MAX_MESSAGES = 50;
const MAX_QUEUE = 5;

const fmtTime = (iso) => {
  const d = iso ? new Date(iso) : new Date();
  return d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });
};

let nextId = 1000;

function buildAiMessage(explanation) {
  const reasoningParts = [];
  if (explanation?.why_flagged) reasoningParts.push(explanation.why_flagged);
  if (explanation?.actions_taken) reasoningParts.push(explanation.actions_taken);
  return {
    id: ++nextId,
    role: 'ai',
    text: explanation?.summary ?? 'Detection completed.',
    reasoning: reasoningParts.join('  '),
    ts: fmtTime(explanation?.generated_at)
  };
}

function buildSystemBanner(label) {
  return { id: ++nextId, role: 'system', text: `Sim launched: ${label}`, ts: fmtTime() };
}

export default function AICopilotPanel() {
  const explanation = useRealtime(selectExplanation);
  const [messages, setMessages] = useState(SEED);
  const [queue, setQueue] = useState([]);
  const [thinking, setThinking] = useState(false);
  const [input, setInput] = useState('');
  const lastSeenRef = useRef(null);
  const scrollRef = useRef(null);

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: 'smooth' });
  }, [messages, thinking]);

  useEffect(() => {
    if (!explanation || lastSeenRef.current === explanation) return;
    lastSeenRef.current = explanation;
    setQueue((q) => [...q, explanation].slice(-MAX_QUEUE));
  }, [explanation]);

  useEffect(() => {
    if (thinking || queue.length === 0) return;
    const start = setTimeout(() => setThinking(true), 0);
    const timer = setTimeout(() => {
      const next = queue[0];
      setMessages((m) => [...m, buildAiMessage(next)].slice(-MAX_MESSAGES));
      setQueue((q) => q.slice(1));
      setThinking(false);
    }, TYPING_MS);
    return () => {
      clearTimeout(start);
      clearTimeout(timer);
    };
  }, [thinking, queue]);

  useEffect(() => bus.on(EVENTS.SIMULATE_REQUEST, (sim) => {
    setMessages((m) => [...m, buildSystemBanner(sim.short)].slice(-MAX_MESSAGES));
  }), []);

  const send = async (text) => {
    const value = (text ?? input).trim();
    if (!value) return;
    setMessages((m) => [...m, { id: ++nextId, role: 'user', text: value, ts: fmtTime() }].slice(-MAX_MESSAGES));
    setInput('');
    setThinking(true);
    try {
      const resp = await copilotChat(value);
      setMessages((m) =>
        [...m, { id: ++nextId, role: 'ai', text: resp.answer ?? 'No response returned.', reasoning: 'Backend copilot provider.', ts: fmtTime() }].slice(-MAX_MESSAGES)
      );
    } catch (err) {
      setMessages((m) =>
        [...m, { id: ++nextId, role: 'ai', text: `Copilot unavailable: ${err?.message ?? 'request failed'}`, reasoning: '', ts: fmtTime() }].slice(-MAX_MESSAGES)
      );
    } finally {
      setThinking(false);
    }
  };

  return (
    <Card className="h-full min-h-0 overflow-hidden">
      <header className="flex items-center gap-2.5 px-4 h-11 border-b border-line shrink-0">
        <span className="flex h-7 w-7 items-center justify-center rounded-md bg-accent-soft text-accent-hover">
          <Bot className="h-4 w-4" />
        </span>
        <div className="min-w-0 flex-1">
          <div className="text-[13px] font-semibold text-fg-0 leading-tight">AI Copilot</div>
          <div className="text-[11px] text-fg-2 leading-tight">Live explanations &amp; reasoning</div>
        </div>
        <span className="inline-flex items-center gap-1 rounded-md border border-line px-1.5 h-5 font-mono text-[10px] text-fg-2">
          <Sparkles className="h-3 w-3 text-accent-hover" /> Sentinel-7
        </span>
      </header>

      <div ref={scrollRef} className="flex-1 min-h-0 overflow-y-auto scrollbar-cyber px-4 py-3 space-y-2.5">
        <AnimatePresence initial={false}>
          {messages.map((m) =>
            m.role === 'system' ? <SystemBanner key={m.id} message={m} /> : <Bubble key={m.id} message={m} />
          )}
          {thinking && <ThinkingBubble />}
        </AnimatePresence>
      </div>

      <div className="px-4 pb-2 pt-1 flex flex-wrap gap-1.5 shrink-0">
        {SUGGESTIONS.map((s) => (
          <Button key={s} variant="outline" size="xs" onClick={() => send(s)} className="rounded-full font-normal">
            {s}
          </Button>
        ))}
      </div>

      <form onSubmit={(e) => { e.preventDefault(); send(); }} className="px-3 pb-3 shrink-0">
        <div className="flex items-center gap-2 h-10 rounded-lg border border-line-strong bg-bg-0 focus-within:border-accent/60 px-2.5">
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Ask Sentinel — e.g. “isolate compromised hosts”"
            className="flex-1 min-w-0 bg-transparent outline-none text-[13px] text-fg-0 placeholder:text-fg-3"
          />
          <Button type="submit" variant="default" size="icon" disabled={!input.trim()} className="h-7 w-7" aria-label="Send">
            <Send className="h-3.5 w-3.5" />
          </Button>
        </div>
      </form>
    </Card>
  );
}

function SystemBanner({ message }) {
  return (
    <motion.div layout initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} transition={{ duration: 0.2 }} className="flex items-center gap-2 my-1" role="status">
      <span className="flex-1 h-px bg-line" />
      <span className="px-2 py-0.5 rounded-full font-mono text-[10px] text-fg-3 border border-line">
        {message.text} · {message.ts}
      </span>
      <span className="flex-1 h-px bg-line" />
    </motion.div>
  );
}

function Bubble({ message }) {
  const isAI = message.role === 'ai';
  return (
    <motion.div layout initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.2 }} className={`flex gap-2 ${isAI ? '' : 'flex-row-reverse'}`}>
      <div className={`shrink-0 mt-0.5 h-6 w-6 rounded-md flex items-center justify-center border border-line ${isAI ? 'bg-accent-soft text-accent-hover' : 'bg-bg-2 text-fg-2'}`}>
        {isAI ? <Bot className="h-3.5 w-3.5" /> : <span className="text-[9px] font-mono">YOU</span>}
      </div>
      <div className={`max-w-[82%] ${isAI ? '' : 'text-right'}`}>
        <div className={`inline-block rounded-lg px-3 py-2 text-[12.5px] leading-snug border text-left ${isAI ? 'bg-bg-2 border-line text-fg-0' : 'bg-accent-soft border-accent/30 text-fg-0'}`}>
          {message.text}
          {isAI && message.reasoning && (
            <div className="mt-1.5 pt-1.5 border-t border-line text-[11px] text-fg-2 font-mono leading-snug">
              {message.reasoning}
            </div>
          )}
        </div>
        <div className="mt-1 font-mono text-[10px] text-fg-3">{isAI ? 'Sentinel' : 'You'} · {message.ts}</div>
      </div>
    </motion.div>
  );
}

function ThinkingBubble() {
  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} transition={{ duration: 0.2 }} className="flex gap-2" aria-label="Sentinel is composing">
      <div className="shrink-0 mt-0.5 h-6 w-6 rounded-md flex items-center justify-center border border-line bg-accent-soft text-accent-hover">
        <Bot className="h-3.5 w-3.5" />
      </div>
      <div className="inline-flex items-center gap-1 rounded-lg px-3 py-2.5 bg-bg-2 border border-line">
        <Dot delay={0} /><Dot delay={0.15} /><Dot delay={0.3} />
      </div>
    </motion.div>
  );
}

function Dot({ delay }) {
  return (
    <motion.span
      animate={{ opacity: [0.25, 1, 0.25], y: [0, -2, 0] }}
      transition={{ duration: 1, repeat: Infinity, delay }}
      className="h-1.5 w-1.5 rounded-full bg-fg-2"
    />
  );
}
