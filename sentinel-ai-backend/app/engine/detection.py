"""Multi-signal, time-aware detection engine.

Architecture
------------
Detection is no longer a single keyword-vs-event match. Each event is
analyzed against several **independent signals** that vote, then risk and
confidence are computed from the resulting signal set. The engine also
maintains an in-memory **sliding window** of recent events so detections
can reason about frequency, repetition, and ordered kill-chain sequences.

Public API (stdlib only, no ML, no external deps):
    detect(event, context=None)               -> Threat
    calculate_risk(event, context, signals)   -> float in [0, 10]
    calculate_confidence(signals)             -> float in [0, 1]
    update_context(event, context=None)       -> None
    DetectionContext(...)                     -> sliding-window state

A module-level default :class:`DetectionContext` is auto-used when no
context is passed, so existing callers (`detect(event)`) keep working.

Signals
-------
Each signal is a small pure function returning a :class:`Signal` with a
[0, 1] strength. Signals are deliberately independent so they can be
composed/extended without ripple effects:

    lexical             — keyword/event-type match (the legacy signal)
    frequency           — how many events of this type in the window
    ip_repetition       — same source IP repeating events
    distributed_sources — many distinct source IPs (DDoS fingerprint)
    severity_history    — recent severity baseline trending up
    kill_chain          — this event completes a known attack sequence

Risk = severity_factor + frequency_factor + repetition_factor + anomaly_factor
Confidence = base + Σ(signal_strength) + multi_signal_alignment_bonus
"""

from __future__ import annotations

from collections import OrderedDict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from threading import Lock
from typing import Iterable, Optional

from app.models.event import Event, EventType, Severity
from app.models.threat import Threat, ThreatType


                                                                        

DEFAULT_WINDOW_SECONDS = 300                                   
DEFAULT_GLOBAL_MAX = 500                                               
DEFAULT_PER_BUCKET_MAX = 50                                           
DEFAULT_MAX_TRACKED_IPS = 1000                                   
DEFAULT_THREAT_HISTORY = 64                                       

                                                                      
FREQ_LOW_THRESHOLD = 5                                                 
FREQ_HIGH_THRESHOLD = 20                                                      

                        
SAME_IP_FOR_REPETITION = 5                                                
DISTINCT_IPS_FOR_DISTRIBUTED = 5                                           

                                                                            
SEVERITY_WEIGHT: dict[Severity, float] = {
    Severity.INFO: 0.0,
    Severity.LOW: 1.0,
    Severity.MEDIUM: 2.0,
    Severity.HIGH: 3.0,
    Severity.CRITICAL: 4.0,
}


                                                                        


@dataclass(frozen=True)
class Signal:
    """One independent detection signal's verdict.

    `strength` is in [0, 1] regardless of whether the signal `fired`. A
    fired signal with strength 0.5 contributed half-credit; a non-fired
    signal contributes nothing.
    """

    name: str
    fired: bool
    strength: float


                                                                         


class DetectionContext:
    """In-memory, time-windowed buffers feeding the detection signals.

    Three indexes are kept in lockstep:
        - global queue (FIFO, capped)
        - per-source-IP queue (LRU on the IP set, FIFO per IP)
        - per-event-type queue (FIFO, capped)

    All queries are time-windowed lazily; bounded queues keep memory
    flat in long-running processes. A single :class:`Lock` protects
    state — critical sections are O(1) and safe under asyncio (single
    threaded today, future-proof for threads).
    """

    def __init__(
        self,
        *,
        window_seconds: int = DEFAULT_WINDOW_SECONDS,
        global_max: int = DEFAULT_GLOBAL_MAX,
        per_bucket_max: int = DEFAULT_PER_BUCKET_MAX,
        max_tracked_ips: int = DEFAULT_MAX_TRACKED_IPS,
        threat_history: int = DEFAULT_THREAT_HISTORY,
    ) -> None:
        self._window = timedelta(seconds=window_seconds)
        self._per_bucket_max = per_bucket_max
        self._max_tracked_ips = max_tracked_ips
        self._lock = Lock()

        self._global: deque[Event] = deque(maxlen=global_max)
        self._by_ip: "OrderedDict[str, deque[Event]]" = OrderedDict()
        self._by_type: dict[EventType, deque[Event]] = {}
        self._threat_history: deque[ThreatType] = deque(maxlen=threat_history)

                                                                       

    def add(self, event: Event) -> None:
        """Push an event into all three indexes."""
        ip = str(event.source_ip)
        with self._lock:
            self._global.append(event)

            bucket = self._by_ip.get(ip)
            if bucket is None:
                bucket = deque(maxlen=self._per_bucket_max)
                self._by_ip[ip] = bucket
                                                                   
                while len(self._by_ip) > self._max_tracked_ips:
                    self._by_ip.popitem(last=False)
            else:
                self._by_ip.move_to_end(ip)
            bucket.append(event)

            type_bucket = self._by_type.setdefault(
                event.event_type, deque(maxlen=self._per_bucket_max)
            )
            type_bucket.append(event)

    def add_threat(self, threat_type: ThreatType) -> None:
        """Record the resolved threat type for kill-chain correlation."""
        with self._lock:
            self._threat_history.append(threat_type)

    def reset(self) -> None:
        """Drop all state. Useful in tests."""
        with self._lock:
            self._global.clear()
            self._by_ip.clear()
            self._by_type.clear()
            self._threat_history.clear()

                                                                      

    def _within_window(self, events: Iterable[Event]) -> list[Event]:
        cutoff = datetime.now(timezone.utc) - self._window
        return [e for e in events if e.timestamp >= cutoff]

    def events_in_window(self) -> list[Event]:
        with self._lock:
            return self._within_window(self._global)

    def events_for_ip(self, ip: str) -> list[Event]:
        with self._lock:
            buf = self._by_ip.get(ip, ())
            return self._within_window(buf)

    def events_for_type(self, event_type: EventType) -> list[Event]:
        with self._lock:
            buf = self._by_type.get(event_type, ())
            return self._within_window(buf)

    def recent_threat_types(self, n: int = 5) -> list[ThreatType]:
        with self._lock:
            return list(self._threat_history)[-n:]


                                                                        

_default_context = DetectionContext()


def get_default_context() -> DetectionContext:
    """Return the singleton context used when callers don't pass one."""
    return _default_context


def reset_default_context() -> None:
    """Replace the singleton with a fresh empty context (test helper)."""
    global _default_context
    _default_context = DetectionContext()


                                                                        

                                                                       
                                                                     
                     
_KEYWORDS: dict[ThreatType, tuple[str, ...]] = {
    ThreatType.DDOS:                  ("flood", "ddos", "amplification", "packets/sec", "gbps"),
    ThreatType.PORT_SCAN:             ("port scan", "nmap", "syn scan"),
    ThreatType.BRUTE_FORCE:           ("brute", "failed login", "failed auth"),
    ThreatType.SQL_INJECTION:         ("sqli", "sql injection", "union select", "or '1'='1", "drop table", "' or 'a'='a"),
    ThreatType.MALWARE:               ("malware", "trojan", "ransomware", "virus"),
    ThreatType.PHISHING:              ("phish", "credential harvesting", "spoofed sender"),
    ThreatType.DATA_EXFILTRATION:     ("exfiltration", "data exfil", "large outbound transfer"),
    ThreatType.PRIVILEGE_ESCALATION:  ("privilege escalation", "sudo abuse", "uid=0"),
    ThreatType.LATERAL_MOVEMENT:      ("psexec", "wmic remote", "smb relay", "lateral"),
}

                                                                       
                                                          
_TYPE_HINT: dict[ThreatType, EventType] = {
    ThreatType.DDOS:                  EventType.NETWORK,
    ThreatType.PORT_SCAN:             EventType.NETWORK,
    ThreatType.BRUTE_FORCE:           EventType.AUTH,
    ThreatType.SQL_INJECTION:         EventType.INTRUSION,
    ThreatType.MALWARE:               EventType.MALWARE,
    ThreatType.PRIVILEGE_ESCALATION:  EventType.PROCESS,
}


def _signal_lexical(event: Event, threat_type: ThreatType) -> Signal:
    """Keyword + event-type alignment for a specific candidate threat type."""
    keywords = _KEYWORDS.get(threat_type, ())
    text = event.message.lower()
    matches = sum(1 for k in keywords if k in text)
    type_hint = _TYPE_HINT.get(threat_type)
    type_match = type_hint is not None and event.event_type == type_hint

    if matches == 0 and not type_match:
        return Signal("lexical", False, 0.0)

                                                                   
    strength = min(1.0, matches * 0.40 + (0.30 if type_match else 0.0))
    return Signal("lexical", True, round(strength, 2))


def _signal_frequency(event: Event, ctx: DetectionContext) -> Signal:
    """How many events of the same EventType occurred in the window?"""
    n = len(ctx.events_for_type(event.event_type))
    if n < FREQ_LOW_THRESHOLD:
        return Signal("frequency", False, 0.0)
    span = max(1, FREQ_HIGH_THRESHOLD - FREQ_LOW_THRESHOLD)
    strength = min(1.0, (n - FREQ_LOW_THRESHOLD) / span)
    return Signal("frequency", True, round(strength, 2))


def _signal_ip_repetition(event: Event, ctx: DetectionContext) -> Signal:
    """Same source IP repeating events (brute-force / scanning fingerprint)."""
    ip = str(event.source_ip)
    n = len(ctx.events_for_ip(ip))
    if n < SAME_IP_FOR_REPETITION:
        return Signal("ip_repetition", False, 0.0)
    strength = min(1.0, n / 20.0)                                       
    return Signal("ip_repetition", True, round(strength, 2))


def _signal_distributed_sources(event: Event, ctx: DetectionContext) -> Signal:
    """Many distinct source IPs hitting the same event type (DDoS)."""
    type_events = ctx.events_for_type(event.event_type)
    distinct_ips = {str(e.source_ip) for e in type_events}
    n = len(distinct_ips)
    if n < DISTINCT_IPS_FOR_DISTRIBUTED:
        return Signal("distributed_sources", False, 0.0)
    strength = min(1.0, n / 20.0)
    return Signal("distributed_sources", True, round(strength, 2))


def _signal_severity_history(event: Event, ctx: DetectionContext) -> Signal:
    """Has the recent severity baseline been climbing? (anomaly proxy)."""
    recent = ctx.events_in_window()[-10:]
    if len(recent) < 3:
        return Signal("severity_history", False, 0.0)
    avg = sum(SEVERITY_WEIGHT[e.severity] for e in recent) / len(recent)
    if avg < 1.5:
        return Signal("severity_history", False, 0.0)
                        
    strength = min(1.0, max(0.0, (avg - 1.5) / 2.5))
    return Signal("severity_history", True, round(strength, 2))


                                                                        

                                                                    
                                                       
KILL_CHAIN_PATTERNS: tuple[tuple[ThreatType, ...], ...] = (
    (ThreatType.BRUTE_FORCE, ThreatType.PRIVILEGE_ESCALATION, ThreatType.DATA_EXFILTRATION),
    (ThreatType.PORT_SCAN, ThreatType.SQL_INJECTION, ThreatType.DATA_EXFILTRATION),
    (ThreatType.PHISHING, ThreatType.MALWARE, ThreatType.LATERAL_MOVEMENT),
    (ThreatType.BRUTE_FORCE, ThreatType.LATERAL_MOVEMENT, ThreatType.DATA_EXFILTRATION),
)


def _is_ordered_subsequence(pattern: tuple[ThreatType, ...], history: list[ThreatType]) -> bool:
    """True if ``pattern`` appears as an ordered (non-contiguous) subsequence."""
    i = 0
    for item in history:
        if i < len(pattern) and item == pattern[i]:
            i += 1
            if i == len(pattern):
                return True
    return False


def _detect_correlation(
    current: ThreatType, ctx: DetectionContext
) -> Optional[str]:
    """Inspect the recent threat history for kill-chain or sustained patterns."""
    history = ctx.recent_threat_types(n=8) + [current]

    for pattern in KILL_CHAIN_PATTERNS:
        if _is_ordered_subsequence(pattern, history):
            return "multi_stage_attack"

                                                                         
    tail = history[-3:]
    if len(tail) == 3 and len(set(tail)) == 1 and tail[0] != ThreatType.UNKNOWN:
        return "sustained_attack"

    return None


                                                                        


def _signal_strength(signals: list[Signal], name: str) -> float:
    """Look up a signal's strength by name (0.0 if not present)."""
    for s in signals:
        if s.name == name:
            return s.strength
    return 0.0


def calculate_risk(
    event: Event,
    context: Optional[DetectionContext] = None,
    signals: Optional[list[Signal]] = None,
) -> float:
    """Compute risk in [0, 10] from severity, frequency, repetition, anomaly.

    Factor budget (max contribution):
        severity         → 3.2 pts (event's own severity)
        frequency        → 3.0 pts (volume of similar events in window)
        repetition       → 2.0 pts (same IP repeats OR distributed sources)
        anomaly          → 2.0 pts (severity baseline climbing)

    Total is clamped to [0, 10].
    """
    _ = context                                                            
    signals = signals or []

    severity_factor   = SEVERITY_WEIGHT[event.severity] * 0.8               
    frequency_factor  = _signal_strength(signals, "frequency") * 3.0         
    repetition_factor = max(
        _signal_strength(signals, "ip_repetition"),
        _signal_strength(signals, "distributed_sources"),
    ) * 2.0                                                                  
    anomaly_factor    = _signal_strength(signals, "severity_history") * 2.0         

    total = severity_factor + frequency_factor + repetition_factor + anomaly_factor
    return round(max(0.0, min(10.0, total)), 2)


def calculate_confidence(signals: list[Signal]) -> float:
    """Compute confidence in [0, 1] from how many signals align and how strongly.

    Scheme:
        base 0.30
        +0.18 per fully-strong fired signal (sums of strengths)
        +0.05 alignment bonus per *additional* fired signal beyond the first
    """
    fired = [s for s in signals if s.fired]
    if not fired:
        return 0.30                                                        
    total_strength = sum(s.strength for s in fired)
    alignment_bonus = 0.05 * (len(fired) - 1)
    confidence = 0.30 + 0.18 * total_strength + alignment_bonus
    return round(max(0.0, min(1.0, confidence)), 2)


                                                                        

                                                                       
CANDIDATE_THREAT_TYPES: tuple[ThreatType, ...] = (
    ThreatType.DDOS,
    ThreatType.PORT_SCAN,
    ThreatType.BRUTE_FORCE,
    ThreatType.SQL_INJECTION,
    ThreatType.MALWARE,
    ThreatType.PHISHING,
    ThreatType.DATA_EXFILTRATION,
    ThreatType.PRIVILEGE_ESCALATION,
    ThreatType.LATERAL_MOVEMENT,
    ThreatType.ANOMALY,
)


def _signals_for(
    threat_type: ThreatType,
    event: Event,
    ctx: DetectionContext,
    cached: dict[str, Signal],
) -> list[Signal]:
    """Build the signal set relevant to a candidate threat type.

    Lexical is per-type; the rest are cached across candidates because
    they're event-wide (frequency, distributed_sources, severity_history)
    or IP-wide (ip_repetition).
    """
    signals: list[Signal] = [_signal_lexical(event, threat_type)]
    signals.append(cached["frequency"])
    if threat_type == ThreatType.DDOS:
        signals.append(cached["distributed_sources"])
    elif threat_type in (
        ThreatType.BRUTE_FORCE,
        ThreatType.SQL_INJECTION,
        ThreatType.PORT_SCAN,
        ThreatType.PRIVILEGE_ESCALATION,
    ):
        signals.append(cached["ip_repetition"])
    signals.append(cached["severity_history"])
    return signals


def _fallback_threat_type(event: Event) -> ThreatType:
    """Map by event_type when no lexical rule matches anything."""
    if event.event_type == EventType.NETWORK:
        return ThreatType.PORT_SCAN if "scan" in event.message.lower() else ThreatType.ANOMALY
    if event.event_type == EventType.AUTH:        return ThreatType.BRUTE_FORCE
    if event.event_type == EventType.INTRUSION:   return ThreatType.SQL_INJECTION
    if event.event_type == EventType.MALWARE:     return ThreatType.MALWARE
    if event.event_type == EventType.ANOMALY:     return ThreatType.ANOMALY
    return ThreatType.UNKNOWN


def _select_threat_type(
    event: Event, ctx: DetectionContext
) -> tuple[ThreatType, list[Signal]]:
    """Score every candidate; return (winner, its signal set).

    Scoring rule for each candidate:
        score = 0.5 × lexical_strength + 0.5 × Σ(other_signal_strengths)

    Lexical match dominates direction; context signals break ties and
    promote borderline cases (e.g., low-keyword event riding on a strong
    frequency or repetition fingerprint).
    """
    cached: dict[str, Signal] = {
        "frequency":           _signal_frequency(event, ctx),
        "ip_repetition":       _signal_ip_repetition(event, ctx),
        "distributed_sources": _signal_distributed_sources(event, ctx),
        "severity_history":    _signal_severity_history(event, ctx),
    }

    best_type: ThreatType = ThreatType.UNKNOWN
    best_signals: list[Signal] = []
    best_score = 0.0

    for tt in CANDIDATE_THREAT_TYPES:
        signals = _signals_for(tt, event, ctx, cached)
        lex = signals[0]                           
        if not lex.fired and tt != ThreatType.ANOMALY:
                                                                        
            continue
        other = sum(s.strength for s in signals[1:] if s.fired)
        score = 0.5 * lex.strength + 0.5 * other
        if score > best_score:
            best_score = score
            best_type = tt
            best_signals = signals

    if best_type == ThreatType.UNKNOWN:
        best_type = _fallback_threat_type(event)
        best_signals = [
            cached["frequency"],
            cached["ip_repetition"],
            cached["severity_history"],
        ]

    return best_type, best_signals


                                                                        


def _severity_for_risk(risk_score: float) -> Severity:
    """Map a 0–10 risk score onto the canonical severity scale."""
    if risk_score >= 8.5: return Severity.CRITICAL
    if risk_score >= 6.5: return Severity.HIGH
    if risk_score >= 4.0: return Severity.MEDIUM
    if risk_score >= 2.0: return Severity.LOW
    return Severity.INFO


                                                                        


def update_context(event: Event, context: Optional[DetectionContext] = None) -> None:
    """Push an event into the sliding window.

    :func:`detect` calls this automatically; expose for replays or tests
    where you want to seed history without producing a Threat.
    """
    (context or get_default_context()).add(event)


def detect(event: Event, context: Optional[DetectionContext] = None) -> Threat:
    """Run multi-signal, time-aware detection on ``event``.

    Steps:
        1. Push event into the sliding-window context (so it can
           participate in its own analysis if appropriate).
        2. For each candidate threat type, compute its signal set.
        3. Pick the threat type with the highest combined score.
        4. Compute risk and confidence from the winning signal set.
        5. Derive output severity from risk.
        6. Check kill-chain correlation against the recent threat history.
        7. Record the resolved threat type for future correlation lookups.
    """
    ctx = context or get_default_context()

                                                                            
                                                                           
                                                                
    ctx.add(event)

                                         
    threat_type, signals = _select_threat_type(event, ctx)

                                          
    risk = calculate_risk(event, ctx, signals)
    confidence = calculate_confidence(signals)

                              
    severity = _severity_for_risk(risk)

                               
    correlation = _detect_correlation(threat_type, ctx)

                                                                             
    ctx.add_threat(threat_type)

    return Threat(
        event_id=event.id,
        threat_type=threat_type,
        confidence=confidence,
        risk_score=risk,
        severity=severity,
        signals=[s.name for s in signals if s.fired],
        correlation=correlation,
    )
