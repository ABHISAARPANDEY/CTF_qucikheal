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

from app.core.thresholds import get_thresholds
from app.engine import anomaly as _anomaly
from app.engine import signatures as _sig
from app.engine.features import FeatureVector
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
    ThreatType.CREDENTIAL_STUFFING:   ("credential stuffing", "stuffing"),
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
    ThreatType.CREDENTIAL_STUFFING:   EventType.AUTH,
    ThreatType.SQL_INJECTION:         EventType.INTRUSION,
    ThreatType.MALWARE:               EventType.MALWARE,
    ThreatType.PRIVILEGE_ESCALATION:  EventType.PROCESS,
}

MITRE: dict[ThreatType, list[str]] = {
    ThreatType.BRUTE_FORCE:          ["T1110.001"],
    ThreatType.CREDENTIAL_STUFFING:  ["T1110.004"],
    ThreatType.PORT_SCAN:            ["T1046", "T1595.001"],
    ThreatType.DDOS:                 ["T1498"],
    ThreatType.SQL_INJECTION:        ["T1190"],
    ThreatType.MALWARE:              ["T1204"],
    ThreatType.PHISHING:             ["T1566"],
    ThreatType.DATA_EXFILTRATION:    ["T1041"],
    ThreatType.PRIVILEGE_ESCALATION: ["T1068"],
    ThreatType.LATERAL_MOVEMENT:     ["T1021"],
    ThreatType.INSIDER:              ["T1078"],
}


def _non_info(events: list[Event]) -> list[Event]:
    return [e for e in events if e.severity != Severity.INFO]


def _signal_lexical(event: Event, threat_type: ThreatType) -> Signal:
    """Keyword + event-type alignment for a specific candidate threat type."""
    keywords = _KEYWORDS.get(threat_type, ())
    text = event.message.lower()
    matches = sum(1 for k in keywords if k in text)
    if matches == 0:
        return Signal("lexical", False, 0.0)
    type_hint = _TYPE_HINT.get(threat_type)
    type_match = type_hint is not None and event.event_type == type_hint
    strength = min(1.0, matches * 0.40 + (0.30 if type_match else 0.0))
    return Signal("lexical", True, round(strength, 2))


def _signal_frequency(event: Event, ctx: DetectionContext) -> Signal:
    """How many non-informational events of the same EventType in the window?

    Informational events never inherit the surrounding volume: an attack
    burst must not raise the risk of a legitimate login that happens to
    share the event type.
    """
    if event.severity == Severity.INFO:
        return Signal("frequency", False, 0.0)
    n = len(_non_info(ctx.events_for_type(event.event_type)))
    if n < FREQ_LOW_THRESHOLD:
        return Signal("frequency", False, 0.0)
    span = max(1, FREQ_HIGH_THRESHOLD - FREQ_LOW_THRESHOLD)
    return Signal("frequency", True, round(min(1.0, (n - FREQ_LOW_THRESHOLD) / span), 2))


def _signal_ip_repetition(event: Event, ctx: DetectionContext) -> Signal:
    """Same source IP repeating non-informational events."""
    n = len(_non_info(ctx.events_for_ip(str(event.source_ip))))
    if n < SAME_IP_FOR_REPETITION:
        return Signal("ip_repetition", False, 0.0)
    return Signal("ip_repetition", True, round(min(1.0, n / 20.0), 2))


def _signal_distributed_sources(event: Event, ctx: DetectionContext) -> Signal:
    """Many distinct source IPs hitting the same event type (DDoS)."""
    distinct_ips = {str(e.source_ip) for e in _non_info(ctx.events_for_type(event.event_type))}
    n = len(distinct_ips)
    if n < DISTINCT_IPS_FOR_DISTRIBUTED:
        return Signal("distributed_sources", False, 0.0)
    return Signal("distributed_sources", True, round(min(1.0, n / 20.0), 2))


def _signal_severity_history(event: Event, ctx: DetectionContext) -> Signal:
    """Has the recent severity baseline been climbing?"""
    recent = ctx.events_in_window()[-10:]
    if len(recent) < 3:
        return Signal("severity_history", False, 0.0)
    avg = sum(SEVERITY_WEIGHT[e.severity] for e in recent) / len(recent)
    if avg < 1.5:
        return Signal("severity_history", False, 0.0)
    return Signal("severity_history", True, round(min(1.0, max(0.0, (avg - 1.5) / 2.5)), 2))


# ---- vector detectors (read FeatureVectors, never the message) ------------


def _signal_port_scan(ip_fv: FeatureVector) -> Signal:
    t = get_thresholds()
    by_count = ip_fv.distinct_ports / t.port_scan_min_ports
    by_seq = ip_fv.port_sequentiality / t.port_scan_seq if t.port_scan_seq > 0 else 0.0
    fired = ip_fv.distinct_ports >= t.port_scan_min_ports or (
        ip_fv.distinct_ports >= 3 and ip_fv.port_sequentiality >= t.port_scan_seq
    )
    strength = min(1.0, max(by_count, by_seq) / 1.5) if fired else 0.0
    return Signal("port_scan", fired, round(strength, 2))


def _signal_credential_stuffing(
    ip_fv: FeatureVector,
    subnet_fv: FeatureVector,
    campaign: Optional[_anomaly.CampaignMatch] = None,
) -> Signal:
    """Many distinct usernames with a high failure ratio — from one IP, one
    /24, or (the proxy-pool case) one distributed campaign fingerprint."""
    t = get_thresholds()
    views: list[tuple[float, float]] = [
        (ip_fv.distinct_users, ip_fv.fail_ratio),
        (subnet_fv.distinct_users, subnet_fv.fail_ratio),
    ]
    if campaign is not None and campaign.signal.fired:
        views.append((float(campaign.distinct_users), campaign.fail_ratio))
    best, fr = max(views, key=lambda v: v[0])
    fired = best >= t.stuffing_min_users and fr >= t.stuffing_fail_ratio
    strength = min(1.0, best / (2.0 * t.stuffing_min_users)) if fired else 0.0
    return Signal("credential_stuffing", fired, round(strength, 2))


def _signal_low_slow_brute(user_fv: FeatureVector | None) -> Signal:
    if user_fv is None:
        return Signal("low_slow_brute", False, 0.0)
    t = get_thresholds()
    fired = (
        user_fv.distinct_ips >= t.lowslow_min_ips
        and user_fv.fail_ratio >= t.lowslow_fail_ratio
        and user_fv.inter_arrival_mean >= t.lowslow_min_gap_s
    )
    strength = min(1.0, user_fv.distinct_ips / (2.0 * t.lowslow_min_ips)) if fired else 0.0
    return Signal("low_slow_brute", fired, round(strength, 2))


# ---- correlation ----------------------------------------------------------

KILL_CHAIN_PATTERNS: tuple[tuple[ThreatType, ...], ...] = (
    (ThreatType.BRUTE_FORCE, ThreatType.PRIVILEGE_ESCALATION, ThreatType.DATA_EXFILTRATION),
    (ThreatType.PORT_SCAN, ThreatType.SQL_INJECTION, ThreatType.DATA_EXFILTRATION),
    (ThreatType.PHISHING, ThreatType.MALWARE, ThreatType.LATERAL_MOVEMENT),
    (ThreatType.BRUTE_FORCE, ThreatType.LATERAL_MOVEMENT, ThreatType.DATA_EXFILTRATION),
    (ThreatType.PORT_SCAN, ThreatType.CREDENTIAL_STUFFING, ThreatType.PRIVILEGE_ESCALATION),
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


def _detect_correlation(current: ThreatType, ctx: DetectionContext) -> Optional[str]:
    """Inspect the recent threat history for kill-chain or sustained patterns."""
    history = [t for t in ctx.recent_threat_types(n=8) if t != ThreatType.BENIGN] + [current]
    for pattern in KILL_CHAIN_PATTERNS:
        if _is_ordered_subsequence(pattern, history):
            return "multi_stage_attack"
    tail = history[-3:]
    if len(tail) == 3 and len(set(tail)) == 1 and tail[0] not in (ThreatType.UNKNOWN, ThreatType.BENIGN):
        return "sustained_attack"
    return None


# ---- scoring --------------------------------------------------------------


def _signal_strength(signals: list[Signal], name: str) -> float:
    """Look up a signal's strength by name (0.0 if not present)."""
    for s in signals:
        if s.name == name:
            return s.strength
    return 0.0


RISK_BUDGET: dict[str, float] = {
    "severity": 1.5,
    "frequency": 1.0,
    "repetition": 1.0,
    "vector": 2.0,
    "behavioral_zscore": 2.0,
    "isolation_forest": 1.5,
    "distributed_campaign": 1.0,
}


def risk_breakdown(event: Event, signals: list[Signal]) -> dict[str, float]:
    """Per-factor risk contributions; values sum to the total risk (≤ 10)."""
    b = RISK_BUDGET
    parts = {
        "severity": SEVERITY_WEIGHT[event.severity] / 4.0 * b["severity"],
        "frequency": _signal_strength(signals, "frequency") * b["frequency"],
        "repetition": max(
            _signal_strength(signals, "ip_repetition"),
            _signal_strength(signals, "distributed_sources"),
        ) * b["repetition"],
        "vector": max(
            _signal_strength(signals, "port_scan"),
            _signal_strength(signals, "credential_stuffing"),
            _signal_strength(signals, "low_slow_brute"),
            _signal_strength(signals, "lexical") * 0.75,
        ) * b["vector"],
        "behavioral_zscore": _signal_strength(signals, "behavioral_zscore") * b["behavioral_zscore"],
        "isolation_forest": _signal_strength(signals, "isolation_forest") * b["isolation_forest"],
        "distributed_campaign": _signal_strength(signals, "distributed_campaign") * b["distributed_campaign"],
    }
    return {k: round(v, 2) for k, v in parts.items()}


def calculate_risk(
    event: Event,
    context: Optional[DetectionContext] = None,
    signals: Optional[list[Signal]] = None,
) -> float:
    """Composite risk in [0, 10] — the sum of :func:`risk_breakdown`."""
    _ = context
    total = sum(risk_breakdown(event, signals or []).values())
    return round(max(0.0, min(10.0, total)), 2)


def calculate_confidence(signals: list[Signal]) -> float:
    """Confidence in [0, 1] from how many signals align and how strongly."""
    fired = [s for s in signals if s.fired]
    if not fired:
        return 0.30
    total_strength = sum(s.strength for s in fired)
    alignment_bonus = 0.05 * (len(fired) - 1)
    return round(max(0.0, min(1.0, 0.30 + 0.18 * total_strength + alignment_bonus)), 2)


CANDIDATE_THREAT_TYPES: tuple[ThreatType, ...] = (
    ThreatType.DDOS,
    ThreatType.PORT_SCAN,
    ThreatType.BRUTE_FORCE,
    ThreatType.CREDENTIAL_STUFFING,
    ThreatType.SQL_INJECTION,
    ThreatType.MALWARE,
    ThreatType.PHISHING,
    ThreatType.DATA_EXFILTRATION,
    ThreatType.PRIVILEGE_ESCALATION,
    ThreatType.LATERAL_MOVEMENT,
    ThreatType.ANOMALY,
)

# Which vector signal can *nominate* a threat type without any keyword match.
_VECTOR_FOR: dict[ThreatType, str] = {
    ThreatType.PORT_SCAN: "port_scan",
    ThreatType.CREDENTIAL_STUFFING: "credential_stuffing",
    ThreatType.BRUTE_FORCE: "low_slow_brute",
}


def _signals_for(threat_type: ThreatType, event: Event, cached: dict[str, Signal]) -> list[Signal]:
    signals: list[Signal] = [_signal_lexical(event, threat_type), cached["frequency"]]
    if threat_type == ThreatType.DDOS:
        signals.append(cached["distributed_sources"])
    elif threat_type in (
        ThreatType.BRUTE_FORCE, ThreatType.SQL_INJECTION, ThreatType.PORT_SCAN,
        ThreatType.PRIVILEGE_ESCALATION, ThreatType.CREDENTIAL_STUFFING,
    ):
        signals.append(cached["ip_repetition"])
    vec = _VECTOR_FOR.get(threat_type)
    if vec:
        signals.append(cached[vec])
    signals.append(cached["severity_history"])
    return signals


def _select_threat_type(
    event: Event, ctx: DetectionContext, analysis: _anomaly.AnalysisResult
) -> tuple[ThreatType, list[Signal]]:
    """Score every candidate; return (winner, its signal set incl. ML signals)."""
    ip_fv = analysis.features["ip"]
    subnet_fv = analysis.features["subnet"]
    user_fv = analysis.features.get("user")
    cached: dict[str, Signal] = {
        "frequency":           _signal_frequency(event, ctx),
        "ip_repetition":       _signal_ip_repetition(event, ctx),
        "distributed_sources": _signal_distributed_sources(event, ctx),
        "severity_history":    _signal_severity_history(event, ctx),
        "port_scan":           _signal_port_scan(ip_fv),
        "credential_stuffing": _signal_credential_stuffing(ip_fv, subnet_fv, analysis.campaign),
        "low_slow_brute":      _signal_low_slow_brute(user_fv),
    }
    ml = [Signal(s.name, s.fired, s.strength) for s in analysis.signals]
    ml_fired = any(s.fired for s in ml)

    # Score only the *specific* candidates (lexical- or vector-nominated). A
    # concrete label like "credential_stuffing" is always more useful to an
    # analyst than the generic "anomaly", so ANOMALY is a fallback used only
    # when no specific detector fired — even if the ML signals are strong.
    best_type, best_signals, best_score = ThreatType.UNKNOWN, [], 0.0
    for tt in CANDIDATE_THREAT_TYPES:
        if tt == ThreatType.ANOMALY:
            continue
        signals = _signals_for(tt, event, cached)
        lex = signals[0]
        vec_name = _VECTOR_FOR.get(tt)
        vec_fired = bool(vec_name) and cached[vec_name].fired
        if not lex.fired and not vec_fired:
            continue
        other = sum(s.strength for s in signals[1:] if s.fired)
        score = 0.5 * lex.strength + (1.0 * cached[vec_name].strength if vec_fired else 0.0) + 0.5 * other
        if score > best_score:
            best_type, best_signals, best_score = tt, signals, score

    if best_type == ThreatType.UNKNOWN:
        if event.severity == Severity.INFO and not ml_fired:
            return ThreatType.BENIGN, ml
        # no specific detector fired — a pure behavioural outlier is an anomaly
        best_type = ThreatType.ANOMALY if ml_fired else ThreatType.UNKNOWN
        best_signals = [cached["frequency"], cached["ip_repetition"], cached["severity_history"]]

    return best_type, best_signals + ml


def _severity_for_risk(risk_score: float) -> Severity:
    """Map a 0–10 risk score onto the canonical severity scale."""
    t = get_thresholds()
    if risk_score >= t.sev_critical: return Severity.CRITICAL
    if risk_score >= t.sev_high:     return Severity.HIGH
    if risk_score >= t.sev_medium:   return Severity.MEDIUM
    if risk_score >= t.sev_low:      return Severity.LOW
    return Severity.INFO


def _attribute(
    event: Event, signals: list[Signal], analysis: _anomaly.AnalysisResult
) -> tuple[dict[str, str], FeatureVector]:
    """Pick the entity an alert should be keyed on.

    Attribution decides de-duplication: a proxy-pool campaign must collapse
    into *one* alert (keyed on the campaign), not one alert per rotating IP.
    """
    t = get_thresholds()
    fired = {s.name for s in signals if s.fired}
    ip_fv = analysis.features["ip"]
    subnet_fv = analysis.features["subnet"]
    campaign = analysis.campaign

    if "low_slow_brute" in fired and event.username:
        return {"type": "user", "key": event.username}, analysis.features["user"]
    if "credential_stuffing" in fired:
        if ip_fv.distinct_users >= t.stuffing_min_users:
            return {"type": "ip", "key": str(event.source_ip)}, ip_fv
        if subnet_fv.distinct_users >= t.stuffing_min_users:
            return {"type": "subnet", "key": analysis.subnet_key}, subnet_fv
        if campaign is not None:
            return {"type": "campaign", "key": campaign.campaign_id}, ip_fv
    if campaign is not None and "distributed_campaign" in fired:
        return {"type": "campaign", "key": campaign.campaign_id}, ip_fv
    return analysis.entity, ip_fv


def update_context(event: Event, context: Optional[DetectionContext] = None) -> None:
    """Push an event into the sliding window without producing a Threat."""
    (context or get_default_context()).add(event)


def detect(event: Event, context: Optional[DetectionContext] = None) -> Threat:
    """Run multi-signal, behaviour-aware detection on ``event``.

    Steps:
        1. Push event into the sliding-window context.
        2. Run the anomaly engine (features → z-score / forest / campaign).
        3. Score every candidate threat type (lexical + vector + context signals).
        4. Compute per-factor risk breakdown, confidence, severity.
        5. Kill-chain correlation; record for future lookups.
        6. Attribute to an entity (user for low-and-slow, else source IP).
    """
    ctx = context or get_default_context()
    ctx.add(event)

    analysis = _anomaly.get_engine().analyze(event)
    indicators = _sig.extract_indicators(event)

    # Fast path: a learned signature identifies this attacker on the first
    # event, before the behavioural window has to build up.
    sig_match = _sig.get_signature_store().match(event)
    if sig_match is not None and event.severity != Severity.INFO:
        risk = round(max(0.0, min(10.0, sig_match.risk)), 2)
        severity = _severity_for_risk(risk)
        ctx.add_threat(sig_match.threat_type)
        primary_fv = analysis.features["ip"]
        # Collapse every instant match of the same signature into ONE alert
        # (a rotating proxy pool sharing a bot UA is one campaign, not N alerts).
        entity = {"type": "signature", "key": sig_match.signature_id}
        breakdown = {"signature": risk}
        return Threat(
            event_id=event.id,
            threat_type=sig_match.threat_type,
            confidence=sig_match.confidence,
            risk_score=risk,
            severity=severity,
            signals=["signature_match"],
            correlation=_detect_correlation(sig_match.threat_type, ctx),
            risk_breakdown=breakdown,
            entity=entity,
            features=primary_fv.as_dict(),
            zscores=analysis.zscores,
            campaign_id=analysis.campaign.campaign_id if analysis.campaign else None,
            mitre=list(sig_match.mitre) or list(MITRE.get(sig_match.threat_type, [])),
            indicators=indicators,
            signature_id=sig_match.signature_id,
            matched_by_signature=True,
        )

    threat_type, signals = _select_threat_type(event, ctx, analysis)

    breakdown = risk_breakdown(event, signals)
    risk = round(max(0.0, min(10.0, sum(breakdown.values()))), 2)

    # Noise floor: normal (INFO) traffic sometimes trips a weak ML signal —
    # the isolation forest flags ~5% of samples by its contamination setting,
    # and z-scores cross 2σ on the tails of a healthy population. Those are not
    # incidents. Keep such low-risk INFO events labelled BENIGN so the live
    # stream isn't a wall of "anomaly", rather than promoting them.
    t = get_thresholds()
    if threat_type == ThreatType.ANOMALY and event.severity == Severity.INFO and risk < t.sev_low:
        threat_type = ThreatType.BENIGN
        signals = []
        breakdown = risk_breakdown(event, signals)
        risk = round(max(0.0, min(10.0, sum(breakdown.values()))), 2)

    confidence = calculate_confidence(signals)
    severity = _severity_for_risk(risk)
    correlation = _detect_correlation(threat_type, ctx)
    ctx.add_threat(threat_type)

    entity, primary_fv = _attribute(event, signals, analysis)

    return Threat(
        event_id=event.id,
        threat_type=threat_type,
        confidence=confidence,
        risk_score=risk,
        severity=severity,
        signals=[s.name for s in signals if s.fired],
        correlation=correlation,
        risk_breakdown=breakdown,
        entity=entity,
        features=primary_fv.as_dict(),
        zscores=analysis.zscores,
        campaign_id=analysis.campaign.campaign_id if analysis.campaign else None,
        mitre=list(MITRE.get(threat_type, [])),
        indicators=indicators,
    )
