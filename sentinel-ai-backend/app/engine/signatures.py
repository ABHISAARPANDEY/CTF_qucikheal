"""Learned attack signatures — fast-path detection from confirmed threats.

The behavioural engine needs a few events to build a window before it is
confident. Once a threat *is* confirmed (an alert is raised), we distil it
into a small, durable :class:`Signature`: the threat type plus a set of
normalized **indicators** (source /24, user-agent family, target endpoint,
port pattern, …). On every subsequent event we check those indicators
first — a match yields an **instant**, high-confidence classification on the
very first packet, instead of waiting for the window to fill.

This is deliberately conservative: signatures are keyed on specific,
attacker-controlled indicators (not on a whole subnet of legitimate users),
and benign traffic never learns a signature because only alert-worthy
threats are fed to :meth:`SignatureStore.learn`.

Persisted to JSON so learning survives restarts.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Optional

from app.models.event import Event
from app.models.threat import Threat, ThreatType

# ---------------------------------------------------------------------------
# Indicator extraction
# ---------------------------------------------------------------------------

_BOT_UA_HINTS = (
    "python-requests", "python-urllib", "urllib", "aiohttp", "httpx", "okhttp",
    "go-http", "curl", "wget", "libwww", "scrapy", "httpclient", "java/", "node-fetch", "axios",
)


def _subnet(ip: str) -> Optional[str]:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if addr.version == 4:
        return str(ipaddress.ip_network(f"{ip}/24", strict=False))
    return str(ipaddress.ip_network(f"{ip}/64", strict=False))


def _bot_ua(ua: Optional[str]) -> Optional[str]:
    """Return the automation-tool family for a UA, or None for a real browser.

    Only inherently-suspicious clients (scripted HTTP libraries) qualify — a
    Chrome/Safari/mobile-app UA is never a signature indicator, so learning a
    signature can never cause a legitimate user to be flagged."""
    if not ua:
        return None
    low = ua.lower()
    for hint in _BOT_UA_HINTS:
        if hint in low:
            return hint
    return None


def extract_indicators(event: Event) -> list[str]:
    """Normalized fingerprints of an event, used for both learn and match.

    ``learn`` further filters these to only the indicators that are safe to
    key a signature on (see :meth:`SignatureStore.learn`)."""
    out: list[str] = []
    sub = _subnet(str(event.source_ip))
    if sub:
        out.append(f"subnet:{sub}")
    bot = _bot_ua(event.user_agent)
    if bot:
        out.append(f"ua:{bot}")
        if event.endpoint:
            out.append(f"ua:{bot}|endpoint:{event.endpoint}")
    if event.dest_port is not None:
        out.append(f"port:{event.dest_port}")
    return out


# ---------------------------------------------------------------------------
# Signature model + store
# ---------------------------------------------------------------------------


@dataclass
class Signature:
    id: str
    threat_type: str
    indicator: str
    risk: float
    confidence: float
    mitre: list[str]
    hits: int = 0
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_matched_at: Optional[str] = None
    source_entity: Optional[dict] = None

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "threat_type": self.threat_type,
            "indicator": self.indicator,
            "risk": round(self.risk, 2),
            "confidence": round(self.confidence, 2),
            "mitre": self.mitre,
            "hits": self.hits,
            "created_at": self.created_at,
            "last_matched_at": self.last_matched_at,
            "source_entity": self.source_entity,
        }


@dataclass
class SignatureMatch:
    signature_id: str
    threat_type: ThreatType
    indicator: str
    risk: float
    confidence: float
    mitre: list[str]


class SignatureStore:
    def __init__(self, *, path: Optional[str] = None, cap: int = 500) -> None:
        self._path = Path(path) if path else None
        self._cap = cap
        self._lock = Lock()
        self._by_indicator: dict[tuple[str, str], Signature] = {}
        if self._path:
            self._load()

    # -- learn ------------------------------------------------------------

    def learn(self, threat: Threat, event: Event) -> list[Signature]:
        """Distil a confirmed threat into signatures. Returns newly created ones."""
        if threat.threat_type in (ThreatType.BENIGN, ThreatType.UNKNOWN):
            return []
        indicators = threat.indicators or extract_indicators(event)
        # Only learn signatures on an automation-tool (bot) User-Agent — that
        # fingerprint recurs across a campaign and never belongs to a real
        # browser, so a learned signature is high-precision and reusable.
        # (Spoofed DDoS /24s and shared ports never recur, so we don't learn
        # them — they'd only create signature sprawl.)
        chosen: list[str] = [i for i in indicators if i.startswith("ua:")]
        seen_c: set[str] = set()
        chosen = [i for i in chosen if not (i in seen_c or seen_c.add(i))]
        if not chosen:
            return []

        created: list[Signature] = []
        tt = threat.threat_type.value
        with self._lock:
            for ind in chosen:
                key = (tt, ind)
                if key in self._by_indicator:
                    continue
                sig = Signature(
                    id=f"sig-{abs(hash(key)) % (10**10):010d}",
                    threat_type=tt,
                    indicator=ind,
                    risk=max(threat.risk_score, 6.0),
                    confidence=max(threat.confidence, 0.9),
                    mitre=list(threat.mitre),
                    source_entity=dict(threat.entity) if threat.entity else None,
                )
                self._by_indicator[key] = sig
                created.append(sig)
                while len(self._by_indicator) > self._cap:
                    # drop the oldest
                    oldest = min(self._by_indicator, key=lambda k: self._by_indicator[k].created_at)
                    del self._by_indicator[oldest]
        if created and self._path:
            self._save()
        return created

    # -- match ------------------------------------------------------------

    def match(self, event: Event) -> Optional[SignatureMatch]:
        """Return the strongest signature matching this event, if any."""
        indicators = extract_indicators(event)
        if not indicators:
            return None
        with self._lock:
            best: Optional[Signature] = None
            for ind in indicators:
                for (tt, sig_ind), sig in self._by_indicator.items():
                    if sig_ind == ind and (best is None or sig.risk > best.risk):
                        best = sig
            if best is None:
                return None
            best.hits += 1
            best.last_matched_at = datetime.now(timezone.utc).isoformat()
            snapshot = best
        # NB: hit-count updates are in-memory only — persisting on every match
        # would put a synchronous disk write in the hot detection path.
        try:
            tt_enum = ThreatType(snapshot.threat_type)
        except ValueError:
            tt_enum = ThreatType.ANOMALY
        return SignatureMatch(
            signature_id=snapshot.id,
            threat_type=tt_enum,
            indicator=snapshot.indicator,
            risk=snapshot.risk,
            confidence=snapshot.confidence,
            mitre=list(snapshot.mitre),
        )

    # -- query / admin ----------------------------------------------------

    def all(self) -> list[dict]:
        with self._lock:
            return [s.as_dict() for s in sorted(self._by_indicator.values(), key=lambda s: s.created_at, reverse=True)]

    def count(self) -> int:
        with self._lock:
            return len(self._by_indicator)

    def clear(self) -> None:
        with self._lock:
            self._by_indicator.clear()
        if self._path:
            self._save()

    # -- persistence ------------------------------------------------------

    def _load(self) -> None:
        if not self._path or not self._path.exists():
            return
        try:
            data = json.loads(self._path.read_text())
        except Exception:
            return
        with self._lock:
            for row in data:
                try:
                    sig = Signature(
                        id=row["id"], threat_type=row["threat_type"], indicator=row["indicator"],
                        risk=row["risk"], confidence=row["confidence"], mitre=row.get("mitre", []),
                        hits=row.get("hits", 0), created_at=row.get("created_at", datetime.now(timezone.utc).isoformat()),
                        last_matched_at=row.get("last_matched_at"), source_entity=row.get("source_entity"),
                    )
                    self._by_indicator[(sig.threat_type, sig.indicator)] = sig
                except Exception:
                    continue

    def _save(self) -> None:
        if not self._path:
            return
        try:
            self._path.write_text(json.dumps(self.all(), indent=2))
        except Exception:
            pass


_store: Optional[SignatureStore] = None


def get_signature_store() -> SignatureStore:
    global _store
    if _store is None:
        _store = SignatureStore()
    return _store


def init_signature_store(*, path: Optional[str] = None, cap: int = 500) -> SignatureStore:
    global _store
    _store = SignatureStore(path=path, cap=cap)
    return _store


def reset_signature_store() -> None:
    global _store
    _store = None
