"""Per-entity behavioural feature extraction.

A :class:`FeatureStore` keeps bounded, time-windowed event histories for
three entity views — source IP, username, and /24 subnet — and, for every
observed event, returns one :class:`FeatureVector` per view. Downstream
scorers (z-score baseline, isolation forest) and the dedicated vector
detectors (port scan, credential stuffing, low-and-slow brute force) read
those vectors; none of them read the raw event message.
"""

from __future__ import annotations

import ipaddress
import math
import statistics
from collections import Counter, OrderedDict, deque
from dataclasses import dataclass, fields
from datetime import datetime, timedelta, timezone
from threading import Lock
from typing import ClassVar, Iterable

from app.models.event import Event

_FAIL_STATUSES = {401, 403, 423, 429}
_FAIL_WORDS = ("failed", "invalid", "denied", "unauthorized")


@dataclass
class FeatureVector:
    fail_ratio: float = 0.0
    attempts_per_min: float = 0.0
    distinct_users: float = 0.0
    distinct_ips: float = 0.0
    distinct_ports: float = 0.0
    port_sequentiality: float = 0.0
    inter_arrival_mean: float = 0.0
    inter_arrival_std: float = 0.0
    ua_entropy: float = 0.0
    hour_of_day_dev: float = 0.0
    endpoint_diversity: float = 0.0

    FIELDS: ClassVar[tuple[str, ...]] = ()  # populated below

    def as_list(self) -> list[float]:
        return [float(getattr(self, f)) for f in FeatureVector.FIELDS]

    def as_dict(self) -> dict[str, float]:
        return {f: round(float(getattr(self, f)), 4) for f in FeatureVector.FIELDS}


FeatureVector.FIELDS = tuple(f.name for f in fields(FeatureVector))


def subnet_of(ip: str) -> str:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if addr.version == 4:
        return str(ipaddress.ip_network(f"{ip}/24", strict=False))
    return str(ipaddress.ip_network(f"{ip}/64", strict=False))


def entity_keys(event: Event) -> dict[str, str]:
    ip = str(event.source_ip)
    keys = {"ip": ip, "subnet": subnet_of(ip)}
    if event.username:
        keys["user"] = event.username
    return keys


def _is_failure(e: Event) -> bool:
    if e.status_code is not None:
        return e.status_code in _FAIL_STATUSES
    msg = e.message.lower()
    return any(w in msg for w in _FAIL_WORDS)


def _entropy(values: Iterable[str]) -> float:
    counts = Counter(values)
    n = sum(counts.values())
    if n <= 1:
        return 0.0
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _sequentiality(ports: Iterable[int]) -> float:
    ps = sorted(set(ports))
    if len(ps) < 3:
        return 0.0
    diffs = [b - a for a, b in zip(ps, ps[1:])]
    return sum(1 for d in diffs if d == 1) / len(diffs)


def compute_features(events: list[Event]) -> FeatureVector:
    """Pure function: events (chronological, same entity) -> FeatureVector."""
    if not events:
        return FeatureVector()
    n = len(events)
    ts = sorted(e.timestamp for e in events)
    span_s = max((ts[-1] - ts[0]).total_seconds(), 60.0)
    gaps = [(b - a).total_seconds() for a, b in zip(ts, ts[1:])]

    ports = [e.dest_port for e in events if e.dest_port is not None]
    latest = events[-1]

    return FeatureVector(
        fail_ratio=sum(1 for e in events if _is_failure(e)) / n,
        attempts_per_min=n * 60.0 / span_s,
        distinct_users=float(len({e.username for e in events if e.username})),
        distinct_ips=float(len({str(e.source_ip) for e in events})),
        distinct_ports=float(len(set(ports))),
        port_sequentiality=_sequentiality(ports),
        inter_arrival_mean=statistics.fmean(gaps) if gaps else 0.0,
        inter_arrival_std=statistics.pstdev(gaps) if len(gaps) > 1 else 0.0,
        ua_entropy=_entropy(e.user_agent for e in events if e.user_agent),
        hour_of_day_dev=abs(latest.timestamp.hour - 13) / 12.0,
        endpoint_diversity=len({e.endpoint for e in events if e.endpoint}) / n,
    )


class FeatureStore:
    """Bounded rolling windows per (entity_type, key) → FeatureVector."""

    def __init__(self, *, window_seconds: int = 300, cap: int = 200, max_entities: int = 5000) -> None:
        self._window = timedelta(seconds=window_seconds)
        self._cap = cap
        self._max_entities = max_entities
        self._lock = Lock()
        self._buckets: dict[str, "OrderedDict[str, deque[Event]]"] = {
            "ip": OrderedDict(), "user": OrderedDict(), "subnet": OrderedDict()
        }

    def _bucket(self, etype: str, key: str) -> deque[Event]:
        od = self._buckets[etype]
        buf = od.get(key)
        if buf is None:
            buf = deque(maxlen=self._cap)
            od[key] = buf
            while len(od) > self._max_entities:
                od.popitem(last=False)
        else:
            od.move_to_end(key)
        return buf

    def _windowed(self, buf: deque[Event]) -> list[Event]:
        cutoff = datetime.now(timezone.utc) - self._window
        return sorted((e for e in buf if e.timestamp >= cutoff), key=lambda e: e.timestamp)

    def observe(self, event: Event) -> dict[str, FeatureVector]:
        """Append ``event`` to every applicable view and return fresh vectors."""
        out: dict[str, FeatureVector] = {}
        with self._lock:
            for etype, key in entity_keys(event).items():
                buf = self._bucket(etype, key)
                buf.append(event)
                out[etype] = compute_features(self._windowed(buf))
        return out

    def features_for(self, etype: str, key: str) -> FeatureVector:
        with self._lock:
            buf = self._buckets[etype].get(key)
            return compute_features(self._windowed(buf)) if buf else FeatureVector()

    def events_for(self, etype: str, key: str) -> list[Event]:
        with self._lock:
            buf = self._buckets[etype].get(key)
            return self._windowed(buf) if buf else []

    def reset(self) -> None:
        with self._lock:
            for od in self._buckets.values():
                od.clear()
