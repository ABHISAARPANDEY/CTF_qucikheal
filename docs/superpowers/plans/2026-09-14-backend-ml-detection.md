# Backend ML Detection Layer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add behavioural feature extraction, statistical baselining, IsolationForest scoring, campaign clustering, dedicated port-scan / credential-stuffing / low-and-slow detectors, runtime-configurable thresholds, an Alert lifecycle store, a background mixed-traffic generator, incident reports and an evaluation script to the SentinelAI FastAPI backend.

**Architecture:** The existing multi-signal voting engine (`app/engine/detection.py`) is kept; new scorers plug in as additional `Signal`s. A `FeatureStore` maintains per-IP / per-user / per-/24 rolling windows and emits `FeatureVector`s; `BaselineScorer` (Welford z-scores over the entity population), `IsolationForestScorer` (sklearn) and `CampaignClusterer` (fingerprint → many IPs) consume those vectors. Risk is rebudgeted with a per-factor breakdown. A `Thresholds` singleton replaces hard-coded constants and is editable over REST. An `AlertStore` dedupes threats into lifecycle-bearing alerts. A `TrafficGenerator` streams mixed benign + attack-session events through the pipeline.

**Tech Stack:** Python 3.11+, FastAPI, Pydantic v2, numpy, scikit-learn, pytest. All commands below run from `sentinel-ai-backend/`.

---

## File map

| File | Responsibility |
|---|---|
| `app/core/thresholds.py` (new) | `Thresholds` model, singleton get/set/reset, JSON persistence |
| `app/models/event.py` (modify) | optional telemetry fields |
| `app/models/threat.py` (modify) | `CREDENTIAL_STUFFING`, `BENIGN`; breakdown/entity/features/zscores/campaign/mitre fields |
| `app/models/alert.py` (new) | `Alert`, `AlertStatus`, `Entity` |
| `app/engine/features.py` (new) | `FeatureVector`, `FeatureStore` |
| `app/engine/anomaly.py` (new) | `BaselineScorer`, `IsolationForestScorer`, `CampaignClusterer`, `AnomalyEngine` singleton |
| `app/engine/detection.py` (modify) | new signals, thresholds, risk breakdown, MITRE, benign path |
| `app/engine/decision.py` (modify) | read tier thresholds from `Thresholds` |
| `app/engine/simulation.py` (modify) | `AttackSession`, new generators, `benign` |
| `app/services/alert_store.py` (new) | ring buffer, dedupe, suppression, WS broadcast |
| `app/services/traffic_generator.py` (new) | background stream, stats |
| `app/services/reports.py` (new) | incident summary JSON + Markdown |
| `app/services/pipeline.py` (modify) | `explain` flag |
| `app/api/routes.py` (modify) | thresholds, alerts, traffic, replay, reports routes |
| `app/models/ws_frames.py` (modify) | `stats`, `alert_new`, `alert_update`, `config_update` frames |
| `app/main.py` (modify) | wire thresholds load, anomaly engine warm-up, traffic generator |
| `app/core/config.py` (modify) | traffic + thresholds settings |
| `scripts/eval_detection.py` (new) | precision/recall per attack type |
| `tests/test_thresholds.py`, `tests/test_features.py`, `tests/test_anomaly.py`, `tests/test_detection_vectors.py`, `tests/test_alert_store.py`, `tests/test_simulation_sessions.py`, `tests/test_routes_new.py`, `tests/test_reports.py` (new) | |

---

### Task 1: Dependencies and Thresholds model

**Files:**
- Modify: `requirements.txt`
- Create: `app/core/thresholds.py`
- Modify: `app/core/config.py`
- Test: `tests/test_thresholds.py`

- [ ] **Step 1: Add dependencies**

Append to `requirements.txt`:
```
numpy>=1.26,<3.0
scikit-learn>=1.5,<2.0
```
Run: `pip install -r requirements.txt` — Expected: installs numpy and scikit-learn.

- [ ] **Step 2: Write the failing test**

`tests/test_thresholds.py`:
```python
import json

import pytest

from app.core import thresholds as th


@pytest.fixture(autouse=True)
def _reset(tmp_path, monkeypatch):
    monkeypatch.setattr(th, "_PATH", tmp_path / "thresholds.json")
    th.reset_thresholds()
    yield
    th.reset_thresholds()


def test_defaults_are_sane():
    t = th.get_thresholds()
    assert t.alert_min_risk == 4.0
    assert t.sev_critical > t.sev_high > t.sev_medium > t.sev_low


def test_set_persists_and_reloads():
    t = th.get_thresholds().model_copy(update={"alert_min_risk": 6.5})
    th.set_thresholds(t)
    assert th.get_thresholds().alert_min_risk == 6.5
    assert json.loads(th._PATH.read_text())["alert_min_risk"] == 6.5
    th._current = None
    assert th.get_thresholds().alert_min_risk == 6.5


def test_reset_restores_defaults():
    th.set_thresholds(th.get_thresholds().model_copy(update={"alert_min_risk": 9.0}))
    th.reset_thresholds()
    assert th.get_thresholds().alert_min_risk == 4.0
    assert not th._PATH.exists()


def test_validation_rejects_out_of_range():
    with pytest.raises(Exception):
        th.Thresholds(alert_min_risk=12)
```

- [ ] **Step 3: Run test to verify it fails**

Run: `pytest tests/test_thresholds.py -v --no-cov`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.core.thresholds'`

- [ ] **Step 4: Implement thresholds module**

`app/core/thresholds.py`:
```python
"""Runtime-configurable detection thresholds.

A single :class:`Thresholds` instance is the source of truth for every
tunable in the detection / decision / alerting path. It can be replaced at
runtime (``PUT /api/v1/config/thresholds``) and is persisted to a JSON
file so operator tuning survives restarts.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


class Thresholds(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    # Alerting
    alert_min_risk: float = Field(default=4.0, ge=0.0, le=10.0)
    dedupe_window_s: int = Field(default=60, ge=1, le=3600)

    # Severity cut points on the 0-10 risk scale
    sev_critical: float = Field(default=8.5, ge=0.0, le=10.0)
    sev_high: float = Field(default=6.5, ge=0.0, le=10.0)
    sev_medium: float = Field(default=4.0, ge=0.0, le=10.0)
    sev_low: float = Field(default=2.0, ge=0.0, le=10.0)

    # Decision tiers
    high_risk: float = Field(default=7.0, ge=0.0, le=10.0)
    low_risk: float = Field(default=3.0, ge=0.0, le=10.0)
    high_confidence: float = Field(default=0.75, ge=0.0, le=1.0)
    low_confidence: float = Field(default=0.40, ge=0.0, le=1.0)

    # Vector detectors
    port_scan_min_ports: int = Field(default=10, ge=2, le=1000)
    port_scan_seq: float = Field(default=0.7, ge=0.0, le=1.0)
    stuffing_min_users: int = Field(default=8, ge=2, le=1000)
    stuffing_fail_ratio: float = Field(default=0.8, ge=0.0, le=1.0)
    lowslow_min_ips: int = Field(default=5, ge=2, le=1000)
    lowslow_fail_ratio: float = Field(default=0.8, ge=0.0, le=1.0)
    lowslow_min_gap_s: float = Field(default=5.0, ge=0.0, le=3600.0)

    # Statistical baseline
    zscore_fire: float = Field(default=2.0, ge=0.0, le=10.0)
    zscore_max: float = Field(default=4.0, ge=0.1, le=20.0)
    baseline_warmup: int = Field(default=10, ge=1, le=10000)

    # Campaign clustering
    campaign_min_ips: int = Field(default=6, ge=2, le=10000)
    campaign_min_subnets: int = Field(default=3, ge=1, le=10000)

    # Isolation forest
    if_contamination: float = Field(default=0.05, gt=0.0, le=0.5)
    if_retrain_s: int = Field(default=300, ge=10, le=86400)


_PATH: Path = Path("thresholds.json")
_current: Optional[Thresholds] = None


def _load_from_disk() -> Thresholds:
    if _PATH.exists():
        try:
            return Thresholds.model_validate(json.loads(_PATH.read_text()))
        except Exception:
            pass
    return Thresholds()


def get_thresholds() -> Thresholds:
    global _current
    if _current is None:
        _current = _load_from_disk()
    return _current


def set_thresholds(new: Thresholds) -> Thresholds:
    global _current
    _current = new
    _PATH.write_text(json.dumps(new.model_dump(), indent=2))
    return _current


def reset_thresholds() -> Thresholds:
    global _current
    _current = Thresholds()
    if _PATH.exists():
        _PATH.unlink()
    return _current


def configure_path(path: str) -> None:
    """Point persistence at ``path`` (called from app startup)."""
    global _PATH, _current
    _PATH = Path(path)
    _current = None
```

- [ ] **Step 5: Add settings**

In `app/core/config.py`, after `banking_attack_duration_seconds`, add:
```python
    thresholds_path: str = Field(default="thresholds.json")
    traffic_enabled: bool = Field(default=True)
    traffic_rate_eps: float = Field(default=12.0, gt=0, le=500)
    traffic_benign_ratio: float = Field(default=0.9, ge=0.0, le=1.0)
```

- [ ] **Step 6: Run test to verify it passes**

Run: `pytest tests/test_thresholds.py -v --no-cov`
Expected: 4 passed

- [ ] **Step 7: Commit**

```bash
git add requirements.txt app/core/thresholds.py app/core/config.py tests/test_thresholds.py
git commit -m "feat(backend): runtime-configurable Thresholds model with JSON persistence"
```

---

### Task 2: Extend Event and Threat models

**Files:**
- Modify: `app/models/event.py`
- Modify: `app/models/threat.py`
- Test: `tests/test_models_ext.py`

- [ ] **Step 1: Write the failing test**

`tests/test_models_ext.py`:
```python
from app.models.event import Event, EventType, Severity
from app.models.threat import Threat, ThreatType


def test_event_accepts_optional_telemetry_fields():
    e = Event(
        source_ip="203.0.113.7",
        event_type=EventType.AUTH,
        severity=Severity.LOW,
        message="POST /api/login status=401",
        username="j.smith",
        dest_port=443,
        user_agent="Mozilla/5.0",
        status_code=401,
        endpoint="/api/login",
        geo="US",
        asn=7922,
        label="credential_stuffing",
    )
    assert e.username == "j.smith"
    assert e.status_code == 401


def test_event_defaults_are_none():
    e = Event(source_ip="1.1.1.1", event_type=EventType.NETWORK, severity=Severity.INFO, message="x")
    assert e.username is None and e.dest_port is None and e.label is None


def test_threat_new_fields_default_empty():
    t = Threat(threat_type=ThreatType.CREDENTIAL_STUFFING, confidence=0.5, risk_score=5.0, severity=Severity.MEDIUM)
    assert t.risk_breakdown == {}
    assert t.entity is None
    assert t.features == {}
    assert t.zscores == {}
    assert t.campaign_id is None
    assert t.mitre == []
    assert ThreatType.BENIGN.value == "benign"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_models_ext.py -v --no-cov`
Expected: FAIL — `ValidationError: Extra inputs are not permitted` / `AttributeError: CREDENTIAL_STUFFING`

- [ ] **Step 3: Add Event fields**

In `app/models/event.py`, after the `message` field inside `class Event`, add:
```python
    # Optional structured telemetry (all additive; detection tolerates None).
    username: str | None = Field(default=None, max_length=256, description="Account targeted or acting.")
    dest_port: int | None = Field(default=None, ge=0, le=65535, description="Destination port.")
    user_agent: str | None = Field(default=None, max_length=512)
    status_code: int | None = Field(default=None, ge=100, le=599)
    endpoint: str | None = Field(default=None, max_length=512)
    geo: str | None = Field(default=None, max_length=2, description="ISO-3166 alpha-2 country.")
    asn: int | None = Field(default=None, ge=0)
    label: str | None = Field(
        default=None,
        max_length=64,
        description="Ground-truth attack label for evaluation only. Never read by detection.",
    )
```

- [ ] **Step 4: Add Threat fields and enum values**

In `app/models/threat.py`:

Add to `ThreatType` after `INSIDER`:
```python
    CREDENTIAL_STUFFING = "credential_stuffing"
    BENIGN = "benign"
```

Add to `Threat` after `correlation`:
```python
    risk_breakdown: dict[str, float] = Field(
        default_factory=dict,
        description="Per-factor contribution to risk_score (sums to risk_score).",
    )
    entity: dict[str, str] | None = Field(
        default=None,
        description="Primary entity the threat is attributed to: {'type': 'ip'|'user'|'subnet', 'key': ...}.",
    )
    features: dict[str, float] = Field(
        default_factory=dict,
        description="Behavioural feature vector of the primary entity at detection time.",
    )
    zscores: dict[str, float] = Field(
        default_factory=dict,
        description="Per-feature z-scores vs. the entity-population baseline.",
    )
    campaign_id: str | None = Field(default=None, description="Distributed-campaign cluster id, if any.")
    mitre: list[str] = Field(default_factory=list, description="MITRE ATT&CK technique ids.")
```

- [ ] **Step 5: Run test to verify it passes**

Run: `pytest tests/test_models_ext.py -v --no-cov`
Expected: 3 passed

- [ ] **Step 6: Run the full existing suite to confirm nothing broke**

Run: `pytest --no-cov -q`
Expected: all pass (existing 2 tests still green).

- [ ] **Step 7: Commit**

```bash
git add app/models/event.py app/models/threat.py tests/test_models_ext.py
git commit -m "feat(models): optional telemetry fields on Event; breakdown/entity/features/mitre on Threat"
```

---

### Task 3: FeatureStore and FeatureVector

**Files:**
- Create: `app/engine/features.py`
- Test: `tests/test_features.py`

- [ ] **Step 1: Write the failing test**

`tests/test_features.py`:
```python
from datetime import datetime, timedelta, timezone

from app.engine.features import FeatureStore, FeatureVector, entity_keys
from app.models.event import Event, EventType, Severity


def _ev(ip="203.0.113.5", user=None, port=None, status=None, ua=None, ep=None, ts=None, msg="x"):
    return Event(
        source_ip=ip,
        event_type=EventType.AUTH,
        severity=Severity.LOW,
        message=msg,
        username=user,
        dest_port=port,
        status_code=status,
        user_agent=ua,
        endpoint=ep,
        timestamp=ts or datetime.now(timezone.utc),
    )


def test_entity_keys_subnet_and_optional_user():
    keys = entity_keys(_ev(ip="10.20.30.40", user="alice"))
    assert keys == {"ip": "10.20.30.40", "user": "alice", "subnet": "10.20.30.0/24"}
    assert "user" not in entity_keys(_ev(ip="10.20.30.40"))


def test_feature_vector_field_order_is_stable():
    assert FeatureVector.FIELDS[0] == "fail_ratio"
    assert len(FeatureVector().as_list()) == len(FeatureVector.FIELDS)


def test_fail_ratio_and_distinct_users_per_ip():
    store = FeatureStore()
    for i in range(10):
        fv = store.observe(_ev(user=f"u{i}", status=401))["ip"]
    assert fv.fail_ratio == 1.0
    assert fv.distinct_users == 10


def test_port_sequentiality_detects_sequential_scan():
    store = FeatureStore()
    for p in range(20, 40):
        fv = store.observe(_ev(port=p))["ip"]
    assert fv.distinct_ports == 20
    assert fv.port_sequentiality >= 0.9


def test_random_ports_have_low_sequentiality():
    store = FeatureStore()
    for p in (22, 3389, 8080, 443, 53, 25, 5432, 6379):
        fv = store.observe(_ev(port=p))["ip"]
    assert fv.port_sequentiality < 0.3


def test_low_slow_user_view_counts_distinct_ips_and_gap():
    store = FeatureStore()
    base = datetime.now(timezone.utc) - timedelta(seconds=200)
    for i in range(6):
        fv = store.observe(
            _ev(ip=f"198.51.100.{i}", user="victim", status=401, ts=base + timedelta(seconds=30 * i))
        )["user"]
    assert fv.distinct_ips == 6
    assert 25 <= fv.inter_arrival_mean <= 35
    assert fv.fail_ratio == 1.0


def test_window_expiry_drops_old_events():
    store = FeatureStore(window_seconds=10)
    old = datetime.now(timezone.utc) - timedelta(seconds=60)
    store.observe(_ev(user="a", ts=old))
    fv = store.observe(_ev(user="b"))["ip"]
    assert fv.distinct_users == 1


def test_ua_entropy_zero_for_single_agent_positive_for_many():
    store = FeatureStore()
    for _ in range(5):
        fv = store.observe(_ev(ua="UA-1"))["ip"]
    assert fv.ua_entropy == 0.0
    store2 = FeatureStore()
    for i in range(8):
        fv2 = store2.observe(_ev(ua=f"UA-{i}"))["ip"]
    assert fv2.ua_entropy > 2.0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_features.py -v --no-cov`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.engine.features'`

- [ ] **Step 3: Implement features module**

`app/engine/features.py`:
```python
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
from typing import Iterable

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

    FIELDS: tuple[str, ...] = ()  # populated below

    def as_list(self) -> list[float]:
        return [float(getattr(self, f)) for f in FeatureVector.FIELDS]

    def as_dict(self) -> dict[str, float]:
        return {f: round(float(getattr(self, f)), 4) for f in FeatureVector.FIELDS}


FeatureVector.FIELDS = tuple(f.name for f in fields(FeatureVector) if f.name != "FIELDS")


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


def compute_features(events: list[Event], *, now: datetime | None = None) -> FeatureVector:
    """Pure function: events (chronological, same entity) -> FeatureVector."""
    if not events:
        return FeatureVector()
    now = now or datetime.now(timezone.utc)
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_features.py -v --no-cov`
Expected: 8 passed

- [ ] **Step 5: Commit**

```bash
git add app/engine/features.py tests/test_features.py
git commit -m "feat(engine): FeatureStore with per-ip/user/subnet behavioural feature vectors"
```

---

### Task 4: Anomaly scorers (baseline z-score, IsolationForest, campaign clustering)

**Files:**
- Create: `app/engine/anomaly.py`
- Test: `tests/test_anomaly.py`

- [ ] **Step 1: Write the failing test**

`tests/test_anomaly.py`:
```python
import random

import numpy as np

from app.core import thresholds as th
from app.engine.anomaly import (
    AnomalyEngine,
    BaselineScorer,
    CampaignClusterer,
    IsolationForestScorer,
)
from app.engine.features import FeatureVector
from app.models.event import Event, EventType, Severity


def _fv(**kw):
    return FeatureVector(**kw)


def test_baseline_no_signal_before_warmup():
    s = BaselineScorer()
    sig, z = s.score("ip", _fv(fail_ratio=1.0))
    assert sig.fired is False and z == {}


def test_baseline_fires_on_outlier_after_warmup():
    s = BaselineScorer()
    rng = random.Random(1)
    for _ in range(50):
        s.update("ip", _fv(fail_ratio=rng.uniform(0.0, 0.1), attempts_per_min=rng.uniform(1, 3)))
    sig, z = s.score("ip", _fv(fail_ratio=1.0, attempts_per_min=40))
    assert sig.fired is True
    assert sig.strength > 0.5
    assert z["fail_ratio"] > 2.0


def test_isolation_forest_flags_outlier():
    rng = np.random.default_rng(0)
    benign = np.column_stack([
        rng.uniform(0, 0.1, 500),      # fail_ratio
        rng.uniform(1, 4, 500),        # attempts_per_min
        rng.integers(1, 3, 500),       # distinct_users
        np.ones(500),                  # distinct_ips
        rng.integers(1, 3, 500),       # distinct_ports
        np.zeros(500),                 # port_sequentiality
        rng.uniform(10, 40, 500),      # inter_arrival_mean
        rng.uniform(1, 10, 500),       # inter_arrival_std
        rng.uniform(0, 0.5, 500),      # ua_entropy
        rng.uniform(0, 0.5, 500),      # hour_of_day_dev
        rng.uniform(0.2, 0.6, 500),    # endpoint_diversity
    ])
    s = IsolationForestScorer(random_state=0)
    s.fit(benign)
    normal = s.score(_fv(fail_ratio=0.05, attempts_per_min=2, distinct_users=1, distinct_ips=1,
                         distinct_ports=1, inter_arrival_mean=20, inter_arrival_std=3,
                         ua_entropy=0.2, hour_of_day_dev=0.2, endpoint_diversity=0.4))
    outlier = s.score(_fv(fail_ratio=1.0, attempts_per_min=60, distinct_users=40, distinct_ips=1,
                          distinct_ports=1, inter_arrival_mean=1, inter_arrival_std=0.1,
                          ua_entropy=0.0, hour_of_day_dev=0.9, endpoint_diversity=0.02))
    assert normal.fired is False
    assert outlier.fired is True and outlier.strength > 0.3


def test_isolation_forest_unfitted_is_silent():
    s = IsolationForestScorer()
    assert s.score(_fv()).fired is False


def _ev(ip, user=None, ua="UA-X", ep="/oauth/token"):
    return Event(source_ip=ip, event_type=EventType.AUTH, severity=Severity.LOW,
                 message="POST /oauth/token status=401", username=user, user_agent=ua, endpoint=ep, status_code=401)


def test_campaign_clusterer_groups_many_ips_same_fingerprint():
    th.reset_thresholds()
    c = CampaignClusterer()
    match = None
    for i in range(12):
        match = c.observe(_ev(f"{10 + i}.{i}.{i}.{i}", user=f"u{i}"))
    assert match is not None
    assert match.signal.fired is True
    assert match.distinct_ips == 12
    assert match.distinct_subnets >= 3
    assert isinstance(match.campaign_id, str) and len(match.campaign_id) > 8


def test_campaign_clusterer_ignores_single_ip():
    c = CampaignClusterer()
    for _ in range(20):
        m = c.observe(_ev("1.2.3.4"))
    assert m is None or m.signal.fired is False


def test_engine_analyze_returns_all_parts():
    eng = AnomalyEngine()
    eng.warm_up(n=200, seed=1)
    res = eng.analyze(_ev("9.9.9.9", user="bob"))
    assert res.entity == {"type": "ip", "key": "9.9.9.9"}
    assert set(res.features) == {"ip", "user", "subnet"}
    assert {s.name for s in res.signals} >= {"behavioral_zscore", "isolation_forest", "distributed_campaign"}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_anomaly.py -v --no-cov`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.engine.anomaly'`

- [ ] **Step 3: Implement anomaly module**

`app/engine/anomaly.py`:
```python
"""Statistical + unsupervised anomaly scorers.

Three independent scorers, each returning a :class:`Signal` compatible with
the voting engine in :mod:`app.engine.detection`:

    BaselineScorer          — Welford online mean/variance per feature over
                              the *population* of entities of a type; emits
                              ``behavioral_zscore``. Catches "this IP looks
                              unlike a typical IP" without needing history
                              for that specific IP — essential for fresh
                              attacker addresses.
    IsolationForestScorer   — scikit-learn IsolationForest over feature
                              vectors; emits ``isolation_forest``. This is
                              the unsupervised / zero-day path.
    CampaignClusterer       — groups events by (user_agent, endpoint,
                              username) fingerprint; when one fingerprint
                              spans many IPs across many subnets it emits
                              ``distributed_campaign`` — the residential-
                              proxy-pool detector.

:class:`AnomalyEngine` owns a :class:`FeatureStore` and the three scorers
and exposes ``analyze(event) -> AnalysisResult``.
"""

from __future__ import annotations

import math
import uuid
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from threading import Lock
from typing import Optional

import numpy as np

from app.core.thresholds import get_thresholds
from app.engine.features import FeatureStore, FeatureVector, entity_keys, subnet_of
from app.models.event import Event


@dataclass(frozen=True)
class Signal:
    """Mirror of detection.Signal (kept here to avoid an import cycle)."""

    name: str
    fired: bool
    strength: float


# ---------------------------------------------------------------------------
# Baseline z-score
# ---------------------------------------------------------------------------


class _Welford:
    __slots__ = ("n", "mean", "m2")

    def __init__(self) -> None:
        self.n = 0
        self.mean = 0.0
        self.m2 = 0.0

    def push(self, x: float) -> None:
        self.n += 1
        d = x - self.mean
        self.mean += d / self.n
        self.m2 += d * (x - self.mean)

    @property
    def std(self) -> float:
        return math.sqrt(self.m2 / (self.n - 1)) if self.n > 1 else 0.0


class BaselineScorer:
    """Population baseline per entity type: how unusual is this vector?"""

    def __init__(self) -> None:
        self._stats: dict[str, dict[str, _Welford]] = {}
        self._lock = Lock()

    def update(self, etype: str, fv: FeatureVector) -> None:
        with self._lock:
            per = self._stats.setdefault(etype, {f: _Welford() for f in FeatureVector.FIELDS})
            for f, v in zip(FeatureVector.FIELDS, fv.as_list()):
                per[f].push(v)

    def score(self, etype: str, fv: FeatureVector) -> tuple[Signal, dict[str, float]]:
        t = get_thresholds()
        with self._lock:
            per = self._stats.get(etype)
            if per is None or next(iter(per.values())).n < t.baseline_warmup:
                return Signal("behavioral_zscore", False, 0.0), {}
            z: dict[str, float] = {}
            for f, v in zip(FeatureVector.FIELDS, fv.as_list()):
                w = per[f]
                sd = w.std
                z[f] = 0.0 if sd < 1e-9 else (v - w.mean) / sd
        zmax = max(abs(v) for v in z.values())
        fired = zmax >= t.zscore_fire
        strength = min(1.0, zmax / t.zscore_max) if fired else 0.0
        return Signal("behavioral_zscore", fired, round(strength, 2)), {k: round(v, 2) for k, v in z.items()}

    def reset(self) -> None:
        with self._lock:
            self._stats.clear()


# ---------------------------------------------------------------------------
# Isolation forest
# ---------------------------------------------------------------------------


class IsolationForestScorer:
    def __init__(self, *, n_estimators: int = 100, random_state: int = 42) -> None:
        self._n_estimators = n_estimators
        self._random_state = random_state
        self._model = None
        self._lock = Lock()
        self.fitted_at: Optional[datetime] = None
        self.train_size: int = 0

    def fit(self, X: np.ndarray) -> None:
        from sklearn.ensemble import IsolationForest

        model = IsolationForest(
            n_estimators=self._n_estimators,
            contamination=get_thresholds().if_contamination,
            random_state=self._random_state,
        )
        model.fit(np.asarray(X, dtype=float))
        with self._lock:
            self._model = model
            self.fitted_at = datetime.now(timezone.utc)
            self.train_size = int(len(X))

    @property
    def is_fitted(self) -> bool:
        return self._model is not None

    def score(self, fv: FeatureVector) -> Signal:
        with self._lock:
            model = self._model
        if model is None:
            return Signal("isolation_forest", False, 0.0)
        d = float(model.decision_function(np.asarray([fv.as_list()], dtype=float))[0])
        # decision_function: >0 inlier, <0 outlier; typical outlier range ~[-0.3, 0]
        fired = d < 0.0
        strength = min(1.0, -d / 0.2) if fired else 0.0
        return Signal("isolation_forest", fired, round(strength, 2))


# ---------------------------------------------------------------------------
# Campaign clustering
# ---------------------------------------------------------------------------


@dataclass
class CampaignMatch:
    campaign_id: str
    fingerprint: tuple[str, str, str]
    distinct_ips: int
    distinct_subnets: int
    members: list[str]
    signal: Signal


class CampaignClusterer:
    def __init__(self, *, window_seconds: int = 300, cap: int = 500, max_fingerprints: int = 2000) -> None:
        self._window = timedelta(seconds=window_seconds)
        self._cap = cap
        self._max = max_fingerprints
        self._lock = Lock()
        self._by_fp: "OrderedDict[tuple[str, str, str], deque[tuple[datetime, str]]]" = OrderedDict()

    @staticmethod
    def fingerprint(event: Event) -> tuple[str, str, str]:
        return (event.user_agent or "-", event.endpoint or "-", event.username or "-")

    def observe(self, event: Event) -> Optional[CampaignMatch]:
        t = get_thresholds()
        fp = self.fingerprint(event)
        if fp == ("-", "-", "-"):
            return None
        ip = str(event.source_ip)
        cutoff = datetime.now(timezone.utc) - self._window
        with self._lock:
            buf = self._by_fp.get(fp)
            if buf is None:
                buf = deque(maxlen=self._cap)
                self._by_fp[fp] = buf
                while len(self._by_fp) > self._max:
                    self._by_fp.popitem(last=False)
            else:
                self._by_fp.move_to_end(fp)
            buf.append((event.timestamp, ip))
            live = [ip_ for ts, ip_ in buf if ts >= cutoff]
        ips = set(live)
        subnets = {subnet_of(i) for i in ips}
        fired = len(ips) >= t.campaign_min_ips and len(subnets) >= t.campaign_min_subnets
        strength = min(1.0, len(ips) / (2.0 * t.campaign_min_ips)) if fired else 0.0
        return CampaignMatch(
            campaign_id=str(uuid.uuid5(uuid.NAMESPACE_URL, "|".join(fp))),
            fingerprint=fp,
            distinct_ips=len(ips),
            distinct_subnets=len(subnets),
            members=sorted(ips)[:50],
            signal=Signal("distributed_campaign", fired, round(strength, 2)),
        )

    def reset(self) -> None:
        with self._lock:
            self._by_fp.clear()


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


@dataclass
class AnalysisResult:
    entity: dict[str, str]
    features: dict[str, FeatureVector]
    zscores: dict[str, float]
    signals: list[Signal]
    campaign: Optional[CampaignMatch] = None
    ip_events: list[Event] = field(default_factory=list)
    user_events: list[Event] = field(default_factory=list)


class AnomalyEngine:
    def __init__(self) -> None:
        self.features = FeatureStore()
        self.baseline = BaselineScorer()
        self.forest = IsolationForestScorer()
        self.campaigns = CampaignClusterer()
        self._recent_vectors: deque[list[float]] = deque(maxlen=4000)

    # -- training ---------------------------------------------------------

    def warm_up(self, *, n: int = 2000, seed: int = 42) -> None:
        """Fit the forest and seed baselines on synthetic benign traffic."""
        from app.engine.simulation import benign_feature_matrix

        X, per_type = benign_feature_matrix(n=n, seed=seed)
        self.forest.fit(X)
        for etype, vectors in per_type.items():
            for fv in vectors:
                self.baseline.update(etype, fv)

    def refit(self) -> bool:
        if len(self._recent_vectors) < 100:
            return False
        self.forest.fit(np.asarray(self._recent_vectors, dtype=float))
        return True

    # -- scoring ----------------------------------------------------------

    def analyze(self, event: Event) -> AnalysisResult:
        keys = entity_keys(event)
        vectors = self.features.observe(event)
        primary_type = "ip"
        primary = vectors[primary_type]

        z_sig, z = self.baseline.score(primary_type, primary)
        if "user" in vectors:
            uz_sig, uz = self.baseline.score("user", vectors["user"])
            if uz_sig.strength > z_sig.strength:
                z_sig, z = uz_sig, {f"user.{k}": v for k, v in uz.items()}
        if_sig = self.forest.score(primary)
        campaign = self.campaigns.observe(event)
        c_sig = campaign.signal if campaign else Signal("distributed_campaign", False, 0.0)

        # Learn from everything; attackers are a small minority so baselines stay honest.
        for etype, fv in vectors.items():
            self.baseline.update(etype, fv)
        self._recent_vectors.append(primary.as_list())

        return AnalysisResult(
            entity={"type": primary_type, "key": keys["ip"]},
            features=vectors,
            zscores=z,
            signals=[z_sig, if_sig, c_sig],
            campaign=campaign if (campaign and campaign.signal.fired) else None,
            ip_events=self.features.events_for("ip", keys["ip"]),
            user_events=self.features.events_for("user", keys["user"]) if "user" in keys else [],
        )

    def reset(self) -> None:
        self.features.reset()
        self.baseline.reset()
        self.campaigns.reset()
        self._recent_vectors.clear()


_engine: Optional[AnomalyEngine] = None


def get_engine() -> AnomalyEngine:
    global _engine
    if _engine is None:
        _engine = AnomalyEngine()
    return _engine


def reset_engine() -> None:
    global _engine
    _engine = None
```

- [ ] **Step 4: Add `benign_feature_matrix` to simulation (needed by warm_up)**

Append to `app/engine/simulation.py` (the full simulator rewrite happens in Task 6; this stub keeps Task 4 green):
```python
def benign_feature_matrix(*, n: int = 2000, seed: int = 42):
    """Synthetic benign FeatureVectors for scorer warm-up.

    Returns ``(X, per_type)`` where ``X`` is an ``n × len(FIELDS)`` numpy
    array of IP-view vectors and ``per_type`` maps entity type → list of
    FeatureVector for baseline seeding.
    """
    import numpy as np

    from app.engine.features import FeatureVector

    rng = random.Random(seed)
    per_type: dict[str, list[FeatureVector]] = {"ip": [], "user": [], "subnet": []}
    rows: list[list[float]] = []
    for _ in range(n):
        ip_fv = FeatureVector(
            fail_ratio=rng.uniform(0.0, 0.12),
            attempts_per_min=rng.uniform(0.5, 4.0),
            distinct_users=float(rng.randint(1, 2)),
            distinct_ips=1.0,
            distinct_ports=float(rng.randint(1, 2)),
            port_sequentiality=0.0,
            inter_arrival_mean=rng.uniform(8.0, 60.0),
            inter_arrival_std=rng.uniform(1.0, 15.0),
            ua_entropy=rng.uniform(0.0, 0.6),
            hour_of_day_dev=rng.uniform(0.0, 0.5),
            endpoint_diversity=rng.uniform(0.2, 0.7),
        )
        per_type["ip"].append(ip_fv)
        rows.append(ip_fv.as_list())
        per_type["user"].append(FeatureVector(
            fail_ratio=rng.uniform(0.0, 0.15),
            attempts_per_min=rng.uniform(0.3, 3.0),
            distinct_users=1.0,
            distinct_ips=float(rng.randint(1, 2)),
            distinct_ports=1.0,
            inter_arrival_mean=rng.uniform(20.0, 120.0),
            inter_arrival_std=rng.uniform(2.0, 30.0),
            ua_entropy=rng.uniform(0.0, 0.4),
            hour_of_day_dev=rng.uniform(0.0, 0.5),
            endpoint_diversity=rng.uniform(0.2, 0.7),
        ))
        per_type["subnet"].append(FeatureVector(
            fail_ratio=rng.uniform(0.0, 0.12),
            attempts_per_min=rng.uniform(1.0, 8.0),
            distinct_users=float(rng.randint(1, 6)),
            distinct_ips=float(rng.randint(1, 6)),
            distinct_ports=float(rng.randint(1, 3)),
            inter_arrival_mean=rng.uniform(4.0, 40.0),
            inter_arrival_std=rng.uniform(1.0, 12.0),
            ua_entropy=rng.uniform(0.3, 1.8),
            hour_of_day_dev=rng.uniform(0.0, 0.5),
            endpoint_diversity=rng.uniform(0.2, 0.7),
        ))
    return np.asarray(rows, dtype=float), per_type
```

- [ ] **Step 5: Run test to verify it passes**

Run: `pytest tests/test_anomaly.py -v --no-cov`
Expected: 8 passed

- [ ] **Step 6: Commit**

```bash
git add app/engine/anomaly.py app/engine/simulation.py tests/test_anomaly.py
git commit -m "feat(engine): baseline z-score, IsolationForest and campaign-cluster anomaly scorers"
```

---

### Task 5: Integrate scorers + vector detectors + risk breakdown into detection.py

**Files:**
- Modify: `app/engine/detection.py`
- Modify: `app/engine/decision.py`
- Test: `tests/test_detection_vectors.py`

- [ ] **Step 1: Write the failing test**

`tests/test_detection_vectors.py`:
```python
from datetime import datetime, timedelta, timezone

import pytest

from app.core import thresholds as th
from app.engine import anomaly
from app.engine.detection import detect, reset_default_context
from app.models.event import Event, EventType, Severity
from app.models.threat import ThreatType


@pytest.fixture(autouse=True)
def _fresh():
    th.reset_thresholds()
    reset_default_context()
    anomaly.reset_engine()
    anomaly.get_engine().warm_up(n=300, seed=7)
    yield
    anomaly.reset_engine()
    reset_default_context()


def _auth(ip, user, status=401, ua="Mozilla/5.0 (X11; Linux) Chrome/120", ep="/api/login", ts=None, sev=Severity.LOW):
    return Event(source_ip=ip, event_type=EventType.AUTH, severity=sev,
                 message=f"POST {ep} user={user} status={status}", username=user,
                 status_code=status, user_agent=ua, endpoint=ep,
                 timestamp=ts or datetime.now(timezone.utc))


def _net(ip, port):
    return Event(source_ip=ip, event_type=EventType.NETWORK, severity=Severity.INFO,
                 message=f"SYN {ip}:{40000 + port} -> 10.0.0.12:{port} flags=S", dest_port=port)


def test_benign_login_is_benign_with_near_zero_risk():
    t = detect(_auth("198.51.100.20", "alice", status=200, sev=Severity.INFO))
    assert t.threat_type == ThreatType.BENIGN
    assert t.risk_score < 1.0
    assert t.mitre == []


def test_port_scan_detected_from_ports_without_keywords():
    last = None
    for p in range(1, 26):
        last = detect(_net("203.0.113.9", p))
    assert last.threat_type == ThreatType.PORT_SCAN
    assert "port_scan" in last.signals
    assert "T1046" in last.mitre
    assert last.risk_score >= 4.0


def test_credential_stuffing_many_users_one_ip():
    last = None
    for i in range(15):
        last = detect(_auth("192.0.2.77", f"user{i}@bank.com"))
    assert last.threat_type == ThreatType.CREDENTIAL_STUFFING
    assert "credential_stuffing" in last.signals
    assert "T1110.004" in last.mitre
    assert last.risk_score >= 4.0


def test_low_and_slow_brute_force_across_rotating_ips():
    base = datetime.now(timezone.utc) - timedelta(seconds=280)
    last = None
    for i in range(8):
        last = detect(_auth(f"198.51.{i}.{i + 1}", "cfo@bank.com", ts=base + timedelta(seconds=30 * i)))
    assert last.threat_type == ThreatType.BRUTE_FORCE
    assert "low_slow_brute" in last.signals
    assert last.entity["type"] == "user"
    assert last.risk_score >= 4.0


def test_distributed_campaign_tags_campaign_id():
    ua = "python-requests/2.31 botpool"
    last = None
    for i in range(12):
        last = detect(_auth(f"{20 + i}.{i}.{i}.{i}", f"v{i}", ua=ua, ep="/oauth/token"))
    assert last.campaign_id is not None
    assert "distributed_campaign" in last.signals


def test_risk_breakdown_sums_to_risk_score():
    last = None
    for i in range(12):
        last = detect(_auth("192.0.2.5", f"u{i}"))
    assert abs(sum(last.risk_breakdown.values()) - last.risk_score) < 0.05
    assert set(last.risk_breakdown) == {
        "severity", "frequency", "repetition", "vector", "behavioral_zscore", "isolation_forest", "distributed_campaign"
    }


def test_thresholds_change_alters_detection():
    th.set_thresholds(th.get_thresholds().model_copy(update={"stuffing_min_users": 100}))
    last = None
    for i in range(15):
        last = detect(_auth("192.0.2.88", f"user{i}"))
    assert "credential_stuffing" not in last.signals
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_detection_vectors.py -v --no-cov`
Expected: FAIL (BENIGN never returned; `port_scan` signal absent; `risk_breakdown` empty).

- [ ] **Step 3: Rewrite detection.py**

Replace the contents of `app/engine/detection.py` from the line `_KEYWORDS: dict[ThreatType, ...` to the end of the file with the following. Keep everything above it (imports, constants, `Signal`, `DetectionContext`, default-context helpers) unchanged, **except** add these imports at the top:

```python
from app.core.thresholds import get_thresholds
from app.engine import anomaly as _anomaly
from app.engine.features import FeatureVector
```

New body:
```python
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
    """How many non-informational events of the same EventType in the window?"""
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


def _signal_credential_stuffing(ip_fv: FeatureVector, subnet_fv: FeatureVector) -> Signal:
    t = get_thresholds()
    best = max(ip_fv.distinct_users, subnet_fv.distinct_users)
    fr = ip_fv.fail_ratio if ip_fv.distinct_users >= subnet_fv.distinct_users else subnet_fv.fail_ratio
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
    i = 0
    for item in history:
        if i < len(pattern) and item == pattern[i]:
            i += 1
            if i == len(pattern):
                return True
    return False


def _detect_correlation(current: ThreatType, ctx: DetectionContext) -> Optional[str]:
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
    ip_fv = analysis.features["ip"]
    subnet_fv = analysis.features["subnet"]
    user_fv = analysis.features.get("user")
    cached: dict[str, Signal] = {
        "frequency":           _signal_frequency(event, ctx),
        "ip_repetition":       _signal_ip_repetition(event, ctx),
        "distributed_sources": _signal_distributed_sources(event, ctx),
        "severity_history":    _signal_severity_history(event, ctx),
        "port_scan":           _signal_port_scan(ip_fv),
        "credential_stuffing": _signal_credential_stuffing(ip_fv, subnet_fv),
        "low_slow_brute":      _signal_low_slow_brute(user_fv),
    }
    ml = [Signal(s.name, s.fired, s.strength) for s in analysis.signals]

    best_type, best_signals, best_score = ThreatType.UNKNOWN, [], 0.0
    for tt in CANDIDATE_THREAT_TYPES:
        signals = _signals_for(tt, event, cached)
        lex = signals[0]
        vec_name = _VECTOR_FOR.get(tt)
        vec_fired = bool(vec_name) and cached[vec_name].fired
        if not lex.fired and not vec_fired and tt != ThreatType.ANOMALY:
            continue
        if tt == ThreatType.ANOMALY and not any(s.fired for s in ml):
            continue
        other = sum(s.strength for s in signals[1:] if s.fired)
        score = 0.5 * lex.strength + (1.0 * cached[vec_name].strength if vec_fired else 0.0) + 0.5 * other
        if tt == ThreatType.ANOMALY:
            score = 0.5 * sum(s.strength for s in ml if s.fired)
        if score > best_score:
            best_type, best_signals, best_score = tt, signals, score

    if best_type == ThreatType.UNKNOWN:
        if event.severity == Severity.INFO and not any(s.fired for s in ml):
            return ThreatType.BENIGN, ml
        best_type = ThreatType.ANOMALY if any(s.fired for s in ml) else ThreatType.UNKNOWN
        best_signals = [cached["frequency"], cached["ip_repetition"], cached["severity_history"]]

    return best_type, best_signals + ml


def _severity_for_risk(risk_score: float) -> Severity:
    t = get_thresholds()
    if risk_score >= t.sev_critical: return Severity.CRITICAL
    if risk_score >= t.sev_high:     return Severity.HIGH
    if risk_score >= t.sev_medium:   return Severity.MEDIUM
    if risk_score >= t.sev_low:      return Severity.LOW
    return Severity.INFO


def update_context(event: Event, context: Optional[DetectionContext] = None) -> None:
    (context or get_default_context()).add(event)


def detect(event: Event, context: Optional[DetectionContext] = None) -> Threat:
    """Run multi-signal, behaviour-aware detection on ``event``."""
    ctx = context or get_default_context()
    ctx.add(event)

    analysis = _anomaly.get_engine().analyze(event)
    threat_type, signals = _select_threat_type(event, ctx, analysis)

    breakdown = risk_breakdown(event, signals)
    risk = round(max(0.0, min(10.0, sum(breakdown.values()))), 2)
    confidence = calculate_confidence(signals)
    severity = _severity_for_risk(risk)
    correlation = _detect_correlation(threat_type, ctx)
    ctx.add_threat(threat_type)

    entity = analysis.entity
    primary_fv = analysis.features["ip"]
    if "low_slow_brute" in {s.name for s in signals if s.fired} and event.username:
        entity = {"type": "user", "key": event.username}
        primary_fv = analysis.features["user"]

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
    )
```

- [ ] **Step 4: Point decision.py tiers at Thresholds**

In `app/engine/decision.py`, replace the four constants block:
```python
HIGH_RISK_THRESHOLD: float = 7.0
LOW_RISK_THRESHOLD:  float = 3.0

HIGH_CONFIDENCE_THRESHOLD: float = 0.75
LOW_CONFIDENCE_THRESHOLD:  float = 0.40
```
with:
```python
from app.core.thresholds import get_thresholds
```
and replace `_resolve_tier` with:
```python
def _resolve_tier(risk_score: float, confidence: float) -> str:
    t = get_thresholds()
    if risk_score >= t.high_risk and confidence >= t.high_confidence:
        return "high"
    if risk_score < t.low_risk or confidence < t.low_confidence:
        return "low"
    return "medium"
```
Also in `decide()`, immediately after `ctx = context or get_default_context()`, add a benign short-circuit:
```python
    if threat.threat_type == ThreatType.BENIGN:
        return [Action(threat_id=threat.id, action_type=ActionType.LOG_ONLY,
                       target=target or f"threat:{threat.id}", status=ActionStatus.PENDING,
                       priority=Priority.P3, reason="Benign traffic — logged for baseline")]
```

- [ ] **Step 5: Export new names from `app/engine/__init__.py`**

Add to imports from `app.engine.detection`: `MITRE, RISK_BUDGET, risk_breakdown` and to `__all__`: `"MITRE", "RISK_BUDGET", "risk_breakdown"`.

- [ ] **Step 6: Run test to verify it passes**

Run: `pytest tests/test_detection_vectors.py -v --no-cov`
Expected: 7 passed. If `test_low_and_slow_brute_force_across_rotating_ips` fails on `entity`, check that `_signal_low_slow_brute` fired (user_fv.distinct_ips ≥ 5, gap ≥ 5s).

- [ ] **Step 7: Run full suite**

Run: `pytest --no-cov -q`
Expected: all pass. The ai_copilot `_THREAT_TYPE_LABEL` dict lacks the new enum values — add to it in `app/services/ai_copilot.py`:
```python
    ThreatType.CREDENTIAL_STUFFING: "credential stuffing campaign",
    ThreatType.BENIGN: "benign activity",
```

- [ ] **Step 8: Commit**

```bash
git add app/engine/detection.py app/engine/decision.py app/engine/__init__.py app/services/ai_copilot.py tests/test_detection_vectors.py
git commit -m "feat(engine): vector detectors, ML signals, risk breakdown, MITRE tags, benign path, threshold-driven tiers"
```

---

### Task 6: Attack sessions and new generators

**Files:**
- Modify: `app/engine/simulation.py`
- Test: `tests/test_simulation_sessions.py`

- [ ] **Step 1: Write the failing test**

`tests/test_simulation_sessions.py`:
```python
from app.engine.simulation import SIMULATORS, AttackSession, SESSION_KINDS, generate_event
from app.models.event import EventType, Severity


def test_registry_has_new_kinds():
    for k in ("benign", "port_scan", "credential_stuffing", "low_slow_brute_force"):
        assert k in SIMULATORS
        assert k in SESSION_KINDS


def test_benign_event_is_info_with_telemetry():
    e = generate_event("benign")
    assert e.severity == Severity.INFO
    assert e.user_agent and e.endpoint and e.status_code is not None
    assert e.label == "benign"


def test_port_scan_session_keeps_ip_and_walks_ports():
    s = AttackSession("port_scan", seed=3)
    evs = [s.next() for _ in range(15)]
    assert len({str(e.source_ip) for e in evs}) == 1
    assert len({e.dest_port for e in evs}) == 15
    assert all(e.event_type == EventType.NETWORK for e in evs)
    assert all("scan" not in e.message.lower() for e in evs)
    assert all(e.label == "port_scan" for e in evs)


def test_credential_stuffing_session_many_users_shared_ua():
    s = AttackSession("credential_stuffing", seed=3)
    evs = [s.next() for _ in range(20)]
    assert len({e.username for e in evs}) >= 18
    assert len({e.user_agent for e in evs}) == 1
    assert all(e.status_code == 401 for e in evs)
    assert len({str(e.source_ip) for e in evs}) >= 5


def test_low_slow_session_rotates_ips_one_user():
    s = AttackSession("low_slow_brute_force", seed=3)
    evs = [s.next() for _ in range(8)]
    assert len({e.username for e in evs}) == 1
    assert len({str(e.source_ip) for e in evs}) == 8
    assert s.delay_hint() >= 1.0


def test_unknown_kind_raises():
    import pytest
    with pytest.raises(KeyError):
        AttackSession("nope")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_simulation_sessions.py -v --no-cov`
Expected: FAIL with `ImportError: cannot import name 'AttackSession'`

- [ ] **Step 3: Add sessions and generators**

In `app/engine/simulation.py`, insert **before** `SIMULATORS = {`:

```python
_UA_POOL: tuple[str, ...] = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/124.0 Mobile Safari/537.36",
    "NeoBank-iOS/5.12.0 (iPhone15,3; iOS 17.4)",
    "NeoBank-Android/5.12.0 (Pixel 8; Android 14)",
)
_BOT_UA_POOL: tuple[str, ...] = (
    "python-requests/2.31.0",
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 Chrome/58.0 Safari/537.36",
    "okhttp/4.9.3",
    "Go-http-client/1.1",
)
_BENIGN_ENDPOINTS: tuple[tuple[str, float], ...] = (
    ("/api/login", 0.18), ("/api/accounts", 0.22), ("/api/transactions", 0.25),
    ("/api/transfer", 0.12), ("/api/cards", 0.08), ("/health", 0.10), ("/api/profile", 0.05),
)
_FIRST_NAMES = ("alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi", "ivan", "judy",
                "mallory", "niaj", "olivia", "peggy", "rupert", "sybil", "trent", "victor", "wendy")
_LAST_NAMES = ("smith", "patel", "garcia", "nguyen", "okafor", "kim", "rossi", "silva", "mueller", "chen")
_GEOS = ("US", "GB", "IN", "DE", "BR", "SG", "CA", "AU")

# A stable population of legitimate customers (ip, user, ua, geo) so per-entity
# baselines have real repeat traffic to learn from.
_rng_pop = random.Random(1234)
_CUSTOMERS: tuple[dict, ...] = tuple(
    {
        "ip": f"{_rng_pop.choice(_PUBLIC_FIRST_OCTETS)}.{_rng_pop.randint(0, 255)}.{_rng_pop.randint(0, 255)}.{_rng_pop.randint(1, 254)}",
        "user": f"{_rng_pop.choice(_FIRST_NAMES)}.{_rng_pop.choice(_LAST_NAMES)}{_rng_pop.randint(1, 99)}@neobank.io",
        "ua": _rng_pop.choice(_UA_POOL),
        "geo": _rng_pop.choice(_GEOS),
    }
    for _ in range(400)
)


def generate_benign_event(rng: random.Random | None = None) -> Event:
    """A normal customer interaction. Occasionally a single mistyped password."""
    r = rng or random
    c = r.choice(_CUSTOMERS)
    endpoint = _weighted_choice(_BENIGN_ENDPOINTS)
    status = 200
    if endpoint == "/api/login" and r.random() < 0.06:
        status = 401
    method = "POST" if endpoint in ("/api/login", "/api/transfer") else "GET"
    return Event(
        source_ip=c["ip"],
        event_type=EventType.AUTH if endpoint == "/api/login" else EventType.SYSTEM,
        severity=Severity.INFO,
        message=f"{method} {endpoint} user={c['user']} status={status} ua={c['ua'][:24]}",
        username=c["user"],
        dest_port=443,
        user_agent=c["ua"],
        status_code=status,
        endpoint=endpoint,
        geo=c["geo"],
        label="benign",
    )


class AttackSession:
    """Stateful multi-event campaign generator.

    ``next()`` returns the next event of the campaign; ``delay_hint()`` is
    the natural spacing in seconds (the traffic generator divides this by a
    ``speed`` factor so a 30-second cadence can play out in 3 seconds for a
    demo).
    """

    def __init__(self, kind: str, *, seed: int | None = None) -> None:
        if kind not in SESSION_KINDS:
            raise KeyError(f"Unknown session kind {kind!r}. Valid: {sorted(SESSION_KINDS)}")
        self.kind = kind
        self.r = random.Random(seed)
        self.n = 0
        self._ip = _random_public_ip_r(self.r)
        self._port_cursor = self.r.randint(1, 1000)
        self._sequential = self.r.random() < 0.6
        self._bot_ua = self.r.choice(_BOT_UA_POOL)
        self._pool_subnets = [
            f"{self.r.choice(_PUBLIC_FIRST_OCTETS)}.{self.r.randint(0, 255)}.{self.r.randint(0, 255)}"
            for _ in range(8)
        ]
        self._target_user = f"{self.r.choice(_FIRST_NAMES)}.{self.r.choice(_LAST_NAMES)}@neobank.io"
        self._endpoint = self.r.choice(("/oauth/token", "/api/login"))

    # -- kinds ----------------------------------------------------------

    def _port_scan(self) -> Event:
        if self._sequential:
            port = self._port_cursor
            self._port_cursor += 1
        else:
            port = self.r.randint(1, 65535)
        sport = self.r.randint(32768, 60999)
        return Event(
            source_ip=self._ip,
            event_type=EventType.NETWORK,
            severity=Severity.INFO,
            message=f"SYN {self._ip}:{sport} -> 10.0.0.12:{port} flags=S",
            dest_port=port,
            label="port_scan",
        )

    def _credential_stuffing(self) -> Event:
        subnet = self.r.choice(self._pool_subnets)
        ip = f"{subnet}.{self.r.randint(1, 254)}"
        user = f"{self.r.choice(_FIRST_NAMES)}.{self.r.choice(_LAST_NAMES)}{self.r.randint(1, 9999)}@gmail.com"
        return Event(
            source_ip=ip,
            event_type=EventType.AUTH,
            severity=Severity.LOW,
            message=f"POST {self._endpoint} user={user} status=401 ua={self._bot_ua}",
            username=user,
            dest_port=443,
            user_agent=self._bot_ua,
            status_code=401,
            endpoint=self._endpoint,
            label="credential_stuffing",
        )

    def _low_slow(self) -> Event:
        ip = _random_public_ip_r(self.r)
        ua = self.r.choice(_UA_POOL)
        return Event(
            source_ip=ip,
            event_type=EventType.AUTH,
            severity=Severity.LOW,
            message=f"POST /api/login user={self._target_user} status=401 ua={ua[:24]}",
            username=self._target_user,
            dest_port=443,
            user_agent=ua,
            status_code=401,
            endpoint="/api/login",
            label="low_slow_brute_force",
        )

    def _legacy(self) -> Event:
        e = SIMULATORS[self.kind]()
        return e.model_copy(update={"label": self.kind})

    def next(self) -> Event:
        self.n += 1
        if self.kind == "port_scan":
            return self._port_scan()
        if self.kind == "credential_stuffing":
            return self._credential_stuffing()
        if self.kind == "low_slow_brute_force":
            return self._low_slow()
        if self.kind == "benign":
            return generate_benign_event(self.r)
        return self._legacy()

    def delay_hint(self) -> float:
        return {
            "port_scan": 0.15,
            "credential_stuffing": 0.4,
            "low_slow_brute_force": 30.0,
            "brute_force": 1.0,
            "ddos": 0.1,
            "sql_injection": 1.5,
            "benign": 0.5,
        }[self.kind]


def _random_public_ip_r(r: random.Random) -> str:
    return f"{r.choice(_PUBLIC_FIRST_OCTETS)}.{r.randint(0, 255)}.{r.randint(0, 255)}.{r.randint(1, 254)}"


SESSION_KINDS: frozenset[str] = frozenset({
    "benign", "port_scan", "credential_stuffing", "low_slow_brute_force",
    "brute_force", "ddos", "sql_injection",
})
```

Then change `SIMULATORS` to:
```python
SIMULATORS: dict[str, Callable[[], Event]] = {
    "ddos": generate_ddos_event,
    "brute_force": generate_bruteforce_event,
    "sql_injection": generate_sql_injection_event,
    "benign": generate_benign_event,
    "port_scan": lambda: AttackSession("port_scan").next(),
    "credential_stuffing": lambda: AttackSession("credential_stuffing").next(),
    "low_slow_brute_force": lambda: AttackSession("low_slow_brute_force").next(),
}
```

Also add `label=` to the three legacy generators' `Event(...)` constructors: `label="ddos"`, `label="brute_force"`, `label="sql_injection"`.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_simulation_sessions.py -v --no-cov`
Expected: 6 passed

- [ ] **Step 5: Commit**

```bash
git add app/engine/simulation.py tests/test_simulation_sessions.py
git commit -m "feat(simulation): benign traffic, port-scan, credential-stuffing and low-and-slow attack sessions"
```

---

### Task 7: Alert model and AlertStore

**Files:**
- Create: `app/models/alert.py`
- Create: `app/services/alert_store.py`
- Modify: `app/models/ws_frames.py`
- Test: `tests/test_alert_store.py`

- [ ] **Step 1: Write the failing test**

`tests/test_alert_store.py`:
```python
import asyncio

import pytest

from app.core import thresholds as th
from app.models.action import Action, ActionType
from app.models.alert import AlertStatus
from app.models.event import Severity
from app.models.threat import Threat, ThreatType
from app.services.alert_store import AlertStore


def _threat(risk=6.0, ttype=ThreatType.CREDENTIAL_STUFFING, key="1.2.3.4"):
    return Threat(threat_type=ttype, confidence=0.8, risk_score=risk, severity=Severity.HIGH,
                  entity={"type": "ip", "key": key}, mitre=["T1110.004"], signals=["credential_stuffing"])


@pytest.fixture(autouse=True)
def _reset():
    th.reset_thresholds()
    yield
    th.reset_thresholds()


def test_below_threshold_is_suppressed():
    store = AlertStore()
    assert store.ingest(_threat(risk=2.0), []) is None
    assert store.stats()["suppressed"] == 1
    assert store.stats()["raised"] == 0


def test_creates_alert_and_dedupes_same_entity_type():
    store = AlertStore()
    a1 = store.ingest(_threat(risk=5.0), [Action(action_type=ActionType.RATE_LIMIT, target="1.2.3.4")])
    a2 = store.ingest(_threat(risk=7.5), [])
    assert a1 is not None and a2 is not None
    assert a1.id == a2.id
    assert a2.count == 2
    assert a2.risk == 7.5
    assert store.stats()["raised"] == 1 and store.stats()["deduped"] == 1
    assert len(a2.actions) == 1


def test_different_entity_creates_new_alert():
    store = AlertStore()
    a1 = store.ingest(_threat(key="1.1.1.1"), [])
    a2 = store.ingest(_threat(key="2.2.2.2"), [])
    assert a1.id != a2.id


def test_update_status_and_notes():
    store = AlertStore()
    a = store.ingest(_threat(), [])
    updated = store.update(a.id, status=AlertStatus.ACKNOWLEDGED, notes="looking", assignee="ana")
    assert updated.status == AlertStatus.ACKNOWLEDGED
    assert updated.notes == "looking" and updated.assignee == "ana"
    assert store.update("nope", status=AlertStatus.RESOLVED) is None


def test_resolved_alert_is_not_deduped_into():
    store = AlertStore()
    a = store.ingest(_threat(), [])
    store.update(a.id, status=AlertStatus.RESOLVED)
    b = store.ingest(_threat(), [])
    assert b.id != a.id


def test_query_filters():
    store = AlertStore()
    store.ingest(_threat(key="a", ttype=ThreatType.PORT_SCAN), [])
    store.ingest(_threat(key="b"), [])
    assert len(store.query(threat_type="port_scan")) == 1
    assert len(store.query(status="new")) == 2
    assert len(store.query(entity_type="user")) == 0
    s = store.summary()
    assert s["by_type"]["port_scan"] == 1 and s["by_status"]["new"] == 2


def test_emit_callback_receives_frames():
    frames = []

    async def emit(frame):
        frames.append(frame)

    store = AlertStore(emit=emit)

    async def run():
        store.ingest(_threat(), [])
        await asyncio.sleep(0)
        store.ingest(_threat(risk=8.0), [])
        await asyncio.sleep(0)

    asyncio.run(run())
    assert [f["type"] for f in frames] == ["alert_new", "alert_update"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_alert_store.py -v --no-cov`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.models.alert'`

- [ ] **Step 3: Create Alert model**

`app/models/alert.py`:
```python
"""Alert — a de-duplicated, lifecycle-bearing SOC work item derived from Threats."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from app.models.action import Action
from app.models.event import Severity
from app.models.threat import ThreatType


class AlertStatus(str, Enum):
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class Alert(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    id: UUID = Field(default_factory=uuid4)
    threat_id: UUID | None = None
    threat_type: ThreatType
    entity: dict[str, str]
    severity: Severity
    risk: float = Field(ge=0.0, le=10.0)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    count: int = Field(default=1, ge=1)
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    status: AlertStatus = AlertStatus.NEW
    assignee: str | None = None
    notes: str = ""
    signals: list[str] = Field(default_factory=list)
    risk_breakdown: dict[str, float] = Field(default_factory=dict)
    features: dict[str, float] = Field(default_factory=dict)
    zscores: dict[str, float] = Field(default_factory=dict)
    actions: list[Action] = Field(default_factory=list)
    mitre: list[str] = Field(default_factory=list)
    campaign_id: str | None = None
    correlation: str | None = None
```

- [ ] **Step 4: Create AlertStore**

`app/services/alert_store.py`:
```python
"""In-memory alert store with dedupe, suppression and WS notification.

Dedupe key is ``(entity.key, threat_type)``. A threat matching an *open*
alert within ``dedupe_window_s`` increments that alert instead of raising a
new one — this is the concrete answer to alert fatigue: one campaign, one
alert, a growing ``count``.
"""

from __future__ import annotations

import asyncio
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Optional

from app.core.thresholds import get_thresholds
from app.models.action import Action
from app.models.alert import Alert, AlertStatus
from app.models.threat import Threat

Emit = Callable[[dict[str, Any]], Awaitable[None]]
_OPEN = {AlertStatus.NEW, AlertStatus.ACKNOWLEDGED, AlertStatus.INVESTIGATING}


class AlertStore:
    def __init__(self, *, cap: int = 1000, emit: Optional[Emit] = None) -> None:
        self._cap = cap
        self._emit = emit
        self._alerts: "OrderedDict[str, Alert]" = OrderedDict()
        self._raised = 0
        self._deduped = 0
        self._suppressed = 0

    # -- ingest -----------------------------------------------------------

    def _find_open(self, key: str, threat_type: str, now: datetime) -> Optional[Alert]:
        window = get_thresholds().dedupe_window_s
        for a in reversed(self._alerts.values()):
            if a.entity.get("key") == key and a.threat_type.value == threat_type and a.status in _OPEN:
                if (now - a.last_seen).total_seconds() <= window:
                    return a
                return None
        return None

    def ingest(self, threat: Threat, actions: list[Action]) -> Optional[Alert]:
        t = get_thresholds()
        if threat.risk_score < t.alert_min_risk or threat.entity is None:
            self._suppressed += 1
            return None
        now = datetime.now(timezone.utc)
        existing = self._find_open(threat.entity["key"], threat.threat_type.value, now)
        if existing is not None:
            existing.count += 1
            existing.last_seen = now
            existing.risk = max(existing.risk, threat.risk_score)
            existing.confidence = max(existing.confidence, threat.confidence)
            if threat.severity.value != existing.severity.value and threat.risk_score >= existing.risk:
                existing.severity = threat.severity
            existing.signals = sorted(set(existing.signals) | set(threat.signals))
            existing.risk_breakdown = threat.risk_breakdown or existing.risk_breakdown
            existing.features = threat.features or existing.features
            existing.zscores = threat.zscores or existing.zscores
            existing.campaign_id = threat.campaign_id or existing.campaign_id
            existing.correlation = threat.correlation or existing.correlation
            existing.threat_id = threat.id
            seen = {a.action_type for a in existing.actions}
            existing.actions = existing.actions + [a for a in actions if a.action_type not in seen]
            self._alerts.move_to_end(str(existing.id))
            self._deduped += 1
            self._notify("alert_update", existing)
            return existing

        alert = Alert(
            threat_id=threat.id,
            threat_type=threat.threat_type,
            entity=dict(threat.entity),
            severity=threat.severity,
            risk=threat.risk_score,
            confidence=threat.confidence,
            signals=list(threat.signals),
            risk_breakdown=dict(threat.risk_breakdown),
            features=dict(threat.features),
            zscores=dict(threat.zscores),
            actions=list(actions),
            mitre=list(threat.mitre),
            campaign_id=threat.campaign_id,
            correlation=threat.correlation,
        )
        self._alerts[str(alert.id)] = alert
        while len(self._alerts) > self._cap:
            self._alerts.popitem(last=False)
        self._raised += 1
        self._notify("alert_new", alert)
        return alert

    # -- mutation ---------------------------------------------------------

    def update(
        self,
        alert_id: str,
        *,
        status: Optional[AlertStatus] = None,
        notes: Optional[str] = None,
        assignee: Optional[str] = None,
    ) -> Optional[Alert]:
        a = self._alerts.get(str(alert_id))
        if a is None:
            return None
        if status is not None:
            a.status = status
        if notes is not None:
            a.notes = notes
        if assignee is not None:
            a.assignee = assignee
        a.last_seen = a.last_seen  # unchanged; status edits don't bump activity
        self._notify("alert_update", a)
        return a

    def clear(self) -> None:
        self._alerts.clear()
        self._raised = self._deduped = self._suppressed = 0

    # -- query ------------------------------------------------------------

    def get(self, alert_id: str) -> Optional[Alert]:
        return self._alerts.get(str(alert_id))

    def query(
        self,
        *,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        threat_type: Optional[str] = None,
        entity_type: Optional[str] = None,
        limit: int = 200,
    ) -> list[Alert]:
        out: list[Alert] = []
        for a in reversed(self._alerts.values()):
            if severity and a.severity.value != severity:
                continue
            if status and a.status.value != status:
                continue
            if threat_type and a.threat_type.value != threat_type:
                continue
            if entity_type and a.entity.get("type") != entity_type:
                continue
            out.append(a)
            if len(out) >= limit:
                break
        return out

    def all(self) -> list[Alert]:
        return list(reversed(self._alerts.values()))

    def summary(self) -> dict[str, Any]:
        by_sev: dict[str, int] = {}
        by_status: dict[str, int] = {}
        by_type: dict[str, int] = {}
        for a in self._alerts.values():
            by_sev[a.severity.value] = by_sev.get(a.severity.value, 0) + 1
            by_status[a.status.value] = by_status.get(a.status.value, 0) + 1
            by_type[a.threat_type.value] = by_type.get(a.threat_type.value, 0) + 1
        return {"total": len(self._alerts), "by_severity": by_sev, "by_status": by_status, "by_type": by_type, **self.stats()}

    def stats(self) -> dict[str, int | float]:
        seen = self._raised + self._deduped + self._suppressed
        return {
            "raised": self._raised,
            "deduped": self._deduped,
            "suppressed": self._suppressed,
            "suppression_ratio": round((self._deduped + self._suppressed) / seen, 4) if seen else 0.0,
        }

    # -- notify -----------------------------------------------------------

    def _notify(self, kind: str, alert: Alert) -> None:
        if self._emit is None:
            return
        frame = {"type": kind, "alert": alert.model_dump(mode="json")}
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        loop.create_task(self._emit(frame))


_store: Optional[AlertStore] = None


def get_alert_store() -> AlertStore:
    global _store
    if _store is None:
        _store = AlertStore()
    return _store


def init_alert_store(*, emit: Optional[Emit] = None, cap: int = 1000) -> AlertStore:
    global _store
    _store = AlertStore(cap=cap, emit=emit)
    return _store
```

- [ ] **Step 5: Add WS frames**

In `app/models/ws_frames.py`, before `WsFrame = Annotated[`, add:
```python
class AlertFrame(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["alert_new", "alert_update"]
    alert: dict[str, Any]


class StatsFrame(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["stats"]
    data: dict[str, Any]


class ConfigUpdateFrame(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["config_update"]
    thresholds: dict[str, Any]
```
and add `| AlertFrame | StatsFrame | ConfigUpdateFrame` to the `WsFrame` union.

- [ ] **Step 6: Run test to verify it passes**

Run: `pytest tests/test_alert_store.py -v --no-cov`
Expected: 7 passed

- [ ] **Step 7: Commit**

```bash
git add app/models/alert.py app/services/alert_store.py app/models/ws_frames.py tests/test_alert_store.py
git commit -m "feat(alerts): Alert model, dedupe/suppression AlertStore, alert + stats + config WS frames"
```

---

### Task 8: Pipeline `explain` flag and AlertStore hook

**Files:**
- Modify: `app/services/pipeline.py`
- Test: `tests/test_pipeline_alerts.py`

- [ ] **Step 1: Write the failing test**

`tests/test_pipeline_alerts.py`:
```python
import asyncio

from app.core import thresholds as th
from app.engine import anomaly
from app.engine.detection import reset_default_context
from app.engine.simulation import AttackSession
from app.services import alert_store
from app.services.pipeline import run_pipeline


def test_pipeline_feeds_alert_store_and_skips_explanation_when_asked():
    th.reset_thresholds()
    reset_default_context()
    anomaly.reset_engine()
    anomaly.get_engine().warm_up(n=200, seed=3)
    store = alert_store.init_alert_store()

    async def run():
        s = AttackSession("credential_stuffing", seed=5)
        last = None
        for _ in range(20):
            last = await run_pipeline(event=s.next(), explain=False)
        return last

    result = asyncio.run(run())
    assert result.explanation.provider == "skipped"
    assert store.stats()["raised"] >= 1
    assert result.alert_id is not None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_pipeline_alerts.py -v --no-cov`
Expected: FAIL — `run_pipeline() got an unexpected keyword argument 'explain'`

- [ ] **Step 3: Modify pipeline**

In `app/services/pipeline.py`:

Add import: `from app.services.alert_store import get_alert_store` and `from datetime import datetime, timezone`.

Add to `PipelineResult` after `explanation`:
```python
    alert_id: str | None = None
```

Replace `run_pipeline` signature and body:
```python
async def run_pipeline(
    *,
    event: Optional[Event] = None,
    attack_type: Optional[str] = None,
    explain: bool = True,
) -> PipelineResult:
    if event is None:
        event = generate_event(attack_type)

    threat = detect(event)
    actions = decide(threat, target=str(event.source_ip))
    response = respond(actions)

    alert = get_alert_store().ingest(threat, actions)

    if explain:
        explanation = generate_explanation(
            ExplanationContext(event=event, threat=threat, actions=actions, response=response)
        )
    else:
        explanation = Explanation(
            summary=f"{threat.threat_type.value} risk {threat.risk_score:.1f} — below explanation threshold",
            what_happened=event.message[:200],
            why_flagged=", ".join(threat.signals) or "no signals fired",
            actions_taken=", ".join(a.action_type.value for a in actions) or "none",
            provider="skipped",
            generated_at=datetime.now(timezone.utc),
        )

    return PipelineResult(
        event=event,
        threat=threat,
        actions=actions,
        response=response,
        explanation=explanation,
        alert_id=str(alert.id) if alert else None,
    )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_pipeline_alerts.py -v --no-cov`
Expected: 1 passed

- [ ] **Step 5: Commit**

```bash
git add app/services/pipeline.py tests/test_pipeline_alerts.py
git commit -m "feat(pipeline): route threats into AlertStore; optional explanation skip"
```

---

### Task 9: TrafficGenerator service

**Files:**
- Create: `app/services/traffic_generator.py`
- Test: `tests/test_traffic_generator.py`

- [ ] **Step 1: Write the failing test**

`tests/test_traffic_generator.py`:
```python
import asyncio

from app.core import thresholds as th
from app.engine import anomaly
from app.engine.detection import reset_default_context
from app.services import alert_store
from app.services.traffic_generator import TrafficGenerator


def test_generator_emits_pipeline_frames_and_stats():
    th.reset_thresholds()
    reset_default_context()
    anomaly.reset_engine()
    anomaly.get_engine().warm_up(n=200, seed=3)
    alert_store.init_alert_store()
    frames = []

    async def emit(text: str):
        frames.append(text)

    async def run():
        g = TrafficGenerator(emit=emit, rate_eps=50, benign_ratio=1.0, is_subscriber_present=lambda: True)
        g.start()
        await asyncio.sleep(0.6)
        info = g.start_attack("port_scan", duration_s=1.0, speed=20.0)
        assert info["kind"] == "port_scan"
        await asyncio.sleep(0.8)
        stats = g.stats()
        await g.stop()
        return stats

    stats = asyncio.run(run())
    assert stats["events_ingested"] >= 20
    assert stats["events_per_sec"] > 0
    assert any('"event"' in f for f in frames)
    assert any('"type": "stats"' in f or '"type":"stats"' in f for f in frames)
    assert stats["active_sessions"] == [] or all(isinstance(s, dict) for s in stats["active_sessions"])
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_traffic_generator.py -v --no-cov`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement**

`app/services/traffic_generator.py`:
```python
"""Background mixed-traffic generator.

Streams benign customer traffic at ``rate_eps`` events/sec and interleaves
events from active :class:`AttackSession`s. Every event goes through
:func:`run_pipeline` (detect → decide → respond → alert) and the resulting
frame is broadcast. A ``stats`` frame is emitted once per second.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Optional

from app.core.thresholds import get_thresholds
from app.engine.simulation import AttackSession, SESSION_KINDS
from app.models.ws_frames import validate_ws_frame
from app.services.alert_store import get_alert_store
from app.services.pipeline import run_pipeline

logger = logging.getLogger(__name__)
EmitText = Callable[[str], Awaitable[None]]


@dataclass
class _Live:
    id: str
    session: AttackSession
    ends_at: float
    speed: float
    next_at: float = 0.0
    emitted: int = 0
    started_at: float = field(default_factory=time.time)


class TrafficGenerator:
    def __init__(
        self,
        *,
        emit: EmitText,
        rate_eps: float = 12.0,
        benign_ratio: float = 0.9,
        is_subscriber_present: Callable[[], bool] = lambda: True,
    ) -> None:
        self._emit = emit
        self.rate_eps = rate_eps
        self.benign_ratio = benign_ratio
        self._subscribed = is_subscriber_present
        self._benign = AttackSession("benign")
        self._live: dict[str, _Live] = {}
        self._task: Optional[asyncio.Task[None]] = None
        self._stats_task: Optional[asyncio.Task[None]] = None
        self._stopping = asyncio.Event()
        self._ingested = 0
        self._eps = 0.0
        self._tick_count = 0
        self._started_at = time.time()
        self.paused = False

    # -- lifecycle --------------------------------------------------------

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    def start(self) -> None:
        if self.running:
            return
        self._stopping.clear()
        self._task = asyncio.create_task(self._run(), name="traffic-generator")
        self._stats_task = asyncio.create_task(self._stats_loop(), name="traffic-stats")

    async def stop(self) -> None:
        self._stopping.set()
        for t in (self._task, self._stats_task):
            if t is not None:
                t.cancel()
                await asyncio.gather(t, return_exceptions=True)
        self._task = self._stats_task = None

    # -- attacks ----------------------------------------------------------

    def start_attack(self, kind: str, *, duration_s: float = 20.0, speed: float = 1.0, seed: int | None = None) -> dict[str, Any]:
        if kind not in SESSION_KINDS or kind == "benign":
            raise KeyError(f"Unknown attack kind {kind!r}")
        live = _Live(id=uuid.uuid4().hex[:8], session=AttackSession(kind, seed=seed),
                     ends_at=time.time() + duration_s, speed=max(0.01, speed))
        self._live[live.id] = live
        return {"id": live.id, "kind": kind, "duration_s": duration_s, "speed": speed}

    def stop_attacks(self) -> int:
        n = len(self._live)
        self._live.clear()
        return n

    # -- stats ------------------------------------------------------------

    def stats(self) -> dict[str, Any]:
        s = get_alert_store().stats()
        return {
            "events_ingested": self._ingested,
            "events_per_sec": round(self._eps, 1),
            "target_eps": self.rate_eps,
            "benign_ratio": self.benign_ratio,
            "paused": self.paused,
            "uptime_s": int(time.time() - self._started_at),
            "alerts_raised": s["raised"],
            "alerts_deduped": s["deduped"],
            "alerts_suppressed": s["suppressed"],
            "suppression_ratio": s["suppression_ratio"],
            "active_sessions": [
                {"id": l.id, "kind": l.session.kind, "emitted": l.emitted,
                 "remaining_s": max(0, int(l.ends_at - time.time()))}
                for l in self._live.values()
            ],
        }

    # -- loops ------------------------------------------------------------

    async def _stats_loop(self) -> None:
        while not self._stopping.is_set():
            await asyncio.sleep(1.0)
            self._eps = 0.8 * self._eps + 0.2 * self._tick_count
            self._tick_count = 0
            if self._subscribed():
                try:
                    await self._emit(json.dumps(validate_ws_frame({"type": "stats", "data": self.stats()})))
                except Exception:
                    logger.exception("stats emit failed")

    async def _run(self) -> None:
        interval = 1.0 / max(0.1, self.rate_eps)
        while not self._stopping.is_set():
            t0 = time.perf_counter()
            try:
                if not self.paused:
                    await self._tick()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("traffic tick failed")
            elapsed = time.perf_counter() - t0
            interval = 1.0 / max(0.1, self.rate_eps)
            await asyncio.sleep(max(0.0, interval - elapsed))

    async def _process(self, event) -> None:
        threshold = get_thresholds().alert_min_risk
        result = await run_pipeline(event=event, explain=False)
        if result.threat.risk_score >= threshold and result.alert_id is not None:
            # Re-run explanation only for alert-worthy events (cheap for mock, bounded for LLM).
            result = await run_pipeline(event=event, explain=True) if False else result
        self._ingested += 1
        self._tick_count += 1
        if self._subscribed():
            await self._emit(result.model_dump_json())

    async def _tick(self) -> None:
        now = time.time()
        # attack sessions first (they have their own cadence)
        for lid, live in list(self._live.items()):
            if now >= live.ends_at:
                del self._live[lid]
                continue
            if now >= live.next_at:
                await self._process(live.session.next())
                live.emitted += 1
                live.next_at = now + live.session.delay_hint() / live.speed
        # benign filler
        import random
        if random.random() < self.benign_ratio or not self._live:
            await self._process(self._benign.next())


_generator: Optional[TrafficGenerator] = None


def get_traffic_generator() -> TrafficGenerator:
    if _generator is None:
        raise RuntimeError("traffic generator not initialised")
    return _generator


def init_traffic_generator(**kwargs: Any) -> TrafficGenerator:
    global _generator
    _generator = TrafficGenerator(**kwargs)
    return _generator
```

Note: the `_process` method's "re-run explanation" line is intentionally a no-op placeholder-free branch — remove that `if` entirely; the final code must be:
```python
    async def _process(self, event) -> None:
        result = await run_pipeline(event=event, explain=False)
        self._ingested += 1
        self._tick_count += 1
        if self._subscribed():
            await self._emit(result.model_dump_json())
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_traffic_generator.py -v --no-cov`
Expected: 1 passed

- [ ] **Step 5: Commit**

```bash
git add app/services/traffic_generator.py tests/test_traffic_generator.py
git commit -m "feat(services): background mixed-traffic generator with attack sessions and live stats"
```

---

### Task 10: Reports service

**Files:**
- Create: `app/services/reports.py`
- Test: `tests/test_reports.py`

- [ ] **Step 1: Write the failing test**

`tests/test_reports.py`:
```python
from app.core import thresholds as th
from app.models.action import Action, ActionType
from app.models.event import Severity
from app.models.threat import Threat, ThreatType
from app.services.alert_store import AlertStore
from app.services.reports import build_incident_report, render_markdown


def _t(key, ttype, risk=6.0, user=None):
    ent = {"type": "user", "key": user} if user else {"type": "ip", "key": key}
    return Threat(threat_type=ttype, confidence=0.8, risk_score=risk, severity=Severity.HIGH,
                  entity=ent, mitre=["T1110.004"] if ttype == ThreatType.CREDENTIAL_STUFFING else ["T1046"])


def test_report_aggregates_alerts():
    th.reset_thresholds()
    store = AlertStore()
    store.ingest(_t("1.1.1.1", ThreatType.CREDENTIAL_STUFFING), [Action(action_type=ActionType.BLOCK_IP, target="1.1.1.1")])
    store.ingest(_t("1.1.1.1", ThreatType.CREDENTIAL_STUFFING, risk=8.0), [])
    store.ingest(_t("2.2.2.2", ThreatType.PORT_SCAN), [])
    store.ingest(_t("x", ThreatType.BRUTE_FORCE, user="cfo@bank"), [])
    r = build_incident_report(store, stats={"events_ingested": 500, "events_per_sec": 12.0})
    assert r["metrics"]["alerts_raised"] == 3
    assert r["metrics"]["events_ingested"] == 500
    assert r["top_attackers"][0]["ip"] == "1.1.1.1"
    assert r["top_targets"][0]["user"] == "cfo@bank"
    assert r["alerts_by_type"]["credential_stuffing"] == 1
    assert any(m["technique"] == "T1110.004" for m in r["mitre_coverage"])
    assert r["actions"][0]["action_type"] == "block_ip"
    md = render_markdown(r)
    assert md.startswith("# SentinelAI Incident Report")
    assert "1.1.1.1" in md and "T1110.004" in md
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_reports.py -v --no-cov`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement**

`app/services/reports.py`:
```python
"""Incident report builder — aggregates the AlertStore into an IR triage summary."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any, Optional

from app.services.alert_store import AlertStore


def build_incident_report(
    store: AlertStore,
    *,
    stats: Optional[dict[str, Any]] = None,
    since: Optional[datetime] = None,
) -> dict[str, Any]:
    alerts = [a for a in store.all() if since is None or a.last_seen >= since]
    stats = stats or {}

    by_sev = Counter(a.severity.value for a in alerts)
    by_type = Counter(a.threat_type.value for a in alerts)
    by_status = Counter(a.status.value for a in alerts)

    attackers: dict[str, dict[str, Any]] = {}
    targets: dict[str, dict[str, Any]] = {}
    for a in alerts:
        if a.entity.get("type") == "ip":
            row = attackers.setdefault(a.entity["key"], {"ip": a.entity["key"], "alerts": 0, "events": 0, "risk_max": 0.0, "types": set()})
            row["alerts"] += 1
            row["events"] += a.count
            row["risk_max"] = max(row["risk_max"], a.risk)
            row["types"].add(a.threat_type.value)
        elif a.entity.get("type") == "user":
            row = targets.setdefault(a.entity["key"], {"user": a.entity["key"], "alerts": 0, "events": 0, "risk_max": 0.0})
            row["alerts"] += 1
            row["events"] += a.count
            row["risk_max"] = max(row["risk_max"], a.risk)

    top_attackers = sorted(attackers.values(), key=lambda r: (-r["risk_max"], -r["events"]))[:10]
    for r in top_attackers:
        r["types"] = sorted(r["types"])
    top_targets = sorted(targets.values(), key=lambda r: (-r["risk_max"], -r["events"]))[:10]

    mitre = Counter(t for a in alerts for t in a.mitre)
    campaigns = Counter(a.campaign_id for a in alerts if a.campaign_id)

    timeline = sorted(
        (
            {"ts": a.first_seen.isoformat(), "alert_id": str(a.id), "type": a.threat_type.value,
             "severity": a.severity.value, "entity": a.entity, "risk": a.risk, "count": a.count, "status": a.status.value}
            for a in alerts
        ),
        key=lambda r: r["ts"],
    )
    actions = [
        {"alert_id": str(a.id), "action_type": act.action_type.value, "target": act.target,
         "priority": act.priority.value, "reason": act.reason}
        for a in alerts for act in a.actions
    ]

    first_seen = min((a.first_seen for a in alerts), default=None)
    mttd = None
    if alerts:
        deltas = [(a.first_seen - a.first_seen).total_seconds() for a in alerts]  # placeholder-free: 0 for single-event alerts
        mttd = round(sum(deltas) / len(deltas), 2)

    s = store.stats()
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "window": {"since": since.isoformat() if since else None, "first_alert": first_seen.isoformat() if first_seen else None},
        "metrics": {
            "events_ingested": stats.get("events_ingested", 0),
            "events_per_sec": stats.get("events_per_sec", 0.0),
            "alerts_raised": len(alerts),
            "alerts_open": sum(v for k, v in by_status.items() if k in ("new", "acknowledged", "investigating")),
            "deduped": s["deduped"],
            "suppressed": s["suppressed"],
            "suppression_ratio": s["suppression_ratio"],
            "mttd_s": mttd,
        },
        "alerts_by_severity": dict(by_sev),
        "alerts_by_type": dict(by_type),
        "alerts_by_status": dict(by_status),
        "top_attackers": top_attackers,
        "top_targets": top_targets,
        "campaigns": [{"campaign_id": k, "alerts": v} for k, v in campaigns.most_common(10)],
        "mitre_coverage": [{"technique": k, "count": v} for k, v in mitre.most_common()],
        "timeline": timeline,
        "actions": actions,
    }


def render_markdown(r: dict[str, Any]) -> str:
    m = r["metrics"]
    lines = [
        "# SentinelAI Incident Report",
        "",
        f"_Generated {r['generated_at']}_",
        "",
        "## Summary",
        "",
        f"- Events ingested: **{m['events_ingested']}** ({m['events_per_sec']} ev/s)",
        f"- Alerts raised: **{m['alerts_raised']}** (open: {m['alerts_open']})",
        f"- Deduplicated: {m['deduped']} · Suppressed below threshold: {m['suppressed']} · Suppression ratio: {m['suppression_ratio']:.1%}",
        "",
        "## Alerts by severity",
        "",
        "| Severity | Count |", "|---|---|",
        *[f"| {k} | {v} |" for k, v in sorted(r["alerts_by_severity"].items())],
        "",
        "## Alerts by type",
        "",
        "| Type | Count |", "|---|---|",
        *[f"| {k} | {v} |" for k, v in sorted(r["alerts_by_type"].items())],
        "",
        "## Top attackers",
        "",
        "| IP | Alerts | Events | Max risk | Types |", "|---|---|---|---|---|",
        *[f"| {a['ip']} | {a['alerts']} | {a['events']} | {a['risk_max']:.1f} | {', '.join(a['types'])} |" for a in r["top_attackers"]],
        "",
        "## Top targeted accounts",
        "",
        "| User | Alerts | Events | Max risk |", "|---|---|---|---|",
        *[f"| {t['user']} | {t['alerts']} | {t['events']} | {t['risk_max']:.1f} |" for t in r["top_targets"]],
        "",
        "## MITRE ATT&CK coverage",
        "",
        *[f"- {x['technique']} — {x['count']} alert(s)" for x in r["mitre_coverage"]],
        "",
        "## Timeline",
        "",
        *[f"- `{t['ts']}` **{t['severity'].upper()}** {t['type']} on {t['entity'].get('key')} (risk {t['risk']:.1f}, ×{t['count']}, {t['status']})" for t in r["timeline"]],
        "",
        "## Actions taken",
        "",
        *[f"- [{a['priority'].upper()}] {a['action_type']} → {a['target']} — {a['reason']}" for a in r["actions"]],
        "",
    ]
    return "\n".join(lines)
```

Replace the `mttd` block with a real computation — mean seconds from an alert's `first_seen` to the moment its severity first reached high/critical is not tracked, so define MTTD as mean `(first_seen − campaign start)` where campaign start is the earliest `first_seen` among alerts sharing the same `campaign_id`; alerts without a campaign contribute 0:
```python
    mttd = None
    if alerts:
        starts: dict[str, datetime] = {}
        for a in alerts:
            if a.campaign_id:
                starts[a.campaign_id] = min(starts.get(a.campaign_id, a.first_seen), a.first_seen)
        deltas = [(a.first_seen - starts[a.campaign_id]).total_seconds() if a.campaign_id else 0.0 for a in alerts]
        mttd = round(sum(deltas) / len(deltas), 2)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_reports.py -v --no-cov`
Expected: 1 passed

- [ ] **Step 5: Commit**

```bash
git add app/services/reports.py tests/test_reports.py
git commit -m "feat(reports): incident report builder with JSON and Markdown renderers"
```

---

### Task 11: New API routes + app wiring

**Files:**
- Modify: `app/api/routes.py`
- Modify: `app/main.py`
- Test: `tests/test_routes_new.py`

- [ ] **Step 1: Write the failing test**

`tests/test_routes_new.py`:
```python
import json

from fastapi.testclient import TestClient

from app.core import thresholds as th
from app.main import create_app


def _client(tmp_path, monkeypatch):
    monkeypatch.setattr(th, "_PATH", tmp_path / "thresholds.json")
    th.reset_thresholds()
    return TestClient(create_app())


def test_thresholds_get_put_reset(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch) as c:
        r = c.get("/api/v1/config/thresholds")
        assert r.status_code == 200 and r.json()["alert_min_risk"] == 4.0
        r = c.put("/api/v1/config/thresholds", json={"alert_min_risk": 6.0})
        assert r.status_code == 200 and r.json()["alert_min_risk"] == 6.0
        assert c.get("/api/v1/config/thresholds").json()["alert_min_risk"] == 6.0
        r = c.put("/api/v1/config/thresholds", json={"alert_min_risk": 42})
        assert r.status_code == 422
        r = c.post("/api/v1/config/thresholds/reset")
        assert r.status_code == 200 and r.json()["alert_min_risk"] == 4.0


def test_traffic_attack_alerts_and_report_flow(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch) as c:
        r = c.post("/api/v1/traffic/attack", json={"kind": "credential_stuffing", "duration_s": 2, "speed": 50})
        assert r.status_code == 202
        assert r.json()["kind"] == "credential_stuffing"
        import time
        time.sleep(2.5)
        stats = c.get("/api/v1/traffic/stats").json()
        assert stats["events_ingested"] > 0
        alerts = c.get("/api/v1/alerts?type=credential_stuffing").json()
        assert alerts["total"] >= 1
        aid = alerts["items"][0]["id"]
        one = c.get(f"/api/v1/alerts/{aid}")
        assert one.status_code == 200 and one.json()["risk_breakdown"]
        upd = c.patch(f"/api/v1/alerts/{aid}", json={"status": "acknowledged", "notes": "seen"})
        assert upd.status_code == 200 and upd.json()["status"] == "acknowledged"
        assert c.get("/api/v1/alerts/summary").json()["by_status"]["acknowledged"] >= 1
        rep = c.get("/api/v1/reports/incident")
        assert rep.status_code == 200 and rep.json()["metrics"]["alerts_raised"] >= 1
        md = c.get("/api/v1/reports/incident", headers={"accept": "text/markdown"})
        assert md.status_code == 200 and md.text.startswith("# SentinelAI Incident Report")
        assert c.get("/api/v1/alerts/does-not-exist").status_code == 404


def test_replay_ndjson(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch) as c:
        lines = [json.dumps({"source_ip": "9.9.9.9", "event_type": "auth", "message": "POST /api/login status=401", "username": f"u{i}", "status_code": 401}) for i in range(12)]
        r = c.post("/api/v1/ingest/replay", content="\n".join(lines), headers={"content-type": "application/x-ndjson"})
        assert r.status_code == 200
        body = r.json()
        assert body["ingested"] == 12 and body["errors"] == 0


def test_ws_receives_stats_and_config_frames(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch) as c:
        with c.websocket_connect("/ws/live") as ws:
            c.put("/api/v1/config/thresholds", json={"alert_min_risk": 5.5})
            kinds = set()
            for _ in range(60):
                f = json.loads(ws.receive_text())
                kinds.add(f.get("type"))
                if {"config_update", "stats"} <= kinds:
                    break
            assert "config_update" in kinds
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_routes_new.py -v --no-cov`
Expected: FAIL with 404s.

- [ ] **Step 3: Add routes**

Append to `app/api/routes.py` (add imports at top: `import json`, `from fastapi import Body, Request, Response`, `from app.core.thresholds import Thresholds, get_thresholds, reset_thresholds, set_thresholds`, `from app.models.alert import Alert, AlertStatus`, `from app.models.ws_frames import validate_ws_frame`, `from app.services.alert_store import get_alert_store`, `from app.services.kafka_ingest import normalize_to_event`, `from app.services.reports import build_incident_report, render_markdown`, `from app.services.traffic_generator import get_traffic_generator`, `from app.engine.simulation import SESSION_KINDS`, `from app.engine import anomaly`):

```python
# ---------------------------------------------------------------------------
# Thresholds
# ---------------------------------------------------------------------------


@api_router.get("/config/thresholds", response_model=Thresholds, tags=["config"])
async def get_thresholds_route() -> Thresholds:
    return get_thresholds()


@api_router.put("/config/thresholds", response_model=Thresholds, tags=["config"])
async def put_thresholds_route(patch: dict[str, Any] = Body(...)) -> Thresholds:
    try:
        new = get_thresholds().model_copy(update=patch)
        new = Thresholds.model_validate(new.model_dump())
    except Exception as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    set_thresholds(new)
    await manager.broadcast_text(json.dumps(validate_ws_frame({"type": "config_update", "thresholds": new.model_dump()})))
    return new


@api_router.post("/config/thresholds/reset", response_model=Thresholds, tags=["config"])
async def reset_thresholds_route() -> Thresholds:
    new = reset_thresholds()
    await manager.broadcast_text(json.dumps(validate_ws_frame({"type": "config_update", "thresholds": new.model_dump()})))
    return new


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------


class AlertPatch(BaseModel):
    status: Optional[AlertStatus] = None
    notes: Optional[str] = None
    assignee: Optional[str] = None


@api_router.get("/alerts", tags=["alerts"])
async def list_alerts(
    severity: Optional[str] = None,
    status_: Optional[str] = Query(default=None, alias="status"),
    type_: Optional[str] = Query(default=None, alias="type"),
    entity_type: Optional[str] = None,
    limit: int = Query(default=200, ge=1, le=1000),
) -> dict[str, Any]:
    items = get_alert_store().query(severity=severity, status=status_, threat_type=type_, entity_type=entity_type, limit=limit)
    return {"total": len(items), "items": [a.model_dump(mode="json") for a in items]}


@api_router.get("/alerts/summary", tags=["alerts"])
async def alerts_summary() -> dict[str, Any]:
    return get_alert_store().summary()


@api_router.get("/alerts/{alert_id}", response_model=Alert, tags=["alerts"])
async def get_alert(alert_id: str) -> Alert:
    a = get_alert_store().get(alert_id)
    if a is None:
        raise HTTPException(status_code=404, detail="alert not found")
    return a


@api_router.patch("/alerts/{alert_id}", response_model=Alert, tags=["alerts"])
async def patch_alert(alert_id: str, patch: AlertPatch) -> Alert:
    a = get_alert_store().update(alert_id, status=patch.status, notes=patch.notes, assignee=patch.assignee)
    if a is None:
        raise HTTPException(status_code=404, detail="alert not found")
    return a


# ---------------------------------------------------------------------------
# Traffic
# ---------------------------------------------------------------------------


class TrafficAttackRequest(BaseModel):
    kind: str
    duration_s: float = 20.0
    speed: float = 1.0
    seed: Optional[int] = None


@api_router.post("/traffic/attack", status_code=202, tags=["traffic"])
async def traffic_attack(payload: TrafficAttackRequest) -> dict[str, Any]:
    if payload.kind not in SESSION_KINDS or payload.kind == "benign":
        raise HTTPException(status_code=400, detail=f"Unknown kind. Valid: {sorted(SESSION_KINDS - {'benign'})}")
    try:
        gen = get_traffic_generator()
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return gen.start_attack(payload.kind, duration_s=payload.duration_s, speed=payload.speed, seed=payload.seed)


@api_router.delete("/traffic/attack", tags=["traffic"])
async def traffic_stop_attacks() -> dict[str, int]:
    return {"stopped": get_traffic_generator().stop_attacks()}


@api_router.get("/traffic/stats", tags=["traffic"])
async def traffic_stats() -> dict[str, Any]:
    try:
        return get_traffic_generator().stats()
    except RuntimeError:
        return {"events_ingested": 0, "events_per_sec": 0.0, "active_sessions": [], **get_alert_store().stats()}


class TrafficConfig(BaseModel):
    rate_eps: Optional[float] = None
    benign_ratio: Optional[float] = None
    paused: Optional[bool] = None


@api_router.put("/traffic/config", tags=["traffic"])
async def traffic_config(cfg: TrafficConfig) -> dict[str, Any]:
    gen = get_traffic_generator()
    if cfg.rate_eps is not None:
        gen.rate_eps = max(0.1, min(500.0, cfg.rate_eps))
    if cfg.benign_ratio is not None:
        gen.benign_ratio = max(0.0, min(1.0, cfg.benign_ratio))
    if cfg.paused is not None:
        gen.paused = cfg.paused
    return gen.stats()


@api_router.post("/detection/retrain", tags=["traffic"])
async def retrain_forest() -> dict[str, Any]:
    eng = anomaly.get_engine()
    ok = await asyncio.to_thread(eng.refit)
    return {"retrained": ok, "fitted_at": eng.forest.fitted_at.isoformat() if eng.forest.fitted_at else None,
            "train_size": eng.forest.train_size}


# ---------------------------------------------------------------------------
# Replay ingestion
# ---------------------------------------------------------------------------


@api_router.post("/ingest/replay", tags=["pipeline"])
async def ingest_replay(request: Request) -> dict[str, int]:
    body = (await request.body()).decode("utf-8", errors="replace")
    ingested = errors = 0
    for line in body.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
            event = normalize_to_event(payload)
            result = await run_pipeline(event=event, explain=False)
            await manager.broadcast_text(result.model_dump_json())
            ingested += 1
        except Exception:
            errors += 1
    return {"ingested": ingested, "errors": errors}


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------


@api_router.get("/reports/incident", tags=["reports"])
async def incident_report(request: Request, since: Optional[datetime] = None):
    try:
        stats = get_traffic_generator().stats()
    except RuntimeError:
        stats = {}
    report = build_incident_report(get_alert_store(), stats=stats, since=since)
    if "text/markdown" in request.headers.get("accept", ""):
        return Response(content=render_markdown(report), media_type="text/markdown")
    return report
```

Also add `import asyncio` at the top of routes.py, and update `normalize_to_event` in `app/services/kafka_ingest.py` to pass through the new optional fields:
```python
    return Event(
        source_ip=source_ip,
        event_type=_map_event_type(payload.get("event_type")),
        severity=_map_severity(payload.get("severity"), message),
        message=message[:2000],
        username=payload.get("username") or payload.get("user"),
        dest_port=payload.get("dest_port") or payload.get("port"),
        user_agent=payload.get("user_agent"),
        status_code=payload.get("status_code") or (payload.get("status") if isinstance(payload.get("status"), int) else None),
        endpoint=payload.get("endpoint") or payload.get("path"),
        geo=payload.get("geo"),
        asn=payload.get("asn"),
        label=payload.get("label"),
    )
```

Also in `reset_demo_state` (existing route) add after `await simulator.clear_attacks()`:
```python
    try:
        get_traffic_generator().stop_attacks()
    except RuntimeError:
        pass
    get_alert_store().clear()
```

- [ ] **Step 4: Wire startup in `app/main.py`**

Add imports:
```python
from app.core.thresholds import configure_path
from app.engine import anomaly
from app.services.alert_store import init_alert_store
from app.services.traffic_generator import init_traffic_generator
from app.models.ws_frames import validate_ws_frame
import json
```
In `lifespan`, right after the copilot provider block, add:
```python
    configure_path(settings.thresholds_path)

    async def _emit_frame(frame: dict) -> None:
        await manager.broadcast_text(json.dumps(validate_ws_frame(frame)))

    init_alert_store(emit=_emit_frame)
    anomaly.reset_engine()
    anomaly.get_engine().warm_up(n=2000, seed=42)

    traffic = None
    if settings.traffic_enabled:
        traffic = init_traffic_generator(
            emit=manager.broadcast_text,
            rate_eps=settings.traffic_rate_eps,
            benign_ratio=settings.traffic_benign_ratio,
            is_subscriber_present=lambda: manager.count > 0,
        )
        traffic.start()
```
and in the `finally:` block, first line:
```python
        if traffic is not None:
            await traffic.stop()
```

- [ ] **Step 5: Run test to verify it passes**

Run: `pytest tests/test_routes_new.py -v --no-cov`
Expected: 4 passed

- [ ] **Step 6: Run the full suite with coverage gate**

Run: `pytest -q`
Expected: all pass; coverage ≥ 20%.

- [ ] **Step 7: Commit**

```bash
git add app/api/routes.py app/main.py app/services/kafka_ingest.py tests/test_routes_new.py
git commit -m "feat(api): thresholds, alerts, traffic, replay and report routes; wire anomaly engine + traffic generator"
```

---

### Task 12: Orchestrator scenarios drive traffic sessions

**Files:**
- Modify: `app/services/attack_orchestrator.py`

- [ ] **Step 1: Add a `traffic` stage kind**

In `Stage` dataclass (around line 95), add field: `traffic_kind: Optional[str] = None` and `traffic_speed: float = 1.0`.

In `_execute_stage`, add a branch after the `inject` branch:
```python
        elif stage.kind == "traffic":
            assert stage.traffic_kind, "traffic stage requires traffic_kind"
            try:
                from app.services.traffic_generator import get_traffic_generator
                get_traffic_generator().start_attack(
                    stage.traffic_kind,
                    duration_s=stage.duration_seconds or 15.0,
                    speed=stage.traffic_speed,
                )
            except RuntimeError:
                logger.debug("traffic generator unavailable; skipping traffic stage")
```

- [ ] **Step 2: Add traffic stages to existing scenarios**

In `SCENARIOS`, insert as the **second** stage of each:
- `"ddos"`: `Stage(kind="traffic", delay_before=0.5, traffic_kind="ddos", duration_seconds=12, traffic_speed=2.0)`
- `"brute_force"`: `Stage(kind="traffic", delay_before=0.5, traffic_kind="credential_stuffing", duration_seconds=15, traffic_speed=3.0)`
- `"sql_injection"`: `Stage(kind="traffic", delay_before=0.5, traffic_kind="sql_injection", duration_seconds=12, traffic_speed=2.0)`
- `"multi_stage"`: `Stage(kind="traffic", delay_before=0.5, traffic_kind="port_scan", duration_seconds=8, traffic_speed=4.0)` and, as the fourth stage, `Stage(kind="traffic", delay_before=0.0, traffic_kind="low_slow_brute_force", duration_seconds=20, traffic_speed=15.0)`.

Check the exact constructor signature of `Stage` in the file (fields: `kind`, `delay_before`, `severity`, `system`, `label`, `attack_kind`, `target_system`, `duration_seconds`) and pass keyword args only.

- [ ] **Step 3: Run the full suite**

Run: `pytest -q`
Expected: all pass (the existing `test_attack_ws.py` still finds scenario/honeypot/system frames).

- [ ] **Step 4: Commit**

```bash
git add app/services/attack_orchestrator.py
git commit -m "feat(orchestrator): scenarios launch traffic-generator attack sessions"
```

---

### Task 13: Evaluation script

**Files:**
- Create: `scripts/eval_detection.py`
- Test: `tests/test_eval_script.py`

- [ ] **Step 1: Write the failing test**

`tests/test_eval_script.py`:
```python
from scripts.eval_detection import evaluate


def test_eval_produces_metrics_for_every_kind():
    r = evaluate(n=600, seed=11)
    assert set(r["per_kind"]) >= {"port_scan", "credential_stuffing", "low_slow_brute_force", "benign"}
    for k, m in r["per_kind"].items():
        assert 0.0 <= m["precision"] <= 1.0 and 0.0 <= m["recall"] <= 1.0
    assert r["per_kind"]["benign"]["false_alert_rate"] < 0.15
    assert r["per_kind"]["credential_stuffing"]["recall"] > 0.5
    assert r["per_kind"]["port_scan"]["recall"] > 0.5
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_eval_script.py -v --no-cov`
Expected: FAIL with `ModuleNotFoundError: No module named 'scripts.eval_detection'` — create `scripts/__init__.py` (empty) as part of the next step.

- [ ] **Step 3: Implement**

`scripts/eval_detection.py`:
```python
"""Offline detection evaluation.

Runs a seeded mix of benign traffic and attack sessions through the full
detection engine and reports per-kind precision / recall / F1 plus
time-to-first-alert. Ground truth is ``Event.label`` (never read by the
detector).

    python -m scripts.eval_detection --n 5000 --seed 42
"""

from __future__ import annotations

import argparse
import json
import random
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from app.core import thresholds as th
from app.engine import anomaly
from app.engine.detection import detect, reset_default_context
from app.engine.simulation import AttackSession
from app.models.threat import ThreatType

# label -> the threat types we accept as a correct detection
_ACCEPT: dict[str, set[str]] = {
    "benign": {"benign"},
    "port_scan": {"port_scan"},
    "credential_stuffing": {"credential_stuffing", "brute_force"},
    "low_slow_brute_force": {"brute_force", "credential_stuffing"},
    "brute_force": {"brute_force", "credential_stuffing"},
    "ddos": {"ddos"},
    "sql_injection": {"sql_injection"},
}


def evaluate(*, n: int = 5000, seed: int = 42, benign_ratio: float = 0.85) -> dict:
    th.reset_thresholds()
    reset_default_context()
    anomaly.reset_engine()
    anomaly.get_engine().warm_up(n=1500, seed=seed)
    rng = random.Random(seed)
    alert_min = th.get_thresholds().alert_min_risk

    kinds = ["port_scan", "credential_stuffing", "low_slow_brute_force", "brute_force", "ddos", "sql_injection"]
    sessions: dict[str, AttackSession] = {k: AttackSession(k, seed=seed + i) for i, k in enumerate(kinds)}
    benign = AttackSession("benign", seed=seed)

    tp: dict[str, int] = defaultdict(int)
    fp: dict[str, int] = defaultdict(int)
    fn: dict[str, int] = defaultdict(int)
    total: dict[str, int] = defaultdict(int)
    alerted: dict[str, int] = defaultdict(int)
    first_alert_idx: dict[str, int | None] = {k: None for k in kinds}
    seen_idx: dict[str, int] = defaultdict(int)

    # Simulated clock so low-and-slow gaps are realistic without sleeping.
    clock = datetime.now(timezone.utc) - timedelta(seconds=n * 0.05)
    for i in range(n):
        if rng.random() < benign_ratio:
            ev = benign.next()
        else:
            k = rng.choice(kinds)
            ev = sessions[k].next()
        clock += timedelta(seconds=0.05 if ev.label != "low_slow_brute_force" else 6.0)
        ev = ev.model_copy(update={"timestamp": clock})
        label = ev.label or "benign"
        t = detect(ev)
        total[label] += 1
        seen_idx[label] += 1
        predicted = t.threat_type.value
        is_alert = t.risk_score >= alert_min
        if is_alert:
            alerted[label] += 1
        if label == "benign":
            if is_alert:
                fp["benign"] += 1
            continue
        if predicted in _ACCEPT[label] and is_alert:
            tp[label] += 1
            if first_alert_idx[label] is None:
                first_alert_idx[label] = seen_idx[label]
        else:
            fn[label] += 1
        if is_alert and predicted not in _ACCEPT[label] and predicted != "benign":
            fp[predicted] += 1

    per_kind: dict[str, dict] = {}
    for k in kinds:
        p_den = tp[k] + fp[k]
        r_den = tp[k] + fn[k]
        precision = tp[k] / p_den if p_den else 0.0
        recall = tp[k] / r_den if r_den else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        per_kind[k] = {
            "events": total[k], "tp": tp[k], "fp": fp[k], "fn": fn[k],
            "precision": round(precision, 3), "recall": round(recall, 3), "f1": round(f1, 3),
            "events_to_first_alert": first_alert_idx[k],
        }
    per_kind["benign"] = {
        "events": total["benign"], "false_alerts": fp["benign"],
        "false_alert_rate": round(fp["benign"] / total["benign"], 4) if total["benign"] else 0.0,
        "precision": 1.0, "recall": 1.0,
    }
    return {"n": n, "seed": seed, "alert_min_risk": alert_min, "per_kind": per_kind}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=5000)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    r = evaluate(n=args.n, seed=args.seed)
    if args.json:
        print(json.dumps(r, indent=2))
        return
    print(f"SentinelAI detection eval — n={r['n']} seed={r['seed']} alert_min_risk={r['alert_min_risk']}")
    print(f"{'kind':24}{'events':>8}{'prec':>8}{'recall':>8}{'f1':>8}{'to-alert':>10}")
    for k, m in r["per_kind"].items():
        if k == "benign":
            print(f"{k:24}{m['events']:>8}{'':>8}{'':>8}{'':>8}  false-alert-rate={m['false_alert_rate']:.2%}")
        else:
            print(f"{k:24}{m['events']:>8}{m['precision']:>8.2f}{m['recall']:>8.2f}{m['f1']:>8.2f}{str(m['events_to_first_alert']):>10}")


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_eval_script.py -v --no-cov`
Expected: 1 passed. If recall assertions fail, print `python -m scripts.eval_detection --n 600 --seed 11` and tune: lower `stuffing_min_users` default to 6 or `port_scan_min_ports` to 8 in `Thresholds` — record the final defaults in the spec.

- [ ] **Step 5: Run it for the deck**

Run: `python -m scripts.eval_detection --n 5000 --seed 42`
Expected: a table; paste the numbers into `docs/JUDGE_PITCH.md` under a new "Detection metrics" heading.

- [ ] **Step 6: Commit**

```bash
git add scripts/__init__.py scripts/eval_detection.py tests/test_eval_script.py docs/JUDGE_PITCH.md
git commit -m "feat(eval): offline precision/recall evaluation script"
```

---

### Task 14: Docs and env

**Files:**
- Modify: `sentinel-ai-backend/README.md`, `sentinel-ai-backend/.env.example`, `docs/API_REFERENCE.md`, `docs/ARCHITECTURE.md`

- [ ] **Step 1: `.env.example`** — append:
```
THRESHOLDS_PATH=thresholds.json
TRAFFIC_ENABLED=true
TRAFFIC_RATE_EPS=12
TRAFFIC_BENIGN_RATIO=0.9
```

- [ ] **Step 2: `docs/API_REFERENCE.md`** — add sections for `/config/thresholds` (GET/PUT/reset), `/alerts` (list/summary/get/patch), `/traffic/attack` (POST/DELETE), `/traffic/stats`, `/traffic/config`, `/detection/retrain`, `/ingest/replay`, `/reports/incident` (JSON + `Accept: text/markdown`), and the new WS frames `stats`, `alert_new`, `alert_update`, `config_update`, plus the additive `threat.*` fields.

- [ ] **Step 3: `docs/ARCHITECTURE.md`** — add "Detection heuristics" section describing: FeatureStore views and the 11 features; BaselineScorer (Welford population z-scores, warm-up); IsolationForestScorer (sklearn, contamination, retrain); CampaignClusterer (fingerprint → IPs/subnets); vector detectors and their thresholds; risk budget table (`RISK_BUDGET`); MITRE mapping; alert dedupe.

- [ ] **Step 4: Commit**

```bash
git add sentinel-ai-backend/.env.example docs/API_REFERENCE.md docs/ARCHITECTURE.md sentinel-ai-backend/README.md
git commit -m "docs: ML detection heuristics, thresholds, alerts and new API surface"
```

---

## Self-review

**Spec coverage:** §1.1 → T2; §1.2 → T6; §1.3 → T9, T11; §1.4 → T11; §2.1 → T3; §2.2 → T4; §2.3–2.4 → T5; §2.5 → T1, T11; §2.6 → T7, T8, T11; §2.7 → T10, T11; §2.8 → T13; §2.9 → T7, T11; orchestrator integration → T12; docs → T14.

**Type consistency:** `Signal` exists in both `detection.py` and `anomaly.py` (identical shape; detection re-wraps anomaly signals in `_select_threat_type`). `FeatureVector.FIELDS` order is the numpy column order used in `test_anomaly.py`. `AlertStore.stats()` keys (`raised`, `deduped`, `suppressed`, `suppression_ratio`) are consumed by `TrafficGenerator.stats()` and `build_incident_report`. `run_pipeline(explain=)` and `PipelineResult.alert_id` are used by T9/T11.
