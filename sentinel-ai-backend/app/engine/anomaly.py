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
    CampaignClusterer       — groups events by (user_agent, endpoint)
                              fingerprint; when one fingerprint spans many
                              IPs across many subnets it emits
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

    def snapshot(self, etype: str) -> dict[str, dict[str, float]]:
        """Population mean/std per feature (for the UI's baseline comparison)."""
        with self._lock:
            per = self._stats.get(etype, {})
            return {f: {"mean": round(w.mean, 4), "std": round(w.std, 4), "n": w.n} for f, w in per.items()}

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
    fingerprint: tuple[str, str]
    distinct_ips: int
    distinct_subnets: int
    distinct_users: int
    fail_ratio: float
    events: int
    members: list[str]
    signal: Signal


class CampaignClusterer:
    def __init__(self, *, window_seconds: int = 300, cap: int = 500, max_fingerprints: int = 2000) -> None:
        self._window = timedelta(seconds=window_seconds)
        self._cap = cap
        self._max = max_fingerprints
        self._lock = Lock()
        # per fingerprint: (timestamp, ip, username, is_failure)
        self._by_fp: "OrderedDict[tuple[str, str], deque[tuple[datetime, str, str, bool]]]" = OrderedDict()

    @staticmethod
    def fingerprint(event: Event) -> tuple[str, str]:
        return (event.user_agent or "-", event.endpoint or "-")

    def observe(self, event: Event) -> Optional[CampaignMatch]:
        t = get_thresholds()
        fp = self.fingerprint(event)
        if fp == ("-", "-"):
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
            is_fail = event.status_code in (401, 403, 423, 429) if event.status_code is not None else "failed" in event.message.lower()
            buf.append((event.timestamp, ip, event.username or "", is_fail))
            live = [row for row in buf if row[0] >= cutoff]
        ips = {row[1] for row in live}
        users = {row[2] for row in live if row[2]}
        fails = sum(1 for row in live if row[3])
        subnets = {subnet_of(i) for i in ips}
        fired = len(ips) >= t.campaign_min_ips and len(subnets) >= t.campaign_min_subnets
        strength = min(1.0, len(ips) / (2.0 * t.campaign_min_ips)) if fired else 0.0
        return CampaignMatch(
            campaign_id=str(uuid.uuid5(uuid.NAMESPACE_URL, "|".join(fp))),
            fingerprint=fp,
            distinct_ips=len(ips),
            distinct_subnets=len(subnets),
            distinct_users=len(users),
            fail_ratio=fails / len(live) if live else 0.0,
            events=len(live),
            members=sorted(ips)[:50],
            signal=Signal("distributed_campaign", fired, round(strength, 2)),
        )

    def campaigns(self) -> list[dict]:
        """Currently-firing campaigns (for the UI strip)."""
        t = get_thresholds()
        cutoff = datetime.now(timezone.utc) - self._window
        out = []
        with self._lock:
            items = list(self._by_fp.items())
        for fp, buf in items:
            live = [row for row in buf if row[0] >= cutoff]
            ips = {row[1] for row in live}
            subnets = {subnet_of(i) for i in ips}
            if len(ips) >= t.campaign_min_ips and len(subnets) >= t.campaign_min_subnets:
                users = {row[2] for row in live if row[2]}
                fails = sum(1 for row in live if row[3])
                out.append({
                    "campaign_id": str(uuid.uuid5(uuid.NAMESPACE_URL, "|".join(fp))),
                    "user_agent": fp[0], "endpoint": fp[1],
                    "distinct_ips": len(ips), "distinct_subnets": len(subnets),
                    "distinct_users": len(users),
                    "fail_ratio": round(fails / len(live), 3) if live else 0.0,
                    "events": len(live), "members": sorted(ips)[:50],
                    "last_seen": max(row[0] for row in live).isoformat(),
                })
        return sorted(out, key=lambda c: -c["distinct_ips"])

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
