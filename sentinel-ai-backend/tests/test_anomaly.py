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
