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
