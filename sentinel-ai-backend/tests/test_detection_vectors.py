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


def test_proxy_pool_stuffing_is_attributed_to_campaign():
    """Rotating IPs across subnets: the alert entity must be the campaign, not each IP."""
    from app.engine.simulation import AttackSession

    s = AttackSession("credential_stuffing", seed=9)
    last = None
    for _ in range(30):
        last = detect(s.next())
    assert last.threat_type == ThreatType.CREDENTIAL_STUFFING
    assert last.entity["type"] == "campaign"
    assert last.entity["key"] == last.campaign_id
