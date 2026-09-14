import pytest

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
    with pytest.raises(KeyError):
        AttackSession("nope")
