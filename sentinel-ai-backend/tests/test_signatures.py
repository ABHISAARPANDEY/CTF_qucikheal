from app.core import thresholds as th
from app.engine import anomaly, signatures
from app.engine.detection import detect, reset_default_context
from app.engine.simulation import AttackSession
from app.models.event import Event, EventType, Severity
from app.models.threat import Threat, ThreatType
import pytest


@pytest.fixture(autouse=True)
def _fresh():
    th.reset_thresholds()
    reset_default_context()
    anomaly.reset_engine()
    anomaly.get_engine().warm_up(n=200, seed=5)
    signatures.reset_signature_store()
    yield
    signatures.reset_signature_store()
    anomaly.reset_engine()
    reset_default_context()


def _t(ttype, ip="45.146.164.10", risk=7.0):
    return Threat(threat_type=ttype, confidence=0.9, risk_score=risk, severity=Severity.HIGH,
                  entity={"type": "ip", "key": ip}, mitre=["T1110.004"])


def _ev(ip="45.146.164.99", ua="python-requests/2.31", ep="/oauth/token", port=None):
    return Event(source_ip=ip, event_type=EventType.AUTH if port is None else EventType.NETWORK,
                 severity=Severity.LOW, message="POST /oauth/token status=401",
                 user_agent=ua, endpoint=ep, dest_port=port, status_code=401)


def test_learn_creates_signature_from_confirmed_threat():
    store = signatures.SignatureStore()
    created = store.learn(_t(ThreatType.CREDENTIAL_STUFFING), _ev())
    assert created
    inds = {s.indicator for s in created}
    # bot UA + compound ua|endpoint, but never a bare endpoint or subnet
    assert "ua:python-requests" in inds
    assert any("|endpoint:" in i for i in inds)
    assert not any(i.startswith("subnet:") for i in inds)


def test_benign_is_never_learned():
    store = signatures.SignatureStore()
    assert store.learn(_t(ThreatType.BENIGN), _ev()) == []


def test_match_returns_instant_classification():
    store = signatures.SignatureStore()
    store.learn(_t(ThreatType.CREDENTIAL_STUFFING), _ev())
    m = store.match(_ev(ip="203.0.113.7"))  # different IP, same UA+endpoint
    assert m is not None
    assert m.threat_type == ThreatType.CREDENTIAL_STUFFING
    assert m.confidence >= 0.9 and m.risk >= 6.0


def test_no_match_for_unknown_fingerprint():
    store = signatures.SignatureStore()
    store.learn(_t(ThreatType.CREDENTIAL_STUFFING), _ev())
    assert store.match(_ev(ip="8.8.8.8", ua="Mozilla/5.0 (Chrome) legit", ep="/api/accounts")) is None


def test_real_browser_never_matches_a_learned_bot_signature():
    store = signatures.SignatureStore()
    store.learn(_t(ThreatType.CREDENTIAL_STUFFING), _ev(ep="/api/login"))
    # a legitimate Chrome user on the same endpoint must not be flagged
    assert store.match(_ev(ip="203.0.113.7", ua="Mozilla/5.0 Chrome/124", ep="/api/login")) is None


def test_persistence_round_trip(tmp_path):
    path = str(tmp_path / "sigs.json")
    s1 = signatures.SignatureStore(path=path)
    s1.learn(_t(ThreatType.PORT_SCAN, ip="203.0.113.5"), _ev(ip="203.0.113.5", ua=None, ep=None, port=22))
    assert s1.count() >= 1
    s2 = signatures.SignatureStore(path=path)
    assert s2.count() == s1.count()


def test_detect_uses_signature_fast_path_after_learning():
    import asyncio

    from app.services import alert_store
    from app.services.pipeline import run_pipeline

    alert_store.init_alert_store()

    async def first_run():
        # First run through the pipeline: takes several events, then learns.
        sess = AttackSession("credential_stuffing", seed=11)
        for _ in range(30):
            await run_pipeline(event=sess.next(), explain=False)

    asyncio.run(first_run())
    assert signatures.get_signature_store().count() >= 1

    # Second run (fresh window, fresh IPs) — first event matches the signature.
    reset_default_context()
    sess2 = AttackSession("credential_stuffing", seed=99)
    t2 = detect(sess2.next())
    assert t2.matched_by_signature is True
    assert t2.signature_id is not None
    assert "signature_match" in t2.signals
    assert t2.risk_score >= th.get_thresholds().alert_min_risk
