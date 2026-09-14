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
