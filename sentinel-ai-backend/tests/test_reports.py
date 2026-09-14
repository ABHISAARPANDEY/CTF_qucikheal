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
