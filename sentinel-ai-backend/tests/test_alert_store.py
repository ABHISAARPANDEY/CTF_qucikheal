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
