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

    def ingest(self, threat: Threat, actions: list[Action], *, sample_message: str = "") -> Optional[Alert]:
        t = get_thresholds()
        if threat.risk_score < t.alert_min_risk or threat.entity is None:
            self._suppressed += 1
            return None
        now = datetime.now(timezone.utc)
        existing = self._find_open(threat.entity["key"], threat.threat_type.value, now)
        if existing is not None:
            existing.count += 1
            existing.last_seen = now
            if threat.risk_score >= existing.risk:
                existing.risk = threat.risk_score
                existing.severity = threat.severity
            existing.confidence = max(existing.confidence, threat.confidence)
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
            sample_message=sample_message[:300],
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
