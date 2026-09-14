"""Alert — a de-duplicated, lifecycle-bearing SOC work item derived from Threats."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from app.models.action import Action
from app.models.event import Severity
from app.models.threat import ThreatType


class AlertStatus(str, Enum):
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class Alert(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    id: UUID = Field(default_factory=uuid4)
    threat_id: UUID | None = None
    threat_type: ThreatType
    entity: dict[str, str]
    severity: Severity
    risk: float = Field(ge=0.0, le=10.0)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    count: int = Field(default=1, ge=1)
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    status: AlertStatus = AlertStatus.NEW
    assignee: str | None = None
    notes: str = ""
    signals: list[str] = Field(default_factory=list)
    risk_breakdown: dict[str, float] = Field(default_factory=dict)
    features: dict[str, float] = Field(default_factory=dict)
    zscores: dict[str, float] = Field(default_factory=dict)
    actions: list[Action] = Field(default_factory=list)
    mitre: list[str] = Field(default_factory=list)
    campaign_id: str | None = None
    correlation: str | None = None
    sample_message: str = ""
