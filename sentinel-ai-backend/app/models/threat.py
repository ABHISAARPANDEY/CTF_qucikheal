"""Threat model — output of the detection / scoring engine."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Annotated
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from app.models.event import Severity


class ThreatType(str, Enum):
    """Canonical threat categories the engine can classify."""

    BRUTE_FORCE = "brute_force"
    PORT_SCAN = "port_scan"
    DDOS = "ddos"
    SQL_INJECTION = "sql_injection"
    MALWARE = "malware"
    PHISHING = "phishing"
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    INSIDER = "insider"
    ANOMALY = "anomaly"
    UNKNOWN = "unknown"


class Threat(BaseModel):
    """A scored threat hypothesis produced from one or more events."""

    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,
        json_schema_extra={
            "example": {
                "id": "9b2f1c0e-1a2b-4c3d-8e7f-0a1b2c3d4e5f",
                "event_id": "f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
                "threat_type": "brute_force",
                "confidence": 0.92,
                "risk_score": 8.4,
                "severity": "high",
                "detected_at": "2026-05-02T08:00:05Z",
            }
        },
    )

    id: UUID = Field(default_factory=uuid4, description="Unique threat identifier.")
    event_id: UUID | None = Field(
        default=None,
        description="Optional reference to the originating event.",
    )
    threat_type: ThreatType = Field(..., description="Detected threat category.")
    confidence: Annotated[float, Field(ge=0.0, le=1.0)] = Field(
        ..., description="Model confidence in the detection (0.0–1.0)."
    )
    risk_score: Annotated[float, Field(ge=0.0, le=10.0)] = Field(
        ..., description="Composite risk score (0.0–10.0)."
    )
    severity: Severity = Field(..., description="Severity derived from risk score.")
    detected_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC time the threat was detected.",
    )
    signals: list[str] = Field(
        default_factory=list,
        description=(
            "Names of signals that fired during detection "
            "(e.g. 'lexical', 'frequency', 'ip_repetition')."
        ),
    )
    correlation: str | None = Field(
        default=None,
        description=(
            "Kill-chain correlation tag if this threat completes a known "
            "attack sequence (e.g. 'multi_stage_attack', 'sustained_attack')."
        ),
    )
