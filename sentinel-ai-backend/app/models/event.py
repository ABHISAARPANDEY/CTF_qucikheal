"""Security event model — the atomic unit ingested by SentinelAI."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Annotated
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress


class Severity(str, Enum):
    """Shared severity scale used by events, threats, and downstream actions."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EventType(str, Enum):
    """Coarse classification of incoming security telemetry."""

    AUTH = "auth"
    NETWORK = "network"
    FILE = "file"
    PROCESS = "process"
    DNS = "dns"
    MALWARE = "malware"
    INTRUSION = "intrusion"
    ANOMALY = "anomaly"
    SYSTEM = "system"
    OTHER = "other"


class Event(BaseModel):
    """A normalized security event flowing through the detection pipeline."""

    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,
        use_enum_values=False,
        json_schema_extra={
            "example": {
                "id": "f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
                "timestamp": "2026-05-02T08:00:00Z",
                "source_ip": "192.168.1.42",
                "event_type": "auth",
                "severity": "high",
                "message": "5 failed SSH login attempts in 30s",
            }
        },
    )

    id: UUID = Field(default_factory=uuid4, description="Unique event identifier.")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC time the event was observed.",
    )
    source_ip: IPvAnyAddress = Field(
        ..., description="Originating IP address (IPv4 or IPv6)."
    )
    event_type: EventType = Field(..., description="High-level event category.")
    severity: Severity = Field(..., description="Initial severity assigned at ingest.")
    message: Annotated[str, Field(min_length=1, max_length=2048)] = Field(
        ..., description="Human-readable description of the event."
    )
