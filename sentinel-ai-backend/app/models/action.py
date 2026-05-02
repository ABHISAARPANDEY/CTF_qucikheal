"""Action model — automated or operator-driven response taken against a threat."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Annotated
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field


class ActionType(str, Enum):
    """Supported response actions the orchestrator can dispatch."""

    BLOCK_IP = "block_ip"
    RATE_LIMIT = "rate_limit"
    RESTRICT_ACCESS = "restrict_access"
    ISOLATE_SERVICE = "isolate_service"
    MONITOR = "monitor"
    QUARANTINE_HOST = "quarantine_host"
    DISABLE_USER = "disable_user"
    KILL_PROCESS = "kill_process"
    ROTATE_CREDENTIALS = "rotate_credentials"
    NOTIFY = "notify"
    ESCALATE = "escalate"
    LOG_ONLY = "log_only"


class ActionStatus(str, Enum):
    """Lifecycle states for a dispatched action.

    ``EXECUTED`` replaces the old ``SUCCESS`` value — vocabulary aligned
    with how SOC tools describe completed responses ("the rule was
    executed", not "the rule succeeded").
    """

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    EXECUTED = "executed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Priority(str, Enum):
    """Operational urgency tier — lower number = more urgent.

    Lex-sortable so ``sorted(actions, key=lambda a: a.priority)`` puts
    P0 (emergency containment) first, P3 (background log) last.
    """

    P0 = "p0"                                                
    P1 = "p1"                          
    P2 = "p2"                       
    P3 = "p3"                          


class Action(BaseModel):
    """A response action executed against a target as a reaction to a threat."""

    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,
        json_schema_extra={
            "example": {
                "id": "5c0a2e1d-9b8a-4f6e-bc1d-2e3f4a5b6c7d",
                "threat_id": "9b2f1c0e-1a2b-4c3d-8e7f-0a1b2c3d4e5f",
                "action_type": "block_ip",
                "target": "192.168.1.42",
                "status": "success",
                "executed_at": "2026-05-02T08:00:07Z",
            }
        },
    )

    id: UUID = Field(default_factory=uuid4, description="Unique action identifier.")
    threat_id: UUID | None = Field(
        default=None,
        description="Optional reference to the threat that triggered this action.",
    )
    action_type: ActionType = Field(..., description="The kind of response to perform.")
    target: Annotated[str, Field(min_length=1, max_length=512)] = Field(
        ...,
        description="Target identifier (IP, hostname, user, process id, etc.).",
    )
    status: ActionStatus = Field(
        default=ActionStatus.PENDING,
        description="Current lifecycle state of the action.",
    )
    priority: Priority = Field(
        default=Priority.P2,
        description="Dispatch urgency. P0 = emergency, P3 = background.",
    )
    reason: str = Field(
        default="Default policy",
        max_length=512,
        description="Human-readable rationale for why this action was chosen.",
    )
    executed_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC time the action was dispatched.",
    )
