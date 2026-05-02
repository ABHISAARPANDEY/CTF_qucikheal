"""Response engine — simulates execution and produces realistic, structured results.

Goal
----
Make every result *read like a real SOC tool log line*, not a generic
"<action> executed against <target>" stub. Each result combines:

    1. A per-action-type **message template** that names the actual
       artifact created (firewall rule id, ACL id, ticket id, etc.).
    2. The decision engine's **reason** (e.g., "high-risk threat") so
       operators see the *why* alongside the *what*.
    3. The handler's structured **detail** dict (preserved from before
       — useful for dashboards, SIEM ingestion, audit).
    4. ISO-8601 UTC **timestamp** + measured **duration_ms**.

Output shape (per spec) — every :class:`ExecutionResult` carries::

    {
      "action_type": "block_ip",          # the spec calls this "action"
      "status":      "executed",          # was "success"; renamed
      "executed_at": "2026-05-02T...",    # the spec calls this "timestamp"
      "message":     "Source IP 1.2.3.4 blocked at edge firewall (rule fw-…)
                      — high-risk threat",
      "target":      "1.2.3.4",
      "duration_ms": 0.42,
      "detail":      {...}                # structured artifact for SIEM / UI
    }

Constraints honored:
    - No real system calls — handlers fabricate plausible artifacts.
    - Realistic — messages reference target + artifact + reason; failures
      get a distinct, descriptive failure line.

Add or replace a handler by registering it in :data:`HANDLERS` and
optionally a template in :data:`MESSAGE_TEMPLATES`.
"""

from __future__ import annotations

import random
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.models.action import Action, ActionStatus, ActionType


_DEFAULT_FAILURE_RATE: float = 0.05


class ExecutionResult(BaseModel):
    """Structured outcome of simulating a single :class:`Action`.

    Fields shown in the OUTPUT FORMAT spec map onto:
        - spec ``action``    → :attr:`action_type` (Pydantic enum)
        - spec ``status``    → :attr:`status` (now uses ``"executed"``)
        - spec ``timestamp`` → :attr:`executed_at`
        - spec ``message``   → :attr:`message`

    Additional fields (``action_id``, ``target``, ``duration_ms``,
    ``detail``) round out the audit trail without changing the shape
    callers receive in the JSON envelope.
    """

    model_config = ConfigDict(extra="forbid")

    action_id: UUID
    action_type: ActionType
    target: str
    status: ActionStatus
    message: str
    duration_ms: float = Field(ge=0.0)
    executed_at: datetime
    detail: dict[str, Any] = Field(default_factory=dict)


class ResponseReport(BaseModel):
    """Aggregate report for a batch of executed actions."""

    model_config = ConfigDict(extra="forbid")

    total: int = Field(ge=0)
    succeeded: int = Field(ge=0)
    failed: int = Field(ge=0)
    skipped: int = Field(ge=0)
    started_at: datetime
    finished_at: datetime
    results: list[ExecutionResult]


                                                                        


def _short_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def _h_block_ip(action: Action) -> dict[str, Any]:
    return {
        "rule_id": _short_id("fw"),
        "ip": action.target,
        "direction": "inbound",
        "ttl_seconds": 3600,
    }


def _h_rate_limit(action: Action) -> dict[str, Any]:
    return {
        "policy_id": _short_id("rl"),
        "target": action.target,
        "requests_per_minute": 60,
        "burst": 30,
    }


def _h_quarantine_host(action: Action) -> dict[str, Any]:
    return {
        "isolation_id": _short_id("iso"),
        "host": action.target,
        "vlan": "quarantine-vlan-99",
    }


def _h_isolate_service(action: Action) -> dict[str, Any]:
    return {
        "policy_id": _short_id("svciso"),
        "target": action.target,
        "method": "egress-deny + ingress-allowlist",
        "ttl_seconds": 1800,
    }


def _h_restrict_access(action: Action) -> dict[str, Any]:
    return {
        "acl_id": _short_id("acl"),
        "target": action.target,
        "allowed_methods": ["GET"],
        "require_mfa": True,
    }


def _h_monitor(action: Action) -> dict[str, Any]:
    return {
        "watch_id": _short_id("watch"),
        "target": action.target,
        "duration_seconds": 600,
    }


def _h_notify(action: Action) -> dict[str, Any]:
    return {
        "channel": "secops-alerts",
        "target": action.target,
    }


def _h_escalate(action: Action) -> dict[str, Any]:
    return {
        "ticket_id": f"INC-{random.randint(10_000, 99_999)}",
        "target": action.target,
        "assignee": "tier2-soc",
    }


def _h_disable_user(action: Action) -> dict[str, Any]:
    return {
        "user": action.target,
        "session_revoked": True,
        "lockout_seconds": 1800,
    }


def _h_kill_process(action: Action) -> dict[str, Any]:
    return {
        "target": action.target,
        "signal": "SIGKILL",
    }


def _h_rotate_credentials(action: Action) -> dict[str, Any]:
    return {
        "principal": action.target,
        "rotation_id": _short_id("rot"),
    }


def _h_log_only(action: Action) -> dict[str, Any]:
    return {
        "log_id": _short_id("log"),
        "target": action.target,
    }


HANDLERS: dict[ActionType, Callable[[Action], dict[str, Any]]] = {
    ActionType.BLOCK_IP: _h_block_ip,
    ActionType.RATE_LIMIT: _h_rate_limit,
    ActionType.QUARANTINE_HOST: _h_quarantine_host,
    ActionType.ISOLATE_SERVICE: _h_isolate_service,
    ActionType.RESTRICT_ACCESS: _h_restrict_access,
    ActionType.MONITOR: _h_monitor,
    ActionType.NOTIFY: _h_notify,
    ActionType.ESCALATE: _h_escalate,
    ActionType.DISABLE_USER: _h_disable_user,
    ActionType.KILL_PROCESS: _h_kill_process,
    ActionType.ROTATE_CREDENTIALS: _h_rotate_credentials,
    ActionType.LOG_ONLY: _h_log_only,
}


                                                                        
                                                                        
                                                                    
                                          

MESSAGE_TEMPLATES: dict[ActionType, str] = {
    ActionType.BLOCK_IP:
        "Source IP {target} blocked at edge firewall "
        "(rule {rule_id}, {direction}, TTL {ttl_seconds}s)",
    ActionType.RATE_LIMIT:
        "Rate-limit policy {policy_id} attached to {target} "
        "({requests_per_minute} req/min, burst {burst})",
    ActionType.ISOLATE_SERVICE:
        "Service {target} isolated via {method} "
        "(policy {policy_id}, TTL {ttl_seconds}s)",
    ActionType.QUARANTINE_HOST:
        "Host {host} quarantined on {vlan} (isolation {isolation_id})",
    ActionType.RESTRICT_ACCESS:
        "ACL {acl_id} tightened on {target} — methods restricted to "
        "{allowed_methods}, MFA required",
    ActionType.MONITOR:
        "Watch {watch_id} enabled on {target} for next {duration_seconds}s",
    ActionType.NOTIFY:
        "SOC channel {channel} notified about activity from {target}",
    ActionType.ESCALATE:
        "Incident {ticket_id} opened for {target}, assigned to {assignee}",
    ActionType.DISABLE_USER:
        "User {user} disabled, session revoked, lockout {lockout_seconds}s",
    ActionType.KILL_PROCESS:
        "Process at {target} terminated with {signal}",
    ActionType.ROTATE_CREDENTIALS:
        "Credentials rotated for {principal} (rotation {rotation_id})",
    ActionType.LOG_ONLY:
        "Activity from {target} logged for trend analysis (log {log_id})",
}


def _build_message(
    action: Action, status: ActionStatus, detail: dict[str, Any]
) -> str:
    """Compose a realistic, threat-aware message line.

    Format: ``<what was done> — <why it was done>``.
    Falls back to a safe generic message if the template can't be filled
    (e.g., a custom handler that returns unexpected keys).
    """
    if status == ActionStatus.FAILED:
        verb = action.action_type.value.replace("_", " ")
        return (
            f"Failed to {verb} for {action.target} — "
            f"{detail.get('reason', 'simulated transient error')}"
        )

    if status == ActionStatus.CANCELLED:
        verb = action.action_type.value.replace("_", " ")
        return f"Skipped {verb} for {action.target} — no handler registered"

    template = MESSAGE_TEMPLATES.get(action.action_type)
    if template is None:
        what = (
            f"{action.action_type.value.replace('_', ' ').title()} "
            f"dispatched against {action.target}"
        )
    else:
                                                                       
                                                                          
                                   
        fmt = {**detail, "target": action.target}
        try:
            what = template.format(**fmt)
        except (KeyError, IndexError):
            what = (
                f"{action.action_type.value.replace('_', ' ').title()} "
                f"dispatched against {action.target}"
            )

                                                              
    reason = (action.reason or "").strip()
    if reason and reason.lower() != "default policy":
                                                                          
        if reason.endswith("(correlation-elevated)"):
            reason = reason[: -len("(correlation-elevated)")].strip().rstrip("—").strip()
        what = f"{what} — {reason}"

    return what


                                                                        


def _execute_one(action: Action, *, failure_rate: float) -> ExecutionResult:
    started = time.perf_counter()
    now = datetime.now(timezone.utc)

    handler = HANDLERS.get(action.action_type)
    if handler is None:
        return ExecutionResult(
            action_id=action.id,
            action_type=action.action_type,
            target=action.target,
            status=ActionStatus.CANCELLED,
            message=_build_message(action, ActionStatus.CANCELLED, {}),
            duration_ms=0.0,
            executed_at=now,
            detail={"reason": "unsupported_action"},
        )

    if failure_rate > 0.0 and random.random() < failure_rate:
        duration_ms = (time.perf_counter() - started) * 1000
        detail = {"reason": "simulated transient handler error"}
        return ExecutionResult(
            action_id=action.id,
            action_type=action.action_type,
            target=action.target,
            status=ActionStatus.FAILED,
            message=_build_message(action, ActionStatus.FAILED, detail),
            duration_ms=round(duration_ms, 3),
            executed_at=now,
            detail=detail,
        )

    try:
        detail = handler(action)
    except Exception as exc:                                                        
        duration_ms = (time.perf_counter() - started) * 1000
        detail = {"reason": f"handler raised {exc!r}"}
        return ExecutionResult(
            action_id=action.id,
            action_type=action.action_type,
            target=action.target,
            status=ActionStatus.FAILED,
            message=_build_message(action, ActionStatus.FAILED, detail),
            duration_ms=round(duration_ms, 3),
            executed_at=now,
            detail=detail,
        )

    duration_ms = (time.perf_counter() - started) * 1000
    return ExecutionResult(
        action_id=action.id,
        action_type=action.action_type,
        target=action.target,
        status=ActionStatus.EXECUTED,
        message=_build_message(action, ActionStatus.EXECUTED, detail),
        duration_ms=round(duration_ms, 3),
        executed_at=now,
        detail=detail,
    )


def respond(
    actions: list[Action],
    *,
    failure_rate: float | None = None,
) -> ResponseReport:
    """Simulate execution of every action and return an aggregate report.

    Args:
        actions: List of :class:`Action` produced by the decision engine.
        failure_rate: Probability in ``[0.0, 1.0]`` that any given action
            is marked ``FAILED``. ``None`` (default) uses
            :data:`_DEFAULT_FAILURE_RATE`. Pass ``0.0`` for deterministic
            execution (e.g. in tests).

    Returns:
        A :class:`ResponseReport` with per-action :class:`ExecutionResult`
        items. Each result carries a realistic message, the executed
        status, the timestamp, and the structured artifact detail.
    """
    rate = _DEFAULT_FAILURE_RATE if failure_rate is None else failure_rate
    if not 0.0 <= rate <= 1.0:
        raise ValueError("failure_rate must be in [0.0, 1.0]")

    started_at = datetime.now(timezone.utc)
    results = [_execute_one(action, failure_rate=rate) for action in actions]
    finished_at = datetime.now(timezone.utc)

    succeeded = sum(1 for r in results if r.status == ActionStatus.EXECUTED)
    failed = sum(1 for r in results if r.status == ActionStatus.FAILED)
    skipped = sum(1 for r in results if r.status == ActionStatus.CANCELLED)

    return ResponseReport(
        total=len(results),
        succeeded=succeeded,
        failed=failed,
        skipped=skipped,
        started_at=started_at,
        finished_at=finished_at,
        results=results,
    )
