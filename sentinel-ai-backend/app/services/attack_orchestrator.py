"""Attack scenario orchestrator — runs scripted multi-stage attack plays
against the :class:`~app.services.banking_simulation.BankingSimulator`.

How it differs from the simulator's own ``inject_attack``
--------------------------------------------------------
``inject_attack`` is a one-shot, low-level call: it lifts a single system
into one attack mode for one duration window. Useful for direct control
from the dashboard.

The **orchestrator** runs a *scenario* — a list of timed stages that:

  * announce the attack via a ``scenario_event`` frame (so dashboards
    can render a timeline / narrative pane);
  * call ``inject_attack`` one or more times across systems;
  * sleep, then escalate severity (info → warning → high → critical);
  * repeat injections to keep an attack hot beyond a single envelope, or
    chain attacks across systems (multi-stage kill chain).

Scenarios are background tasks — the ``POST /attack`` handler returns
the moment the run is scheduled, and the WebSocket stream is what the
dashboard observes for the actual progression.

Wire format for narrative frames
--------------------------------
::

    {
      "type": "scenario_event",
      "scenario": "multi_stage",
      "run_id": "multi_stage-7b2af31c",
      "stage": 5,
      "total_stages": 11,
      "system": "database",
      "severity": "high",
      "label": "Lateral movement: SQLi probing /accounts/balance",
      "ts": "2026-05-02T13:51:08.412Z"
    }
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Literal, Optional

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from app.services.banking_simulation import (
    API_GATEWAY,
    AUTH_SERVICE,
    DATABASE,
    TRANSACTION_SERVICE,
    BankingSimulator,
)
from app.services.honeypot_simulation import HoneypotSimulator

logger = logging.getLogger(__name__)

EmitFn = Callable[[dict[str, Any]], Awaitable[None]]


                                                                              


StageKind = Literal["emit", "inject"]
Severity = Literal["info", "warning", "high", "critical"]


@dataclass(frozen=True)
class Stage:
    """One step in a scenario.

    Stages are executed in declared order. Before each stage runs, the
    runner sleeps for ``delay_before`` seconds — so total scenario length
    is the sum of those delays (plus negligible execution time).
    """

    delay_before: float
    kind: StageKind

                     
    severity: Severity = "info"
    system: Optional[str] = None
    label: Optional[str] = None

                       
    attack_kind: Optional[str] = None
    target_system: Optional[str] = None
    duration_seconds: Optional[float] = None


@dataclass(frozen=True)
class Scenario:
    """A scripted attack sequence."""

    name: str
    description: str
    stages: tuple[Stage, ...]

    @property
    def estimated_duration_seconds(self) -> float:
        return sum(s.delay_before for s in self.stages)


                                                                              
                                                                          
                                                                           
                                                                    


SCENARIOS: dict[str, Scenario] = {
                                                                           
    "ddos": Scenario(
        name="ddos",
        description="Volumetric HTTP flood saturating the edge gateway.",
        stages=(
            Stage(0.0, "emit", severity="info", system=API_GATEWAY,
                  label="Volumetric pattern observed: TCP SYN ratio elevated 6×"),
            Stage(1.2, "inject", attack_kind="ddos", target_system=API_GATEWAY,
                  duration_seconds=16.0),
            Stage(3.0, "emit", severity="warning", system=API_GATEWAY,
                  label="Edge listener pool saturated — rate limiter degraded"),
            Stage(5.0, "emit", severity="high", system=API_GATEWAY,
                  label="L7 flood peaking @ 9.2 Gbps from rotating /16 ranges"),
            Stage(6.0, "emit", severity="critical", system=API_GATEWAY,
                  label="Upstream auth_service feeling backpressure (HTTP 502 climbing)"),
        ),
    ),

                                                                           
    "brute_force": Scenario(
        name="brute_force",
        description="Credential stuffing burst that escalates to login flood.",
        stages=(
            Stage(0.0, "emit", severity="info", system=AUTH_SERVICE,
                  label="Failed-auth rate doubled in last 60s window"),
            Stage(1.0, "inject", attack_kind="brute_force",
                  target_system=AUTH_SERVICE, duration_seconds=10.0),
            Stage(3.0, "emit", severity="warning", system=AUTH_SERVICE,
                  label="Account lockouts triggering across high-value accounts"),
            Stage(5.0, "inject", attack_kind="login_flood",
                  target_system=AUTH_SERVICE, duration_seconds=8.0),
            Stage(2.5, "emit", severity="high", system=AUTH_SERVICE,
                  label="MFA bypass attempts detected — TOTP brute force"),
            Stage(4.0, "emit", severity="critical", system=AUTH_SERVICE,
                  label="Three admin sessions compromised — token rotation forced"),
        ),
    ),

                                                                           
    "sql_injection": Scenario(
        name="sql_injection",
        description="Boolean-blind SQL injection enumerating the accounts schema.",
        stages=(
            Stage(0.0, "emit", severity="info", system=DATABASE,
                  label="Suspicious SQL pattern on /accounts/balance"),
            Stage(1.0, "inject", attack_kind="sql_injection",
                  target_system=DATABASE, duration_seconds=12.0),
            Stage(3.0, "emit", severity="warning", system=DATABASE,
                  label="UNION-based payloads enumerating information_schema"),
            Stage(4.5, "emit", severity="high", system=DATABASE,
                  label="Sensitive table accessed: customers.pii_v2"),
            Stage(4.0, "emit", severity="critical", system=DATABASE,
                  label="Bulk extraction in progress — 12.4M rows so far"),
        ),
    ),

                                                                          
    "insider": Scenario(
        name="insider",
        description="Insider threat: off-hours bulk read + privilege escalation.",
        stages=(
            Stage(0.0, "emit", severity="info", system=DATABASE,
                  label="Off-hours bulk SELECT on customer_accounts table"),
            Stage(1.0, "inject", attack_kind="insider",
                  target_system=DATABASE, duration_seconds=12.0),
            Stage(3.0, "emit", severity="warning", system=DATABASE,
                  label="App-layer rate limit bypassed — direct DB session via VPN"),
            Stage(3.0, "emit", severity="high", system=DATABASE,
                  label="Privilege escalation: GRANT SELECT ON pii.* attempted"),
            Stage(3.5, "inject", attack_kind="insider",
                  target_system=TRANSACTION_SERVICE, duration_seconds=8.0),
            Stage(2.5, "emit", severity="critical", system=TRANSACTION_SERVICE,
                  label="Lateral data flow to external endpoint 198.51.100.42"),
        ),
    ),

                                                                          
    "multi_stage": Scenario(
        name="multi_stage",
        description="Full kill chain: recon → access → lateral → exfil → persistence.",
        stages=(
                                
            Stage(0.0, "emit", severity="info", system=API_GATEWAY,
                  label="[T-0] Reconnaissance: subdomain & endpoint enumeration"),
            Stage(2.0, "inject", attack_kind="ddos",
                  target_system=API_GATEWAY, duration_seconds=4.0),

                                
            Stage(2.5, "emit", severity="warning", system=AUTH_SERVICE,
                  label="[T-1] Initial access: credential stuffing on /oauth/token"),
            Stage(1.0, "inject", attack_kind="brute_force",
                  target_system=AUTH_SERVICE, duration_seconds=8.0),

                                  
            Stage(4.0, "emit", severity="high", system=DATABASE,
                  label="[T-2] Lateral movement: SQLi probing /accounts/balance"),
            Stage(1.0, "inject", attack_kind="sql_injection",
                  target_system=DATABASE, duration_seconds=10.0),

                                        
            Stage(4.0, "emit", severity="high", system=DATABASE,
                  label="[T-3] Privilege escalation + bulk data extraction"),
            Stage(1.0, "inject", attack_kind="insider",
                  target_system=DATABASE, duration_seconds=8.0),

                             
            Stage(5.0, "emit", severity="critical", system=TRANSACTION_SERVICE,
                  label="[T-4] Persistence: crypto miner deployed on tx_service"),
            Stage(2.0, "inject", attack_kind="crypto_miner",
                  target_system=TRANSACTION_SERVICE, duration_seconds=12.0),

                        
            Stage(6.0, "emit", severity="critical", system=None,
                  label="[KILL CHAIN COMPLETE] Full compromise across all 4 systems"),
        ),
    ),
}


SCENARIO_TYPES: tuple[str, ...] = tuple(SCENARIOS.keys())


                                                                              


@dataclass
class _RunHandle:
    run_id: str
    scenario: str
    started_at: float
    expected_end_at: float
    task: asyncio.Task[None] = field(repr=False)


class AttackOrchestrator:
    """Schedules scenarios as background tasks against the simulator."""

    def __init__(
        self,
        *,
        simulator: BankingSimulator,
        emit: EmitFn,
    ) -> None:
        self._simulator = simulator
        self._emit = emit
        self._honeypot = HoneypotSimulator(emit=emit)
        self._runs: dict[str, _RunHandle] = {}
        self._lock = asyncio.Lock()

                                                                            

    @property
    def active_runs(self) -> list[dict[str, Any]]:
        return [
            {
                "run_id": h.run_id,
                "scenario": h.scenario,
                "started_at": _iso(h.started_at),
                "expected_end_at": _iso(h.expected_end_at),
            }
            for h in self._runs.values()
            if not h.task.done()
        ]

    async def trigger(self, scenario_type: str) -> dict[str, Any]:
        """Schedule the scenario to run in the background.

        Returns immediately with a summary (run_id, stage count, estimated
        duration). The actual scenario plays out asynchronously and is
        observable via the ``/ws/live`` socket.
        """
        if scenario_type not in SCENARIOS:
            valid = ", ".join(sorted(SCENARIOS))
            raise KeyError(
                f"Unknown attack type {scenario_type!r}. Valid: {valid}"
            )
        scenario = SCENARIOS[scenario_type]
        run_id = f"{scenario_type}-{uuid.uuid4().hex[:8]}"
        now = time.time()
        expected_end = now + scenario.estimated_duration_seconds + 1.0

        task = asyncio.create_task(
            self._run_bundle(run_id, scenario),
            name=f"attack-scenario:{run_id}",
        )

        async with self._lock:
            self._runs[run_id] = _RunHandle(
                run_id=run_id,
                scenario=scenario.name,
                started_at=now,
                expected_end_at=expected_end,
                task=task,
            )

                                                                          
        task.add_done_callback(
            lambda _t, rid=run_id: asyncio.create_task(self._reap(rid))
        )

        logger.info(
            "attack scenario scheduled: %s (run_id=%s, %d stages, ~%.1fs)",
            scenario.name,
            run_id,
            len(scenario.stages),
            scenario.estimated_duration_seconds,
        )

        return {
            "type": scenario.name,
            "run_id": run_id,
            "stages": len(scenario.stages),
            "estimated_duration_seconds": round(scenario.estimated_duration_seconds, 1),
            "started_at": _iso(now),
            "expected_end_at": _iso(expected_end),
        }

    async def cancel_all(self) -> int:
        """Cancel every active scenario task. Returns count cancelled."""
        async with self._lock:
            handles = list(self._runs.values())
        cancelled = 0
        for h in handles:
            if not h.task.done():
                h.task.cancel()
                cancelled += 1
                                                                     
        await asyncio.gather(
            *(h.task for h in handles), return_exceptions=True
        )
        return cancelled

                                                                            

    async def _reap(self, run_id: str) -> None:
        async with self._lock:
            self._runs.pop(run_id, None)

    async def _run_scenario(self, run_id: str, scenario: Scenario) -> None:
        total = len(scenario.stages)
        try:
            for idx, stage in enumerate(scenario.stages):
                if stage.delay_before > 0:
                    await asyncio.sleep(stage.delay_before)

                try:
                    await self._execute_stage(
                        stage=stage,
                        scenario_name=scenario.name,
                        run_id=run_id,
                        stage_idx=idx,
                        total_stages=total,
                    )
                except asyncio.CancelledError:
                    raise
                except Exception:
                    logger.exception(
                        "attack scenario stage failed: scenario=%s stage=%d/%d",
                        scenario.name,
                        idx + 1,
                        total,
                    )
        except asyncio.CancelledError:
            logger.info("attack scenario cancelled: %s (%s)", scenario.name, run_id)
            raise
        else:
            logger.info("attack scenario complete: %s (%s)", scenario.name, run_id)

    async def _run_bundle(self, run_id: str, scenario: Scenario) -> None:
        """Run scenario + honeypot behavior stream concurrently.

        This is the integration point the user asked for:
          POST /attack trigger
              -> scenario_event + system_update (existing)
              -> honeypot_activity + honeypot_analysis (new)
        """
        scenario_task = asyncio.create_task(
            self._run_scenario(run_id, scenario),
            name=f"attack-main:{run_id}",
        )
        honeypot_task = asyncio.create_task(
            self._honeypot.run_sequence(attack_type=scenario.name, run_id=run_id),
            name=f"attack-honeypot:{run_id}",
        )
        try:
            results = await asyncio.gather(
                scenario_task, honeypot_task, return_exceptions=True
            )
            for res in results:
                if isinstance(res, Exception):
                                                                             
                                                      
                    logger.warning(
                        "attack bundle stream failed: scenario=%s run_id=%s err=%r",
                        scenario.name,
                        run_id,
                        res,
                    )
        except asyncio.CancelledError:
            scenario_task.cancel()
            honeypot_task.cancel()
            await asyncio.gather(
                scenario_task, honeypot_task, return_exceptions=True
            )
            raise

    async def _execute_stage(
        self,
        *,
        stage: Stage,
        scenario_name: str,
        run_id: str,
        stage_idx: int,
        total_stages: int,
    ) -> None:
        if stage.kind == "emit":
            payload = {
                "type": "scenario_event",
                "scenario": scenario_name,
                "run_id": run_id,
                "stage": stage_idx + 1,
                "total_stages": total_stages,
                "severity": stage.severity,
                "system": stage.system,
                "label": stage.label or "",
                "ts": _iso(time.time()),
            }
            await self._emit(payload)
            logger.debug(
                "scenario_event scenario=%s stage=%d/%d sev=%s system=%s",
                scenario_name,
                stage_idx + 1,
                total_stages,
                stage.severity,
                stage.system,
            )
        elif stage.kind == "inject":
            assert stage.attack_kind, "inject stage requires attack_kind"
            await self._simulator.inject_attack(
                stage.attack_kind,
                target_system=stage.target_system,
                duration_seconds=stage.duration_seconds,
            )
        else:                                      
            raise ValueError(f"Unknown stage kind: {stage.kind!r}")


                                                                              


_orchestrator: Optional[AttackOrchestrator] = None


def init_attack_orchestrator(
    *,
    simulator: BankingSimulator,
    emit: EmitFn,
) -> AttackOrchestrator:
    """Install a fresh :class:`AttackOrchestrator` as the active instance.

    Always constructs a new instance so its asyncio primitives bind to
    the current event loop (matches the pattern used by the simulator).
    """
    global _orchestrator
    _orchestrator = AttackOrchestrator(simulator=simulator, emit=emit)
    return _orchestrator


def get_attack_orchestrator() -> AttackOrchestrator:
    """Return the active orchestrator — raises if not yet initialized."""
    if _orchestrator is None:
        raise RuntimeError(
            "AttackOrchestrator has not been initialized. "
            "Call init_attack_orchestrator(...) during application startup."
        )
    return _orchestrator


def _reset_for_tests() -> None:
    """Drop the active instance — used by tests to fully reset state."""
    global _orchestrator
    _orchestrator = None


                                                                              


def make_websocket_emitter(manager: Any) -> EmitFn:
    """Build an :data:`EmitFn` that JSON-encodes frames and broadcasts."""

    async def _emit(frame: dict[str, Any]) -> None:
        await manager.broadcast_text(json.dumps(frame, default=str))

    return _emit


def _iso(epoch: float) -> str:
    return (
        datetime.fromtimestamp(epoch, tz=timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


                                                                              


class AttackTriggerRequest(BaseModel):
    """Request body for ``POST /attack``."""

    type: Literal[
        "ddos",
        "brute_force",
        "sql_injection",
        "insider",
        "multi_stage",
    ] = Field(..., description="Which scenario to play.")


class AttackTriggerResponse(BaseModel):
    type: str
    run_id: str
    stages: int
    estimated_duration_seconds: float
    started_at: str
    expected_end_at: str


attack_router = APIRouter(tags=["attack"])
"""Mounted at root in ``app/main.py`` so the canonical path is ``POST /attack``."""


@attack_router.post(
    "/attack",
    response_model=AttackTriggerResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Trigger an attack scenario against the simulator",
)
async def trigger_attack(payload: AttackTriggerRequest) -> AttackTriggerResponse:
    """Schedule a multi-stage attack scenario to run in the background.

    The endpoint returns immediately with a ``run_id``. The actual scenario
    plays out across the next several seconds and is observable on the
    ``/ws/live`` WebSocket as a mix of ``scenario_event`` (narrative) and
    ``system_update`` (telemetry) frames. Severity escalates progressively
    (``info`` → ``warning`` → ``high`` → ``critical``) as the play unfolds.
    """
    try:
        orchestrator = get_attack_orchestrator()
    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc
    summary = await orchestrator.trigger(payload.type)
    return AttackTriggerResponse(**summary)


@attack_router.get(
    "/attack",
    summary="List active attack scenarios",
)
async def list_active_attacks() -> dict[str, Any]:
    try:
        orchestrator = get_attack_orchestrator()
    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc
    return {
        "available_types": list(SCENARIO_TYPES),
        "active": orchestrator.active_runs,
    }


@attack_router.delete(
    "/attack",
    status_code=status.HTTP_200_OK,
    summary="Cancel every in-flight attack scenario",
)
async def cancel_all_attacks() -> dict[str, Any]:
    try:
        orchestrator = get_attack_orchestrator()
    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc
    cancelled = await orchestrator.cancel_all()
    return {"cancelled": cancelled}
