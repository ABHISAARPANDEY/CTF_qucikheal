"""Honeypot behavior simulation streamed over WebSocket.

Triggered by the attack orchestrator when ``POST /attack`` schedules a run.
Emits two frame families:

1) honeypot_activity
   {
     "type": "honeypot_activity",
     "run_id": "<attack-run-id>",
     "data": {"action": "scanning"}
   }

2) honeypot_analysis
   {
     "type": "honeypot_analysis",
     "run_id": "<attack-run-id>",
     "data": {"pattern": "credential harvesting", "risk": "high"}
   }
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable

logger = logging.getLogger(__name__)

EmitFn = Callable[[dict[str, Any]], Awaitable[None]]


@dataclass(frozen=True)
class HoneypotStep:
    delay_before: float
    action: str
    pattern: str
    risk: str


_BASE_STEPS: tuple[HoneypotStep, ...] = (
    HoneypotStep(0.8, "scanning", "surface mapping", "low"),
    HoneypotStep(1.2, "credential_dump", "credential harvesting", "medium"),
    HoneypotStep(1.0, "data_extraction", "bulk data exfiltration", "high"),
)

_TYPE_EXTRA: dict[str, tuple[HoneypotStep, ...]] = {
    "ddos": (
        HoneypotStep(0.9, "scanning", "endpoint pressure profiling", "medium"),
    ),
    "brute_force": (
        HoneypotStep(0.7, "credential_dump", "credential harvesting", "high"),
    ),
    "sql_injection": (
        HoneypotStep(0.9, "data_extraction", "schema enumeration", "high"),
    ),
    "insider": (
        HoneypotStep(0.8, "data_extraction", "unusual data access", "high"),
    ),
    "multi_stage": (
        HoneypotStep(0.8, "scanning", "lateral movement mapping", "medium"),
        HoneypotStep(1.0, "credential_dump", "credential harvesting", "high"),
        HoneypotStep(1.1, "data_extraction", "staged exfiltration", "critical"),
    ),
}


class HoneypotSimulator:
    """Emits attacker-behavior + analysis frames with staged delays."""

    def __init__(self, *, emit: EmitFn) -> None:
        self._emit = emit

    async def run_sequence(self, *, attack_type: str, run_id: str) -> None:
        """Stream one honeypot sequence for the given attack run."""
        steps = _BASE_STEPS + _TYPE_EXTRA.get(attack_type, ())
        logger.debug(
            "honeypot sequence started: type=%s run_id=%s steps=%d",
            attack_type,
            run_id,
            len(steps),
        )

        for idx, step in enumerate(steps):
            if step.delay_before > 0:
                                                                              
                import asyncio

                await asyncio.sleep(step.delay_before)

            ts = _iso(time.time())
            await self._emit(
                {
                    "type": "honeypot_activity",
                    "run_id": run_id,
                    "attack_type": attack_type,
                    "step": idx + 1,
                    "total_steps": len(steps),
                    "ts": ts,
                    "data": {"action": step.action},
                }
            )
            await self._emit(
                {
                    "type": "honeypot_analysis",
                    "run_id": run_id,
                    "attack_type": attack_type,
                    "step": idx + 1,
                    "total_steps": len(steps),
                    "ts": ts,
                    "data": {"pattern": step.pattern, "risk": step.risk},
                }
            )

        logger.debug("honeypot sequence completed: type=%s run_id=%s", attack_type, run_id)


def _iso(epoch: float) -> str:
    return (
        datetime.fromtimestamp(epoch, tz=timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )
