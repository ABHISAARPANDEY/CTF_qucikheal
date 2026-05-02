"""Pipeline orchestration — the single source of truth for one full run.

Flow
----
    simulation → detection → decision → response → AI

This module is the *only* place where those five steps are composed.
Transport layers (WebSocket, REST, CLI, queue consumers) call
:func:`run_pipeline` and forward the resulting :class:`PipelineResult`.

Async safety
------------
:func:`run_pipeline` is ``async`` so callers can ``await`` it without
ceremony. All current engines are pure-Python and microsecond-fast, so
they run inline. If a future provider (e.g., a real LLM in
``ai_copilot``) becomes network-bound, wrap its call in
``asyncio.to_thread(...)`` — no other change is required here.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, ConfigDict

from app.engine import decide, detect, generate_event, respond
from app.engine.response import ResponseReport
from app.models.action import Action
from app.models.event import Event
from app.models.threat import Threat
from app.services.ai_copilot import (
    Explanation,
    ExplanationContext,
    generate_explanation,
)


class PipelineResult(BaseModel):
    """The complete payload of one pipeline run.

    This is the canonical shape sent to the frontend (over WebSocket or
    REST). All five outputs are linked by id (``threat.event_id``,
    ``action.threat_id``, ``execution_result.action_id``) so consumers can
    trace any artifact back to its origin event.
    """

    model_config = ConfigDict(extra="forbid")

    event: Event
    threat: Threat
    actions: list[Action]
    response: ResponseReport
    explanation: Explanation


async def run_pipeline(
    *,
    event: Optional[Event] = None,
    attack_type: Optional[str] = None,
) -> PipelineResult:
    """Run the full SentinelAI pipeline and return a structured result.

    Steps:
        1. **simulate** — synthetic attack event (skipped if ``event`` is provided).
        2. **detect**   — rule-based classification into a scored :class:`Threat`.
        3. **decide**   — policy-driven action plan.
        4. **respond**  — simulated execution of the actions.
        5. **AI**       — human-readable explanation via the active provider.

    Args:
        event: Use this event instead of generating one (e.g., for replays
            or real ingestion). When ``None``, an event is simulated.
        attack_type: When ``event`` is ``None``, restrict simulation to this
            attack type. ``None`` picks a random type.

    Returns:
        A :class:`PipelineResult` containing every step's output.
    """
    if event is None:
        event = generate_event(attack_type)

    threat = detect(event)
    actions = decide(threat, target=str(event.source_ip))
    response = respond(actions)
    explanation = generate_explanation(
        ExplanationContext(
            event=event,
            threat=threat,
            actions=actions,
            response=response,
        )
    )

    return PipelineResult(
        event=event,
        threat=threat,
        actions=actions,
        response=response,
        explanation=explanation,
    )
