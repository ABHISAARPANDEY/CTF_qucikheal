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

from datetime import datetime, timezone
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
from app.services.alert_store import get_alert_store
from app.engine.signatures import get_signature_store


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
    alert_id: str | None = None


async def run_pipeline(
    *,
    event: Optional[Event] = None,
    attack_type: Optional[str] = None,
    explain: bool = True,
) -> PipelineResult:
    """Run the full SentinelAI pipeline and return a structured result.

    Steps:
        1. **simulate** — synthetic attack event (skipped if ``event`` is provided).
        2. **detect**   — multi-signal + ML classification into a scored :class:`Threat`.
        3. **decide**   — policy-driven action plan.
        4. **respond**  — simulated execution of the actions.
        5. **alert**    — dedupe/suppress into the :class:`AlertStore`.
        6. **AI**       — human-readable explanation (skipped when ``explain`` is False,
           e.g. for high-volume background traffic).

    Args:
        event: Use this event instead of generating one (e.g., for replays
            or real ingestion). When ``None``, an event is simulated.
        attack_type: When ``event`` is ``None``, restrict simulation to this
            attack type. ``None`` picks a random type.
        explain: Whether to call the copilot provider for a narrative.

    Returns:
        A :class:`PipelineResult` containing every step's output.
    """
    if event is None:
        event = generate_event(attack_type)

    threat = detect(event)
    actions = decide(threat, target=str(event.source_ip))
    response = respond(actions)

    alert = get_alert_store().ingest(threat, actions, sample_message=event.message)
    # Learn a signature from every confirmed (alert-raising) detection so the
    # next occurrence of this attacker fingerprint is flagged instantly.
    if alert is not None and not threat.matched_by_signature:
        get_signature_store().learn(threat, event)

    if explain:
        explanation = generate_explanation(
            ExplanationContext(event=event, threat=threat, actions=actions, response=response)
        )
    else:
        explanation = Explanation(
            summary=f"{threat.threat_type.value} risk {threat.risk_score:.1f}",
            what_happened=event.message[:200],
            why_flagged=", ".join(threat.signals) or "no signals fired",
            actions_taken=", ".join(a.action_type.value for a in actions) or "none",
            provider="skipped",
            generated_at=datetime.now(timezone.utc),
        )

    return PipelineResult(
        event=event,
        threat=threat,
        actions=actions,
        response=response,
        explanation=explanation,
        alert_id=str(alert.id) if alert else None,
    )
