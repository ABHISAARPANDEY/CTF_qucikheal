"""Top-level API router and base routes."""

from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel

from app.core.config import get_settings
from app.engine.simulation import SIMULATORS
from app.services.ai_copilot import generate_chat_response
from app.services.anomaly_simulation import stream_attack_side_channel
from app.services.attack_orchestrator import get_attack_orchestrator
from app.services.banking_simulation import (
    ATTACK_TYPES,
    SYSTEMS,
    get_banking_simulator,
)
from app.services.pipeline import PipelineResult, run_pipeline
from app.services.websocket import manager

api_router = APIRouter()


                                                       
                                                                        
                                                                      
_PIPELINE_TO_BANKING: dict[str, str] = {
    "ddos": "ddos",
    "brute_force": "brute_force",
    "sql_injection": "sql_injection",
}
_THREAT_TO_SCENARIO: dict[str, str] = {
    "ddos": "ddos",
    "brute_force": "brute_force",
    "sql_injection": "sql_injection",
    "insider": "insider",
}


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    environment: str
    timestamp: datetime


@api_router.get(
    "/health",
    response_model=HealthResponse,
    status_code=status.HTTP_200_OK,
    tags=["system"],
    summary="Service health check",
)
async def health_check() -> HealthResponse:
    """Lightweight liveness probe used by orchestrators and uptime monitors."""
    settings = get_settings()
    return HealthResponse(
        status="ok",
        service=settings.app_name,
        version=settings.app_version,
        environment=settings.environment,
        timestamp=datetime.now(timezone.utc),
    )


@api_router.post(
    "/pipeline/run",
    response_model=PipelineResult,
    status_code=status.HTTP_200_OK,
    tags=["pipeline"],
    summary="Trigger one pipeline run on demand and broadcast to WS clients",
)
async def trigger_pipeline(
    attack_type: Optional[str] = Query(
        default=None,
        description=(
            "Force a specific attack type. Valid values: "
            f"{sorted(SIMULATORS)}. Omit for a random attack."
        ),
    ),
) -> PipelineResult:
    """Run one full pipeline iteration and push the result to all WS clients.

    The synchronous response and the WebSocket broadcast carry the *same*
    :class:`PipelineResult`. Callers that are already subscribed to
    ``/ws/live`` will see the event arrive over the socket as well.
    """
    if attack_type is not None and attack_type not in SIMULATORS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown attack_type {attack_type!r}. "
            f"Valid: {sorted(SIMULATORS)}",
        )

                                                                         
                                                                          
                                                                           
                             
    banking_kind = _PIPELINE_TO_BANKING.get(attack_type) if attack_type else None
    if banking_kind is not None:
        try:
            await get_banking_simulator().inject_attack(banking_kind)
        except RuntimeError:
                                                                 
            pass

                                                                             
                                                                              
    await stream_attack_side_channel(manager, attack_type)

    result = await run_pipeline(attack_type=attack_type)
    await manager.broadcast_text(result.model_dump_json())
    if result.threat.severity.value in {"high", "critical"}:
        scenario_type = _THREAT_TO_SCENARIO.get(result.threat.threat_type.value)
        if scenario_type is not None:
            try:
                await get_attack_orchestrator().trigger(scenario_type)
            except Exception:
                pass
    return result


                                                                             


class BankingAttackResponse(BaseModel):
    system: str
    attack_type: str
    duration_seconds: float
    expires_at: str
    peer_system: str


class CopilotChatRequest(BaseModel):
    prompt: str


class CopilotChatResponse(BaseModel):
    answer: str


@api_router.post(
    "/banking/attack",
    response_model=BankingAttackResponse,
    status_code=status.HTTP_200_OK,
    tags=["banking"],
    summary="Inject an attack into the banking infrastructure simulator",
)
async def trigger_banking_attack(
    attack_type: str = Query(
        ...,
        description=(
            "The attack vector to simulate. Valid values: "
            f"{sorted(ATTACK_TYPES)}."
        ),
    ),
    target_system: Optional[str] = Query(
        default=None,
        description=(
            "Override the attack's default primary system. Valid values: "
            f"{sorted(SYSTEMS)}."
        ),
    ),
    duration_seconds: Optional[float] = Query(
        default=None,
        gt=0,
        description="Override engagement length. Defaults to server config.",
    ),
) -> BankingAttackResponse:
    """Lift one banking system into attack mode and broadcast frames.

    The simulator emits ``system_update`` events over ``/ws/live`` showing
    elevated CPU, traffic / login spikes, abnormal queries and unknown
    processes (``suspicious_script.sh``, ``crypto_miner``, etc.) until the
    engagement window expires. The paired system in the same cluster is
    automatically lifted to ``warning`` (lateral pressure).
    """
    if attack_type not in ATTACK_TYPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown attack_type {attack_type!r}. "
            f"Valid: {sorted(ATTACK_TYPES)}",
        )
    if target_system is not None and target_system not in SYSTEMS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown target_system {target_system!r}. "
            f"Valid: {sorted(SYSTEMS)}",
        )

    try:
        simulator = get_banking_simulator()
    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc

    summary = await simulator.inject_attack(
        attack_type,
        target_system=target_system,
        duration_seconds=duration_seconds,
    )
    return BankingAttackResponse(**summary)


@api_router.post(
    "/banking/clear",
    status_code=status.HTTP_204_NO_CONTENT,
    tags=["banking"],
    summary="Clear all active banking attacks immediately",
)
async def clear_banking_attacks() -> None:
    try:
        simulator = get_banking_simulator()
    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc
    await simulator.clear_attacks()


@api_router.get(
    "/banking/snapshot",
    tags=["banking"],
    summary="Return the current per-system snapshot without emitting",
)
async def banking_snapshot() -> dict:
    """Useful for REST clients that want a one-shot view of the topology."""
    try:
        simulator = get_banking_simulator()
    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc
    frames = await simulator.snapshot()
    return {"frames": frames}


@api_router.post(
    "/copilot/chat",
    response_model=CopilotChatResponse,
    status_code=status.HTTP_200_OK,
    tags=["copilot"],
    summary="Send a prompt to AI copilot provider",
)
async def copilot_chat(payload: CopilotChatRequest) -> CopilotChatResponse:
    if not payload.prompt.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="prompt must not be empty",
        )
    answer = generate_chat_response(payload.prompt.strip())
    return CopilotChatResponse(answer=answer)
