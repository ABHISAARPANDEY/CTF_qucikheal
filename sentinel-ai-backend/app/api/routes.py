"""Top-level API router and base routes."""

import asyncio
import json
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Body, HTTPException, Query, Request, Response, status
from pydantic import BaseModel

from app.core.config import get_settings
from app.core.thresholds import Thresholds, get_thresholds, reset_thresholds, set_thresholds
from app.engine import anomaly
from app.engine.simulation import SESSION_KINDS, SIMULATORS
from app.models.alert import Alert, AlertStatus
from app.models.ws_frames import validate_ws_frame
from app.services.ai_copilot import generate_chat_response
from app.services.alert_store import get_alert_store
from app.services.anomaly_simulation import stream_attack_side_channel
from app.services.attack_orchestrator import get_attack_orchestrator
from app.services.banking_simulation import (
    ATTACK_TYPES,
    SYSTEMS,
    get_banking_simulator,
)
from app.services.kafka_ingest import normalize_to_event
from app.services.pipeline import PipelineResult, run_pipeline
from app.services.reports import build_incident_report, render_markdown
from app.services.traffic_generator import get_traffic_generator
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
    "port_scan": "multi_stage",
    "malware": "multi_stage",
    "phishing": "insider",
    "data_exfiltration": "insider",
    "privilege_escalation": "multi_stage",
    "lateral_movement": "multi_stage",
    "anomaly": "multi_stage",
    "unknown": "multi_stage",
}


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    environment: str
    timestamp: datetime


class ReadyResponse(BaseModel):
    status: str
    orchestrator_enabled: bool
    banking_simulator_enabled: bool
    attack_orchestrator_ready: bool
    banking_simulator_ready: bool
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


@api_router.get(
    "/ready",
    response_model=ReadyResponse,
    status_code=status.HTTP_200_OK,
    tags=["system"],
    summary="Service readiness check",
)
async def readiness_check() -> ReadyResponse:
    settings = get_settings()
    attack_ready = True
    banking_ready = True

    if settings.banking_simulator_enabled:
        try:
            get_banking_simulator()
        except RuntimeError:
            banking_ready = False
    if settings.banking_simulator_enabled:
        try:
            get_attack_orchestrator()
        except RuntimeError:
            attack_ready = False

    ready = attack_ready and banking_ready
    return ReadyResponse(
        status="ready" if ready else "not_ready",
        orchestrator_enabled=settings.orchestrator_enabled,
        banking_simulator_enabled=settings.banking_simulator_enabled,
        attack_orchestrator_ready=attack_ready,
        banking_simulator_ready=banking_ready,
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
        scenario_type = _THREAT_TO_SCENARIO.get(
            result.threat.threat_type.value, "multi_stage"
        )
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


class DemoResetResponse(BaseModel):
    cancelled_scenarios: int
    banking_attacks_cleared: bool
    active_after_reset: list[dict[str, Any]]


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


@api_router.post(
    "/demo/reset",
    response_model=DemoResetResponse,
    status_code=status.HTTP_200_OK,
    tags=["system"],
    summary="Reset active attacks and scenarios for demos",
)
async def reset_demo_state() -> DemoResetResponse:
    try:
        simulator = get_banking_simulator()
        orchestrator = get_attack_orchestrator()
    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc

    cancelled = await orchestrator.cancel_all()
    await simulator.clear_attacks()
    try:
        get_traffic_generator().stop_attacks()
    except RuntimeError:
        pass
    get_alert_store().clear()
    return DemoResetResponse(
        cancelled_scenarios=cancelled,
        banking_attacks_cleared=True,
        active_after_reset=orchestrator.active_runs,
    )


# ---------------------------------------------------------------------------
# Thresholds
# ---------------------------------------------------------------------------


async def _broadcast_config(t: Thresholds) -> None:
    await manager.broadcast_text(
        json.dumps(validate_ws_frame({"type": "config_update", "thresholds": t.model_dump()}))
    )


@api_router.get("/config/thresholds", response_model=Thresholds, tags=["config"])
async def get_thresholds_route() -> Thresholds:
    return get_thresholds()


@api_router.put("/config/thresholds", response_model=Thresholds, tags=["config"])
async def put_thresholds_route(patch: dict[str, Any] = Body(...)) -> Thresholds:
    """Partial update: only the supplied keys change. Validated as a whole."""
    try:
        merged = {**get_thresholds().model_dump(), **patch}
        new = Thresholds.model_validate(merged)
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from exc
    set_thresholds(new)
    await _broadcast_config(new)
    return new


@api_router.post("/config/thresholds/reset", response_model=Thresholds, tags=["config"])
async def reset_thresholds_route() -> Thresholds:
    new = reset_thresholds()
    await _broadcast_config(new)
    return new


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------


class AlertPatch(BaseModel):
    status: Optional[AlertStatus] = None
    notes: Optional[str] = None
    assignee: Optional[str] = None


@api_router.get("/alerts", tags=["alerts"])
async def list_alerts(
    severity: Optional[str] = None,
    status_: Optional[str] = Query(default=None, alias="status"),
    type_: Optional[str] = Query(default=None, alias="type"),
    entity_type: Optional[str] = None,
    limit: int = Query(default=200, ge=1, le=1000),
) -> dict[str, Any]:
    items = get_alert_store().query(
        severity=severity, status=status_, threat_type=type_, entity_type=entity_type, limit=limit
    )
    return {"total": len(items), "items": [a.model_dump(mode="json") for a in items]}


@api_router.get("/alerts/summary", tags=["alerts"])
async def alerts_summary() -> dict[str, Any]:
    return get_alert_store().summary()


@api_router.get("/alerts/{alert_id}", response_model=Alert, tags=["alerts"])
async def get_alert(alert_id: str) -> Alert:
    a = get_alert_store().get(alert_id)
    if a is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="alert not found")
    return a


@api_router.patch("/alerts/{alert_id}", response_model=Alert, tags=["alerts"])
async def patch_alert(alert_id: str, patch: AlertPatch) -> Alert:
    a = get_alert_store().update(alert_id, status=patch.status, notes=patch.notes, assignee=patch.assignee)
    if a is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="alert not found")
    return a


# ---------------------------------------------------------------------------
# Traffic generator / detection engine
# ---------------------------------------------------------------------------


class TrafficAttackRequest(BaseModel):
    kind: str
    duration_s: float = 20.0
    speed: float = 1.0
    seed: Optional[int] = None


@api_router.post("/traffic/attack", status_code=status.HTTP_202_ACCEPTED, tags=["traffic"])
async def traffic_attack(payload: TrafficAttackRequest) -> dict[str, Any]:
    if payload.kind not in SESSION_KINDS or payload.kind == "benign":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown kind. Valid: {sorted(SESSION_KINDS - {'benign'})}",
        )
    try:
        gen = get_traffic_generator()
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc
    return gen.start_attack(payload.kind, duration_s=payload.duration_s, speed=payload.speed, seed=payload.seed)


@api_router.delete("/traffic/attack", tags=["traffic"])
async def traffic_stop_attacks() -> dict[str, int]:
    try:
        return {"stopped": get_traffic_generator().stop_attacks()}
    except RuntimeError:
        return {"stopped": 0}


@api_router.get("/traffic/stats", tags=["traffic"])
async def traffic_stats() -> dict[str, Any]:
    try:
        return get_traffic_generator().stats()
    except RuntimeError:
        s = get_alert_store().stats()
        return {"events_ingested": 0, "events_per_sec": 0.0, "active_sessions": [],
                "alerts_raised": s["raised"], "alerts_deduped": s["deduped"],
                "alerts_suppressed": s["suppressed"], "suppression_ratio": s["suppression_ratio"]}


class TrafficConfig(BaseModel):
    rate_eps: Optional[float] = None
    benign_ratio: Optional[float] = None
    paused: Optional[bool] = None


@api_router.put("/traffic/config", tags=["traffic"])
async def traffic_config(cfg: TrafficConfig) -> dict[str, Any]:
    try:
        gen = get_traffic_generator()
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc
    if cfg.rate_eps is not None:
        gen.rate_eps = max(0.1, min(500.0, cfg.rate_eps))
    if cfg.benign_ratio is not None:
        gen.benign_ratio = max(0.0, min(1.0, cfg.benign_ratio))
    if cfg.paused is not None:
        gen.paused = cfg.paused
    return gen.stats()


@api_router.get("/detection/status", tags=["detection"])
async def detection_status() -> dict[str, Any]:
    eng = anomaly.get_engine()
    return {
        "forest": {
            "fitted": eng.forest.is_fitted,
            "fitted_at": eng.forest.fitted_at.isoformat() if eng.forest.fitted_at else None,
            "train_size": eng.forest.train_size,
        },
        "baseline": {etype: eng.baseline.snapshot(etype) for etype in ("ip", "user", "subnet")},
        "campaigns": eng.campaigns.campaigns(),
    }


@api_router.get("/detection/campaigns", tags=["detection"])
async def detection_campaigns() -> dict[str, Any]:
    return {"campaigns": anomaly.get_engine().campaigns.campaigns()}


@api_router.get("/detection/entity/{etype}/{key:path}", tags=["detection"])
async def detection_entity(etype: str, key: str) -> dict[str, Any]:
    if etype not in ("ip", "user", "subnet", "campaign"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="etype must be ip|user|subnet|campaign")
    eng = anomaly.get_engine()
    if etype == "campaign":
        camp = next((c for c in eng.campaigns.campaigns() if c["campaign_id"] == key), None)
        alerts = [a for a in get_alert_store().all() if a.entity.get("key") == key or a.campaign_id == key][:50]
        if camp is None and not alerts:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="campaign not found")
        return {
            "entity": {"type": "campaign", "key": key},
            "campaign": camp,
            "features": alerts[0].features if alerts else {},
            "zscores": alerts[0].zscores if alerts else {},
            "baseline": eng.baseline.snapshot("ip"),
            "events": [],
            "alerts": [a.model_dump(mode="json") for a in alerts],
        }
    fv = eng.features.features_for(etype, key)
    events = eng.features.events_for(etype, key)
    _, z = eng.baseline.score(etype, fv)
    alerts = [a for a in get_alert_store().all() if a.entity.get("key") == key][:50]
    return {
        "entity": {"type": etype, "key": key},
        "features": fv.as_dict(),
        "zscores": z,
        "baseline": eng.baseline.snapshot(etype),
        "events": [e.model_dump(mode="json") for e in events[-100:]],
        "alerts": [a.model_dump(mode="json") for a in alerts],
    }


@api_router.post("/detection/retrain", tags=["detection"])
async def retrain_forest() -> dict[str, Any]:
    eng = anomaly.get_engine()
    ok = await asyncio.to_thread(eng.refit)
    return {
        "retrained": ok,
        "fitted_at": eng.forest.fitted_at.isoformat() if eng.forest.fitted_at else None,
        "train_size": eng.forest.train_size,
    }


# ---------------------------------------------------------------------------
# Replay ingestion
# ---------------------------------------------------------------------------


@api_router.post("/ingest/replay", tags=["pipeline"])
async def ingest_replay(request: Request) -> dict[str, int]:
    """Ingest NDJSON (one raw log object per line) through the full pipeline."""
    body = (await request.body()).decode("utf-8", errors="replace")
    ingested = errors = 0
    for line in body.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
            event = normalize_to_event(payload)
            result = await run_pipeline(event=event, explain=False)
            await manager.broadcast_text(result.model_dump_json())
            ingested += 1
        except Exception:
            errors += 1
    return {"ingested": ingested, "errors": errors}


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------


@api_router.get("/reports/incident", tags=["reports"])
async def incident_report(request: Request, since: Optional[datetime] = None):
    try:
        stats = get_traffic_generator().stats()
    except RuntimeError:
        stats = {}
    report = build_incident_report(get_alert_store(), stats=stats, since=since)
    if "text/markdown" in request.headers.get("accept", ""):
        return Response(content=render_markdown(report), media_type="text/markdown")
    return report
