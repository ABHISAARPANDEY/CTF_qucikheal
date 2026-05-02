from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter


class ProcessEntry(BaseModel):
    model_config = ConfigDict(extra="allow")

    name: str
    pid: int
    cpu: float
    status: str
    malicious: bool


class SystemUpdateData(BaseModel):
    model_config = ConfigDict(extra="allow")

    cpu: float
    requests: int
    latency_ms: int
    error_rate: float
    status: str
    anomalies: list[str]
    processes: list[ProcessEntry]
    ts: str


class SystemUpdateFrame(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["system_update"]
    system: str
    data: SystemUpdateData


class ScenarioEventFrame(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["scenario_event"]
    scenario: str
    run_id: str
    stage: int
    total_stages: int
    severity: str
    system: str | None = None
    label: str
    ts: str


class HoneypotActivityData(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: str


class HoneypotActivityFrame(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["honeypot_activity"]
    run_id: str
    attack_type: str
    step: int
    total_steps: int
    ts: str
    data: HoneypotActivityData


class HoneypotAnalysisData(BaseModel):
    model_config = ConfigDict(extra="forbid")

    pattern: str
    risk: str


class HoneypotAnalysisFrame(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["honeypot_analysis"]
    run_id: str
    attack_type: str
    step: int
    total_steps: int
    ts: str
    data: HoneypotAnalysisData


class AnomalyData(BaseModel):
    model_config = ConfigDict(extra="allow")

    kind: str
    status: str


class AnomalyFrame(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["anomaly"]
    system: str
    data: AnomalyData


class ProcessLogData(BaseModel):
    model_config = ConfigDict(extra="forbid")

    level: str
    process: str
    message: str
    pid: int | None = None


class ProcessLogFrame(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["process_log"]
    system: str
    data: ProcessLogData


class RecoveryData(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: str
    target: str
    status: str
    detail: str | None = None


class RecoveryFrame(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["recovery"]
    system: str
    data: RecoveryData


WsFrame = Annotated[
    SystemUpdateFrame
    | ScenarioEventFrame
    | HoneypotActivityFrame
    | HoneypotAnalysisFrame
    | AnomalyFrame
    | ProcessLogFrame
    | RecoveryFrame,
    Field(discriminator="type"),
]

_WS_FRAME_ADAPTER = TypeAdapter(WsFrame)


def validate_ws_frame(payload: dict[str, Any]) -> dict[str, Any]:
    frame = _WS_FRAME_ADAPTER.validate_python(payload)
    return frame.model_dump(mode="json", exclude_none=True)
