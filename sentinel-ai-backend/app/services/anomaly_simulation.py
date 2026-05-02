"""System-level anomaly simulation — streams synthetic host telemetry over WebSocket.

Emitted during ``POST /api/v1/pipeline/run`` *before* the canonical
:class:`~app.services.pipeline.PipelineResult` payload so clients can show
precursor activity (CPU spikes, rogue processes, odd queries) then the
correlated detection tick.

Envelope shapes (JSON objects sent as WebSocket text frames)::

    {"type": "anomaly", "system": "auth_server", "data": {...}}
    {"type": "process_log", "system": "api_server", "data": {...}}
    {"type": "recovery", "system": "database", "data": {...}}

These messages deliberately omit ``event`` / ``threat`` keys so existing
dashboard parsers leave pipeline state unchanged until the final broadcast.
"""

from __future__ import annotations

import asyncio
import json
import logging
import random
from typing import Any, Optional

from app.models.ws_frames import validate_ws_frame
from app.services.websocket import ConnectionManager

logger = logging.getLogger(__name__)

                                                                             
API_SERVER = "api_server"
AUTH_SERVER = "auth_server"
DATABASE = "database"

SYSTEMS = (API_SERVER, AUTH_SERVER, DATABASE)

                                                       
_ATTACK_PRIMARY_SYSTEM: dict[str, str] = {
    "ddos": API_SERVER,
    "brute_force": AUTH_SERVER,
    "sql_injection": DATABASE,
}


def resolve_primary_system(attack_type: Optional[str]) -> str:
    """Pick the host under heaviest synthetic stress for this attack."""
    if attack_type and attack_type in _ATTACK_PRIMARY_SYSTEM:
        return _ATTACK_PRIMARY_SYSTEM[attack_type]
    return random.choice(SYSTEMS)


                                                                              


def anomaly_payload(
    *,
    kind: str,
    status: str,
    **extra: Any,
) -> dict[str, Any]:
    """Normalized ``data`` object for ``type: anomaly``."""
    body: dict[str, Any] = {"kind": kind, "status": status}
    body.update(extra)
    return body


def anomaly_message(system: str, data: dict[str, Any]) -> dict[str, Any]:
    return {"type": "anomaly", "system": system, "data": data}


def process_log_message(
    system: str,
    *,
    level: str,
    process: str,
    message: str,
    pid: Optional[int] = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "type": "process_log",
        "system": system,
        "data": {
            "level": level,
            "process": process,
            "message": message,
        },
    }
    if pid is not None:
        payload["data"]["pid"] = pid
    return payload


def recovery_message(
    system: str,
    *,
    action: str,
    target: str,
    status: str,
    detail: Optional[str] = None,
) -> dict[str, Any]:
    data: dict[str, Any] = {
        "action": action,
        "target": target,
        "status": status,
    }
    if detail:
        data["detail"] = detail
    return {"type": "recovery", "system": system, "data": data}


                                                                              


def _sequence_for_attack(primary: str, attack_type: Optional[str]) -> list[dict[str, Any]]:
    """Ordered list of WS JSON objects for one engagement preamble."""

                                                               
    others = [s for s in SYSTEMS if s != primary]
    secondary = others[0]
    tertiary = others[1]

    lines: list[dict[str, Any]] = []

                                                                            
    lines.append(
        process_log_message(
            API_SERVER,
            level="info",
            process="nginx",
            message="worker idle, upstream latency p99 42ms",
            pid=4412,
        )
    )
    lines.append(
        process_log_message(
            primary,
            level="info",
            process=_baseline_daemon(primary),
            message=_baseline_message(primary),
            pid=random.randint(9000, 32000),
        )
    )

                                                                            
    lines.append(
        anomaly_message(
            primary,
            anomaly_payload(
                kind="high_cpu",
                status="elevated",
                cpu_percent=round(random.uniform(87.0, 98.5), 1),
                process=_hot_process(primary),
            ),
        )
    )

    lines.append(
        anomaly_message(
            secondary,
            anomaly_payload(
                kind="unknown_process",
                status="investigating",
                process=_foreign_binary(),
                cmdline="/tmp/.xdg-helper --daemon",
                uid=65534,
            ),
        )
    )

                                                                    
    lines.append(
        anomaly_message(
            AUTH_SERVER,
            {
                "process": "suspicious_script.sh",
                "status": "malicious",
                "kind": "suspicious_script",
            },
        )
    )

    lines.append(
        anomaly_message(
            DATABASE,
            anomaly_payload(
                kind="abnormal_db_queries",
                status="anomalous",
                query_snippet="SELECT * FROM users WHERE 1=1 OR ''=''",
                rows_examined=2_400_000,
                duration_ms=8420,
            ),
        )
    )

    if attack_type == "sql_injection":
        lines.append(
            anomaly_message(
                DATABASE,
                anomaly_payload(
                    kind="abnormal_db_queries",
                    status="critical",
                    query_snippet="' UNION SELECT password FROM admins--",
                    rows_examined=12,
                    duration_ms=120,
                ),
            )
        )

                                                                            
    lines.append(
        process_log_message(
            tertiary,
            level="debug",
            process="metrics-agent",
            message="scrape cycle OK — exporters responsive",
        )
    )

                                                                            
    lines.append(
        recovery_message(
            primary,
            action="cgroups_throttle",
            target=_hot_process(primary),
            status="applied",
            detail="CPU quota restored to baseline tier",
        )
    )
    lines.append(
        recovery_message(
            AUTH_SERVER,
            action="process_terminated",
            target="suspicious_script.sh",
            status="contained",
        )
    )
    lines.append(
        recovery_message(
            DATABASE,
            action="query_kill",
            target="pid 88421",
            status="session_terminated",
            detail="connection stamped suspect — honeypot tier",
        )
    )

    return lines


def _baseline_daemon(system: str) -> str:
    return {
        API_SERVER: "uvicorn",
        AUTH_SERVER: "keycloak",
        DATABASE: "postgresql",
    }[system]


def _baseline_message(system: str) -> str:
    return {
        API_SERVER: "request throughput nominal — routing mesh stable",
        AUTH_SERVER: "token mint latency steady — JWKS refresh OK",
        DATABASE: "checkpoint complete — WAL archived",
    }[system]


def _hot_process(system: str) -> str:
    return {
        API_SERVER: "uvicorn",
        AUTH_SERVER: "sshd",
        DATABASE: "postgres",
    }[system]


def _foreign_binary() -> str:
    return random.choice(("kthread_worker", "dbus-spawn", ".systemd-private-cache"))


                                                                              


async def broadcast_json(manager: ConnectionManager, payload: dict[str, Any]) -> None:
    """Serialize ``payload`` and fan out to all WS clients."""
    validated = validate_ws_frame(payload)
    await manager.broadcast_text(json.dumps(validated, default=str))


async def stream_attack_side_channel(
    manager: ConnectionManager,
    attack_type: Optional[str],
    *,
    step_delay_ms: float = 135.0,
) -> None:
    """Emit normal logs, anomalies, and recovery frames before the pipeline tick.

    No-op when there are no subscribers (cheap early exit inside broadcast).
    """
    primary = resolve_primary_system(attack_type)
    sequence = _sequence_for_attack(primary, attack_type)

    delay_sec = max(0.0, step_delay_ms / 1000.0)

    for i, frame in enumerate(sequence):
        await broadcast_json(manager, frame)
        logger.debug(
            "anomaly_simulation frame %d/%d type=%s system=%s",
            i + 1,
            len(sequence),
            frame.get("type"),
            frame.get("system"),
        )
        if delay_sec > 0 and i < len(sequence) - 1:
            await asyncio.sleep(delay_sec)


