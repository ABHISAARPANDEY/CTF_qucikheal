"""Detection / analysis engine.

Threat detection, scoring, and pipeline components live here.
"""

from app.engine.decision import (
    PLAYBOOK,
    decide,
)
from app.engine.detection import (
    KILL_CHAIN_PATTERNS,
    DetectionContext,
    Signal,
    calculate_confidence,
    calculate_risk,
    detect,
    get_default_context,
    reset_default_context,
    update_context,
)
from app.engine.response import (
    HANDLERS,
    ExecutionResult,
    ResponseReport,
    respond,
)
from app.engine.simulation import (
    SIMULATORS,
    generate_batch,
    generate_bruteforce_event,
    generate_ddos_event,
    generate_event,
    generate_sql_injection_event,
)

__all__ = [
    "DetectionContext",
    "ExecutionResult",
    "HANDLERS",
    "KILL_CHAIN_PATTERNS",
    "PLAYBOOK",
    "ResponseReport",
    "SIMULATORS",
    "Signal",
    "calculate_confidence",
    "calculate_risk",
    "decide",
    "detect",
    "generate_batch",
    "generate_bruteforce_event",
    "generate_ddos_event",
    "generate_event",
    "generate_sql_injection_event",
    "get_default_context",
    "reset_default_context",
    "respond",
    "update_context",
]
