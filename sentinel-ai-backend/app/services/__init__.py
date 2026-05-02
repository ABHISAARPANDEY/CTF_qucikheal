"""Service layer orchestrating business workflows between API and engine."""

from app.services.ai_copilot import (
    Explanation,
    ExplanationContext,
    ExplanationProvider,
    MockProvider,
    generate_explanation,
    get_provider,
    set_provider,
)
from app.services.pipeline import PipelineResult, run_pipeline
from app.services.websocket import (
    ConnectionManager,
    Orchestrator,
    init_orchestrator,
    manager,
    ws_router,
)

__all__ = [
    "ConnectionManager",
    "Explanation",
    "ExplanationContext",
    "ExplanationProvider",
    "MockProvider",
    "Orchestrator",
    "PipelineResult",
    "generate_explanation",
    "get_provider",
    "init_orchestrator",
    "manager",
    "run_pipeline",
    "set_provider",
    "ws_router",
]
