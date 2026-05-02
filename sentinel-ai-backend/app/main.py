"""FastAPI application entrypoint for SentinelAI."""

from contextlib import asynccontextmanager
import time
from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import api_router
from app.core.config import get_settings
from app.core.logger import configure_logging, get_logger
from app.services.attack_orchestrator import (
    attack_router,
    init_attack_orchestrator,
)
from app.services.attack_orchestrator import (
    make_websocket_emitter as make_attack_emitter,
)
from app.services.banking_simulation import (
    init_banking_simulator,
    make_websocket_emitter,
)
from app.services.ai_copilot import make_a4f_provider, set_provider
from app.services.websocket import init_orchestrator, manager, ws_router

settings = get_settings()
configure_logging(settings.log_level)
logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(
        "Starting %s v%s in %s mode",
        settings.app_name,
        settings.app_version,
        settings.environment,
    )
    if settings.copilot_provider.lower() == "a4f":
        set_provider(
            make_a4f_provider(
                api_key=settings.a4f_api_key,
                base_url=settings.a4f_base_url,
                model=settings.a4f_model,
            )
        )

    orchestrator = None
    if settings.orchestrator_enabled:
        orchestrator = init_orchestrator(
            interval_seconds=settings.orchestrator_interval_seconds
        )
        orchestrator.start()

    banking = None
    attack_orch = None
    if settings.banking_simulator_enabled:
        banking = init_banking_simulator(
            emit=make_websocket_emitter(manager),
            interval_seconds=settings.banking_simulator_interval_seconds,
            attack_duration_seconds=settings.banking_attack_duration_seconds,
            is_subscriber_present=lambda: manager.count > 0,
        )
        banking.start()

                                                                        
                                                                          
                                                    
        attack_orch = init_attack_orchestrator(
            simulator=banking,
            emit=make_attack_emitter(manager),
        )

    try:
        yield
    finally:
        if attack_orch is not None:
            await attack_orch.cancel_all()
        if banking is not None:
            await banking.stop()
        if orchestrator is not None:
            await orchestrator.stop()
        logger.info("Shutting down %s", settings.app_name)


def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description="SentinelAI — AI-driven cybersecurity backend.",
        docs_url="/docs" if settings.enable_docs else None,
        redoc_url="/redoc" if settings.enable_docs else None,
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.middleware("http")
    async def request_context_middleware(request: Request, call_next):
        request_id = request.headers.get("x-request-id") or uuid4().hex
        started = time.perf_counter()
        response = await call_next(request)
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        response.headers["x-request-id"] = request_id
        logger.info(
            "request_id=%s method=%s path=%s status=%s duration_ms=%s",
            request_id,
            request.method,
            request.url.path,
            response.status_code,
            elapsed_ms,
        )
        return response

    app.include_router(api_router, prefix=settings.api_prefix)
    app.include_router(ws_router)                                       
    app.include_router(attack_router)                                   

    return app


app = create_app()
