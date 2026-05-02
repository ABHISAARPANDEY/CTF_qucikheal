"""WebSocket transport for the SentinelAI pipeline.

This module is purely the **transport layer**:
    - :class:`ConnectionManager` — asyncio-safe pool of active websockets.
    - :class:`Orchestrator`      — periodically calls
      :func:`app.services.pipeline.run_pipeline` and broadcasts the result.
    - :data:`ws_router`          — exposes ``/ws/live``.

The pipeline composition (simulate → detect → decide → respond → AI) lives
in :mod:`app.services.pipeline`. This file does not know about engines or
models directly — only about the :class:`PipelineResult` payload it ships.

Wiring (see ``app/main.py``):
    1. App startup → :func:`init_orchestrator` + ``orchestrator.start()``.
    2. App includes :data:`ws_router` (mounted at root, exposing ``/ws/live``).
    3. App shutdown → ``orchestrator.stop()``.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.services.pipeline import PipelineResult, run_pipeline

logger = logging.getLogger(__name__)


class ConnectionManager:
    """Asyncio-safe registry of active WebSocket connections.

    Uses a :class:`asyncio.Lock` to serialize membership mutations and
    :func:`asyncio.gather` to fan out broadcasts in parallel. Failed sends
    cause the connection to be evicted on the same tick.
    """

    def __init__(self) -> None:
        self._connections: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    @property
    def count(self) -> int:
        return len(self._connections)

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        async with self._lock:
            self._connections.add(ws)
        logger.info("ws connected (total=%d)", len(self._connections))

    async def disconnect(self, ws: WebSocket) -> None:
        async with self._lock:
            self._connections.discard(ws)
        logger.info("ws disconnected (total=%d)", len(self._connections))

    async def broadcast_text(self, payload: str) -> int:
        """Send ``payload`` to every connection in parallel.

        Returns the number of successful deliveries. Failed connections are
        evicted before returning.
        """
        async with self._lock:
            connections = list(self._connections)

        if not connections:
            return 0

        results = await asyncio.gather(
            *(self._safe_send(ws, payload) for ws in connections),
            return_exceptions=False,
        )

        dead = [ws for ws, ok in zip(connections, results) if not ok]
        if dead:
            async with self._lock:
                for ws in dead:
                    self._connections.discard(ws)
            logger.warning("evicted %d dead connection(s)", len(dead))

        return sum(1 for ok in results if ok)

    @staticmethod
    async def _safe_send(ws: WebSocket, payload: str) -> bool:
        try:
            await ws.send_text(payload)
            return True
        except Exception as exc:
            logger.debug("ws send failed (%r); marking for eviction", exc)
            return False


class Orchestrator:
    """Background pipeline runner that broadcasts each tick to all clients."""

    def __init__(
        self,
        manager: ConnectionManager,
        *,
        interval_seconds: float = 1.0,
    ) -> None:
        if interval_seconds <= 0:
            raise ValueError("interval_seconds must be > 0")
        self._manager = manager
        self._interval = interval_seconds
        self._task: Optional[asyncio.Task[None]] = None
        self._stopping = asyncio.Event()

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    def start(self) -> None:
        if self.running:
            return
        self._stopping.clear()
        self._task = asyncio.create_task(self._run(), name="sentinelai-orchestrator")
        logger.info("orchestrator started (interval=%.2fs)", self._interval)

    async def stop(self) -> None:
        self._stopping.set()
        if self._task is None:
            return
        self._task.cancel()
        try:
            await self._task
        except asyncio.CancelledError:
            pass
        finally:
            self._task = None
        logger.info("orchestrator stopped")

    async def _run(self) -> None:
        while not self._stopping.is_set():
            try:
                await self._tick()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("orchestrator tick failed")

                                                               
            try:
                await asyncio.wait_for(self._stopping.wait(), timeout=self._interval)
            except asyncio.TimeoutError:
                continue

    async def _tick(self) -> None:
                                                                           
                                                                 
        if self._manager.count == 0:
            return

        result: PipelineResult = await run_pipeline()
        delivered = await self._manager.broadcast_text(result.model_dump_json())

        logger.debug(
            "broadcast: type=%s sev=%s actions=%d delivered=%d",
            result.threat.threat_type.value,
            result.threat.severity.value,
            len(result.actions),
            delivered,
        )


manager: ConnectionManager = ConnectionManager()
orchestrator: Optional[Orchestrator] = None


def init_orchestrator(*, interval_seconds: float = 1.0) -> Orchestrator:
    """Create the singleton :class:`Orchestrator` (idempotent)."""
    global orchestrator
    if orchestrator is None:
        orchestrator = Orchestrator(manager, interval_seconds=interval_seconds)
    return orchestrator


ws_router = APIRouter()


@ws_router.websocket("/ws/live")
async def websocket_live(ws: WebSocket) -> None:
    """Stream real-time SentinelAI pipeline events to the client.

    Inbound messages are accepted but ignored — the receive loop exists
    purely to detect client disconnects promptly.
    """
    await manager.connect(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        pass
    except Exception:
        logger.exception("ws receive loop error")
    finally:
        await manager.disconnect(ws)
