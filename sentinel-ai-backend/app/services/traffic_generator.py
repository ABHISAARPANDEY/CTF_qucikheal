"""Background mixed-traffic generator.

Streams benign customer traffic at ``rate_eps`` events/sec and interleaves
events from active :class:`AttackSession`s. Every event goes through
:func:`run_pipeline` (detect → decide → respond → alert) and the resulting
frame is broadcast. A ``stats`` frame is emitted once per second.
"""

from __future__ import annotations

import asyncio
import json
import logging
import random
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Optional

from app.engine.simulation import AttackSession, SESSION_KINDS
from app.models.ws_frames import validate_ws_frame
from app.services.alert_store import get_alert_store
from app.services.pipeline import run_pipeline

logger = logging.getLogger(__name__)
EmitText = Callable[[str], Awaitable[None]]


@dataclass
class _Live:
    id: str
    session: AttackSession
    ends_at: float
    speed: float
    next_at: float = 0.0
    emitted: int = 0
    started_at: float = field(default_factory=time.time)


class TrafficGenerator:
    def __init__(
        self,
        *,
        emit: EmitText,
        rate_eps: float = 12.0,
        benign_ratio: float = 0.9,
        is_subscriber_present: Callable[[], bool] = lambda: True,
    ) -> None:
        self._emit = emit
        self.rate_eps = rate_eps
        self.benign_ratio = benign_ratio
        self._subscribed = is_subscriber_present
        self._benign = AttackSession("benign")
        self._live: dict[str, _Live] = {}
        self._task: Optional[asyncio.Task[None]] = None
        self._stats_task: Optional[asyncio.Task[None]] = None
        self._stopping = asyncio.Event()
        self._ingested = 0
        self._eps = 0.0
        self._tick_count = 0
        self._started_at = time.time()
        self.paused = False

    # -- lifecycle --------------------------------------------------------

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    def start(self) -> None:
        if self.running:
            return
        self._stopping.clear()
        self._task = asyncio.create_task(self._run(), name="traffic-generator")
        self._stats_task = asyncio.create_task(self._stats_loop(), name="traffic-stats")
        logger.info("traffic generator started (rate=%.1f eps, benign=%.0f%%)", self.rate_eps, self.benign_ratio * 100)

    async def stop(self) -> None:
        self._stopping.set()
        for t in (self._task, self._stats_task):
            if t is not None:
                t.cancel()
                await asyncio.gather(t, return_exceptions=True)
        self._task = self._stats_task = None
        logger.info("traffic generator stopped")

    # -- attacks ----------------------------------------------------------

    def start_attack(
        self, kind: str, *, duration_s: float = 20.0, speed: float = 1.0, seed: int | None = None
    ) -> dict[str, Any]:
        if kind not in SESSION_KINDS or kind == "benign":
            raise KeyError(f"Unknown attack kind {kind!r}")
        live = _Live(
            id=uuid.uuid4().hex[:8],
            session=AttackSession(kind, seed=seed),
            ends_at=time.time() + duration_s,
            speed=max(0.01, speed),
        )
        self._live[live.id] = live
        return {"id": live.id, "kind": kind, "duration_s": duration_s, "speed": speed}

    def stop_attacks(self) -> int:
        n = len(self._live)
        self._live.clear()
        return n

    # -- stats ------------------------------------------------------------

    def stats(self) -> dict[str, Any]:
        s = get_alert_store().stats()
        now = time.time()
        return {
            "events_ingested": self._ingested,
            "events_per_sec": round(self._eps, 1),
            "target_eps": self.rate_eps,
            "benign_ratio": self.benign_ratio,
            "paused": self.paused,
            "uptime_s": int(now - self._started_at),
            "alerts_raised": s["raised"],
            "alerts_deduped": s["deduped"],
            "alerts_suppressed": s["suppressed"],
            "suppression_ratio": s["suppression_ratio"],
            "active_sessions": [
                {"id": l.id, "kind": l.session.kind, "emitted": l.emitted, "remaining_s": max(0, int(l.ends_at - now))}
                for l in self._live.values()
            ],
        }

    # -- loops ------------------------------------------------------------

    async def _stats_loop(self) -> None:
        while not self._stopping.is_set():
            await asyncio.sleep(1.0)
            self._eps = 0.7 * self._eps + 0.3 * self._tick_count
            self._tick_count = 0
            if self._subscribed():
                try:
                    await self._emit(json.dumps(validate_ws_frame({"type": "stats", "data": self.stats()})))
                except Exception:
                    logger.exception("stats emit failed")

    async def _run(self) -> None:
        while not self._stopping.is_set():
            t0 = time.perf_counter()
            try:
                if not self.paused:
                    await self._tick()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("traffic tick failed")
            interval = 1.0 / max(0.1, self.rate_eps)
            elapsed = time.perf_counter() - t0
            await asyncio.sleep(max(0.0, interval - elapsed))

    async def _process(self, event) -> None:
        result = await run_pipeline(event=event, explain=False)
        self._ingested += 1
        self._tick_count += 1
        if self._subscribed():
            await self._emit(result.model_dump_json())

    async def _tick(self) -> None:
        now = time.time()
        for lid, live in list(self._live.items()):
            if now >= live.ends_at:
                del self._live[lid]
                continue
            if now >= live.next_at:
                await self._process(live.session.next())
                live.emitted += 1
                live.next_at = now + live.session.delay_hint() / live.speed
        if random.random() < self.benign_ratio or not self._live:
            await self._process(self._benign.next())


_generator: Optional[TrafficGenerator] = None


def get_traffic_generator() -> TrafficGenerator:
    if _generator is None:
        raise RuntimeError("traffic generator not initialised")
    return _generator


def init_traffic_generator(**kwargs: Any) -> TrafficGenerator:
    global _generator
    _generator = TrafficGenerator(**kwargs)
    return _generator
