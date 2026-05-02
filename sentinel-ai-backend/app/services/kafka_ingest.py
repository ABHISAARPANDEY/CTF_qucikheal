from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
from typing import Any, Optional

from app.models.event import Event, EventType, Severity
from app.services.pipeline import run_pipeline
from app.services.websocket import manager

logger = logging.getLogger(__name__)


def _safe_source_ip(raw: Any) -> str:
    candidate = str(raw or "").strip()
    if not candidate:
        return "203.0.113.10"
    try:
        ipaddress.ip_address(candidate)
        return candidate
    except ValueError:
        return "203.0.113.10"


def _map_event_type(raw: Any) -> EventType:
    text = str(raw or "").strip().lower()
    for item in EventType:
        if item.value == text:
            return item
    if text in {"http", "web"}:
        return EventType.INTRUSION
    return EventType.OTHER


def _map_severity(raw: Any, message: str) -> Severity:
    text = str(raw or "").strip().lower()
    for item in Severity:
        if item.value == text:
            return item
    msg = message.lower()
    if any(k in msg for k in ("drop table", "union select", "sqli", "credential stuffing")):
        return Severity.HIGH
    if any(k in msg for k in ("scan", "failed login", "brute", "suspicious")):
        return Severity.MEDIUM
    return Severity.LOW


def normalize_to_event(payload: dict[str, Any]) -> Event:
    source_ip = _safe_source_ip(payload.get("source_ip") or payload.get("remote_addr"))

    if payload.get("message"):
        message = str(payload["message"])
    else:
        method = payload.get("method") or payload.get("http_method") or "GET"
        path = payload.get("path") or payload.get("url") or "/"
        status = payload.get("status") or payload.get("status_code") or "unknown"
        ua = payload.get("user_agent") or "unknown-agent"
        message = f"{method} {path} status={status} ua={ua}"

    return Event(
        source_ip=source_ip,
        event_type=_map_event_type(payload.get("event_type")),
        severity=_map_severity(payload.get("severity"), message),
        message=message[:2000],
    )


class KafkaIngestor:
    def __init__(
        self,
        *,
        bootstrap_servers: str,
        topic: str,
        group_id: str,
    ) -> None:
        self._bootstrap_servers = bootstrap_servers
        self._topic = topic
        self._group_id = group_id
        self._consumer = None
        self._task: Optional[asyncio.Task[None]] = None
        self._stopping = asyncio.Event()

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    async def start(self) -> None:
        if self.running:
            return
        try:
            from aiokafka import AIOKafkaConsumer
        except Exception as exc:
            logger.warning("Kafka disabled: aiokafka unavailable (%r)", exc)
            return

        self._consumer = AIOKafkaConsumer(
            self._topic,
            bootstrap_servers=self._bootstrap_servers,
            group_id=self._group_id,
            enable_auto_commit=True,
            value_deserializer=lambda b: json.loads(b.decode("utf-8")),
        )
        await self._consumer.start()
        self._stopping.clear()
        self._task = asyncio.create_task(self._run(), name="kafka-ingestor")
        logger.info(
            "kafka ingestor started topic=%s servers=%s",
            self._topic,
            self._bootstrap_servers,
        )

    async def stop(self) -> None:
        self._stopping.set()
        if self._task is not None:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
            self._task = None
        if self._consumer is not None:
            await self._consumer.stop()
            self._consumer = None
        logger.info("kafka ingestor stopped")

    async def _run(self) -> None:
        assert self._consumer is not None
        try:
            async for msg in self._consumer:
                if self._stopping.is_set():
                    break
                try:
                    payload = msg.value if isinstance(msg.value, dict) else {}
                    event = normalize_to_event(payload)
                    result = await run_pipeline(event=event)
                    await manager.broadcast_text(result.model_dump_json())
                except Exception:
                    logger.exception("kafka event processing failed")
        except asyncio.CancelledError:
            return


_ingestor: Optional[KafkaIngestor] = None


def init_kafka_ingestor(
    *,
    bootstrap_servers: str,
    topic: str,
    group_id: str,
) -> KafkaIngestor:
    global _ingestor
    _ingestor = KafkaIngestor(
        bootstrap_servers=bootstrap_servers,
        topic=topic,
        group_id=group_id,
    )
    return _ingestor

