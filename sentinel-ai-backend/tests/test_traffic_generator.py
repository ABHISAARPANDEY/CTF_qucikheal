import asyncio

from app.core import thresholds as th
from app.engine import anomaly
from app.engine.detection import reset_default_context
from app.services import alert_store
from app.services.traffic_generator import TrafficGenerator


def test_generator_emits_pipeline_frames_and_stats():
    th.reset_thresholds()
    reset_default_context()
    anomaly.reset_engine()
    anomaly.get_engine().warm_up(n=200, seed=3)
    alert_store.init_alert_store()
    frames = []

    async def emit(text: str):
        frames.append(text)

    async def run():
        g = TrafficGenerator(emit=emit, rate_eps=50, benign_ratio=1.0, is_subscriber_present=lambda: True)
        g.start()
        await asyncio.sleep(0.6)
        info = g.start_attack("port_scan", duration_s=1.0, speed=20.0)
        assert info["kind"] == "port_scan"
        await asyncio.sleep(0.8)
        stats = g.stats()
        await g.stop()
        return stats

    stats = asyncio.run(run())
    assert stats["events_ingested"] >= 20
    assert stats["events_per_sec"] > 0
    assert any('"event"' in f for f in frames)
    assert any('"type": "stats"' in f or '"type":"stats"' in f for f in frames)
    assert all(isinstance(s, dict) for s in stats["active_sessions"])
