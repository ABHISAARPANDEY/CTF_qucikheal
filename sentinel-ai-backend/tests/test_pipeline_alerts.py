import asyncio

from app.core import thresholds as th
from app.engine import anomaly
from app.engine.detection import reset_default_context
from app.engine.simulation import AttackSession
from app.services import alert_store
from app.services.pipeline import run_pipeline


def test_pipeline_feeds_alert_store_and_skips_explanation_when_asked():
    th.reset_thresholds()
    reset_default_context()
    anomaly.reset_engine()
    anomaly.get_engine().warm_up(n=200, seed=3)
    store = alert_store.init_alert_store()

    async def run():
        s = AttackSession("credential_stuffing", seed=5)
        last = None
        for _ in range(20):
            last = await run_pipeline(event=s.next(), explain=False)
        return last

    result = asyncio.run(run())
    assert result.explanation.provider == "skipped"
    assert store.stats()["raised"] >= 1
    assert result.alert_id is not None
