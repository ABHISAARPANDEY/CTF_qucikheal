import time

from fastapi.testclient import TestClient

from app.core import thresholds as th
from app.engine import signatures
from app.main import create_app


def _client(tmp_path, monkeypatch):
    from app.main import settings as app_settings

    monkeypatch.setattr(th, "_PATH", tmp_path / "thresholds.json")
    monkeypatch.setattr(th, "_current", None)
    monkeypatch.setattr(app_settings, "signatures_path", str(tmp_path / "sigs.json"))
    signatures.reset_signature_store()
    return TestClient(create_app())


def test_signatures_learned_and_listed_then_cleared(tmp_path, monkeypatch):
    import json

    with _client(tmp_path, monkeypatch) as c:
        assert c.get("/api/v1/signatures").json()["count"] == 0
        # Drive a credential-stuffing campaign synchronously through the replay
        # endpoint (processed inline, no dependence on the background loop) so
        # the pipeline confirms an alert and learns a signature deterministically.
        lines = [
            json.dumps({
                "source_ip": f"45.146.{i}.{i + 1}", "event_type": "auth",
                "message": "POST /oauth/token status=401", "username": f"user{i}@corp.com",
                "user_agent": "python-requests/2.31.0", "endpoint": "/oauth/token", "status_code": 401,
            })
            for i in range(20)
        ]
        r = c.post("/api/v1/ingest/replay", content="\n".join(lines), headers={"content-type": "application/x-ndjson"})
        assert r.status_code == 200 and r.json()["ingested"] == 20
        listing = c.get("/api/v1/signatures").json()
        assert listing["count"] >= 1
        sig = listing["signatures"][0]
        assert sig["threat_type"]  # a concrete threat type was learned
        assert sig["indicator"].startswith(("ua:", "subnet:", "port:"))
        # every learned indicator is attacker-specific, never a real browser
        assert not any("chrome" in s["indicator"] or "firefox" in s["indicator"] for s in listing["signatures"])
        cleared = c.delete("/api/v1/signatures").json()
        assert cleared["cleared"] >= 1
        assert c.get("/api/v1/signatures").json()["count"] == 0


def test_scenario_detects_before_engaging_honeypot(tmp_path, monkeypatch):
    import json

    with _client(tmp_path, monkeypatch) as c:
        with c.websocket_connect("/ws/live") as ws:
            r = c.post("/attack", json={"type": "brute_force"})
            assert r.status_code == 202
            run_id = r.json()["run_id"]
            first_pipeline_at = None
            first_honeypot_at = None
            for i in range(200):
                f = json.loads(ws.receive_text())
                t = f.get("type")
                if first_pipeline_at is None and f.get("threat") is not None:
                    first_pipeline_at = i
                if first_honeypot_at is None and t == "honeypot_activity" and f.get("run_id") == run_id:
                    first_honeypot_at = i
                if first_pipeline_at is not None and first_honeypot_at is not None:
                    break
            assert first_pipeline_at is not None, "no detection frame seen"
            assert first_honeypot_at is not None, "no honeypot frame seen"
            # detection must surface before the honeypot engages
            assert first_pipeline_at <= first_honeypot_at
