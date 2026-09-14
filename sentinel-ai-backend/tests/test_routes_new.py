import json
import time

from fastapi.testclient import TestClient

from app.core import thresholds as th
from app.main import create_app


def _client(tmp_path, monkeypatch):
    monkeypatch.setattr(th, "_PATH", tmp_path / "thresholds.json")
    monkeypatch.setattr(th, "_current", None)
    return TestClient(create_app())


def test_thresholds_get_put_reset(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch) as c:
        r = c.get("/api/v1/config/thresholds")
        assert r.status_code == 200 and r.json()["alert_min_risk"] == 4.0
        r = c.put("/api/v1/config/thresholds", json={"alert_min_risk": 6.0})
        assert r.status_code == 200 and r.json()["alert_min_risk"] == 6.0
        assert c.get("/api/v1/config/thresholds").json()["alert_min_risk"] == 6.0
        r = c.put("/api/v1/config/thresholds", json={"alert_min_risk": 42})
        assert r.status_code == 422
        r = c.post("/api/v1/config/thresholds/reset")
        assert r.status_code == 200 and r.json()["alert_min_risk"] == 4.0


def test_traffic_attack_alerts_and_report_flow(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch) as c:
        r = c.post("/api/v1/traffic/attack", json={"kind": "credential_stuffing", "duration_s": 2, "speed": 50})
        assert r.status_code == 202
        assert r.json()["kind"] == "credential_stuffing"
        time.sleep(2.5)
        stats = c.get("/api/v1/traffic/stats").json()
        assert stats["events_ingested"] > 0
        alerts = c.get("/api/v1/alerts?type=credential_stuffing").json()
        assert alerts["total"] >= 1
        aid = alerts["items"][0]["id"]
        one = c.get(f"/api/v1/alerts/{aid}")
        assert one.status_code == 200 and one.json()["risk_breakdown"]
        upd = c.patch(f"/api/v1/alerts/{aid}", json={"status": "acknowledged", "notes": "seen"})
        assert upd.status_code == 200 and upd.json()["status"] == "acknowledged"
        assert c.get("/api/v1/alerts/summary").json()["by_status"]["acknowledged"] >= 1
        rep = c.get("/api/v1/reports/incident")
        assert rep.status_code == 200 and rep.json()["metrics"]["alerts_raised"] >= 1
        md = c.get("/api/v1/reports/incident", headers={"accept": "text/markdown"})
        assert md.status_code == 200 and md.text.startswith("# SentinelAI Incident Report")
        assert c.get("/api/v1/alerts/does-not-exist").status_code == 404
        st = c.get("/api/v1/detection/status").json()
        assert st["forest"]["fitted"] is True
        ent = c.get(f"/api/v1/detection/entity/ip/{alerts['items'][0]['entity']['key']}")
        assert ent.status_code == 200 and "features" in ent.json()


def test_replay_ndjson(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch) as c:
        lines = [
            json.dumps({"source_ip": "9.9.9.9", "event_type": "auth", "message": "POST /api/login status=401",
                        "username": f"u{i}", "status_code": 401})
            for i in range(12)
        ]
        r = c.post("/api/v1/ingest/replay", content="\n".join(lines), headers={"content-type": "application/x-ndjson"})
        assert r.status_code == 200
        body = r.json()
        assert body["ingested"] == 12 and body["errors"] == 0


def test_ws_receives_stats_and_config_frames(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch) as c:
        with c.websocket_connect("/ws/live") as ws:
            c.put("/api/v1/config/thresholds", json={"alert_min_risk": 5.5})
            kinds = set()
            for _ in range(80):
                f = json.loads(ws.receive_text())
                kinds.add(f.get("type"))
                if "config_update" in kinds:
                    break
            assert "config_update" in kinds
