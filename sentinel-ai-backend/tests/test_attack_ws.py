import json

from fastapi.testclient import TestClient

from app.main import create_app


def _drain_messages(ws, limit=120):
    out = []
    for _ in range(limit):
        out.append(json.loads(ws.receive_text()))
    return out


def _assert_system_update_contract(frame):
    assert frame["type"] == "system_update"
    assert isinstance(frame["system"], str)
    data = frame["data"]
    assert isinstance(data["cpu"], (int, float))
    assert isinstance(data["requests"], int)
    assert isinstance(data["latency_ms"], int)
    assert isinstance(data["error_rate"], (int, float))
    assert data["status"] in {"normal", "warning", "critical"}
    assert isinstance(data["anomalies"], list)
    assert isinstance(data["processes"], list)
    assert isinstance(data["ts"], str)


def _assert_scenario_event_contract(frame):
    assert frame["type"] == "scenario_event"
    assert isinstance(frame["scenario"], str)
    assert isinstance(frame["run_id"], str)
    assert isinstance(frame["stage"], int)
    assert isinstance(frame["total_stages"], int)
    assert frame["severity"] in {"info", "warning", "high", "critical"}
    assert "label" in frame
    assert isinstance(frame["ts"], str)


def _assert_honeypot_contract(frame, expected_type):
    assert frame["type"] == expected_type
    assert isinstance(frame["run_id"], str)
    assert isinstance(frame["attack_type"], str)
    assert isinstance(frame["step"], int)
    assert isinstance(frame["total_steps"], int)
    assert isinstance(frame["ts"], str)
    assert isinstance(frame["data"], dict)


def test_attack_lifecycle_and_websocket_contracts():
    app = create_app()
    with TestClient(app) as client:
        with client.websocket_connect("/ws/live") as ws:
            ws.send_text("hello")
            created = client.post("/attack", json={"type": "ddos"})
            assert created.status_code == 202
            created_json = created.json()
            run_id = created_json["run_id"]

            active = client.get("/attack")
            assert active.status_code == 200
            active_runs = active.json()["active"]
            assert any(run["run_id"] == run_id for run in active_runs)

            frames = _drain_messages(ws, limit=140)
            scenario = [f for f in frames if f.get("type") == "scenario_event" and f.get("run_id") == run_id]
            hp_activity = [f for f in frames if f.get("type") == "honeypot_activity" and f.get("run_id") == run_id]
            hp_analysis = [f for f in frames if f.get("type") == "honeypot_analysis" and f.get("run_id") == run_id]
            system_updates = [f for f in frames if f.get("type") == "system_update"]

            assert scenario
            assert hp_activity
            assert hp_analysis
            assert system_updates

            _assert_scenario_event_contract(scenario[0])
            _assert_honeypot_contract(hp_activity[0], "honeypot_activity")
            assert "action" in hp_activity[0]["data"]
            _assert_honeypot_contract(hp_analysis[0], "honeypot_analysis")
            assert "pattern" in hp_analysis[0]["data"]
            assert "risk" in hp_analysis[0]["data"]
            _assert_system_update_contract(system_updates[0])


def test_cancel_and_reconnect_behavior():
    app = create_app()
    with TestClient(app) as client:
        with client.websocket_connect("/ws/live") as ws1:
            ws1.send_text("start")
            started = client.post("/attack", json={"type": "multi_stage"})
            assert started.status_code == 202
            run_id = started.json()["run_id"]
            frames = _drain_messages(ws1, limit=60)
            assert any(f.get("run_id") == run_id for f in frames if f.get("type") == "scenario_event")

            cancelled = client.delete("/attack")
            assert cancelled.status_code == 200
            assert cancelled.json()["cancelled"] >= 1

        with client.websocket_connect("/ws/live") as ws2:
            ws2.send_text("reconnect")
            started2 = client.post("/attack", json={"type": "brute_force"})
            assert started2.status_code == 202
            run_id_2 = started2.json()["run_id"]
            frames2 = _drain_messages(ws2, limit=80)
            assert any(
                f.get("type") == "scenario_event" and f.get("run_id") == run_id_2
                for f in frames2
            )

            reset = client.post("/api/v1/demo/reset")
            assert reset.status_code == 200
            payload = reset.json()
            assert payload["banking_attacks_cleared"] is True
            assert payload["active_after_reset"] == []
