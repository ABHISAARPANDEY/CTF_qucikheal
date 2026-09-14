from scripts.eval_detection import evaluate


def test_eval_produces_metrics_for_every_kind():
    r = evaluate(n=1500, seed=11)
    assert set(r["per_kind"]) >= {"port_scan", "credential_stuffing", "low_slow_brute_force", "benign"}
    for k, m in r["per_kind"].items():
        assert 0.0 <= m["precision"] <= 1.0 and 0.0 <= m["recall"] <= 1.0
    assert r["per_kind"]["benign"]["false_alert_rate"] < 0.05
    for k in ("credential_stuffing", "port_scan", "low_slow_brute_force"):
        assert r["per_kind"][k]["recall"] > 0.5, k
        assert r["per_kind"][k]["events_to_first_alert"] <= 10, k
