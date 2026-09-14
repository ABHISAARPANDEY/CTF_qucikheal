"""Offline detection evaluation.

Runs a seeded mix of benign traffic and attack sessions through the full
detection engine and reports per-kind precision / recall / F1 plus
events-to-first-alert. Ground truth is ``Event.label`` (never read by the
detector).

    python -m scripts.eval_detection --n 5000 --seed 42
"""

from __future__ import annotations

import argparse
import json
import random
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from app.core import thresholds as th
from app.engine import anomaly
from app.engine.detection import detect, reset_default_context
from app.engine.simulation import AttackSession

# label -> the threat types we accept as a correct detection
_ACCEPT: dict[str, set[str]] = {
    "benign": {"benign"},
    "port_scan": {"port_scan"},
    "credential_stuffing": {"credential_stuffing", "brute_force"},
    "low_slow_brute_force": {"brute_force", "credential_stuffing"},
    "brute_force": {"brute_force", "credential_stuffing"},
    "ddos": {"ddos"},
    "sql_injection": {"sql_injection"},
}

KINDS = ["port_scan", "credential_stuffing", "low_slow_brute_force", "brute_force", "ddos", "sql_injection"]


def evaluate(*, n: int = 5000, seed: int = 42, benign_ratio: float = 0.85) -> dict:
    th.reset_thresholds()
    reset_default_context()
    anomaly.reset_engine()
    anomaly.get_engine().warm_up(n=1500, seed=seed)
    rng = random.Random(seed)
    alert_min = th.get_thresholds().alert_min_risk

    sessions: dict[str, AttackSession] = {k: AttackSession(k, seed=seed + i) for i, k in enumerate(KINDS)}
    benign = AttackSession("benign", seed=seed)

    tp: dict[str, int] = defaultdict(int)
    fp: dict[str, int] = defaultdict(int)
    fn: dict[str, int] = defaultdict(int)
    total: dict[str, int] = defaultdict(int)
    first_alert_idx: dict[str, int | None] = {k: None for k in KINDS}
    seen_idx: dict[str, int] = defaultdict(int)

    # Simulated clock so low-and-slow gaps are realistic without sleeping.
    clock = datetime.now(timezone.utc) - timedelta(seconds=n * 0.05)
    for _ in range(n):
        if rng.random() < benign_ratio:
            ev = benign.next()
        else:
            ev = sessions[rng.choice(KINDS)].next()
        clock += timedelta(seconds=0.05 if ev.label != "low_slow_brute_force" else 6.0)
        ev = ev.model_copy(update={"timestamp": clock})
        label = ev.label or "benign"
        t = detect(ev)
        total[label] += 1
        seen_idx[label] += 1
        predicted = t.threat_type.value
        is_alert = t.risk_score >= alert_min
        if label == "benign":
            if is_alert:
                fp["benign"] += 1
            continue
        if predicted in _ACCEPT[label] and is_alert:
            tp[label] += 1
            if first_alert_idx[label] is None:
                first_alert_idx[label] = seen_idx[label]
        else:
            fn[label] += 1
        if is_alert and predicted not in _ACCEPT[label] and predicted != "benign":
            fp[predicted] += 1

    per_kind: dict[str, dict] = {}
    for k in KINDS:
        p_den = tp[k] + fp[k]
        r_den = tp[k] + fn[k]
        precision = tp[k] / p_den if p_den else 0.0
        recall = tp[k] / r_den if r_den else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        per_kind[k] = {
            "events": total[k], "tp": tp[k], "fp": fp[k], "fn": fn[k],
            "precision": round(precision, 3), "recall": round(recall, 3), "f1": round(f1, 3),
            "events_to_first_alert": first_alert_idx[k],
        }
    per_kind["benign"] = {
        "events": total["benign"], "false_alerts": fp["benign"],
        "false_alert_rate": round(fp["benign"] / total["benign"], 4) if total["benign"] else 0.0,
        "precision": 1.0, "recall": 1.0,
    }
    return {"n": n, "seed": seed, "alert_min_risk": alert_min, "per_kind": per_kind}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=5000)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    r = evaluate(n=args.n, seed=args.seed)
    if args.json:
        print(json.dumps(r, indent=2))
        return
    print(f"SentinelAI detection eval — n={r['n']} seed={r['seed']} alert_min_risk={r['alert_min_risk']}")
    print(f"{'kind':24}{'events':>8}{'prec':>8}{'recall':>8}{'f1':>8}{'to-alert':>10}")
    for k, m in r["per_kind"].items():
        if k == "benign":
            print(f"{k:24}{m['events']:>8}{'':>8}{'':>8}{'':>8}  false-alert-rate={m['false_alert_rate']:.2%}")
        else:
            print(f"{k:24}{m['events']:>8}{m['precision']:>8.2f}{m['recall']:>8.2f}{m['f1']:>8.2f}{str(m['events_to_first_alert']):>10}")


if __name__ == "__main__":
    main()
