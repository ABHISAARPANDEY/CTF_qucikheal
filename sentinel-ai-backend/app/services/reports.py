"""Incident report builder — aggregates the AlertStore into an IR triage summary."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any, Optional

from app.services.alert_store import AlertStore


def build_incident_report(
    store: AlertStore,
    *,
    stats: Optional[dict[str, Any]] = None,
    since: Optional[datetime] = None,
) -> dict[str, Any]:
    alerts = [a for a in store.all() if since is None or a.last_seen >= since]
    stats = stats or {}

    by_sev = Counter(a.severity.value for a in alerts)
    by_type = Counter(a.threat_type.value for a in alerts)
    by_status = Counter(a.status.value for a in alerts)

    attackers: dict[str, dict[str, Any]] = {}
    targets: dict[str, dict[str, Any]] = {}
    for a in alerts:
        if a.entity.get("type") == "ip":
            row = attackers.setdefault(
                a.entity["key"], {"ip": a.entity["key"], "alerts": 0, "events": 0, "risk_max": 0.0, "types": set()}
            )
            row["alerts"] += 1
            row["events"] += a.count
            row["risk_max"] = max(row["risk_max"], a.risk)
            row["types"].add(a.threat_type.value)
        elif a.entity.get("type") == "user":
            row = targets.setdefault(a.entity["key"], {"user": a.entity["key"], "alerts": 0, "events": 0, "risk_max": 0.0})
            row["alerts"] += 1
            row["events"] += a.count
            row["risk_max"] = max(row["risk_max"], a.risk)

    top_attackers = sorted(attackers.values(), key=lambda r: (-r["risk_max"], -r["events"]))[:10]
    for r in top_attackers:
        r["types"] = sorted(r["types"])
    top_targets = sorted(targets.values(), key=lambda r: (-r["risk_max"], -r["events"]))[:10]

    mitre = Counter(t for a in alerts for t in a.mitre)
    campaigns = Counter(a.campaign_id for a in alerts if a.campaign_id)

    timeline = sorted(
        (
            {
                "ts": a.first_seen.isoformat(), "alert_id": str(a.id), "type": a.threat_type.value,
                "severity": a.severity.value, "entity": a.entity, "risk": a.risk, "count": a.count,
                "status": a.status.value,
            }
            for a in alerts
        ),
        key=lambda r: r["ts"],
    )
    actions = [
        {
            "alert_id": str(a.id), "action_type": act.action_type.value, "target": act.target,
            "priority": act.priority.value, "reason": act.reason,
        }
        for a in alerts
        for act in a.actions
    ]

    first_seen = min((a.first_seen for a in alerts), default=None)

    # MTTD: mean seconds between a campaign's earliest alert and each of its
    # subsequent alerts (0 for alerts outside any campaign).
    mttd = None
    if alerts:
        starts: dict[str, datetime] = {}
        for a in alerts:
            if a.campaign_id:
                starts[a.campaign_id] = min(starts.get(a.campaign_id, a.first_seen), a.first_seen)
        deltas = [(a.first_seen - starts[a.campaign_id]).total_seconds() if a.campaign_id else 0.0 for a in alerts]
        mttd = round(sum(deltas) / len(deltas), 2)

    s = store.stats()
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "window": {
            "since": since.isoformat() if since else None,
            "first_alert": first_seen.isoformat() if first_seen else None,
        },
        "metrics": {
            "events_ingested": stats.get("events_ingested", 0),
            "events_per_sec": stats.get("events_per_sec", 0.0),
            "alerts_raised": len(alerts),
            "alerts_open": sum(v for k, v in by_status.items() if k in ("new", "acknowledged", "investigating")),
            "deduped": s["deduped"],
            "suppressed": s["suppressed"],
            "suppression_ratio": s["suppression_ratio"],
            "mttd_s": mttd,
        },
        "alerts_by_severity": dict(by_sev),
        "alerts_by_type": dict(by_type),
        "alerts_by_status": dict(by_status),
        "top_attackers": top_attackers,
        "top_targets": top_targets,
        "campaigns": [{"campaign_id": k, "alerts": v} for k, v in campaigns.most_common(10)],
        "mitre_coverage": [{"technique": k, "count": v} for k, v in mitre.most_common()],
        "timeline": timeline,
        "actions": actions,
    }


def render_markdown(r: dict[str, Any]) -> str:
    m = r["metrics"]
    lines = [
        "# SentinelAI Incident Report",
        "",
        f"_Generated {r['generated_at']}_",
        "",
        "## Summary",
        "",
        f"- Events ingested: **{m['events_ingested']}** ({m['events_per_sec']} ev/s)",
        f"- Alerts raised: **{m['alerts_raised']}** (open: {m['alerts_open']})",
        f"- Deduplicated: {m['deduped']} · Suppressed below threshold: {m['suppressed']} · Suppression ratio: {m['suppression_ratio']:.1%}",
        "",
        "## Alerts by severity",
        "",
        "| Severity | Count |", "|---|---|",
        *[f"| {k} | {v} |" for k, v in sorted(r["alerts_by_severity"].items())],
        "",
        "## Alerts by type",
        "",
        "| Type | Count |", "|---|---|",
        *[f"| {k} | {v} |" for k, v in sorted(r["alerts_by_type"].items())],
        "",
        "## Top attackers",
        "",
        "| IP | Alerts | Events | Max risk | Types |", "|---|---|---|---|---|",
        *[f"| {a['ip']} | {a['alerts']} | {a['events']} | {a['risk_max']:.1f} | {', '.join(a['types'])} |" for a in r["top_attackers"]],
        "",
        "## Top targeted accounts",
        "",
        "| User | Alerts | Events | Max risk |", "|---|---|---|---|",
        *[f"| {t['user']} | {t['alerts']} | {t['events']} | {t['risk_max']:.1f} |" for t in r["top_targets"]],
        "",
        "## MITRE ATT&CK coverage",
        "",
        *[f"- {x['technique']} — {x['count']} alert(s)" for x in r["mitre_coverage"]],
        "",
        "## Timeline",
        "",
        *[
            f"- `{t['ts']}` **{t['severity'].upper()}** {t['type']} on {t['entity'].get('key')} "
            f"(risk {t['risk']:.1f}, ×{t['count']}, {t['status']})"
            for t in r["timeline"]
        ],
        "",
        "## Actions taken",
        "",
        *[f"- [{a['priority'].upper()}] {a['action_type']} → {a['target']} — {a['reason']}" for a in r["actions"]],
        "",
    ]
    return "\n".join(lines)
