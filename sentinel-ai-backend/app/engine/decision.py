"""Adaptive, context-aware decision engine.

Tiered playbook plus automated anomaly containment (malware → kill_process,
data exfiltration → quarantine_host, CPU/flood/anomaly → rate_limit).

Replaces the old static severity-table policy with a tiered playbook
driven by the joint signal of ``risk_score × confidence``, plus two
independent escalation modifiers:

    1. Repetition escalation — if the same threat type has been seen
       multiple times in the recent context window, ratchet up.
    2. Correlation escalation — if the threat carries a kill-chain tag
       (``multi_stage_attack`` / ``sustained_attack``), trigger
       containment-grade actions.

Public API:
    decide(threat, *, target=None, context=None) -> list[Action]

Each returned :class:`Action` carries a structured ``priority`` and a
human-readable ``reason`` so SOC analysts and audit trails can answer
"why did the system do that?" without grepping logs.

Design principles:
    - Lightweight: pure stdlib, no external systems.
    - Modular: tier resolution, base playbook, and escalation modifiers
      are each independent functions and can be tuned in isolation.
    - Backward compatible: ``decide(threat)`` still works (context falls
      back to the detection engine's default singleton).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from app.engine.detection import DetectionContext, get_default_context
from app.models.action import Action, ActionStatus, ActionType, Priority
from app.models.threat import Threat, ThreatType


                                                                        
                                                                        

HIGH_RISK_THRESHOLD: float = 7.0
LOW_RISK_THRESHOLD:  float = 3.0

HIGH_CONFIDENCE_THRESHOLD: float = 0.75
LOW_CONFIDENCE_THRESHOLD:  float = 0.40

                                                                   
                                                    
REPETITION_THRESHOLD: int = 3
PERSISTENCE_THRESHOLD: int = 5
RECENT_WINDOW: int = 10                                               


                                                                        


@dataclass(frozen=True)
class _ActionTemplate:
    """A planned action before it gets a target/threat_id bolted on."""

    action_type: ActionType
    priority: Priority
    reason: str
                                                                                                  
    target_override: Optional[str] = None


                                                                        


def _resolve_tier(risk_score: float, confidence: float) -> str:
    """Map (risk, confidence) to one of: 'high' | 'medium' | 'low'.

    HIGH:   both risk *and* confidence cross their high bars.
            (the spec's "high risk + high confidence" cell)
    LOW:    either signal is below its low bar — could be a false
            positive or a non-event; respond conservatively.
    MEDIUM: everything else.
    """
    if risk_score >= HIGH_RISK_THRESHOLD and confidence >= HIGH_CONFIDENCE_THRESHOLD:
        return "high"
    if risk_score < LOW_RISK_THRESHOLD or confidence < LOW_CONFIDENCE_THRESHOLD:
        return "low"
    return "medium"


                                                                        
                                                                    
                                                                   
                                                

PLAYBOOK: dict[str, tuple[_ActionTemplate, ...]] = {
    "high": (
        _ActionTemplate(
            action_type=ActionType.BLOCK_IP,
            priority=Priority.P1,
            reason="High risk + high confidence — block source",
        ),
        _ActionTemplate(
            action_type=ActionType.ISOLATE_SERVICE,
            priority=Priority.P1,
            reason="High risk + high confidence — isolate exposed service",
        ),
    ),
    "medium": (
        _ActionTemplate(
            action_type=ActionType.RATE_LIMIT,
            priority=Priority.P2,
            reason="Moderate signal — throttle source",
        ),
        _ActionTemplate(
            action_type=ActionType.MONITOR,
            priority=Priority.P2,
            reason="Moderate signal — observe for escalation",
        ),
    ),
    "low": (
        _ActionTemplate(
            action_type=ActionType.LOG_ONLY,
            priority=Priority.P3,
            reason="Low signal — log for trend analysis",
        ),
    ),
}


                                                                        


def _bump(priority: Priority) -> Priority:
    """Promote a priority one step up (P3 → P2 → P1 → P0)."""
    order = (Priority.P3, Priority.P2, Priority.P1, Priority.P0)
    idx = order.index(priority)
    return order[min(idx + 1, len(order) - 1)]


def _escalate_for_repetition(
    threat_type: ThreatType,
    context: DetectionContext,
) -> list[_ActionTemplate]:
    """Add escalation actions when this threat type keeps recurring.

    The repetition signal comes from the detection engine's own
    threat-history buffer, so we don't duplicate state.
    """
    history = context.recent_threat_types(n=RECENT_WINDOW)
    count = history.count(threat_type)

    if count >= PERSISTENCE_THRESHOLD:
        return [
            _ActionTemplate(
                action_type=ActionType.BLOCK_IP,
                priority=Priority.P1,
                reason=f"Persistent {threat_type.value} — {count}× in last {RECENT_WINDOW} threats",
            ),
            _ActionTemplate(
                action_type=ActionType.NOTIFY,
                priority=Priority.P1,
                reason="Persistent threat — paging on-call analyst",
            ),
        ]
    if count >= REPETITION_THRESHOLD:
        return [
            _ActionTemplate(
                action_type=ActionType.NOTIFY,
                priority=Priority.P2,
                reason=f"Repeated {threat_type.value} — {count}× in last {RECENT_WINDOW} threats",
            ),
        ]
    return []


def _escalate_for_correlation(threat: Threat) -> list[_ActionTemplate]:
    """Trigger containment when the threat completes a known kill chain."""
    if threat.correlation == "multi_stage_attack":
        return [
            _ActionTemplate(
                action_type=ActionType.QUARANTINE_HOST,
                priority=Priority.P0,
                reason="Multi-stage attack — full host containment",
            ),
            _ActionTemplate(
                action_type=ActionType.ROTATE_CREDENTIALS,
                priority=Priority.P0,
                reason="Multi-stage attack — rotate potentially compromised credentials",
            ),
            _ActionTemplate(
                action_type=ActionType.ESCALATE,
                priority=Priority.P0,
                reason="Multi-stage attack — escalate to incident response",
            ),
        ]
    if threat.correlation == "sustained_attack":
        return [
            _ActionTemplate(
                action_type=ActionType.ESCALATE,
                priority=Priority.P1,
                reason="Sustained attack — escalating for human review",
            ),
        ]
    return []


def _promote_for_correlation(
    base: list[_ActionTemplate], correlation: str | None
) -> list[_ActionTemplate]:
    """Bump base-playbook priority when correlation is in play."""
    if not correlation:
        return base
    suffix = " (correlation-elevated)"
    return [
        _ActionTemplate(
            action_type=t.action_type,
            priority=_bump(t.priority),
            reason=t.reason + suffix,
            target_override=t.target_override,
        )
        for t in base
    ]


                                                                          


def _wants_rate_limit_for_resource_pressure(threat: Threat) -> bool:
    """CPU spike / flood proxy → adaptive rate limit."""
    if threat.threat_type == ThreatType.ANOMALY:
        return True
    if threat.threat_type == ThreatType.DDOS:
        return True
    if "severity_history" in threat.signals:
        return threat.threat_type not in (
            ThreatType.MALWARE,
            ThreatType.DATA_EXFILTRATION,
        )
    return False


def _automated_containment_templates(threat: Threat) -> list[_ActionTemplate]:
    """Malicious process → kill; CPU spike / flood → rate limit; exfil → isolate host."""
    out: list[_ActionTemplate] = []

    if threat.threat_type == ThreatType.MALWARE:
        out.append(
            _ActionTemplate(
                action_type=ActionType.KILL_PROCESS,
                priority=Priority.P0,
                reason=(
                    "Malicious process indicator — terminating offending workload "
                    "(automated containment)"
                ),
                target_override=f"pid:{threat.id.hex[:8]} — suspicious_payload",
            )
        )

    if threat.threat_type == ThreatType.DATA_EXFILTRATION:
        out.append(
            _ActionTemplate(
                action_type=ActionType.QUARANTINE_HOST,
                priority=Priority.P0,
                reason=(
                    "Data exfiltration pattern — host isolated from peer subnets "
                    "pending forensic snapshot"
                ),
            )
        )

    if _wants_rate_limit_for_resource_pressure(threat):
        out.append(
            _ActionTemplate(
                action_type=ActionType.RATE_LIMIT,
                priority=Priority.P1,
                reason=(
                    "CPU / baseline anomaly or flood signature — adaptive rate limit "
                    "at ingress (automated)"
                ),
            )
        )

    return out


                                                                        


def _dedupe_keep_highest_priority(
    templates: list[_ActionTemplate],
) -> list[_ActionTemplate]:
    """Collapse duplicate action_types, keeping the most urgent priority.

    Reasons are concatenated so the audit trail explains every contributor.
    """
    seen: dict[ActionType, _ActionTemplate] = {}
    for t in templates:
        prior = seen.get(t.action_type)
        if prior is None:
            seen[t.action_type] = t
            continue
                                                       
        higher = t if _bump(prior.priority) == t.priority or t.priority.value < prior.priority.value else prior
        merged_reason = (
            prior.reason if t.reason in prior.reason
            else f"{prior.reason}; {t.reason}"
        )
        tgt = t.target_override or prior.target_override
        seen[t.action_type] = _ActionTemplate(
            action_type=t.action_type,
            priority=higher.priority,
            reason=merged_reason,
            target_override=tgt,
        )

                                                                      
    priority_rank = {Priority.P0: 0, Priority.P1: 1, Priority.P2: 2, Priority.P3: 3}
    return sorted(seen.values(), key=lambda t: priority_rank[t.priority])


                                                                        


def decide(
    threat: Threat,
    *,
    target: Optional[str] = None,
    context: Optional[DetectionContext] = None,
) -> list[Action]:
    """Adaptively choose response actions for ``threat``.

    Args:
        threat:  The scored threat from the detection engine. Uses
            ``risk_score``, ``confidence``, ``threat_type``, and the new
            ``correlation`` field.
        target:  Optional concrete target (IP / hostname / user). If
            omitted, a stable threat reference is used so an orchestrator
            can patch it at dispatch time.
        context: Sliding-window state from the detection engine, used to
            detect repetition. Falls back to the engine's default
            singleton when omitted (preserves the simple call signature).

    Returns:
        A non-empty, priority-ordered list of :class:`Action` instances.
        Each action carries its ``action_type``, ``priority``, and
        ``reason`` so downstream code can dispatch, sort, audit, and
        explain every decision.
    """
    ctx = context or get_default_context()
    resolved_target = target or f"threat:{threat.id}"

                                                      
    tier = _resolve_tier(threat.risk_score, threat.confidence)
    base = list(PLAYBOOK[tier])

                                          
    repetition = _escalate_for_repetition(threat.threat_type, ctx)
    correlation = _escalate_for_correlation(threat)

                                                                        
    base = _promote_for_correlation(base, threat.correlation)

                                                                                           
    automated = _automated_containment_templates(threat)

                                                                          
                                                                                
    plan = _dedupe_keep_highest_priority(automated + base + repetition + correlation)

                                                                            
    return [
        Action(
            threat_id=threat.id,
            action_type=t.action_type,
            target=t.target_override if t.target_override is not None else resolved_target,
            status=ActionStatus.PENDING,
            priority=t.priority,
            reason=t.reason,
        )
        for t in plan
    ]
