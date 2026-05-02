"""AI Copilot — turns a pipeline run into a human-readable explanation.

Architecture
------------
A small Provider abstraction lets us swap implementations without changing
any callers:

    >>> from app.services.ai_copilot import generate_explanation, set_provider
    >>> set_provider(OpenAIProvider(api_key=...))
    >>> explanation = generate_explanation(ctx)

Today we ship a deterministic, template-based :class:`MockProvider` that
produces realistic SOC-analyst-style narratives with zero external calls.

To plug in a real LLM, implement the :class:`ExplanationProvider` protocol::

    class OpenAIProvider:
        name = "openai-gpt-4o"

        def explain(self, ctx: ExplanationContext) -> Explanation:
            prompt = build_prompt(ctx)              # your prompt template
            payload = openai_client.chat.completions.create(
                model="gpt-4o", messages=prompt,
                response_format={"type": "json_object"},
            )
            data = json.loads(payload.choices[0].message.content)
            return Explanation(
                summary=data["summary"],
                what_happened=data["what_happened"],
                why_flagged=data["why_flagged"],
                actions_taken=data["actions_taken"],
                provider=self.name,
                generated_at=datetime.now(timezone.utc),
            )

    set_provider(OpenAIProvider())

The output schema (:class:`Explanation`) is the integration contract — a
real LLM should be asked to produce JSON matching that shape.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Optional, Protocol, runtime_checkable
from urllib import request
from urllib.error import URLError

from pydantic import BaseModel, ConfigDict, Field

from app.engine.response import ResponseReport
from app.models.action import Action, ActionType
from app.models.event import Event
from app.models.threat import Threat, ThreatType


class ExplanationContext(BaseModel):
    """Pipeline outputs bundled together for a single explanation request."""

    model_config = ConfigDict(extra="forbid")

    event: Event
    threat: Threat
    actions: list[Action]
    response: Optional[ResponseReport] = None


class Explanation(BaseModel):
    """Structured, human-readable narrative of a pipeline run."""

    model_config = ConfigDict(extra="forbid")

    summary: str = Field(..., description="One-line headline of the incident.")
    what_happened: str = Field(..., description="What was observed in the environment.")
    why_flagged: str = Field(..., description="Why the detection engine raised it.")
    actions_taken: str = Field(..., description="Response dispatched and outcome.")
    provider: str = Field(..., description="Identifier of the backend that produced the text.")
    generated_at: datetime

    def to_text(self) -> str:
        """Render the explanation as a plain-text incident report."""
        return (
            f"{self.summary}\n\n"
            f"WHAT HAPPENED\n{self.what_happened}\n\n"
            f"WHY IT WAS FLAGGED\n{self.why_flagged}\n\n"
            f"ACTIONS TAKEN\n{self.actions_taken}\n"
        )


@runtime_checkable
class ExplanationProvider(Protocol):
    """Pluggable backend for explanation generation."""

    name: str

    def explain(self, ctx: ExplanationContext) -> Explanation: ...
    def chat(self, prompt: str) -> str: ...


_THREAT_TYPE_LABEL: dict[ThreatType, str] = {
    ThreatType.DDOS: "distributed denial-of-service attack",
    ThreatType.BRUTE_FORCE: "brute-force authentication attempt",
    ThreatType.SQL_INJECTION: "SQL injection attempt",
    ThreatType.PORT_SCAN: "network reconnaissance scan",
    ThreatType.MALWARE: "malware activity",
    ThreatType.PHISHING: "phishing attempt",
    ThreatType.DATA_EXFILTRATION: "data exfiltration attempt",
    ThreatType.PRIVILEGE_ESCALATION: "privilege escalation attempt",
    ThreatType.LATERAL_MOVEMENT: "lateral movement attempt",
    ThreatType.INSIDER: "suspicious insider activity",
    ThreatType.ANOMALY: "anomalous activity",
    ThreatType.UNKNOWN: "unclassified suspicious activity",
}


def _format_action_list(actions: list[Action]) -> str:
    if not actions:
        return "no actions"
    return ", ".join(a.action_type.value.replace("_", " ") for a in actions)


def _capitalize_first(text: str) -> str:
    """Uppercase the first character only — preserves acronyms like 'SQL'."""
    return text[:1].upper() + text[1:] if text else text


def _automated_policy_explanation(actions: list[Action]) -> str:
    """Extra AI-facing prose for anomaly-driven automated responses."""
    if not actions:
        return ""
    lines: list[str] = []
    kinds = {a.action_type for a in actions}
    if ActionType.KILL_PROCESS in kinds:
        lines.append(
            "Automated containment selected **process kill** after a malware-class "
            "classification so the workload cannot continue executing."
        )
    if ActionType.RATE_LIMIT in kinds:
        lines.append(
            "Edge policy applied **adaptive rate limiting** to absorb CPU / flood "
            "pressure without dropping the entire tenant."
        )
    if ActionType.QUARANTINE_HOST in kinds:
        lines.append(
            "**Host isolation** was triggered for exfiltration containment — "
            "lateral movement and egress are cut until analysts release."
        )
    return " ".join(lines)


def _format_outcome(actions: list[Action], response: Optional[ResponseReport]) -> str:
    if response is None:
        return f"{len(actions)} action(s) were planned but not yet executed."
    parts = [f"{response.succeeded} of {response.total} action(s) executed successfully"]
    if response.failed:
        parts.append(f"{response.failed} failed")
    if response.skipped:
        parts.append(f"{response.skipped} skipped")
    return "; ".join(parts) + "."


class MockProvider:
    """Template-based provider — deterministic, offline, free.

    Produces SOC-analyst-style prose suitable for dashboards, audit logs,
    or as a demo while a real LLM provider is being wired up. Templates
    are tuned per :class:`ThreatType` via :data:`_THREAT_TYPE_LABEL`.
    """

    name: str = "mock-template-v1"

    def explain(self, ctx: ExplanationContext) -> Explanation:
        threat_label = _THREAT_TYPE_LABEL.get(
            ctx.threat.threat_type, "unclassified threat"
        )
        target = ctx.actions[0].target if ctx.actions else str(ctx.event.source_ip)
        action_list = _format_action_list(ctx.actions)
        outcome = _format_outcome(ctx.actions, ctx.response)

        what_happened = (
            f"At {ctx.event.timestamp.isoformat()}, a "
            f"{ctx.event.event_type.value} event was observed from "
            f"{ctx.event.source_ip} with reported severity "
            f"'{ctx.event.severity.value}'. Source signal: "
            f"\"{ctx.event.message}\"."
        )

        why_flagged = (
            f"The detection engine classified this signal as a "
            f"{threat_label} (threat type: {ctx.threat.threat_type.value}) "
            f"with {ctx.threat.confidence:.0%} confidence and a risk score "
            f"of {ctx.threat.risk_score:.1f}/10, raising the incident "
            f"severity to '{ctx.threat.severity.value}'."
        )

        policy_note = _automated_policy_explanation(ctx.actions)

        actions_taken = (
            f"In response, {len(ctx.actions)} action(s) were dispatched "
            f"against {target}: {action_list}. {outcome}"
        )
        if policy_note:
            actions_taken = f"{actions_taken}\n\n{policy_note}"

        summary = (
            f"{_capitalize_first(threat_label)} from {ctx.event.source_ip} "
            f"({ctx.threat.severity.value} severity) — "
            f"{len(ctx.actions)} action(s) dispatched."
        )
        if policy_note:
            summary = summary + " Automated containment rules fired."

        why_extra = ""
        if policy_note:
            why_extra = (
                " Sentinel policy hooks elevated this incident because automated "
                "playbooks (kill / throttle / isolate) align with the detected class."
            )

        return Explanation(
            summary=summary,
            what_happened=what_happened,
            why_flagged=why_flagged + why_extra,
            actions_taken=actions_taken,
            provider=self.name,
            generated_at=datetime.now(timezone.utc),
        )

    def chat(self, prompt: str) -> str:
        return (
            "Acknowledged. I am running in mock mode, so this is a local response. "
            f"Your prompt was: {prompt}"
        )


_provider: ExplanationProvider = MockProvider()


class A4FProvider:
    name: str = "a4f-openai-compatible"

    def __init__(
        self,
        *,
        api_key: str,
        base_url: str,
        model: str,
        timeout_seconds: float = 12.0,
    ) -> None:
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._timeout_seconds = timeout_seconds

    def explain(self, ctx: ExplanationContext) -> Explanation:
        body = {
            "model": self._model,
            "temperature": 0.2,
            "response_format": {"type": "json_object"},
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a SOC copilot. Return strict JSON with keys: "
                        "summary, what_happened, why_flagged, actions_taken."
                    ),
                },
                {
                    "role": "user",
                    "content": json.dumps(
                        {
                            "event": ctx.event.model_dump(mode="json"),
                            "threat": ctx.threat.model_dump(mode="json"),
                            "actions": [a.model_dump(mode="json") for a in ctx.actions],
                            "response": (
                                ctx.response.model_dump(mode="json")
                                if ctx.response is not None
                                else None
                            ),
                        }
                    ),
                },
            ],
        }
        req = request.Request(
            url=f"{self._base_url}/chat/completions",
            data=json.dumps(body).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with request.urlopen(req, timeout=self._timeout_seconds) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except URLError as exc:
            return MockProvider().explain(ctx).model_copy(
                update={"provider": f"{self.name}:fallback:{exc.__class__.__name__}"}
            )
        content = (
            payload.get("choices", [{}])[0]
            .get("message", {})
            .get("content", "")
        )
        try:
            data = json.loads(content) if isinstance(content, str) else {}
        except json.JSONDecodeError:
            data = {}
        if not data:
            return MockProvider().explain(ctx).model_copy(
                update={"provider": f"{self.name}:fallback:invalid-json"}
            )
        return Explanation(
            summary=str(data.get("summary", "Security event analyzed.")),
            what_happened=str(data.get("what_happened", "Telemetry inspected.")),
            why_flagged=str(data.get("why_flagged", "Threat scoring threshold exceeded.")),
            actions_taken=str(data.get("actions_taken", "Automated policy response dispatched.")),
            provider=self.name,
            generated_at=datetime.now(timezone.utc),
        )

    def chat(self, prompt: str) -> str:
        body = {
            "model": self._model,
            "temperature": 0.3,
            "messages": [
                {
                    "role": "system",
                    "content": "You are SentinelAI Copilot. Reply with concise SOC guidance.",
                },
                {"role": "user", "content": prompt},
            ],
        }
        req = request.Request(
            url=f"{self._base_url}/chat/completions",
            data=json.dumps(body).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with request.urlopen(req, timeout=self._timeout_seconds) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except URLError:
            return MockProvider().chat(prompt)
        return (
            payload.get("choices", [{}])[0]
            .get("message", {})
            .get("content", "")
            .strip()
            or MockProvider().chat(prompt)
        )


def set_provider(provider: ExplanationProvider) -> None:
    """Swap the active explanation provider at runtime.

    Useful for plugging in a real LLM (OpenAI, Anthropic, local model) at
    application startup, or for stubbing in tests.
    """
    global _provider
    _provider = provider


def get_provider() -> ExplanationProvider:
    """Return the currently registered provider."""
    return _provider


def generate_explanation(data: ExplanationContext) -> Explanation:
    """Generate a human-readable explanation of a pipeline run.

    Args:
        data: An :class:`ExplanationContext` bundling the event, threat,
            actions, and (optionally) the response report.

    Returns:
        A structured :class:`Explanation` from the active provider.
    """
    return _provider.explain(data)


def generate_chat_response(prompt: str) -> str:
    return _provider.chat(prompt)


def make_a4f_provider(*, api_key: str, base_url: str, model: str) -> ExplanationProvider:
    if not api_key.strip():
        return MockProvider()
    return A4FProvider(api_key=api_key, base_url=base_url, model=model)
