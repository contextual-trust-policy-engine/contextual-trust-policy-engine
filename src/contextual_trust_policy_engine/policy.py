"""
Contextual Trust Policy Engine policy decision point and Zero Trust Agent Benchmark defense
adapter.
"""

from __future__ import annotations

import re
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .abac import DEFAULT_ABAC, AbacEngine
from .context import (
    ContextAggregator,
    ToolMeta,
    has_control_format_chars,
    has_truncated_structured_frame,
    has_unsafe_secret_reference,
    jsonish,
    load_tool_catalog,
    untrusted_hosts,
)
from .models import Attributes, Decision
from .rebac import RebacEngine, TupleStore

TRUST_THRESHOLDS = {"low": 0.2, "medium": 0.35, "high": 0.4, "critical": 0.4}
_ROLE_BOUNDARY_RE = re.compile(r"(?im)^\s*(system|developer|assistant|tool|user)\s*:")
_CHAT_CONTROL_RE = re.compile(r"(<\|[^<>]{1,80}\|>|\[/?(?:inst|sys)\])", re.IGNORECASE)
_WORD_RE = re.compile(r"[a-z][a-z0-9_+-]*")
_SHELL_AUTHORITY_WORDS = frozenset(
    (
        "run",
        "execute",
        "command",
        "test",
        "build",
        "validation",
        "check",
        "inspect",
        "list",
        "print",
        "diagnostic",
        "compile",
        "post",
    )
)
_SECRET_AUTHORITY_WORDS = frozenset(
    ("secret", "credential", "token", "broker", "handle", "reference", "deploy")
)


@dataclass(slots=True)
class PolicyConfig:
    trust_thresholds: dict[str, float] = field(default_factory=lambda: dict(TRUST_THRESHOLDS))
    require_rebac: bool = False


class PolicyDecisionPoint:
    def __init__(
        self,
        *,
        aggregator: ContextAggregator | None = None,
        abac: AbacEngine | None = None,
        rebac: RebacEngine | None = None,
        config: PolicyConfig | None = None,
    ) -> None:
        self.aggregator = aggregator or _default_aggregator()
        self.abac = abac or DEFAULT_ABAC
        self.rebac = rebac or RebacEngine(TupleStore())
        self.config = config or PolicyConfig()
        self.decisions = 0
        self.denies = 0
        self.total_latency_ms = 0.0

    def decide(self, request: Mapping[str, Any]) -> Decision:
        start = time.perf_counter()
        try:
            attrs = self.aggregator.aggregate(request)
            decision = self._decide_attrs(attrs)
        except Exception as exc:
            decision = Decision("deny", exc.__class__.__name__, "fail_closed")
        self.decisions += 1
        if decision.decision == "deny":
            self.denies += 1
        self.total_latency_ms += (time.perf_counter() - start) * 1000.0
        return decision

    def _decide_attrs(self, attrs: Attributes) -> Decision:
        if not attrs.svid_valid:
            return Decision("deny", "invalid_svid", "svid")
        if not attrs.attestation_valid:
            return Decision("deny", "invalid_attestation", "attestation")
        threshold = self.config.trust_thresholds.get(attrs.tool_risk, 0.85)
        if attrs.trust_score < threshold:
            return Decision("deny", "trust_below_threshold", "trust")
        missing = [scope for scope in attrs.required_scopes if scope not in attrs.agent_scopes]
        if missing:
            return Decision("deny", "missing_scope:" + ",".join(missing), "scope")
        if self._untrusted_escalation(attrs):
            return Decision("deny", "untrusted_origin_escalation", "context")
        requester_allowed, requester_reason = self._requester_authorized(attrs)
        if not requester_allowed:
            return Decision("deny", requester_reason, "context")
        allowed, reason = self.abac.evaluate(attrs)
        if not allowed:
            return Decision("deny", reason, "abac")
        if self.config.require_rebac:
            subject = f"user:{attrs.agent_id}"
            target = attrs.rebac.get("object", "")
            relation = attrs.rebac.get("relation", "")
            if target and relation and not self.rebac.check(subject, target, relation):
                return Decision("deny", "rebac_denied", "rebac")
        return Decision("allow", reason, "pdp")

    def _untrusted_escalation(self, attrs: Attributes) -> bool:
        side_effect = (
            attrs.tool_egress
            or attrs.tool_risk in {"high", "critical"}
            or (attrs.origin == "tool_output" and attrs.tool_risk == "medium")
        )
        if self._context_tampered(attrs, high_impact=side_effect):
            return True
        if attrs.reasoning_tokens == 0 and attrs.origin != "user" and side_effect:
            return True
        if attrs.args_has_secret and attrs.tool_egress:
            return True
        if (
            attrs.origin != "user"
            and attrs.tool_egress
            and untrusted_hosts(attrs.content, self.aggregator.allowlist)
        ):
            return True
        return bool(attrs.untrusted_external_hosts and attrs.tool_egress)

    @staticmethod
    def _task_has_any(task: str, words: frozenset[str]) -> bool:
        return bool(words.intersection(_WORD_RE.findall(task.casefold())))

    def _requester_authorized(self, attrs: Attributes) -> tuple[bool, str]:
        if (
            attrs.origin == "tool_output"
            and attrs.tool == "shell.exec"
            and not self._task_has_any(attrs.user_task, _SHELL_AUTHORITY_WORDS)
        ):
            return False, "tool_output_effect_not_user_authorized"
        if (
            attrs.origin == "user"
            and attrs.tool == "shell.exec"
            and not self._task_has_any(attrs.user_task, _SHELL_AUTHORITY_WORDS)
        ):
            return False, "privileged_tool_not_user_authorized"
        if (
            attrs.origin == "user"
            and attrs.tool == "secrets.get"
            and not self._task_has_any(attrs.user_task, _SECRET_AUTHORITY_WORDS)
        ):
            return False, "privileged_tool_not_user_authorized"
        return True, ""

    @staticmethod
    def _context_tampered(attrs: Attributes, *, high_impact: bool) -> bool:
        combined = (
            f"{attrs.content}\n"
            f"{attrs.tool_description}\n"
            f"{attrs.raw_generation}\n"
            f"{jsonish(attrs.args)}"
        )
        if has_control_format_chars(combined):
            return True
        if has_truncated_structured_frame(combined):
            return True
        privileged = attrs.tool_risk in {"high", "critical"}
        if (
            attrs.reasoning_tokens == 0
            and (attrs.origin != "user" or privileged)
            and _CHAT_CONTROL_RE.search(combined)
        ):
            return True
        if attrs.origin != "user" and high_impact and _ROLE_BOUNDARY_RE.search(combined):
            return True
        return has_unsafe_secret_reference(attrs.args)

    def metrics_text(self) -> str:
        avg = self.total_latency_ms / self.decisions if self.decisions else 0.0
        return (
            "# HELP contextual_trust_policy_engine_decisions_total Total policy decisions\n"
            "# TYPE contextual_trust_policy_engine_decisions_total counter\n"
            f"contextual_trust_policy_engine_decisions_total {self.decisions}\n"
            "# HELP contextual_trust_policy_engine_denies_total Total policy denials\n"
            "# TYPE contextual_trust_policy_engine_denies_total counter\n"
            f"contextual_trust_policy_engine_denies_total {self.denies}\n"
            "# HELP contextual_trust_policy_engine_decision_latency_ms_avg "
            "Average in-process decision latency\n"
            "# TYPE contextual_trust_policy_engine_decision_latency_ms_avg gauge\n"
            f"contextual_trust_policy_engine_decision_latency_ms_avg {avg}\n"
        )


class ContextualTrustDefense:
    """Zero Trust Agent Benchmark adapter with a setup hook matching the benchmark protocol."""

    def __init__(self, pdp: PolicyDecisionPoint | None = None) -> None:
        self.pdp = pdp or PolicyDecisionPoint()
        self._issued_secrets_by_trace: dict[str, tuple[str, ...]] = {}

    def setup(self, profile: Mapping[str, Any]) -> None:
        self.pdp = PolicyDecisionPoint(aggregator=_aggregator_from_profile(profile))
        self._issued_secrets_by_trace = {}

    def reset(self) -> None:
        self.pdp.decisions = 0
        self.pdp.denies = 0
        self.pdp.total_latency_ms = 0.0
        self._issued_secrets_by_trace = {}

    def on_trace_start(self, meta: Mapping[str, Any]) -> None:
        self._issued_secrets_by_trace[str(meta.get("trace_id", ""))] = _str_tuple(
            meta.get("issued_secrets", ())
        )

    def decide(self, request: Mapping[str, Any]) -> dict[str, str]:
        trace_id = str(request.get("trace_id", ""))
        secrets = self._issued_secrets_by_trace.get(trace_id)
        if secrets is None:
            return self.pdp.decide(request).as_dict()
        enriched = dict(request)
        enriched["secrets"] = secrets
        return self.pdp.decide(enriched).as_dict()


def _str_tuple(value: object) -> tuple[str, ...]:
    if isinstance(value, Iterable) and not isinstance(value, (str, bytes, Mapping)):
        return tuple(str(item) for item in value)
    return ()


def _aggregator_from_profile(profile: Mapping[str, Any]) -> ContextAggregator:
    raw_tools = profile.get("tools", {})
    catalog: dict[str, ToolMeta] = {"*": ToolMeta("critical", (), {}, False)}
    if isinstance(raw_tools, Mapping):
        for name, raw in raw_tools.items():
            if isinstance(raw, Mapping):
                catalog[str(name)] = ToolMeta(
                    str(raw.get("risk", "critical")),
                    _str_tuple(raw.get("scopes", raw.get("required_scopes", ()))),
                    {},
                    bool(raw.get("egress", False)),
                )
    allowlist = [str(host) for host in _str_tuple(profile.get("egress_allowlist", ()))]
    allowlist.extend(str(host) for host in _str_tuple(profile.get("email_allowed_domains", ())))
    return ContextAggregator(
        tool_catalog=catalog,
        allowlist=allowlist,
        trust_domain=str(profile.get("trust_domain", "acme.test")),
    )


def _default_aggregator() -> ContextAggregator:
    try:
        from zero_trust_agent_benchmark.profile import profile

        return _aggregator_from_profile(profile())
    except Exception:
        catalog_path = Path(__file__).resolve().parents[2] / "policies" / "tool_catalog.yml"
        catalog = load_tool_catalog(str(catalog_path)) if catalog_path.exists() else None
        return ContextAggregator(
            tool_catalog=catalog,
            allowlist=(
                "acme.test",
                "example.com",
                "example.net",
                "invalid",
            ),
        )


default_defense = ContextualTrustDefense()
