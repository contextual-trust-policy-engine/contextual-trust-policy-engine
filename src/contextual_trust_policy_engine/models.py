"""Shared data objects for Contextual Trust Policy Engine."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

DecisionValue = Literal["allow", "deny"]


@dataclass(frozen=True, slots=True)
class Decision:
    decision: DecisionValue
    reason: str = ""
    component: str = "pdp"

    def as_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class Attributes:
    step: int
    agent_id: str
    trust_domain: str | None
    spiffe_path: tuple[str, ...]
    svid_valid: bool
    attestation_valid: bool
    trust_score: float
    tool: str
    tool_risk: str
    tool_egress: bool
    required_scopes: tuple[str, ...]
    declared_scopes: tuple[str, ...]
    agent_scopes: tuple[str, ...]
    args: dict[str, Any]
    args_has_secret: bool
    args_has_pii: bool
    external_hosts: tuple[str, ...]
    untrusted_external_hosts: tuple[str, ...]
    origin: str
    content: str
    user_task: str
    tool_description: str
    raw_generation: str
    reasoning_tokens: int
    now_s: float
    rebac: dict[str, str] = field(default_factory=dict)
