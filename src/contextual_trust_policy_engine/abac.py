"""Small deny-overrides ABAC engine compiled from YAML-like rules."""

from __future__ import annotations

import fnmatch
import operator
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal

import yaml

from .models import Attributes

Effect = Literal["allow", "deny"]
_Condition = Callable[[Attributes], bool]
_GLOB_CHARS = frozenset("*?[")


@dataclass(frozen=True, slots=True)
class Rule:
    rule_id: str
    effect: Effect
    tools: tuple[str, ...]
    conditions: tuple[_Condition, ...]
    reason: str = ""

    def matches(self, attrs: Attributes) -> bool:
        return any(fnmatch.fnmatchcase(attrs.tool, pat) for pat in self.tools) and all(
            cond(attrs) for cond in self.conditions
        )


def _get(attrs: Attributes, path: str) -> Any:
    current: Any = attrs
    for part in path.split("."):
        current = current.get(part) if isinstance(current, Mapping) else getattr(current, part)
    return current


def _one_condition(spec: Mapping[str, Any]) -> _Condition:
    path = str(spec["field"])
    if "exists" in spec:
        expected = bool(spec["exists"])
        return lambda attrs: (_get(attrs, path) is not None) is expected
    ops: dict[str, Callable[[Any, Any], bool]] = {
        "eq": operator.eq,
        "gte": operator.ge,
        "lte": operator.le,
    }
    for name, func in ops.items():
        if name in spec:
            expected = spec[name]

            def compare(
                attrs: Attributes, f: Callable[[Any, Any], bool] = func, e: Any = expected
            ) -> bool:
                return f(_get(attrs, path), e)

            return compare
    if "in" in spec:
        allowed = set(spec["in"])
        return lambda attrs: _get(attrs, path) in allowed
    if "not_in" in spec:
        denied = set(spec["not_in"])
        return lambda attrs: _get(attrs, path) not in denied
    if "matches" in spec:
        regex = re.compile(str(spec["matches"]))
        return lambda attrs: regex.search(str(_get(attrs, path))) is not None
    raise ValueError(f"unsupported condition: {spec}")


def _conditions(raw: object) -> tuple[_Condition, ...]:
    if not isinstance(raw, Sequence) or isinstance(raw, str):
        return ()
    return tuple(_one_condition(x) for x in raw if isinstance(x, Mapping))


class AbacEngine:
    """Compiled ABAC rule set with deny-overrides semantics."""

    def __init__(self, rules: Sequence[Rule] = ()) -> None:
        self.rules = tuple(rules)
        exact: dict[str, list[int]] = {}
        pattern_indexes: set[int] = set()
        for idx, rule in enumerate(self.rules):
            for tool_pattern in rule.tools:
                if _is_exact_tool(tool_pattern):
                    exact.setdefault(tool_pattern, []).append(idx)
                else:
                    pattern_indexes.add(idx)
        self._exact_tool_indexes = {tool: tuple(indexes) for tool, indexes in exact.items()}
        self._pattern_indexes = tuple(sorted(pattern_indexes))

    @classmethod
    def from_dicts(cls, raw_rules: Sequence[Mapping[str, Any]]) -> AbacEngine:
        rules: list[Rule] = []
        for idx, item in enumerate(raw_rules):
            effect: Effect = "deny" if item.get("effect") == "deny" else "allow"
            tools_obj = item.get("tools", ["*"])
            tools = (
                (str(tools_obj),)
                if isinstance(tools_obj, str)
                else tuple(str(t) for t in tools_obj)
            )
            rules.append(
                Rule(
                    str(item.get("id", f"rule-{idx}")),
                    effect,
                    tools,
                    _conditions(item.get("conditions", ())),
                    str(item.get("reason", item.get("id", f"rule-{idx}"))),
                )
            )
        return cls(rules)

    @classmethod
    def from_yaml(cls, path: str) -> AbacEngine:
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        rules = data.get("rules", data) if isinstance(data, Mapping) else []
        if not isinstance(rules, Sequence):
            raise ValueError("rules must be a list")
        return cls.from_dicts([r for r in rules if isinstance(r, Mapping)])

    def evaluate(self, attrs: Attributes) -> tuple[bool, str]:
        matched_allow: str | None = None
        candidates = set(self._pattern_indexes)
        candidates.update(self._exact_tool_indexes.get(attrs.tool, ()))
        for idx in sorted(candidates):
            rule = self.rules[idx]
            if rule.matches(attrs):
                if rule.effect == "deny":
                    return False, rule.reason or rule.rule_id
                matched_allow = matched_allow or rule.reason or rule.rule_id
        if matched_allow is None:
            return False, "no_matching_allow"
        return True, matched_allow


def _is_exact_tool(pattern: str) -> bool:
    return not any(ch in pattern for ch in _GLOB_CHARS)


DEFAULT_ABAC = AbacEngine.from_dicts(
    [
        {
            "id": "deny_secret_egress",
            "effect": "deny",
            "tools": ["*"],
            "conditions": [
                {"field": "args_has_secret", "eq": True},
                {"field": "tool_egress", "eq": True},
            ],
            "reason": "secret_in_egress_args",
        },
        {
            "id": "allow_authenticated_tools",
            "effect": "allow",
            "tools": ["*"],
            "conditions": [
                {"field": "svid_valid", "eq": True},
                {"field": "attestation_valid", "eq": True},
            ],
            "reason": "abac_allow",
        },
    ]
)
