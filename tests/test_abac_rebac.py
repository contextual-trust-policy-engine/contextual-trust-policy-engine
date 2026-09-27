from __future__ import annotations

from contextual_trust_policy_engine.abac import AbacEngine
from contextual_trust_policy_engine.context import ContextAggregator, ToolMeta
from contextual_trust_policy_engine.rebac import NamespaceConfig, RebacEngine, Rewrite, TupleStore


def _attrs():
    catalog = {
        "http.get": ToolMeta("low", ("net:read",), {}, True),
        "*": ToolMeta("critical", (), {}, False),
    }
    return ContextAggregator(tool_catalog=catalog, allowlist=("acme.test",)).aggregate(
        {
            "trace_id": "t",
            "step": 0,
            "agent": {
                "agent_id": "a",
                "spiffe_id": "spiffe://acme.test/agent/a",
                "svid": "valid",
                "attestation": "valid",
                "trust_history": ["benign"] * 40,
                "scopes": ["net:read"],
            },
            "tool": "http.get",
            "args": {"url": "https://docs.acme.test"},
            "context": {"origin": "user", "content": "ok", "reasoning_tokens": 1},
        }
    )


def test_abac_deny_overrides() -> None:
    engine = AbacEngine.from_dicts(
        [
            {"id": "allow", "effect": "allow", "tools": ["*"], "conditions": []},
            {
                "id": "deny_low",
                "effect": "deny",
                "tools": ["http.*"],
                "conditions": [{"field": "tool_risk", "eq": "low"}],
                "reason": "low denied",
            },
        ]
    )
    assert engine.evaluate(_attrs()) == (False, "low denied")


def test_abac_supports_matches_in_not_in() -> None:
    engine = AbacEngine.from_dicts(
        [
            {
                "id": "allow_get",
                "effect": "allow",
                "tools": ["http.*"],
                "conditions": [
                    {"field": "tool", "matches": "http\\.get"},
                    {"field": "origin", "in": ["user"]},
                    {"field": "tool_risk", "not_in": ["critical"]},
                ],
            }
        ]
    )
    assert engine.evaluate(_attrs())[0]


def test_rebac_direct_and_userset() -> None:
    store = TupleStore(
        ["doc:1#read@user:a", "group:eng#member@user:b", "doc:2#read@group:eng#member"]
    )
    rebac = RebacEngine(store)
    assert rebac.check("user:a", "doc:1", "read")
    assert rebac.check("user:b", "doc:2", "read")
    assert not rebac.check("user:c", "doc:2", "read")


def test_rebac_rewrites() -> None:
    store = TupleStore(["folder:1#parent@org:1", "org:1#admin@user:a", "folder:1#banned@user:b"])
    cfg = NamespaceConfig(
        {
            "admin": Rewrite("this"),
            "parent": Rewrite("this"),
            "banned": Rewrite("this"),
            "view": Rewrite(
                "exclusion",
                children=(
                    Rewrite("tuple_to_userset", tupleset="parent", computed="admin"),
                    Rewrite("computed_userset", relation="banned"),
                ),
            ),
        }
    )
    rebac = RebacEngine(store, {"default": NamespaceConfig.simple([]), "folder": cfg, "org": cfg})
    assert rebac.check("user:a", "folder:1", "view")
    assert not rebac.check("user:b", "folder:1", "view")
    assert "user:a" in rebac.expand("org:1", "admin")
