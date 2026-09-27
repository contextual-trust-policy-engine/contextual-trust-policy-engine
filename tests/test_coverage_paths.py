from __future__ import annotations

import pytest

from contextual_trust_policy_engine.abac import AbacEngine
from contextual_trust_policy_engine.context import (
    ContextAggregator,
    ToolMeta,
    contains_secret_marker,
    load_tool_catalog,
)
from contextual_trust_policy_engine.policy import PolicyConfig, PolicyDecisionPoint
from contextual_trust_policy_engine.rebac import NamespaceConfig, RebacEngine, Rewrite, TupleStore


def base_req() -> dict:
    return {
        "trace_id": "cov",
        "step": 0,
        "agent": {
            "agent_id": "agent-cov",
            "spiffe_id": "spiffe://acme.test/agent/agent-cov",
            "svid": "valid",
            "attestation": "valid",
            "trust_history": ["benign"] * 40,
            "scopes": ["net:read", "net:write", "email:send", "mcp:use"],
        },
        "tool": "http.get",
        "args": {"url": "https://docs.acme.test"},
        "context": {"origin": "user", "content": "ok", "reasoning_tokens": 1},
    }


def attrs():
    catalog = {
        "http.get": ToolMeta("low", ("net:read",), {}, True),
        "*": ToolMeta("critical", (), {}, False),
    }
    return ContextAggregator(tool_catalog=catalog, allowlist=("acme.test",)).aggregate(base_req())


def test_abac_exists_gte_lte_and_no_match() -> None:
    engine = AbacEngine.from_dicts(
        [
            {
                "id": "allow-rich",
                "effect": "allow",
                "tools": ["http.get"],
                "conditions": [
                    {"field": "trust_score", "gte": 0.9},
                    {"field": "step", "lte": 0},
                    {"field": "agent_id", "exists": True},
                ],
            }
        ]
    )
    assert engine.evaluate(attrs())[0]
    assert AbacEngine.from_dicts([]).evaluate(attrs()) == (False, "no_matching_allow")


def test_abac_from_yaml_and_invalid_rules(tmp_path) -> None:
    good = tmp_path / "rules.yml"
    good.write_text("rules:\n- id: a\n  effect: allow\n  tools: ['*']\n", encoding="utf-8")
    assert AbacEngine.from_yaml(str(good)).evaluate(attrs())[0]
    bad = tmp_path / "bad.yml"
    bad.write_text("rules: {not: a-list}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="rules"):
        AbacEngine.from_yaml(str(bad))
    with pytest.raises(ValueError, match="unsupported"):
        AbacEngine.from_dicts([{"conditions": [{"field": "tool", "bad": 1}]}])


def test_context_catalog_and_fallbacks(tmp_path) -> None:
    catalog = tmp_path / "tools.yml"
    catalog.write_text(
        "tools:\n"
        "  custom.*:\n"
        "    risk: medium\n"
        "    required_scopes: [custom:use]\n"
        "    relations: {target: use}\n",
        encoding="utf-8",
    )
    loaded = load_tool_catalog(str(catalog))
    assert loaded["custom.*"].relations == {"target": "use"}
    r = base_req()
    r["tool"] = "custom.action"
    r["agent"]["trust_history"] = ["not-real"]
    a = ContextAggregator(tool_catalog=loaded).aggregate(r)
    assert a.tool_risk == "medium"
    assert a.required_scopes == ("custom:use",)


def test_context_handles_sequences_and_decode_errors() -> None:
    r = base_req()
    r["args"] = {"items": ["https://one.acme.test", "%%%%not-base64%%%%"]}
    a = ContextAggregator().aggregate(r)
    assert "one.acme.test" in a.external_hosts
    assert not contains_secret_marker({"body": "%%%%not-base64%%%%"})


def test_policy_rebac_denies_and_allows() -> None:
    store = TupleStore(["doc:1#read@user:agent-cov"])
    pdp = PolicyDecisionPoint(rebac=RebacEngine(store), config=PolicyConfig(require_rebac=True))
    r = base_req()
    r["rebac"] = {"object": "doc:2", "relation": "read"}
    assert pdp.decide(r).component == "rebac"
    r["rebac"] = {"object": "doc:1", "relation": "read"}
    assert pdp.decide(r).decision == "allow"


def test_policy_abac_denial_and_fail_closed() -> None:
    pdp = PolicyDecisionPoint(abac=AbacEngine.from_dicts([]))
    assert pdp.decide(base_req()).component == "abac"
    assert PolicyDecisionPoint().decide([]).component == "fail_closed"


def test_policy_extra_escalation_branches() -> None:
    pdp = PolicyDecisionPoint()
    r = base_req()
    r["tool"] = "mcp.notes.search"
    r["context"] = {"origin": "mcp_server", "content": "ok", "reasoning_tokens": 0}
    r["agent"]["scopes"].append("mcp:use")
    assert pdp.decide(r).decision == "allow"
    r["args"] = {"query": "notes", "attachment": "secret://vault/item extra"}
    assert pdp.decide(r).component == "context"
    r = base_req()
    r["tool"] = "http.post"
    r["args"] = {"url": "https://8.8.8.8/collect"}
    assert pdp.decide(r).component == "context"


def test_rebac_rewrite_variants_and_cache() -> None:
    store = TupleStore(
        [
            "doc:1#owner@user:a",
            "doc:1#editor@user:a",
            "doc:1#blocked@user:b",
            "doc:1#parent@org:1",
            "org:1#admin@user:c",
        ]
    )
    cfg = NamespaceConfig(
        {
            "owner": Rewrite("this"),
            "editor": Rewrite("this"),
            "blocked": Rewrite("this"),
            "parent": Rewrite("this"),
            "read": Rewrite(
                "union",
                children=(
                    Rewrite("computed_userset", relation="owner"),
                    Rewrite("computed_userset", relation="editor"),
                ),
            ),
            "strict": Rewrite(
                "intersection",
                children=(
                    Rewrite("computed_userset", relation="owner"),
                    Rewrite("computed_userset", relation="editor"),
                ),
            ),
            "admin_read": Rewrite("tuple_to_userset", tupleset="parent", computed="admin"),
            "unknown_kind": Rewrite("not_a_kind"),  # type: ignore[arg-type]
        }
    )
    rebac = RebacEngine(store, {"default": NamespaceConfig.simple([]), "doc": cfg, "org": cfg})
    assert rebac.check("user:a", "doc:1", "read")
    assert rebac.check("user:a", "doc:1", "read")  # memoized hit
    assert rebac.check("user:a", "doc:1", "strict")
    assert rebac.check("user:c", "doc:1", "admin_read")
    assert not rebac.check("user:x", "doc:1", "unknown_kind")
    rebac.bulk_load(["doc:2#owner@user:z"])
    assert rebac.check("user:z", "doc:2", "read")
    assert not RebacEngine(TupleStore(["doc:1#read@user:a"]), max_depth=-1).check(
        "user:a", "doc:1", "read"
    )
