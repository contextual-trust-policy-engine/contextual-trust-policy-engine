from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from contextual_trust_policy_engine.context import ContextAggregator, untrusted_hosts
from contextual_trust_policy_engine.models import Attributes
from contextual_trust_policy_engine.policy import PolicyDecisionPoint

pytestmark = pytest.mark.integration


def _side_effect(a: Attributes) -> bool:
    return (
        a.tool_egress
        or a.tool_risk in {"high", "critical"}
        or (a.origin == "tool_output" and a.tool_risk == "medium")
    )


def _opa_input_from_attrs(a: Attributes) -> dict[str, Any]:
    pdp = PolicyDecisionPoint()
    context_tampered = PolicyDecisionPoint._context_tampered(a, high_impact=_side_effect(a))
    requester_authorized, _ = pdp._requester_authorized(a)
    return {
        "svid_valid": a.svid_valid,
        "attestation_valid": a.attestation_valid,
        "trust_score": a.trust_score,
        "tool": a.tool,
        "tool_risk": a.tool_risk,
        "tool_egress": a.tool_egress,
        "origin": a.origin,
        "args_has_secret": a.args_has_secret,
        "untrusted_external_hosts_count": len(a.untrusted_external_hosts),
        "content_untrusted_external_hosts_count": len(
            untrusted_hosts(a.content, pdp.aggregator.allowlist)
        ),
        "requester_authorized": requester_authorized,
        "required_scopes": list(a.required_scopes),
        "agent_scopes": list(a.agent_scopes),
        "reasoning_tokens": a.reasoning_tokens,
        "context_tampered": context_tampered,
    }


def _run_opa(input_obj: dict[str, Any]) -> str:
    cmd = [
        "docker",
        "run",
        "--rm",
        "-i",
        "-v",
        f"{Path.cwd()}:/work:ro",
        "openpolicyagent/opa:1.10.1-static",
        "eval",
        "-d",
        "/work/policies/contextual_trust_policy_engine.rego",
        "-I",
        "data.contextual_trust_policy_engine.authz.decision.decision",
    ]
    proc = subprocess.run(
        cmd, input=json.dumps(input_obj), text=True, capture_output=True, check=True
    )
    return str(json.loads(proc.stdout)["result"][0]["expressions"][0]["value"])


def _native_decision(input_obj: dict[str, Any]) -> str:
    args: dict[str, Any] = {"url": "https://docs.acme.test", "body": "normal"}
    if input_obj["context_tampered"]:
        args["unsafe_ref"] = "secret://vault/item extra"
    content = "project status update"
    if input_obj.get("content_untrusted_external_hosts_count", 0):
        content = "contact reviewer@outside.example.org"
    user_task = "project status update"
    attrs = Attributes(
        0,
        "agent-p",
        "acme.test",
        ("agent", "agent-p"),
        bool(input_obj["svid_valid"]),
        bool(input_obj["attestation_valid"]),
        float(input_obj["trust_score"]),
        "tool.generated",
        str(input_obj["tool_risk"]),
        bool(input_obj["tool_egress"]),
        tuple(str(s) for s in input_obj["required_scopes"]),
        (),
        tuple(str(s) for s in input_obj["agent_scopes"]),
        args,
        bool(input_obj["args_has_secret"]),
        False,
        ("evil.example",) if input_obj["untrusted_external_hosts_count"] else (),
        ("evil.example",) if input_obj["untrusted_external_hosts_count"] else (),
        str(input_obj["origin"]),
        content,
        user_task,
        "",
        "",
        int(input_obj["reasoning_tokens"]),
        0.0,
        {},
    )
    return PolicyDecisionPoint()._decide_attrs(attrs).decision


@pytest.mark.skipif(
    os.environ.get("RUN_INTEGRATION_TESTS") != "1", reason="set RUN_INTEGRATION_TESTS=1"
)
def test_opa_unit_tests() -> None:
    subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{Path.cwd()}:/work:ro",
            "openpolicyagent/opa:1.10.1-static",
            "test",
            "/work/policies",
        ],
        check=True,
    )


@pytest.mark.skipif(
    os.environ.get("RUN_INTEGRATION_TESTS") != "1", reason="set RUN_INTEGRATION_TESTS=1"
)
@pytest.mark.parametrize(
    "tool,origin,expected", [("http.get", "user", "allow"), ("email.send", "retrieved_doc", "deny")]
)
def test_opa_agrees_with_native(tool: str, origin: str, expected: str) -> None:
    req: dict[str, Any] = {
        "trace_id": "t",
        "step": 0,
        "agent": {
            "agent_id": "a",
            "spiffe_id": "spiffe://acme.test/agent/a",
            "svid": "valid",
            "attestation": "valid",
            "trust_history": ["benign"] * 40,
            "scopes": ["net:read", "email:send"],
        },
        "tool": tool,
        "args": {"url": "https://docs.acme.test", "to": "user@acme.test"},
        "context": {
            "origin": origin,
            "content": "ok",
            "reasoning_tokens": 0 if expected == "deny" else 1,
        },
    }
    assert PolicyDecisionPoint().decide(req).decision == expected
    assert _run_opa(_opa_input_from_attrs(ContextAggregator().aggregate(req))) == expected


_scope = st.sampled_from(["net:read", "net:write", "email:send", "fs:write", "mcp:use"])
_opa_cases = st.fixed_dictionaries(
    {
        "svid_valid": st.booleans(),
        "attestation_valid": st.booleans(),
        "trust_score": st.floats(min_value=0.0, max_value=1.0, allow_nan=False),
        "tool_risk": st.sampled_from(["low", "medium", "high", "critical", "unknown"]),
        "tool_egress": st.booleans(),
        "origin": st.sampled_from(["user", "tool_output", "retrieved_doc", "mcp_server"]),
        "args_has_secret": st.booleans(),
        "untrusted_external_hosts_count": st.integers(min_value=0, max_value=2),
        "content_untrusted_external_hosts_count": st.integers(min_value=0, max_value=2),
        "requester_authorized": st.just(True),
        "required_scopes": st.lists(_scope, unique=True, max_size=3),
        "agent_scopes": st.lists(_scope, unique=True, max_size=5),
        "reasoning_tokens": st.integers(min_value=0, max_value=8),
        "context_tampered": st.booleans(),
    }
)


@pytest.mark.skipif(
    os.environ.get("RUN_INTEGRATION_TESTS") != "1", reason="set RUN_INTEGRATION_TESTS=1"
)
@settings(max_examples=25, deadline=None)
@given(_opa_cases)
def test_opa_hypothesis_differential(case: dict[str, Any]) -> None:
    assert _run_opa(case) == _native_decision(case)
