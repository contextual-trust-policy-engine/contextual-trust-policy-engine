from __future__ import annotations

from contextual_trust_policy_engine.context import (
    ContextAggregator,
    ToolMeta,
    contains_secret_marker,
    parse_spiffe_id,
)
from contextual_trust_policy_engine.policy import ContextualTrustDefense, PolicyDecisionPoint


def _request(
    tool: str = "http.get", origin: str = "user", history: list[str] | None = None
) -> dict:
    return {
        "trace_id": "t-1",
        "step": 0,
        "agent": {
            "agent_id": "agent-1",
            "spiffe_id": "spiffe://acme.test/agent/agent-1",
            "svid": "valid",
            "attestation": "valid",
            "trust_history": history or ["benign"] * 40,
            "scopes": ["net:read", "net:write", "email:send"],
        },
        "tool": tool,
        "args": {"url": "https://docs.acme.test/a", "body": "hello"},
        "context": {"origin": origin, "content": "normal", "reasoning_tokens": 10},
    }


def test_parse_spiffe() -> None:
    assert parse_spiffe_id("spiffe://acme.test/agent/a") == ("acme.test", ("agent", "a"))
    assert parse_spiffe_id("https://x") == (None, ())


def test_aggregator_classifies_hosts_and_trust() -> None:
    catalog = {
        "http.get": ToolMeta("low", ("net:read",), {}, True),
        "*": ToolMeta("critical", (), {}, False),
    }
    attrs = ContextAggregator(tool_catalog=catalog, allowlist=("acme.test",)).aggregate(_request())
    assert attrs.svid_valid and attrs.attestation_valid and attrs.trust_score > 0.9
    assert attrs.external_hosts == ("docs.acme.test",) and attrs.untrusted_external_hosts == ()


def test_secret_detection_base64() -> None:
    assert contains_secret_marker({"body": "QUtJQTEyMzQ1Njc4OTBBQkNE"})


def test_policy_allows_safe_read() -> None:
    assert PolicyDecisionPoint().decide(_request()).decision == "allow"


def test_policy_denies_invalid_svid() -> None:
    req = _request()
    req["agent"]["svid"] = "forged"
    dec = PolicyDecisionPoint().decide(req)
    assert dec.decision == "deny" and dec.component == "svid"


def test_policy_allows_reasoned_untrusted_side_effect() -> None:
    dec = PolicyDecisionPoint().decide(_request("email.send", "retrieved_doc"))
    assert dec.decision == "allow"


def test_policy_denies_zero_reasoning_untrusted_side_effect() -> None:
    request = _request("email.send", "retrieved_doc")
    request["context"]["reasoning_tokens"] = 0
    dec = PolicyDecisionPoint().decide(request)
    assert dec.decision == "deny" and dec.component == "context"


def test_policy_denies_low_trust_high_risk() -> None:
    dec = PolicyDecisionPoint().decide(_request("email.send", "user", ["malicious"] * 40))
    assert dec.decision == "deny" and dec.component == "trust"


def test_benchmark_adapter_returns_dict() -> None:
    assert ContextualTrustDefense().decide(_request())["decision"] == "allow"
