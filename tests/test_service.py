from __future__ import annotations

from starlette.testclient import TestClient

from contextual_trust_policy_engine.service import create_app


def test_service_endpoints() -> None:
    with TestClient(create_app()) as client:
        assert client.get("/healthz").json() == {"status": "ok"}
        req = {
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
        assert client.post("/v1/decide", json=req).json()["decision"] == "allow"
        assert "contextual_trust_policy_engine_decisions_total" in client.get("/metrics").text
        assert client.post(
            "/v1/check", json={"subject": "u", "object": "o", "relation": "r"}
        ).json() == {"allowed": False}


def test_fail_closed_on_bad_json_shape() -> None:
    with TestClient(create_app()) as client:
        response = client.post("/v1/decide", json=[])
        assert response.status_code == 200 and response.json()["decision"] == "deny"
