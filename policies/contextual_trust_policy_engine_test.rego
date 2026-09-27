package contextual_trust_policy_engine.authz

test_allow_http_get if {
	decision with input as {
		"svid_valid": true,
		"attestation_valid": true,
		"trust_score": 0.95,
		"tool": "http.get",
		"tool_risk": "low",
		"tool_egress": true,
		"origin": "user",
		"args_has_secret": false,
		"untrusted_external_hosts_count": 0,
		"required_scopes": ["net:read"],
		"agent_scopes": ["net:read"],
		"reasoning_tokens": 8,
		"context_tampered": false,
	} == {"decision": "allow", "reason": "opa_allow", "component": "opa"}
}

test_deny_untrusted_email if {
	decision with input as {
		"svid_valid": true,
		"attestation_valid": true,
		"trust_score": 0.95,
		"tool": "email.send",
		"tool_risk": "high",
		"tool_egress": true,
		"origin": "retrieved_doc",
		"args_has_secret": false,
		"untrusted_external_hosts_count": 0,
		"required_scopes": ["email:send"],
		"agent_scopes": ["email:send"],
		"reasoning_tokens": 0,
		"context_tampered": false,
	} == {"decision": "deny", "reason": "untrusted_origin_escalation", "component": "context"}
}
