package contextual_trust_policy_engine.authz

default decision := {"decision": "deny", "reason": "deny_by_default", "component": "opa"}

risk_threshold := {"low": 0.2, "medium": 0.35, "high": 0.4, "critical": 0.4}

risk := object.get(input, "tool_risk", "critical")

threshold := object.get(risk_threshold, risk, 0.85)

valid_identity if {
	input.svid_valid == true
	input.attestation_valid == true
}

valid_base if {
	valid_identity
	input.trust_score >= threshold
	not missing_scope
	not untrusted_escalation
	not requester_unauthorized
}

side_effect if {
	input.tool_egress == true
}

side_effect if {
	risk == "high"
}

side_effect if {
	risk == "critical"
}

side_effect if {
	input.origin == "tool_output"
	risk == "medium"
}

untrusted_escalation if {
	input.context_tampered == true
}

untrusted_escalation if {
	input.reasoning_tokens == 0
	input.origin != "user"
	side_effect
}

untrusted_escalation if {
	input.args_has_secret == true
	input.tool_egress == true
}

untrusted_escalation if {
	input.untrusted_external_hosts_count > 0
	input.tool_egress == true
}

untrusted_escalation if {
	object.get(input, "content_untrusted_external_hosts_count", 0) > 0
	input.origin != "user"
	input.tool_egress == true
}

requester_unauthorized if {
	object.get(input, "requester_authorized", true) == false
}

missing_scope if {
	some scope in input.required_scopes
	not scope in input.agent_scopes
}

decision := {"decision": "allow", "reason": "opa_allow", "component": "opa"} if {
	valid_base
}

decision := {"decision": "deny", "reason": "invalid_svid", "component": "svid"} if {
	input.svid_valid != true
}

decision := {"decision": "deny", "reason": "invalid_attestation", "component": "attestation"} if {
	input.svid_valid == true
	input.attestation_valid != true
}

decision := {"decision": "deny", "reason": "trust_below_threshold", "component": "trust"} if {
	valid_identity
	input.trust_score < threshold
}

decision := {"decision": "deny", "reason": "missing_scope", "component": "scope"} if {
	valid_identity
	input.trust_score >= threshold
	missing_scope
}

decision := {"decision": "deny", "reason": "untrusted_origin_escalation", "component": "context"} if {
	valid_identity
	input.trust_score >= threshold
	not missing_scope
	untrusted_escalation
}

decision := {"decision": "deny", "reason": "requester_unauthorized", "component": "context"} if {
	valid_identity
	input.trust_score >= threshold
	not missing_scope
	not untrusted_escalation
	requester_unauthorized
}
