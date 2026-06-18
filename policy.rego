package policyengine

# Rego reproduction of the v0 net-allowlist rule, behind the AuthZEN decide() seam.
#
# Input shape (marshaled from the AuthZEN request by opa.go):
#   {
#     "host":      "<resolved target host>",   # resource.id, or resource.properties.host
#     "allowlist": {"<host>": true, ...}        # the configured net allowlist
#   }
#
# Output: the `result` object — { decision, reason, obligations } — translated back into the
# AuthZEN response by opa.go. No OPA/Rego type is allowed to escape that translation.

default decision := "deny"

# allow iff a host is resolved AND it is in the allowlist.
decision := "allow" {
	input.host != ""
	input.allowlist[input.host]
}

allowed {
	decision == "allow"
}

reason := msg {
	allowed
	msg := sprintf("host '%s' is in the net allowlist", [input.host])
}

reason := msg {
	not allowed
	msg := sprintf("host '%s' is not in the net allowlist", [input.host])
}

# Obligations on allow mirror the v0 emission exactly; deny carries none.
obligations := obs {
	allowed
	obs := [
		{"type": "tier_select", "value": "bubblewrap"},
		{"type": "vault_injection_floor", "value": "proxy"},
		{"type": "audit_emit", "value": true},
	]
}

obligations := [] {
	not allowed
}

result := {
	"decision": decision,
	"reason": reason,
	"obligations": obligations,
}
