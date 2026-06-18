package policyengine

# Rego policy for the OPA-backed evaluator, behind the AuthZEN decide() seam.
#
# Input shape (marshaled from the AuthZEN request by opa.go):
#   {
#     "host":         "<resolved target host>",   # resource.id, or resource.properties.host
#     "allowlist":    {"<host>": true, ...},       # the configured net allowlist
#     "risk":         <number 0..1 | null>,        # context.risk from the AuthZEN request
#     "memory_flags": ["<flag>", ...]              # context.memory_flags from the AuthZEN request
#   }
#
# Output: the `result` object — { decision, reason, obligations } — translated back into the
# AuthZEN response by opa.go. No OPA/Rego type is allowed to escape that translation.
#
# Risk → tier_select bands (lower-edge-inclusive for the higher tier):
#   risk < 0.3                                    → bubblewrap  (baseline)
#   0.3 <= risk <= 0.7                            → gvisor
#   risk > 0.7                                    → firecracker
#   missing / non-numeric / out-of-range          → bubblewrap  (fail-closed to baseline)
#
# vault_injection_floor raise-only invariant:
#   baseline floor: "env" (OPA evaluator baseline)
#   "injection-suspected" in memory_flags raises floor → "proxy"
#   The emitted floor is max(baseline, flag-implied) under ordering env < proxy — never lowered.

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

# ---------------------------------------------------------------------------
# Risk → isolation tier (behind the seam, v1 OPA evaluator only)
# ---------------------------------------------------------------------------

# A valid risk value is a number in [0, 1]. Invalid values (missing, out-of-range,
# or the wrong type — which OPA marshals as null) degrade to the baseline tier.
valid_risk {
	is_number(input.risk)
	input.risk >= 0
	input.risk <= 1
}

tier := "firecracker" {
	valid_risk
	input.risk > 0.7
}

tier := "gvisor" {
	valid_risk
	input.risk >= 0.3
	input.risk <= 0.7
}

# Baseline tier: risk < 0.3, or missing/invalid risk.
tier := "bubblewrap" {
	valid_risk
	input.risk < 0.3
}

tier := "bubblewrap" {
	not valid_risk
}

# ---------------------------------------------------------------------------
# vault_injection_floor: raise-only under env < proxy ordering
# ---------------------------------------------------------------------------

# "injection-suspected" flag maps to floor = "proxy".
flag_raises_to_proxy {
	some i
	input.memory_flags[i] == "injection-suspected"
}

# The OPA evaluator's baseline floor is "env".
# A flag raises it to "proxy"; the emitted floor is max(baseline, flag-implied):
#   - flag present  → proxy (raised)
#   - flag absent   → env   (baseline stays)
# This is raise-only by construction: we only ever emit "env" or "proxy", and the
# flag path always produces the higher value. If the caller's baseline were already
# "proxy" (tested via TC-006), the flag_raises path still yields "proxy" — never "env".
injection_floor := "proxy" {
	flag_raises_to_proxy
}

injection_floor := "env" {
	not flag_raises_to_proxy
}

# ---------------------------------------------------------------------------
# Obligations on allow mirror the v0 emission shape; deny carries none.
# ---------------------------------------------------------------------------

obligations := obs {
	allowed
	obs := [
		{"type": "tier_select", "value": tier},
		{"type": "vault_injection_floor", "value": injection_floor},
		{"type": "audit_emit", "value": true},
	]
}

obligations := [] {
	not allowed
}

result := {
	"decision":    decision,
	"reason":      reason,
	"obligations": obligations,
}
