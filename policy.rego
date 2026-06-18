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

# allow iff a host is resolved AND it is in the allowlist AND the approval gate did not trip.
decision := "allow" {
	host_allowed
	not approval_gate
}

# require_approval is a gate layered ABOVE the risk-scored allow (ADR-003): an otherwise-allowable
# request (allowlisted host) escalates to require_approval when the approval gate trips. Fail-closed
# precedence is preserved structurally: the gate is conditioned on host_allowed, so a non-allowlisted
# host or unresolvable host can NEVER reach require_approval — it stays the default deny.
decision := "require_approval" {
	host_allowed
	approval_gate
}

# host_allowed is the underlying authorization predicate: a resolved, allowlisted host. It is the
# shared precondition for both allow and require_approval, and is NEVER true for a denied request.
host_allowed {
	input.host != ""
	input.allowlist[input.host]
}

# allowed: an emitted decision that carries the risk-scored obligations. Both allow and
# require_approval carry them (ADR-003 — the floor-raise rides along into the approval state).
allowed {
	host_allowed
}

reason := msg {
	host_allowed
	msg := sprintf("host '%s' is in the net allowlist", [input.host])
}

reason := msg {
	not host_allowed
	msg := sprintf("host '%s' is not in the net allowlist", [input.host])
}

# ---------------------------------------------------------------------------
# require_approval gate (ADR-003): layered ABOVE the risk-scored obligations.
# ---------------------------------------------------------------------------
#
# The gate trips on an otherwise-allowable request when EITHER:
#   - the risk score is at/above the approval threshold (risk >= 0.9), OR
#   - the memory state signals a suspicious pattern (injection-suspected).
# When it trips, the decision becomes require_approval and the response carries a structured
# escalation payload PLUS the risk-scored tier_select / vault_injection_floor / audit_emit
# obligations (defense-in-depth rides along while the action is paused).
#
# Fail-closed precedence: this gate is only consulted under host_allowed, so a deny is never
# upgraded to require_approval (see the decision rules above).

# Approval threshold: the top of the firecracker band. risk >= 0.9 escalates rather than
# auto-allowing into the strongest sandbox.
approval_threshold := 0.9

risk_at_threshold {
	valid_risk
	input.risk >= approval_threshold
}

approval_gate {
	risk_at_threshold
}

approval_gate {
	injection_flag
}

# triggered_by names which signal fired. When BOTH fire, the memory flag takes precedence — a
# suspected-injection pattern is the stronger human-in-the-loop signal (ADR-003), so it is named
# even when the numeric risk also crossed the threshold.
triggered_by := "memory_flag" {
	injection_flag
}

triggered_by := "risk_threshold" {
	not injection_flag
	risk_at_threshold
}

# Echoed risk for the escalation payload: the numeric risk when valid, else 0 (a missing/invalid
# risk that reached approval did so via the memory flag, not the threshold).
echoed_risk := input.risk {
	valid_risk
}

echoed_risk := 0 {
	not valid_risk
}

approval_reason := "memory state flagged 'injection-suspected'; human approval required before proceeding" {
	triggered_by == "memory_flag"
}

approval_reason := sprintf("risk score %v is at or above the approval threshold %v; human approval required before proceeding", [echoed_risk, approval_threshold]) {
	triggered_by == "risk_threshold"
}

# The escalation payload — a plain AuthZEN-only JSON object carried as the require_approval
# obligation's value. No engine-specific type appears here.
escalation_payload := {
	"reason":              approval_reason,
	"risk":                echoed_risk,
	"triggered_by":        triggered_by,
	"required_to_proceed": "operator approval",
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
# vault_injection_floor: raise-only via explicit max under env(0) < proxy(1) ordering
# ---------------------------------------------------------------------------

# Rank mapping: env=0, proxy=1.  Higher rank = stricter floor.
# A future flag that maps to a lower rank can never lower the emitted floor
# because we always emit the floor_names entry at max(baseline_rank, flag_rank).
floor_rank("env")   := 0
floor_rank("proxy") := 1

# The OPA evaluator's baseline floor.
baseline_floor := "env"
baseline_floor_rank := floor_rank(baseline_floor)

# injection_flag is true when "injection-suspected" appears in memory_flags.
injection_flag {
	some i
	input.memory_flags[i] == "injection-suspected"
}

# "injection-suspected" flag implies floor = "proxy" (rank 1).
flag_floor := "proxy" {
	injection_flag
}

# Default flag floor is "env" (rank 0) — no flag, no raise.
flag_floor := "env" {
	not injection_flag
}

flag_floor_rank := floor_rank(flag_floor)

# floor_names indexed by rank, used to resolve max rank → name.
floor_names := {0: "env", 1: "proxy"}

# The emitted floor is max(baseline_rank, flag_rank) resolved back to a name.
# This is raise-only by construction: even if a future flag maps to rank 0 (env),
# max(0, 0) = 0 = "env" — it never pulls a baseline already at rank 1 (proxy) down.
injection_floor := floor_names[max_rank] {
	max_rank := max({baseline_floor_rank, flag_floor_rank})
}

# ---------------------------------------------------------------------------
# Obligations: allow and require_approval both carry the risk-scored set; deny carries none.
# require_approval additionally carries the structured escalation payload (ADR-003).
# ---------------------------------------------------------------------------

# Risk-scored base obligations, emitted under any host_allowed decision (allow OR require_approval).
risk_obligations := [
	{"type": "tier_select", "value": tier},
	{"type": "vault_injection_floor", "value": injection_floor},
	{"type": "audit_emit", "value": true},
]

# allow: the risk-scored obligations only.
obligations := risk_obligations {
	allowed
	not approval_gate
}

# require_approval: the risk-scored obligations PLUS exactly one require_approval obligation
# carrying the escalation payload (ADR-003 — the floor-raise rides along into the approval state).
obligations := obs {
	allowed
	approval_gate
	obs := array.concat(
		[{"type": "require_approval", "value": escalation_payload}],
		risk_obligations,
	)
}

obligations := [] {
	not allowed
}

result := {
	"decision":    decision,
	"reason":      reason,
	"obligations": obligations,
}
