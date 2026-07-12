// SPDX-License-Identifier: Apache-2.0
package main

// resolveIdentity is the single translation point from an AuthZEN request's subject to the
// verified-agent identity pair (task 009 / ADR-006). It reads ONLY `subject.properties.spiffe_id`
// and `subject.properties.trust_tier` — `subject.id` is never consulted for identity, so an
// opaque v0 subject id that happens to look like a SPIFFE URI never becomes an identity.
//
// TRUSTED AS GIVEN (interim, pending agent-mesh task 008): this function performs NO validation
// of either field — no SPIFFE URI syntax check, no trust_tier enumeration, no signature or peer
// credential check. Any caller can claim any spiffe_id today and it is accepted verbatim. This is
// deliberate and documented (REQ-006): until agent-mesh's identity-propagation contract
// (X.509-SVID verified principal) lands, per-identity rate-limit buckets (ratelimit.go) are an
// abuse-resistance measure bounded by the identity cap and the shared global fallback bucket, NOT
// an authentication boundary. Do not "at least" syntax-check the URI here — half-validation would
// create a false sense of authentication while agent-mesh 008 is the real boundary.
//
// Absent or malformed input never panics: any missing field, wrong-typed subject/properties, or
// non-string spiffe_id/trust_tier resolves to "" for that field.
func resolveIdentity(req map[string]any) (spiffeID, trustTier string) {
	subject, _ := req["subject"].(map[string]any)
	if subject == nil {
		return "", ""
	}
	props, _ := subject["properties"].(map[string]any)
	if props == nil {
		return "", ""
	}
	spiffeID, _ = props["spiffe_id"].(string)
	trustTier, _ = props["trust_tier"].(string)
	return spiffeID, trustTier
}
