package main

import (
	"errors"
	"fmt"
)

// errNotReady is the fail-closed sentinel returned when an OPA-backed engine did not initialize.
// selectDecider wraps it with context; the not-ready gate is shared so tests can assert it.
var errNotReady = errors.New("OPA policy/query did not prepare (fail-closed: no fallback to allowlist)")

// errCedarNotReady is the fail-closed sentinel returned when a Cedar-backed engine did not
// initialize (policy set / entity store did not build). selectDecider wraps it with context; the
// not-ready gate is shared so tests can assert it. A distinct sentinel from errNotReady keeps the
// two evaluators' init-failure reasons separable.
var errCedarNotReady = errors.New("cedar policy set did not parse (fail-closed: no fallback to allowlist)")

// Decider is the AuthZEN adapter seam as an interface: AuthZEN request in, AuthZEN response out.
// Both the v0 in-memory *Engine (policy.go) and the OPA/Rego *OPAEngine (opa.go) already satisfy
// it. The binary (serve / cmdServe / cmdDecide) operates on a Decider, never a concrete engine,
// so the evaluator is selectable at the boundary without leaking any engine-specific (rego.*/ast.*)
// type into the request/response. The interface IS the seam — it is not itself an evaluator type.
type Decider interface {
	Decide(map[string]any) map[string]any
}

// Evaluator names accepted by --evaluator. Default is allowlist (exact v0 behavior, back-compat).
const (
	EvaluatorAllowlist = "allowlist"
	EvaluatorOPA       = "opa"
	EvaluatorCedar     = "cedar"
)

// selectDecider maps an --evaluator value to a ready Decider over the given net allowlist.
//
//   - "allowlist" (and the no-flag default) -> *Engine (NewEngine): exact v0 behavior.
//   - "opa"                                 -> *OPAEngine (NewOPAEngine); fail-closed: if the OPA
//     query did not prepare (Ready()==false) it returns an error instead of a usable Decider —
//     it NEVER falls back to the allowlist (a silent evaluator downgrade is a self-grant vector).
//   - "cedar"                               -> *CedarEngine (NewCedarEngine); same fail-closed
//     posture: if the Cedar policy set did not parse (Ready()==false) it returns an error instead
//     of a usable Decider — NEVER an allowlist fallback. Cedar reproduces the v0 baseline decision
//     only (no risk scoring / approval gating — that asymmetry vs opa is intentional, ADR-005).
//   - anything else                         -> an error naming the accepted values.
//
// Marshal in, translate out: the returned Decider is the AuthZEN seam, nothing engine-specific
// crosses it.
func selectDecider(evaluator string, allow ...string) (Decider, error) {
	switch evaluator {
	case EvaluatorAllowlist:
		return NewEngine(allow...), nil
	case EvaluatorOPA:
		e := NewOPAEngine(allow...)
		if !e.Ready() {
			// Fail-closed: OPA could not initialize (policy load / query prepare failed). Refuse
			// to hand back a usable Decider rather than silently downgrade to the allowlist.
			return nil, fmt.Errorf("evaluator %q failed to initialize: %w", EvaluatorOPA, errNotReady)
		}
		return e, nil
	case EvaluatorCedar:
		e := NewCedarEngine(allow...)
		if !e.Ready() {
			// Fail-closed: Cedar could not initialize (policy set did not parse). Refuse to hand
			// back a usable Decider rather than silently downgrade to the allowlist.
			return nil, fmt.Errorf("evaluator %q failed to initialize: %w", EvaluatorCedar, errCedarNotReady)
		}
		return e, nil
	default:
		return nil, fmt.Errorf("unknown evaluator %q: accepted values are %q, %q or %q", evaluator, EvaluatorAllowlist, EvaluatorOPA, EvaluatorCedar)
	}
}
