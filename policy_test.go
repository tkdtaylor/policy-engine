package main

import "testing"

func req(host string) map[string]any {
	return map[string]any{
		"subject":  map[string]any{"type": "agent", "id": "t"},
		"action":   map[string]any{"name": "net"},
		"resource": map[string]any{"type": "host", "id": host},
		"context":  map[string]any{"risk": 0.2},
	}
}

func TestAllowlistedHostIsAllowedWithObligations(t *testing.T) {
	e := NewEngine("api.example.com")
	out := e.Decide(req("api.example.com"))
	if out["decision"] != Allow {
		t.Fatalf("expected allow, got %v", out["decision"])
	}
	obs := out["context"].(map[string]any)["obligations"].([]map[string]any)
	var floor string
	for _, o := range obs {
		if o["type"] == "vault_injection_floor" {
			floor = o["value"].(string)
		}
	}
	if floor != "proxy" {
		t.Fatalf("expected injection floor raised to proxy, got %q", floor)
	}
}

func TestNonAllowlistedHostIsDenied(t *testing.T) {
	e := NewEngine("api.example.com")
	out := e.Decide(req("evil.example.net"))
	if out["decision"] != Deny {
		t.Fatalf("expected deny, got %v", out["decision"])
	}
}
