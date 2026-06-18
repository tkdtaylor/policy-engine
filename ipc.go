package main

import (
	"bufio"
	"encoding/json"
	"net"
	"os"
)

// rateLimiter gates the IPC decide op. Implemented by *tokenBucket (ratelimit.go). A nil limiter
// means no rate limiting is configured (the decide op proceeds unguarded). Allow() returning false
// is fail-closed: the server rejects with the rate_limited error, never an allow.
type rateLimiter interface {
	Allow() bool
}

// serve runs the JSON-over-Unix-socket IPC form: {op:"decide", request:{…AuthZEN…}}.
// policy-engine runs OUT OF PROCESS so a compromised agent cannot self-grant. The decision is
// produced by the supplied Decider (the AuthZEN seam) — either the v0 allowlist *Engine or the
// OPA-backed *OPAEngine — selected at the binary boundary, not hard-wired here. On the serve path
// the Decider may be wrapped by a cachingDecider (ADR-004); the cache composes through the seam and
// is invisible here. The limiter (when non-nil) gates the decide op BEFORE evaluation.
func serve(socketPath string, engine Decider, limiter rateLimiter) error {
	_ = os.Remove(socketPath)
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return err
	}
	defer ln.Close()
	_ = os.Chmod(socketPath, 0o600)

	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go func(c net.Conn) {
			defer c.Close()
			line, err := bufio.NewReader(c).ReadBytes('\n')
			if err != nil && len(line) == 0 {
				return
			}
			var req map[string]any
			if err := json.Unmarshal(line, &req); err != nil {
				writeJSON(c, errShape("bad_request", err.Error()))
				return
			}
			switch req["op"] {
			case "decide":
				// Rate-limit the decide op BEFORE evaluation. A rejection is fail-closed: the
				// structured rate_limited error, NEVER an allow (ADR-004). ping is not limited.
				if limiter != nil && !limiter.Allow() {
					writeJSON(c, errShapeRetryable("rate_limited", "decision rate limit exceeded; retry after backing off"))
					return
				}
				r, _ := req["request"].(map[string]any)
				if r == nil {
					writeJSON(c, errShape("bad_request", "missing request"))
					return
				}
				writeJSON(c, engine.Decide(r))
			case "ping":
				writeJSON(c, map[string]any{"ok": true})
			default:
				writeJSON(c, errShape("unknown_op", "unsupported op"))
			}
		}(conn)
	}
}

func writeJSON(conn net.Conn, v any) {
	b, _ := json.Marshal(v)
	conn.Write(append(b, '\n'))
}

func errShape(code, msg string) map[string]any {
	return map[string]any{"error": map[string]any{
		"code": code, "message": msg, "retryable": false}}
}

// errShapeRetryable is the same stable error shape with retryable:true — used for transient
// conditions a caller may retry (e.g. rate_limited, ADR-004). It is a documented extension of the
// v0 error shape, not a new shape: still {error:{code,message,retryable}}. A retryable error is
// still a non-allow the caller treats as fail-closed.
func errShapeRetryable(code, msg string) map[string]any {
	return map[string]any{"error": map[string]any{
		"code": code, "message": msg, "retryable": true}}
}
