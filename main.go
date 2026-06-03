// Command policy-engine is the out-of-process authorization control plane. It gates every
// agent action before exec-sandbox runs, so a compromised agent cannot self-grant.
//
// Contract (interface-contracts.md §2, v1): AuthZEN-shaped
//
//	decide(context) -> { decision, context:{ reason, obligations:[] } }
//
// Usage:
//
//	policy-engine serve  --socket /run/policy.sock --allow api.example.com
//	policy-engine decide --allow api.example.com --host api.example.com   # CLI (stdin JSON also ok)
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: policy-engine <serve|decide> [flags]")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "serve":
		cmdServe(os.Args[2:])
	case "decide":
		cmdDecide(os.Args[2:])
	default:
		fmt.Fprintln(os.Stderr, "unknown command:", os.Args[1])
		os.Exit(2)
	}
}

func cmdServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	socket := fs.String("socket", "", "unix socket path (required)")
	allow := fs.String("allow", "", "comma-separated net allowlist")
	fs.Parse(args)
	if *socket == "" {
		fmt.Fprintln(os.Stderr, "serve: --socket is required")
		os.Exit(2)
	}
	engine := NewEngine(splitCSV(*allow)...)
	fmt.Fprintf(os.Stderr, "policy-engine serving on %s (allow=%v)\n", *socket, *allow)
	if err := serve(*socket, engine); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func cmdDecide(args []string) {
	fs := flag.NewFlagSet("decide", flag.ExitOnError)
	allow := fs.String("allow", "", "comma-separated net allowlist")
	host := fs.String("host", "", "target host (shortcut; or pipe a full AuthZEN request on stdin)")
	fs.Parse(args)
	engine := NewEngine(splitCSV(*allow)...)

	var req map[string]any
	if *host != "" {
		req = map[string]any{
			"subject":  map[string]any{"type": "agent", "id": "cli"},
			"action":   map[string]any{"name": "net"},
			"resource": map[string]any{"type": "host", "id": *host},
			"context":  map[string]any{"risk": 0.2},
		}
	} else {
		data, _ := io.ReadAll(os.Stdin)
		if err := json.Unmarshal(data, &req); err != nil {
			fmt.Fprintln(os.Stderr, "decide: provide --host or a JSON AuthZEN request on stdin")
			os.Exit(2)
		}
	}
	out := engine.Decide(req)
	b, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println(string(b))
	if out["decision"] != Allow {
		os.Exit(1)
	}
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}
