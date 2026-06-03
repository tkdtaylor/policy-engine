package main

import (
	"bufio"
	"encoding/json"
	"net"
	"os"
)

// serve runs the JSON-over-Unix-socket IPC form: {op:"decide", request:{…AuthZEN…}}.
// policy-engine runs OUT OF PROCESS so a compromised agent cannot self-grant.
func serve(socketPath string, engine *Engine) error {
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
