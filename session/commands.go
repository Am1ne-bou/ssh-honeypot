package session

import (
	"os"
	"strings"
)

// Cmd is a honeypot shell command.
type Cmd interface {
	Run(args []string) (string, uint32)
}

var registry = map[string]Cmd{}

// fakeEnv is the environment the fake shell pretends to have.
var fakeEnv = map[string]string{
	"HOME":     "/root",
	"USER":     "root",
	"LOGNAME":  "root",
	"PATH":     "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
	"SHELL":    "/bin/bash",
	"PWD":      "/root",
	"HOSTNAME": "ubuntu",
	"UID":      "0",
	"TERM":     "xterm-256color",
	"LANG":     "en_US.UTF-8",
	"?":        "0",
}

// register adds c under name; called from init() in cmd_*.go files.
func register(name string, c Cmd) {
	registry[name] = c
}

// expandVars replaces $VAR and ${VAR} with values from fakeEnv.
func expandVars(s string) string {
	return os.Expand(s, func(key string) string {
		return fakeEnv[key] // unset vars -> empty string, same as bash
	})
}

// dispatch parses cmd, runs the matching Cmd, returns (stdout, exit).
// Handles $VAR expansion and single-pipe splitting before lookup.
func dispatch(cmd string) (string, uint32) {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return "", 0
	}
	cmd = expandVars(cmd)

	// pipes: run only the first segment -- real output would be piped but
	// we don't have a runtime; the full pipeline is already logged by shell.
	if idx := strings.Index(cmd, "|"); idx >= 0 {
		cmd = strings.TrimSpace(cmd[:idx])
		if cmd == "" {
			return "", 0
		}
	}

	fields := strings.Fields(cmd)
	name, args := fields[0], fields[1:]
	impl, ok := registry[name]
	if !ok {
		return "bash: " + name + ": command not found\n", 127
	}
	return impl.Run(args)
}
