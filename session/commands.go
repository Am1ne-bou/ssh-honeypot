package session

import "strings"

// Cmd is a honeypot shell command.
type Cmd interface {
	Run(args []string) (string, uint32)
}

var registry = map[string]Cmd{}

// register adds c under name; called from init() in cmd_*.go files.
func register(name string, c Cmd) {
	registry[name] = c
}

// dispatch parses cmd, runs the matching Cmd, returns (stdout, exit).
func dispatch(cmd string) (string, uint32) {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return "", 0
	}
	fields := strings.Fields(cmd)
	name, args := fields[0], fields[1:]
	impl, ok := registry[name]
	if !ok {
		return "bash: " + name + ": command not found\n", 127
	}
	return impl.Run(args)
}
