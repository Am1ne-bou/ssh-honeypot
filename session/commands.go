package session

import (
	"os"
	"strings"
)

type Cmd interface {
	Run(args []string) (string, uint32)
}

var registry = map[string]Cmd{}

// env we pretend to have. ? is $? (last exit code), always 0 for now.
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

func register(name string, c Cmd) {
	registry[name] = c
}

func expandVars(s string) string {
	return os.Expand(s, func(k string) string {
		return fakeEnv[k] // unset -> "" like bash
	})
}

func dispatch(cmd string) (string, uint32) {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return "", 0
	}
	cmd = expandVars(cmd)

	// no real pipes -- just run the LHS. full pipeline is in the log line anyway.
	// TODO: parse properly when we add file state
	if i := strings.Index(cmd, "|"); i >= 0 {
		cmd = strings.TrimSpace(cmd[:i])
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
