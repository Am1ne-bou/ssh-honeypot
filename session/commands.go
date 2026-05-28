package session

import (
	"os"
	"path"
	"strings"
)

// Cmd is the interface every fake command implements.
// stdin carries output from the previous pipeline stage (empty for the first stage).
// sess holds per-connection mutable state (cwd, virtual filesystem).
type Cmd interface {
	Run(args []string, stdin string, sess *Session) (string, uint32)
}

var registry = map[string]Cmd{}

// Session holds per-connection mutable state.
// Commands execute single-threaded per session so no locking needed.
type Session struct {
	cwd  string
	fs   map[string][]byte // virtual filesystem: absolute path -> content
	dirs map[string]bool   // which directories exist
}

func newSession() *Session {
	s := &Session{
		cwd:  "/root",
		fs:   make(map[string][]byte),
		dirs: make(map[string]bool),
	}
	// fakeFiles defined in cmd_fs.go -- pre-populate so cat works immediately
	for p, content := range fakeFiles {
		s.fs[p] = []byte(content)
	}
	for _, d := range []string{
		"/", "/root", "/tmp", "/etc", "/bin", "/usr",
		"/usr/bin", "/var", "/home", "/lib", "/proc", "/dev",
	} {
		s.dirs[d] = true
	}
	return s
}

// resolvePath makes p absolute relative to cwd.
func (s *Session) resolvePath(p string) string {
	if p == "" || p == "." {
		return s.cwd
	}
	if p == "~" || p == "~/" {
		return "/root"
	}
	if !strings.HasPrefix(p, "/") {
		p = s.cwd + "/" + p
	}
	return path.Clean(p)
}

// sessionLS lists the direct children of dir from the session FS.
func (s *Session) sessionLS(dir string) []string {
	dir = path.Clean(strings.TrimSuffix(dir, "/"))
	prefix := dir + "/"
	seen := map[string]bool{}
	var out []string
	for p := range s.fs {
		if strings.HasPrefix(p, prefix) {
			name := strings.SplitN(strings.TrimPrefix(p, prefix), "/", 2)[0]
			if name != "" && !seen[name] {
				seen[name] = true
				out = append(out, name)
			}
		}
	}
	for p := range s.dirs {
		if p == dir {
			continue
		}
		if strings.HasPrefix(p, prefix) {
			name := strings.SplitN(strings.TrimPrefix(p, prefix), "/", 2)[0]
			if name != "" && !seen[name] {
				seen[name] = true
				out = append(out, name+"/")
			}
		}
	}
	return out
}

// fakeEnv is the environment variables we pretend to have.
// ? is $? (last exit code), always 0 for now.
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

// dispatch creates a fresh session and runs cmd. Used in tests and places without a live session.
func dispatch(cmd string) (string, uint32) {
	return newSession().dispatch(cmd)
}

// dispatchSegment runs a single pipe pipeline (no && handling).
func (s *Session) dispatchSegment(cmd string) (string, uint32) {
	stages := strings.Split(cmd, "|")
	out := ""
	exit := uint32(0)
	for _, stage := range stages {
		stage = strings.TrimSpace(stage)
		if stage == "" {
			continue
		}
		fields := strings.Fields(stage)
		if len(fields) == 0 {
			continue
		}
		name := fields[0]
		args := fields[1:]
		impl, ok := registry[name]
		if !ok {
			out = "bash: " + name + ": command not found\n"
			exit = 127
			break
		}
		out, exit = impl.Run(args, out, s)
	}
	return out, exit
}

// dispatch runs cmd, handling && chaining and | pipelines.
func (s *Session) dispatch(cmd string) (string, uint32) {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return "", 0
	}
	cmd = expandVars(cmd)
	cmd = strings.ReplaceAll(cmd, "> /dev/null", "")
	out := ""
	exit := uint32(0)
	for _, seg := range strings.Split(cmd, "&&") {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			continue
		}
		out, exit = s.dispatchSegment(seg)
		if exit != 0 {
			return out, exit
		}
	}
	return out, exit
}
