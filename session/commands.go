package session

import (
	"fmt"
	"log/slog"
	"os"
	"path"
	"regexp"
	"strconv"
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
	cron string            // per-session crontab content
	log  *slog.Logger      // for commands that need to log (wget, curl URL capture)
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

var arithRe = regexp.MustCompile(`\$\(\(([^)]+)\)\)`)

// expandArith replaces $((expr)) with the evaluated integer result.
// handles +, -, *, / with correct precedence via recursive descent.
func expandArith(s string) string {
	return arithRe.ReplaceAllStringFunc(s, func(m string) string {
		inner := arithRe.FindStringSubmatch(m)[1]
		v, err := evalArith(strings.TrimSpace(inner))
		if err != nil {
			return m // leave untouched on parse error
		}
		return fmt.Sprintf("%d", v)
	})
}

// evalArith is a minimal recursive descent parser for integer arithmetic.
func evalArith(expr string) (int64, error) {
	p := &arithParser{s: strings.TrimSpace(expr)}
	v, err := p.parseAdd()
	if err != nil || p.pos < len(p.s) {
		return 0, fmt.Errorf("parse error")
	}
	return v, nil
}

type arithParser struct {
	s   string
	pos int
}

func (p *arithParser) peek() byte {
	for p.pos < len(p.s) && p.s[p.pos] == ' ' {
		p.pos++
	}
	if p.pos >= len(p.s) {
		return 0
	}
	return p.s[p.pos]
}

func (p *arithParser) parseAdd() (int64, error) {
	left, err := p.parseMul()
	if err != nil {
		return 0, err
	}
	for {
		c := p.peek()
		if c != '+' && c != '-' {
			return left, nil
		}
		p.pos++
		right, err := p.parseMul()
		if err != nil {
			return 0, err
		}
		if c == '+' {
			left += right
		} else {
			left -= right
		}
	}
}

func (p *arithParser) parseMul() (int64, error) {
	left, err := p.parseNum()
	if err != nil {
		return 0, err
	}
	for {
		c := p.peek()
		if c != '*' && c != '/' {
			return left, nil
		}
		p.pos++
		right, err := p.parseNum()
		if err != nil {
			return 0, err
		}
		if c == '*' {
			left *= right
		} else {
			if right == 0 {
				return 0, fmt.Errorf("div by zero")
			}
			left /= right
		}
	}
}

func (p *arithParser) parseNum() (int64, error) {
	for p.pos < len(p.s) && p.s[p.pos] == ' ' {
		p.pos++
	}
	if p.pos >= len(p.s) {
		return 0, fmt.Errorf("unexpected end")
	}
	start := p.pos
	if p.s[p.pos] == '-' {
		p.pos++
	}
	for p.pos < len(p.s) && p.s[p.pos] >= '0' && p.s[p.pos] <= '9' {
		p.pos++
	}
	if p.pos == start {
		return 0, fmt.Errorf("expected number")
	}
	return strconv.ParseInt(p.s[start:p.pos], 10, 64)
}

func expandVars(s string) string {
	s = expandArith(s)
	return os.Expand(s, func(k string) string {
		// $1, $2 etc are awk/positional field references -- preserve them
		if _, err := strconv.Atoi(k); err == nil {
			return "$" + k
		}
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
