package session

import (
	"strings"
	"testing"
)

func TestDispatchEmpty(t *testing.T) {
	out, exit := dispatch("")
	if out != "" || exit != 0 {
		t.Errorf("empty cmd: got (%q, %d)", out, exit)
	}
}

func TestDispatchUnknown(t *testing.T) {
	out, exit := dispatch("notacommand")
	if exit != 127 {
		t.Errorf("unknown cmd: want exit 127, got %d", exit)
	}
	if !strings.Contains(out, "notacommand") {
		t.Errorf("unknown cmd: want command name in output, got %q", out)
	}
}

func TestDispatchWhoami(t *testing.T) {
	out, exit := dispatch("whoami")
	if exit != 0 {
		t.Errorf("whoami: want exit 0, got %d", exit)
	}
	if strings.TrimSpace(out) != "root" {
		t.Errorf("whoami: want 'root', got %q", out)
	}
}

func TestDispatchCatPasswd(t *testing.T) {
	out, exit := dispatch("cat /etc/passwd")
	if exit != 0 {
		t.Errorf("cat /etc/passwd: want exit 0, got %d", exit)
	}
	if !strings.Contains(out, "root:x:0:0") {
		t.Errorf("cat /etc/passwd: missing root entry, got %q", out)
	}
}

func TestDispatchCatShadowDenied(t *testing.T) {
	out, exit := dispatch("cat /etc/shadow")
	if exit != 1 {
		t.Errorf("cat /etc/shadow: want exit 1, got %d", exit)
	}
	if !strings.Contains(out, "Permission denied") {
		t.Errorf("cat /etc/shadow: want permission denied, got %q", out)
	}
}

func TestDispatchPipe(t *testing.T) {
	// pipe should run only the first segment
	out, exit := dispatch("cat /etc/passwd | grep root")
	if exit != 0 {
		t.Errorf("pipe: want exit 0, got %d", exit)
	}
	// should get full passwd, not grep'd output
	if !strings.Contains(out, "daemon") {
		t.Errorf("pipe: expected full cat output, got %q", out)
	}
}

func TestDispatchVarExpansion(t *testing.T) {
	out, exit := dispatch("echo $HOME")
	if exit != 0 {
		t.Errorf("echo $HOME: want exit 0, got %d", exit)
	}
	if strings.TrimSpace(out) != "/root" {
		t.Errorf("echo $HOME: want '/root', got %q", out)
	}
}

func TestDispatchSudo(t *testing.T) {
	// sudo whoami should behave like whoami
	out, exit := dispatch("sudo whoami")
	if exit != 0 {
		t.Errorf("sudo whoami: want exit 0, got %d", exit)
	}
	if strings.TrimSpace(out) != "root" {
		t.Errorf("sudo whoami: want 'root', got %q", out)
	}
}

func TestDispatchBashC(t *testing.T) {
	out, exit := dispatch("bash -c whoami")
	if exit != 0 {
		t.Errorf("bash -c whoami: want exit 0, got %d", exit)
	}
	if strings.TrimSpace(out) != "root" {
		t.Errorf("bash -c whoami: want 'root', got %q", out)
	}
}

func TestDispatchEnv(t *testing.T) {
	out, exit := dispatch("env")
	if exit != 0 {
		t.Errorf("env: want exit 0, got %d", exit)
	}
	if !strings.Contains(out, "HOME=/root") {
		t.Errorf("env: missing HOME=/root, got %q", out)
	}
	if !strings.Contains(out, "USER=root") {
		t.Errorf("env: missing USER=root, got %q", out)
	}
}

func TestExpandVars(t *testing.T) {
	cases := []struct{ in, want string }{
		{"$HOME", "/root"},
		{"${USER}", "root"},
		{"$UNSET", ""},
		{"$HOME/.ssh", "/root/.ssh"},
	}
	for _, c := range cases {
		got := expandVars(c.in)
		if got != c.want {
			t.Errorf("expandVars(%q): want %q, got %q", c.in, c.want, got)
		}
	}
}
