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
	// real pipe: grep filters cat output
	out, exit := dispatch("cat /etc/passwd | grep root")
	if exit != 0 {
		t.Errorf("pipe: want exit 0, got %d", exit)
	}
	if !strings.Contains(out, "root") {
		t.Errorf("pipe: want 'root' in output, got %q", out)
	}
	// grep should have filtered out non-root lines
	if strings.Contains(out, "daemon") {
		t.Errorf("pipe: grep should have filtered 'daemon' line, got %q", out)
	}
}

func TestDispatchPipeNvidiaSmi(t *testing.T) {
	// recon script: nvidia-smi -q | grep "Product Name" | awk | wc -l | head -c 1
	// should produce "1" (one Tesla T4 GPU)
	out, _ := dispatch(`nvidia-smi -q | grep "Product Name" | awk | wc -l | head -c 1`)
	if out != "1" {
		t.Errorf("nvidia-smi recon pipeline: want '1', got %q", out)
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

func TestSessionMkdirLS(t *testing.T) {
	sess := newSession()
	sess.dispatch("mkdir /tmp/xlxeavrjsw")
	out, exit := sess.dispatch("ls /tmp")
	if exit != 0 {
		t.Errorf("ls /tmp after mkdir: want exit 0, got %d", exit)
	}
	if !strings.Contains(out, "xlxeavrjsw") {
		t.Errorf("ls /tmp: want new dir in output, got %q", out)
	}
}

func TestSessionCd(t *testing.T) {
	sess := newSession()
	sess.dispatch("mkdir /tmp/work")
	out, exit := sess.dispatch("cd /tmp/work")
	if exit != 0 {
		t.Errorf("cd existing dir: want exit 0, got %d (out: %q)", exit, out)
	}
	pwd, _ := sess.dispatch("pwd")
	if strings.TrimSpace(pwd) != "/tmp/work" {
		t.Errorf("pwd after cd: want '/tmp/work', got %q", pwd)
	}
}

func TestSessionCdMissing(t *testing.T) {
	sess := newSession()
	_, exit := sess.dispatch("cd /nonexistent")
	if exit == 0 {
		t.Error("cd missing dir: want non-zero exit")
	}
}

func TestSessionCatUploadedFile(t *testing.T) {
	sess := newSession()
	// simulate scp writing a file into session FS
	sess.fs["/tmp/miner"] = []byte("#!/bin/sh\necho pwned\n")
	out, exit := sess.dispatch("cat /tmp/miner")
	if exit != 0 {
		t.Errorf("cat uploaded file: want exit 0, got %d", exit)
	}
	if !strings.Contains(out, "pwned") {
		t.Errorf("cat uploaded file: want file content, got %q", out)
	}
}

func TestSessionCatBinEcho(t *testing.T) {
	// /bin/echo now exists in fakeFiles as ELF bytes -- closes T2
	out, exit := dispatch("cat /bin/echo")
	if exit != 0 {
		t.Errorf("cat /bin/echo: want exit 0, got %d", exit)
	}
	_ = out // content is binary, just check it doesn't 404
}

func TestDispatchAnd(t *testing.T) {
	// both sides succeed -- output is from last segment
	out, exit := dispatch("whoami && whoami")
	if exit != 0 {
		t.Errorf("whoami && whoami: want exit 0, got %d", exit)
	}
	if strings.TrimSpace(out) != "root" {
		t.Errorf("whoami && whoami: want 'root', got %q", out)
	}
}

func TestDispatchAndShortCircuit(t *testing.T) {
	// first side fails -- second side must not run
	out, exit := dispatch("notacommand && whoami")
	if exit == 0 {
		t.Error("notacommand && whoami: want non-zero exit")
	}
	// output should be the error from notacommand, not root
	if strings.TrimSpace(out) == "root" {
		t.Error("notacommand && whoami: second side ran after failure")
	}
}

func TestDispatchDiicot(t *testing.T) {
	// exact command Diicot runs -- must return 3D controller line
	out, exit := dispatch("lspci | egrep VGA && lspci | grep 3D")
	if exit != 0 {
		t.Errorf("diicot lspci pipeline: want exit 0, got %d", exit)
	}
	if !strings.Contains(out, "3D") {
		t.Errorf("diicot lspci pipeline: want '3D' in output, got %q", out)
	}
}

func TestDispatchRedirectDevNull(t *testing.T) {
	// > /dev/null stripped -- command still runs, output discarded by shell semantics
	// but since we strip it, echo output comes through (same as bash with no redirect)
	_, exit := dispatch("echo 1 > /dev/null && cat /bin/echo")
	if exit != 0 {
		t.Errorf("echo && cat after redirect strip: want exit 0, got %d", exit)
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
