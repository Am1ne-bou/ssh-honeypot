package session

import (
	"path"
	"strings"
)

func init() {
	register("sudo", sudoCmd{})
	register("su", suCmd{})
	register("apt", aptCmd{})
	register("apt-get", aptCmd{})
	register("which", whichCmd{})
	register("whereis", whereisCmd{})
	register("find", findCmd{})
	register("chmod", noopCmd{})
	register("chown", noopCmd{})
	register("passwd", passwdCmd{})
	register("clear", staticCmd{out: "\x1b[H\x1b[2J"})
	register("cd", cdCmd{})
	register("export", noopCmd{})
	register("unset", noopCmd{})
	register("set", staticCmd{out: ""})
	register("ssh", sshCmd{})
	register("scp", scpCmd{})
	register("touch", touchCmd{})
	register("mkdir", mkdirCmd{})
	register("rm", rmCmd{})
	register("rmdir", noopCmd{})
	register("kill", noopCmd{})
	register("pkill", noopCmd{})
	register("killall", noopCmd{})
	register("chattr", noopCmd{})
	register("disown", noopCmd{})
	register("chpasswd", noopCmd{})
	register("service", serviceCmd{})
	register("systemctl", systemctlCmd{})
}

type noopCmd struct{}

func (noopCmd) Run(_ []string, _ string, _ *Session) (string, uint32) { return "", 0 }

type cdCmd struct{}

func (cdCmd) Run(args []string, _ string, sess *Session) (string, uint32) {
	target := "/root"
	if len(args) > 0 && args[0] != "" && args[0] != "~" {
		target = sess.resolvePath(args[0])
	}
	if !sess.dirs[target] {
		return "bash: cd: " + args[0] + ": No such file or directory\n", 1
	}
	sess.cwd = target
	return "", 0
}

type mkdirCmd struct{}

func (mkdirCmd) Run(args []string, _ string, sess *Session) (string, uint32) {
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		dir := sess.resolvePath(a)
		sess.dirs[dir] = true
		// also mark parent if it's new
		parent := path.Dir(dir)
		if !sess.dirs[parent] {
			sess.dirs[parent] = true
		}
	}
	return "", 0
}

type touchCmd struct{}

func (touchCmd) Run(args []string, _ string, sess *Session) (string, uint32) {
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		p := sess.resolvePath(a)
		if _, ok := sess.fs[p]; !ok {
			sess.fs[p] = []byte{}
		}
	}
	return "", 0
}

type rmCmd struct{}

func (rmCmd) Run(args []string, _ string, sess *Session) (string, uint32) {
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		p := sess.resolvePath(a)
		delete(sess.fs, p)
		delete(sess.dirs, p)
	}
	return "", 0
}

type sudoCmd struct{}

func (sudoCmd) Run(args []string, _ string, sess *Session) (string, uint32) {
	if len(args) == 0 {
		return "usage: sudo -h | -K | -k | -V\nusage: sudo -v [-AknS] [-g group] [-h host] [-p prompt] [-u user]\n", 1
	}
	if args[0] == "-l" || args[0] == "-ll" {
		return "Matching Defaults entries for root on ubuntu:\n" +
			"    env_reset, mail_badpass,\n" +
			"    secure_path=/usr/local/sbin\\:/usr/local/bin\\:/usr/sbin\\:/usr/bin\\:/sbin\\:/bin\n\n" +
			"User root may run the following commands on ubuntu:\n" +
			"    (ALL : ALL) ALL\n", 0
	}
	if args[0] == "-v" || args[0] == "-V" {
		return "Sudo version 1.9.15p5\nSudoers policy plugin version 1.9.15p5\nSudoers file grammar version 50\n", 0
	}
	rest := args
	for len(rest) > 0 && strings.HasPrefix(rest[0], "-") {
		rest = rest[1:]
	}
	if len(rest) == 0 {
		return "", 0
	}
	return sess.dispatch(strings.Join(rest, " "))
}

type suCmd struct{}

func (suCmd) Run(_ []string, _ string, _ *Session) (string, uint32) { return "", 0 }

type aptCmd struct{}

func (aptCmd) Run(args []string, _ string, _ *Session) (string, uint32) {
	if len(args) == 0 {
		return "apt 2.7.14ubuntu0.1 (amd64)\nUsage: apt [options] command\n", 0
	}
	switch args[0] {
	case "update":
		return "Hit:1 http://archive.ubuntu.com/ubuntu noble InRelease\n" +
			"Hit:2 http://archive.ubuntu.com/ubuntu noble-updates InRelease\n" +
			"Hit:3 http://archive.ubuntu.com/ubuntu noble-security InRelease\n" +
			"Reading package lists... Done\n", 0
	case "upgrade", "dist-upgrade":
		return "Reading package lists... Done\nBuilding dependency tree... Done\n" +
			"Reading state information... Done\n0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n", 0
	case "install":
		if len(args) < 2 {
			return "E: Invalid operation install\n", 100
		}
		return "Reading package lists... Done\nBuilding dependency tree... Done\n" +
			"E: Unable to locate package " + args[1] + "\n", 100
	case "list":
		return "Listing... Done\n", 0
	}
	return "E: Invalid operation " + args[0] + "\n", 100
}

type whichCmd struct{}

var fakeBinaries = map[string]string{
	"sh": "/usr/bin/sh", "bash": "/usr/bin/bash", "ls": "/usr/bin/ls",
	"cat": "/usr/bin/cat", "ps": "/usr/bin/ps", "wget": "/usr/bin/wget",
	"curl": "/usr/bin/curl", "python3": "/usr/bin/python3", "perl": "/usr/bin/perl",
	"gcc": "/usr/bin/gcc", "ssh": "/usr/bin/ssh", "scp": "/usr/bin/scp",
	"sudo": "/usr/bin/sudo", "su": "/usr/bin/su", "apt": "/usr/bin/apt",
	"chmod": "/usr/bin/chmod", "chown": "/usr/bin/chown",
	"nvidia-smi": "/usr/bin/nvidia-smi",
	"chpasswd":   "/usr/sbin/chpasswd",
	"killall":    "/usr/bin/killall",
	"chattr":     "/usr/bin/chattr",
	"awk":        "/usr/bin/awk",
	"grep":       "/usr/bin/grep",
	"wc":         "/usr/bin/wc",
	"head":       "/usr/bin/head",
	"tail":       "/usr/bin/tail",
}

func (whichCmd) Run(args []string, _ string, _ *Session) (string, uint32) {
	if len(args) == 0 {
		return "", 1
	}
	out := ""
	exit := uint32(0)
	for _, a := range args {
		if p, ok := fakeBinaries[a]; ok {
			out += p + "\n"
		} else {
			exit = 1
		}
	}
	return out, exit
}

type whereisCmd struct{}

func (whereisCmd) Run(args []string, _ string, _ *Session) (string, uint32) {
	if len(args) == 0 {
		return "", 0
	}
	out := ""
	for _, a := range args {
		if p, ok := fakeBinaries[a]; ok {
			out += a + ": " + p + "\n"
		} else {
			out += a + ":\n"
		}
	}
	return out, 0
}

type findCmd struct{}

func (findCmd) Run(_ []string, _ string, _ *Session) (string, uint32) { return "", 0 }

type passwdCmd struct{}

func (passwdCmd) Run(_ []string, _ string, _ *Session) (string, uint32) {
	return "Changing password for root.\nCurrent password: \n", 1
}

type sshCmd struct{}

func (sshCmd) Run(args []string, _ string, _ *Session) (string, uint32) {
	target := ""
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			target = a
			break
		}
	}
	if target == "" {
		return "usage: ssh [-options] destination\n", 255
	}
	return "ssh: connect to host " + target + " port 22: Network is unreachable\n", 255
}

type scpCmd struct{}

func (scpCmd) Run(args []string, _ string, _ *Session) (string, uint32) {
	for _, a := range args {
		if a == "-t" {
			return "", 0
		}
	}
	return "ssh: Network is unreachable\nlost connection\n", 1
}

type serviceCmd struct{}

func (serviceCmd) Run(args []string, _ string, _ *Session) (string, uint32) {
	if len(args) < 2 {
		return "Usage: service < option > | --status-all | [ service_name [ command | --full-restart ] ]\n", 1
	}
	return "", 0
}

type systemctlCmd struct{}

func (systemctlCmd) Run(args []string, _ string, _ *Session) (string, uint32) {
	if len(args) == 0 {
		return "", 0
	}
	switch args[0] {
	case "status":
		return "● ubuntu\n    State: running\n    Jobs: 0 queued\n    Failed: 0 units\n", 0
	case "list-units", "list-unit-files":
		return "UNIT FILE                              STATE   VENDOR PRESET\nssh.service                            enabled enabled\n", 0
	}
	return "", 0
}
