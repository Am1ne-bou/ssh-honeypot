package session

import (
	"fmt"
	"time"
)

func init() {
	register("whoami", staticCmd{out: "root\n"})
	register("id", staticCmd{out: "uid=0(root) gid=0(root) groups=0(root)\n"})
	register("hostname", hostnameCmd{})
	register("pwd", staticCmd{out: "/root\n"})
	register("uname", unameCmd{})
	register("date", dateCmd{})
	register("uptime", uptimeCmd{})
	register("w", wCmd{})
	register("who", whoCmd{})
	register("last", lastCmd{})
	register("echo", echoCmd{})
}

// staticCmd returns a fixed string with exit 0.
type staticCmd struct{ out string }

func (s staticCmd) Run(_ []string) (string, uint32) { return s.out, 0 }

// hostnameCmd handles `hostname` and `hostname -i`.
type hostnameCmd struct{}

func (hostnameCmd) Run(args []string) (string, uint32) {
	if len(args) > 0 && args[0] == "-i" {
		return "10.0.0.42\n", 0
	}
	return "ubuntu\n", 0
}

// unameCmd handles common uname flag combinations.
type unameCmd struct{}

func (unameCmd) Run(args []string) (string, uint32) {
	if len(args) == 0 {
		return "Linux\n", 0
	}
	switch args[0] {
	case "-a":
		return "Linux ubuntu 6.8.0-49-generic #49-Ubuntu SMP PREEMPT_DYNAMIC Mon Feb 24 14:24:20 UTC 2025 x86_64 x86_64 x86_64 GNU/Linux\n", 0
	case "-r":
		return "6.8.0-49-generic\n", 0
	case "-m":
		return "x86_64\n", 0
	case "-s":
		return "Linux\n", 0
	case "-n":
		return "ubuntu\n", 0
	}
	return "Linux\n", 0
}

// echoCmd joins args with spaces, like /bin/echo with no flags.
type echoCmd struct{}

func (echoCmd) Run(args []string) (string, uint32) {
	out := ""
	for i, a := range args {
		if i > 0 {
			out += " "
		}
		out += a
	}
	return out + "\n", 0
}

// bootTime is the fake server's boot, fixed for the process lifetime.
var bootTime = time.Now().Add(-47*24*time.Hour - 3*time.Hour - 14*time.Minute)

// dateCmd returns the current UTC date in `date`'s default format.
type dateCmd struct{}

func (dateCmd) Run(_ []string) (string, uint32) {
	return time.Now().UTC().Format("Mon Jan _2 15:04:05 MST 2006") + "\n", 0
}

// uptimeFields returns the current time and uptime string used by uptime/w.
func uptimeFields() (string, string) {
	now := time.Now().UTC()
	d := now.Sub(bootTime)
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	mins := int(d.Minutes()) % 60
	return now.Format("15:04:05"),
		fmt.Sprintf("up %d days, %2d:%02d", days, hours, mins)
}

// uptimeCmd returns the standard uptime line.
type uptimeCmd struct{}

func (uptimeCmd) Run(_ []string) (string, uint32) {
	t, up := uptimeFields()
	return fmt.Sprintf(" %s %s,  1 user,  load average: 0.08, 0.03, 0.01\n", t, up), 0
}

// wCmd returns the `w` header followed by one fake session line.
type wCmd struct{}

func (wCmd) Run(_ []string) (string, uint32) {
	t, up := uptimeFields()
	return fmt.Sprintf(
		" %s %s,  1 user,  load average: 0.08, 0.03, 0.01\n"+
			"USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n"+
			"root     pts/0    10.0.0.1         %s    0.00s  0.04s  0.00s w\n",
		t, up, time.Now().UTC().Format("15:04")), 0
}

// whoCmd returns one fake login line.
type whoCmd struct{}

func (whoCmd) Run(_ []string) (string, uint32) {
	now := time.Now().UTC()
	return fmt.Sprintf("root     pts/0        %s (10.0.0.1)\n",
		now.Format("2006-01-02 15:04")), 0
}

// lastCmd returns a short login history rooted at bootTime.
type lastCmd struct{}

func (lastCmd) Run(_ []string) (string, uint32) {
	now := time.Now().UTC()
	return fmt.Sprintf(
		"root     pts/0        10.0.0.1         %s   still logged in\n"+
			"reboot   system boot  6.8.0-49-generic %s   still running\n\n"+
			"wtmp begins %s\n",
		now.Format("Mon Jan _2 15:04"),
		bootTime.Format("Mon Jan _2 15:04"),
		bootTime.Format("Mon Jan _2 15:04:05 2006")), 0
}
