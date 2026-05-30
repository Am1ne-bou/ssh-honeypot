package session

import (
	"fmt"
	"strings"
	"time"
)

func init() {
	register("whoami", staticCmd{out: "root\n"})
	register("id", staticCmd{out: "uid=0(root) gid=0(root) groups=0(root)\n"})
	register("hostname", hostnameCmd{})
	register("pwd", pwdCmd{})
	register("uname", unameCmd{})
	register("date", dateCmd{})
	register("uptime", uptimeCmd{})
	register("w", wCmd{})
	register("who", whoCmd{})
	register("last", lastCmd{})
	register("echo", echoCmd{})
	register("nproc", staticCmd{out: "8\n"})
	register("lspci", staticCmd{out: "" +
		"00:00.0 Host bridge: Intel Corporation 440FX - 82441FX PMC [Natoma] (rev 02)\n" +
		"00:01.0 ISA bridge: Intel Corporation 82371SB PIIX3 ISA [Natoma/Triton II]\n" +
		"00:01.1 IDE interface: Intel Corporation 82371SB PIIX3 IDE [Natoma/Triton II]\n" +
		"00:01.3 Bridge: Intel Corporation 82371AB/EB/MB PIIX4 ACPI (rev 03)\n" +
		"00:02.0 VGA compatible controller: Cirrus Logic GD 5446\n" +
		"00:04.0 3D controller: NVIDIA Corporation TU104GL [Tesla T4] (rev a1)\n" +
		"00:05.0 Ethernet controller: Red Hat, Inc. Virtio network device\n",
	})
	register("nvidia-smi", nvidiaSmiCmd{})
}

type staticCmd struct{ out string }

func (s staticCmd) Run(_ []string, _ string, _ *Session) (string, uint32) { return s.out, 0 }

// nvidiaSmiCmd returns output consistent with the Tesla T4 advertised by lspci.
// Closes T1: bots grep "Product Name" from -q output to decide whether to mine.
type nvidiaSmiCmd struct{}

func (nvidiaSmiCmd) Run(args []string, _ string, _ *Session) (string, uint32) {
	if len(args) > 0 && args[0] == "-L" {
		return "GPU 0: Tesla T4 (UUID: GPU-4c3f2da3-bd96-b3b7-6b17-2ad5de1fe891)\n", 0
	}
	if len(args) > 0 && args[0] == "-q" {
		return "==============NVSMI LOG==============\n\n" +
			"Timestamp                                 : " + time.Now().UTC().Format("Mon Jan  2 15:04:05 2006") + "\n" +
			"Driver Version                            : 525.85.12\n" +
			"CUDA Version                              : 12.0\n\n" +
			"Attached GPUs                             : 1\n" +
			"GPU 00000000:00:04.0\n" +
			"    Product Name                          : Tesla T4\n" +
			"    Product Brand                         : NVIDIA\n" +
			"    Display Mode                          : Enabled\n" +
			"    Persistence Mode                      : Disabled\n" +
			"    MIG Mode\n" +
			"        Current                           : Disabled\n" +
			"    Temperature\n" +
			"        GPU Current Temp                  : 42 C\n" +
			"        GPU Shutdown Temp                 : 90 C\n" +
			"    Power Readings\n" +
			"        Power Draw                        : 26.51 W\n" +
			"        Power Limit                       : 70.00 W\n" +
			"    Clocks\n" +
			"        Graphics                          : 585 MHz\n" +
			"        Memory                            : 5001 MHz\n", 0
	}
	// bare nvidia-smi -- summary table
	return "" +
		"+-----------------------------------------------------------------------------+\n" +
		"| NVIDIA-SMI 525.85.12    Driver Version: 525.85.12    CUDA Version: 12.0   |\n" +
		"|-------------------------------+----------------------+----------------------+\n" +
		"| GPU  Name        Persistence-M| Bus-Id        Disp.A | Volatile Uncorr. ECC |\n" +
		"| Fan  Temp  Perf  Pwr:Usage/Cap|         Memory-Usage | GPU-Util  Compute M. |\n" +
		"|===============================+======================+======================|\n" +
		"|   0  Tesla T4           Off  | 00000000:00:04.0 Off |                    0 |\n" +
		"| N/A   42C    P0    26W /  70W |      0MiB / 15109MiB |      0%      Default |\n" +
		"+-----------------------------------------------------------------------------+\n\n" +
		"+-----------------------------------------------------------------------------+\n" +
		"| Processes:                                                                  |\n" +
		"|  GPU   GI   CI        PID   Type   Process name                  GPU Memory |\n" +
		"|        ID   ID                                                    Usage      |\n" +
		"|=============================================================================|\n" +
		"|  No running processes found                                                 |\n" +
		"+-----------------------------------------------------------------------------+\n", 0
}

type hostnameCmd struct{}

func (hostnameCmd) Run(args []string, _ string, _ *Session) (string, uint32) {
	if len(args) > 0 && args[0] == "-i" {
		return "10.0.0.42\n", 0
	}
	return "ubuntu\n", 0
}

type unameCmd struct{}

func (unameCmd) Run(args []string, _ string, _ *Session) (string, uint32) {
	if len(args) == 0 {
		return "Linux\n", 0
	}
	flags := strings.Join(args, "")
	switch flags {
	case "-a":
		return "Linux ubuntu 6.8.0-49-generic #49-Ubuntu SMP PREEMPT_DYNAMIC Mon Feb 24 14:24:20 UTC 2025 x86_64 x86_64 x86_64 GNU/Linux\n", 0
	case "-s-v-n-r-m":
		return "Linux #49-Ubuntu SMP PREEMPT_DYNAMIC Mon Feb 24 14:24:20 UTC 2025 ubuntu 6.8.0-49-generic x86_64\n", 0
	case "-srm":
		// uname -srm: kernel-name release machine -- used by SSHCHK family
		return "Linux 6.8.0-49-generic x86_64\n", 0
	case "-s-m", "-sm":
		// uname -s -m: kernel-name machine -- used by minimal OS scanner (family 9)
		return "Linux x86_64\n", 0
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

type echoCmd struct{}

func (echoCmd) Run(args []string, _ string, _ *Session) (string, uint32) {
	out := ""
	for i, a := range args {
		if i > 0 {
			out += " "
		}
		out += a
	}
	return out + "\n", 0
}

// boot 47-ish days ago, fixed at process start so uptime stays consistent
var bootTime = time.Now().Add(-47*24*time.Hour - 3*time.Hour - 14*time.Minute)

type dateCmd struct{}

func (dateCmd) Run(_ []string, _ string, _ *Session) (string, uint32) {
	return time.Now().UTC().Format("Mon Jan _2 15:04:05 MST 2006") + "\n", 0
}

func uptimeFields() (string, string) {
	now := time.Now().UTC()
	d := now.Sub(bootTime)
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	mins := int(d.Minutes()) % 60
	return now.Format("15:04:05"),
		fmt.Sprintf("up %d days, %2d:%02d", days, hours, mins)
}

type uptimeCmd struct{}

func (uptimeCmd) Run(_ []string, _ string, _ *Session) (string, uint32) {
	t, up := uptimeFields()
	return fmt.Sprintf(" %s %s,  1 user,  load average: 0.08, 0.03, 0.01\n", t, up), 0
}

type wCmd struct{}

func (wCmd) Run(_ []string, _ string, _ *Session) (string, uint32) {
	t, up := uptimeFields()
	return fmt.Sprintf(
		" %s %s,  1 user,  load average: 0.08, 0.03, 0.01\n"+
			"USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n"+
			"root     pts/0    10.0.0.1         %s    0.00s  0.04s  0.00s w\n",
		t, up, time.Now().UTC().Format("15:04")), 0
}

type whoCmd struct{}

func (whoCmd) Run(_ []string, _ string, _ *Session) (string, uint32) {
	now := time.Now().UTC()
	return fmt.Sprintf("root     pts/0        %s (10.0.0.1)\n",
		now.Format("2006-01-02 15:04")), 0
}

type lastCmd struct{}

func (lastCmd) Run(_ []string, _ string, _ *Session) (string, uint32) {
	now := time.Now().UTC()
	return fmt.Sprintf(
		"root     pts/0        10.0.0.1         %s   still logged in\n"+
			"reboot   system boot  6.8.0-49-generic %s   still running\n\n"+
			"wtmp begins %s\n",
		now.Format("Mon Jan _2 15:04"),
		bootTime.Format("Mon Jan _2 15:04"),
		bootTime.Format("Mon Jan _2 15:04:05 2006")), 0
}
