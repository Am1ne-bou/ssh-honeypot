package session

func init() {
	register("ls", lsCmd{})
	register("cat", catCmd{})
	register("df", dfCmd{})
	register("free", freeCmd{})
	register("mount", mountCmd{})
	register("ps", psCmd{})
	register("crontab", crontabCmd{})
	register("history", staticCmd{out: ""})
}

// lsCmd handles `ls`, `ls -l`, `ls -la`/`-al`, and `ls /`.
type lsCmd struct{}

func (lsCmd) Run(args []string) (string, uint32) {
	flags, paths := splitArgs(args)
	path := "."
	if len(paths) > 0 {
		path = paths[0]
	}

	if path == "/" {
		return "bin   dev  home  lib32  libx32  media  opt   root  sbin  srv  tmp  usr\n" +
			"boot  etc  lib   lib64  lost+found  mnt  proc  run   sbin  sys  var\n", 0
	}

	hasL := containsFlag(flags, 'l')
	hasA := containsFlag(flags, 'a')

	switch {
	case hasL && hasA:
		return "total 28\n" +
			"drwx------ 4 root root 4096 Apr 25 14:22 .\n" +
			"drwxr-xr-x 1 root root 4096 Apr 24 09:11 ..\n" +
			"-rw------- 1 root root  142 Apr 25 14:22 .bash_history\n" +
			"-rw-r--r-- 1 root root 3106 Oct 15  2021 .bashrc\n" +
			"drwx------ 2 root root 4096 Apr 24 09:11 .cache\n" +
			"-rw-r--r-- 1 root root  161 Jul  9  2019 .profile\n" +
			"drwx------ 2 root root 4096 Apr 25 14:22 .ssh\n", 0
	case hasL:
		return "total 0\n", 0
	case hasA:
		return ".  ..  .bash_history  .bashrc  .cache  .profile  .ssh\n", 0
	}
	return "\n", 0
}

// splitArgs separates flag tokens (-x, --foo) from positional args.
func splitArgs(args []string) (flags, rest []string) {
	for _, a := range args {
		if len(a) > 0 && a[0] == '-' {
			flags = append(flags, a)
		} else {
			rest = append(rest, a)
		}
	}
	return
}

// containsFlag returns true if any flag token contains the short letter c.
func containsFlag(flags []string, c byte) bool {
	for _, f := range flags {
		for i := 1; i < len(f); i++ {
			if f[i] == c {
				return true
			}
		}
	}
	return false
}

// catCmd serves a small set of fake files; everything else is "No such file".
type catCmd struct{}

var fakeFiles = map[string]string{
	"/etc/passwd": "root:x:0:0:root:/root:/bin/bash\n" +
		"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n" +
		"bin:x:2:2:bin:/bin:/usr/sbin/nologin\n" +
		"sys:x:3:3:sys:/dev:/usr/sbin/nologin\n" +
		"sync:x:4:65534:sync:/bin:/bin/sync\n" +
		"www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n" +
		"sshd:x:108:65534::/run/sshd:/usr/sbin/nologin\n" +
		"ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n",
	"/etc/os-release": "PRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\nNAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\n" +
		"VERSION=\"24.04.1 LTS (Noble Numbat)\"\nVERSION_CODENAME=noble\nID=ubuntu\nID_LIKE=debian\n" +
		"UBUNTU_CODENAME=noble\n",
	"/proc/cpuinfo": "processor\t: 0\nvendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel\t\t: 85\n" +
		"model name\t: Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz\ncpu MHz\t\t: 2399.998\n" +
		"cache size\t: 35840 KB\ncpu cores\t: 2\n",
	"/proc/meminfo": "MemTotal:        2039844 kB\nMemFree:         1523992 kB\nMemAvailable:    1789120 kB\n" +
		"Buffers:           42168 kB\nCached:           312044 kB\nSwapTotal:       2097148 kB\nSwapFree:        2097148 kB\n",
	"/etc/resolv.conf": "nameserver 8.8.8.8\nnameserver 1.1.1.1\n",
	"/etc/hostname":    "ubuntu\n",
	"/etc/issue":       "Ubuntu 24.04.1 LTS \\n \\l\n\n",
	"/proc/version": "Linux version 6.8.0-49-generic (buildd@lcy02-amd64-103) " +
		"(gcc-13 (Ubuntu 13.2.0-23ubuntu4) 13.2.0, GNU ld (GNU Binutils for Ubuntu) 2.42) " +
		"#49-Ubuntu SMP PREEMPT_DYNAMIC Mon Feb 24 14:24:20 UTC 2025\n",
}

var permDeniedFiles = map[string]bool{
	"/etc/shadow":  true,
	"/etc/gshadow": true,
	"/etc/sudoers": true,
}

func (catCmd) Run(args []string) (string, uint32) {
	if len(args) == 0 {
		return "", 0
	}
	path := args[0]
	if permDeniedFiles[path] {
		return "cat: " + path + ": Permission denied\n", 1
	}
	if out, ok := fakeFiles[path]; ok {
		return out, 0
	}
	return "cat: " + path + ": No such file or directory\n", 1
}

type dfCmd struct{}

func (dfCmd) Run(args []string) (string, uint32) {
	if len(args) > 0 && args[0] == "-h" {
		return "Filesystem      Size  Used Avail Use% Mounted on\n" +
			"/dev/vda1        39G  7.9G   30G  22% /\n" +
			"tmpfs           200M     0  200M   0% /run\n", 0
	}
	return "Filesystem     1K-blocks    Used Available Use% Mounted on\n" +
		"/dev/vda1       40581564 8234712  30654328  22% /\n" +
		"tmpfs             204096       0    204096   0% /run\n", 0
}

type freeCmd struct{}

func (freeCmd) Run(args []string) (string, uint32) {
	if len(args) > 0 && (args[0] == "-m" || args[0] == "-h") {
		return "               total        used        free      shared  buff/cache   available\n" +
			"Mem:            1992         158        1488           1         345        1747\n" +
			"Swap:           2047           0        2047\n", 0
	}
	return "               total        used        free      shared  buff/cache   available\n" +
		"Mem:         2039844      161808     1523992        1264      354044     1789120\n" +
		"Swap:        2097148           0     2097148\n", 0
}

type mountCmd struct{}

func (mountCmd) Run(_ []string) (string, uint32) {
	return "/dev/vda1 on / type ext4 (rw,relatime,discard)\n" +
		"proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)\n" +
		"sysfs on /sys type sysfs (rw,nosuid,nodev,noexec,relatime)\n" +
		"tmpfs on /run type tmpfs (rw,nosuid,nodev,size=204096k,mode=755)\n", 0
}

type psCmd struct{}

func (psCmd) Run(args []string) (string, uint32) {
	hasAux := false
	for _, a := range args {
		if a == "aux" || a == "-aux" || a == "-ef" {
			hasAux = true
		}
	}
	if hasAux {
		return "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n" +
			"root           1  0.0  0.3 168432 11892 ?        Ss   Mar09   0:42 /sbin/init\n" +
			"root         412  0.0  0.2  72132  6248 ?        Ss   Mar09   0:01 /usr/sbin/sshd -D\n" +
			"root        1893  0.0  0.1   8924  4012 pts/0    Ss   14:22   0:00 -bash\n" +
			"root        2104  0.0  0.0   9180  3144 pts/0    R+   14:23   0:00 ps aux\n", 0
	}
	return "    PID TTY          TIME CMD\n" +
		"   1893 pts/0    00:00:00 bash\n" +
		"   2104 pts/0    00:00:00 ps\n", 0
}

type crontabCmd struct{}

func (crontabCmd) Run(args []string) (string, uint32) {
	if len(args) > 0 && args[0] == "-l" {
		return "no crontab for root\n", 1
	}
	return "", 0
}
