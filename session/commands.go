package session

import "strings"

// canned maps a command's first token to its stdout response.
var canned = map[string]string{
	// recon
	"whoami":      "root\n",
	"id":          "uid=0(root) gid=0(root) groups=0(root)\n",
	"uname":       "Linux\n",
	"uname -a":    "Linux ubuntu 6.8.0-49-generic #49-Ubuntu SMP PREEMPT_DYNAMIC Mon Feb 24 14:24:20 UTC 2025 x86_64 x86_64 x86_64 GNU/Linux\n",
	"uname -r":    "6.8.0-49-generic\n",
	"uname -m":    "x86_64\n",
	"uname -s":    "Linux\n",
	"hostname":    "ubuntu\n",
	"hostname -i": "10.0.0.42\n",
	"w":           " 14:23:01 up 47 days,  3:14,  1 user,  load average: 0.08, 0.03, 0.01\nUSER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\nroot     pts/0    10.0.0.1         14:22    0.00s  0.04s  0.00s w\n",
	"who":         "root     pts/0        2026-04-25 14:22 (10.0.0.1)\n",
	"last":        "root     pts/0        10.0.0.1         Fri Apr 25 14:22   still logged in\nroot     pts/0        10.0.0.1         Thu Apr 24 09:11 - 18:42  (09:31)\nreboot   system boot  6.8.0-49-generic Sun Mar  9 11:08   still running\n\nwtmp begins Sun Mar  9 11:08:42 2026\n",
	"uptime":      " 14:23:01 up 47 days,  3:14,  1 user,  load average: 0.08, 0.03, 0.01\n",
	"date":        "Fri Apr 25 14:23:01 UTC 2026\n",
	"pwd":         "/root\n",

	// filesystem
	"ls":                  "\n",
	"ls -l":               "total 0\n",
	"ls -la":              "total 28\ndrwx------ 4 root root 4096 Apr 25 14:22 .\ndrwxr-xr-x 1 root root 4096 Apr 24 09:11 ..\n-rw------- 1 root root  142 Apr 25 14:22 .bash_history\n-rw-r--r-- 1 root root 3106 Oct 15  2021 .bashrc\ndrwx------ 2 root root 4096 Apr 24 09:11 .cache\n-rw-r--r-- 1 root root  161 Jul  9  2019 .profile\ndrwx------ 2 root root 4096 Apr 25 14:22 .ssh\n",
	"ls /":                "bin   dev  home  lib32  libx32  media  opt   root  sbin  srv  tmp  usr\nboot  etc  lib   lib64  lost+found  mnt  proc  run   sbin  sys  var\n",
	"cat /etc/passwd":     "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\n",
	"cat /etc/shadow":     "cat: /etc/shadow: Permission denied\n",
	"cat /etc/os-release": "PRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\nNAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nVERSION=\"24.04.1 LTS (Noble Numbat)\"\nVERSION_CODENAME=noble\nID=ubuntu\nID_LIKE=debian\nUBUNTU_CODENAME=noble\n",
	"cat /proc/cpuinfo":   "processor\t: 0\nvendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel\t\t: 85\nmodel name\t: Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz\ncpu MHz\t\t: 2399.998\ncache size\t: 35840 KB\nphysical id\t: 0\nsiblings\t: 2\ncore id\t\t: 0\ncpu cores\t: 2\n\nprocessor\t: 1\nvendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel\t\t: 85\nmodel name\t: Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz\ncpu MHz\t\t: 2399.998\ncache size\t: 35840 KB\nphysical id\t: 0\nsiblings\t: 2\ncore id\t\t: 1\ncpu cores\t: 2\n",
	"cat /proc/meminfo":   "MemTotal:        2039844 kB\nMemFree:         1523992 kB\nMemAvailable:    1789120 kB\nBuffers:           42168 kB\nCached:           312044 kB\nSwapTotal:       2097148 kB\nSwapFree:        2097148 kB\n",
	"df":                  "Filesystem     1K-blocks    Used Available Use% Mounted on\n/dev/vda1       40581564 8234712  30654328  22% /\ntmpfs             204096       0    204096   0% /run\n",
	"df -h":               "Filesystem      Size  Used Avail Use% Mounted on\n/dev/vda1        39G  7.9G   30G  22% /\ntmpfs           200M     0  200M   0% /run\n",
	"free":                "               total        used        free      shared  buff/cache   available\nMem:         2039844      161808     1523992        1264      354044     1789120\nSwap:        2097148           0     2097148\n",
	"free -m":             "               total        used        free      shared  buff/cache   available\nMem:            1992         158        1488           1         345        1747\nSwap:           2047           0        2047\n",

	// network
	"ifconfig":             "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet 10.0.0.42  netmask 255.255.255.0  broadcast 10.0.0.255\n        ether 52:54:00:a1:b2:c3  txqueuelen 1000  (Ethernet)\n        RX packets 142853  bytes 198473821 (189.2 MiB)\n        TX packets 89234  bytes 14829473 (14.1 MiB)\n\nlo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n        inet 127.0.0.1  netmask 255.0.0.0\n        loop  txqueuelen 1000  (Local Loopback)\n",
	"ip a":                 "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n    inet 127.0.0.1/8 scope host lo\n2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000\n    link/ether 52:54:00:a1:b2:c3 brd ff:ff:ff:ff:ff:ff\n    inet 10.0.0.42/24 brd 10.0.0.255 scope global eth0\n",
	"ip addr":              "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n    inet 127.0.0.1/8 scope host lo\n2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000\n    link/ether 52:54:00:a1:b2:c3 brd ff:ff:ff:ff:ff:ff\n    inet 10.0.0.42/24 brd 10.0.0.255 scope global eth0\n",
	"netstat -an":          "Active Internet connections (servers and established)\nProto Recv-Q Send-Q Local Address           Foreign Address         State\ntcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\ntcp        0      0 10.0.0.42:22            10.0.0.1:54291          ESTABLISHED\n",
	"ss -tunlp":            "Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port\ntcp   LISTEN 0      128          0.0.0.0:22        0.0.0.0:*\n",
	"route":                "Kernel IP routing table\nDestination     Gateway         Genmask         Flags Metric Ref    Use Iface\n0.0.0.0         10.0.0.1        0.0.0.0         UG    100    0        0 eth0\n10.0.0.0        0.0.0.0         255.255.255.0   U     100    0        0 eth0\n",
	"ip r":                 "default via 10.0.0.1 dev eth0 proto dhcp metric 100\n10.0.0.0/24 dev eth0 proto kernel scope link src 10.0.0.42 metric 100\n",
	"ip route":             "default via 10.0.0.1 dev eth0 proto dhcp metric 100\n10.0.0.0/24 dev eth0 proto kernel scope link src 10.0.0.42 metric 100\n",
	"cat /etc/resolv.conf": "nameserver 8.8.8.8\nnameserver 1.1.1.1\n",
	"arp -a":               "? (10.0.0.1) at 52:54:00:12:34:56 [ether] on eth0\n",
}

// dispatch returns the canned stdout for cmd, or a not-found message.
func dispatch(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return ""
	}
	if out, ok := canned[cmd]; ok {
		return out
	}
	first := cmd
	for i, r := range cmd {
		if r == ' ' {
			first = cmd[:i]
			break
		}
	}
	return "bash: " + first + ": command not found\n"
}
