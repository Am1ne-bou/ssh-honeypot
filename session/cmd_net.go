package session

func init() {
	register("ifconfig", ifconfigCmd{})
	register("ip", ipCmd{})
	register("netstat", netstatCmd{})
	register("ss", ssCmd{})
	register("route", routeCmd{})
	register("arp", arpCmd{})
	register("ping", pingCmd{})
	register("curl", curlCmd{})
	register("wget", wgetCmd{})
	register("dig", digCmd{})
	register("nslookup", nslookupCmd{})
}

type ifconfigCmd struct{}

func (ifconfigCmd) Run(_ []string) (string, uint32) {
	return "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n" +
		"        inet 10.0.0.42  netmask 255.255.255.0  broadcast 10.0.0.255\n" +
		"        ether 52:54:00:a1:b2:c3  txqueuelen 1000  (Ethernet)\n" +
		"        RX packets 142853  bytes 198473821 (189.2 MiB)\n" +
		"        TX packets 89234  bytes 14829473 (14.1 MiB)\n\n" +
		"lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n" +
		"        inet 127.0.0.1  netmask 255.0.0.0\n" +
		"        loop  txqueuelen 1000  (Local Loopback)\n", 0
}

// ipCmd dispatches on the iproute2 subcommand (a, addr, r, route, link).
type ipCmd struct{}

func (ipCmd) Run(args []string) (string, uint32) {
	if len(args) == 0 {
		return "Usage: ip [ OPTIONS ] OBJECT { COMMAND | help }\n", 255
	}
	switch args[0] {
	case "a", "addr":
		return "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n" +
			"    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n" +
			"    inet 127.0.0.1/8 scope host lo\n" +
			"2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000\n" +
			"    link/ether 52:54:00:a1:b2:c3 brd ff:ff:ff:ff:ff:ff\n" +
			"    inet 10.0.0.42/24 brd 10.0.0.255 scope global eth0\n", 0
	case "r", "route":
		return "default via 10.0.0.1 dev eth0 proto dhcp metric 100\n" +
			"10.0.0.0/24 dev eth0 proto kernel scope link src 10.0.0.42 metric 100\n", 0
	case "link":
		return "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\n" +
			"    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n" +
			"2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000\n" +
			"    link/ether 52:54:00:a1:b2:c3 brd ff:ff:ff:ff:ff:ff\n", 0
	}
	return "Object \"" + args[0] + "\" is unknown, try \"ip help\".\n", 255
}

type netstatCmd struct{}

func (netstatCmd) Run(_ []string) (string, uint32) {
	return "Active Internet connections (servers and established)\n" +
		"Proto Recv-Q Send-Q Local Address           Foreign Address         State\n" +
		"tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\n" +
		"tcp        0      0 10.0.0.42:22            10.0.0.1:54291          ESTABLISHED\n", 0
}

type ssCmd struct{}

func (ssCmd) Run(_ []string) (string, uint32) {
	return "Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port\n" +
		"tcp   LISTEN 0      128          0.0.0.0:22        0.0.0.0:*\n", 0
}

type routeCmd struct{}

func (routeCmd) Run(_ []string) (string, uint32) {
	return "Kernel IP routing table\n" +
		"Destination     Gateway         Genmask         Flags Metric Ref    Use Iface\n" +
		"0.0.0.0         10.0.0.1        0.0.0.0         UG    100    0        0 eth0\n" +
		"10.0.0.0        0.0.0.0         255.255.255.0   U     100    0        0 eth0\n", 0
}

type arpCmd struct{}

func (arpCmd) Run(_ []string) (string, uint32) {
	return "? (10.0.0.1) at 52:54:00:12:34:56 [ether] on eth0\n", 0
}

// pingCmd fakes a successful single-host reply; ignores -c, -W, etc.
type pingCmd struct{}

func (pingCmd) Run(args []string) (string, uint32) {
	target := "8.8.8.8"
	for _, a := range args {
		if len(a) > 0 && a[0] != '-' {
			target = a
			break
		}
	}
	return "PING " + target + " (" + target + ") 56(84) bytes of data.\n" +
		"64 bytes from " + target + ": icmp_seq=1 ttl=117 time=12.3 ms\n" +
		"64 bytes from " + target + ": icmp_seq=2 ttl=117 time=11.8 ms\n\n" +
		"--- " + target + " ping statistics ---\n" +
		"2 packets transmitted, 2 received, 0% packet loss, time 1003ms\n" +
		"rtt min/avg/max/mdev = 11.800/12.050/12.300/0.250 ms\n", 0
}

// curlCmd / wgetCmd are bait — attackers chain them to drop payloads.
// Logging happens in shell.go via the "shell" log line; we just return
// realistic "connection refused" so retries are quick.
type curlCmd struct{}

func (curlCmd) Run(args []string) (string, uint32) {
	url := ""
	for _, a := range args {
		if len(a) > 0 && a[0] != '-' {
			url = a
			break
		}
	}
	if url == "" {
		return "curl: try 'curl --help' or 'curl --manual' for more information\n", 2
	}
	return "curl: (7) Failed to connect to " + url + ": Connection refused\n", 7
}

type wgetCmd struct{}

func (wgetCmd) Run(args []string) (string, uint32) {
	url := ""
	for _, a := range args {
		if len(a) > 0 && a[0] != '-' {
			url = a
			break
		}
	}
	if url == "" {
		return "wget: missing URL\n", 1
	}
	return "--2026-04-25 14:23:01--  " + url + "\n" +
		"Resolving host... failed: Temporary failure in name resolution.\n" +
		"wget: unable to resolve host address\n", 4
}

type digCmd struct{}

func (digCmd) Run(_ []string) (string, uint32) {
	return ";; communications error to 8.8.8.8#53: timed out\n\n" +
		";; no servers could be reached\n", 9
}

type nslookupCmd struct{}

func (nslookupCmd) Run(_ []string) (string, uint32) {
	return ";; communications error to 8.8.8.8#53: timed out\n\n" +
		";; no servers could be reached\n", 1
}
