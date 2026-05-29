package config

import "flag"

type Config struct {
	Addr          string
	LogDir        string
	KeyFile       string
	MaxConn       int
	QuarantineDir string
	AuthThreshold int
}

func Parse() *Config {
	c := &Config{}
	flag.StringVar(&c.Addr, "addr", ":2222", "listen address")
	flag.StringVar(&c.LogDir, "log-dir", "./logs", "directory for log files")
	flag.StringVar(&c.KeyFile, "host-key", "./host.key", "path to ed25519 host key file")
	flag.IntVar(&c.MaxConn, "max-conn", 100, "maximum concurrent SSH connections")
	flag.StringVar(&c.QuarantineDir, "quarantine-dir", "", "directory for captured payloads (empty = disabled)")
	flag.IntVar(&c.AuthThreshold, "auth-threshold", 1, "accept after N password attempts (1 = accept immediately)")
	flag.Parse()
	return c
}
