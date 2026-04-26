package config

import "flag"

type Config struct {
	Addr   string
	LogDir string
}

// Parse reads command-line flags and returns a Config.
func Parse() *Config {
	c := &Config{}
	flag.StringVar(&c.Addr, "addr", ":2222", "listen address")
	flag.StringVar(&c.LogDir, "log-dir", "./logs", "directory for log files")
	flag.Parse()
	return c
}
