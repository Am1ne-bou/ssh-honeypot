package config

import "flag"

type Config struct {
	Addr string
}

// Parse reads command-line flags and returns a Config.
func Parse() *Config {
	c := &Config{}
	flag.StringVar(&c.Addr, "addr", ":2222", "listen address")
	flag.Parse()
	return c
}
