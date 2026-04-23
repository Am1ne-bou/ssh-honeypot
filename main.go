package main

import (
	"os"

	"github.com/Am1ne-bou/ssh-honeypot/config"
	"github.com/Am1ne-bou/ssh-honeypot/logger"
	"github.com/Am1ne-bou/ssh-honeypot/server"
)

func main() {
	cfg := config.Parse()
	log := logger.New(os.Stderr)

	if err := server.Serve(cfg.Addr, log); err != nil {
		log.Error("server failed", "err", err)
		os.Exit(1)
	}
}
