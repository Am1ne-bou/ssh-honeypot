package main

import (
	"os"

	"github.com/Am1ne-bou/ssh-honeypot/config"
	"github.com/Am1ne-bou/ssh-honeypot/hostkey"
	"github.com/Am1ne-bou/ssh-honeypot/logger"
	"github.com/Am1ne-bou/ssh-honeypot/server"
)

func main() {
	cfg := config.Parse()
	log := logger.New(os.Stderr)

	signer, err := hostkey.Generate()
	if err != nil {
		log.Error("host key generation failed", "err", err)
		os.Exit(1)
	}

	opts := &server.Options{
		Addr:   cfg.Addr,
		Signer: signer,
		Logger: log,
	}

	if err := server.Serve(opts); err != nil {
		log.Error("server failed", "err", err)
		os.Exit(1)
	}
}
