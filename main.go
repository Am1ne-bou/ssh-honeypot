package main

import (
	"fmt"
	"os"

	"github.com/Am1ne-bou/ssh-honeypot/config"
	"github.com/Am1ne-bou/ssh-honeypot/hostkey"
	"github.com/Am1ne-bou/ssh-honeypot/logger"
	"github.com/Am1ne-bou/ssh-honeypot/server"
)

func main() {
	cfg := config.Parse()
	logs, err := logger.New(cfg.LogDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "logger init:", err)
		os.Exit(1)
	}
	defer logs.Close()

	signer, err := hostkey.Generate()
	if err != nil {
		logs.Server.Error("host key generation failed", "err", err)
		os.Exit(1)
	}

	opts := &server.Options{
		Addr:    cfg.Addr,
		Signer:  signer,
		Auth:    logs.Auth,
		Session: logs.Session,
		Server:  logs.Server,
	}

	if err := server.Serve(opts); err != nil {
		logs.Server.Error("server failed", "err", err)
		os.Exit(1)
	}
}
