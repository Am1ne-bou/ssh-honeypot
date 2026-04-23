package server

import (
	"log/slog"
	"net"

	"github.com/Am1ne-bou/ssh-honeypot/session"
)

// Serve listens on addr and handles each incoming connection.
func Serve(addr string, log *slog.Logger) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer ln.Close()

	log.Info("listening", "addr", addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Error("accept failed", "err", err)
			continue
		}
		go session.Handle(conn, log)
	}
}
