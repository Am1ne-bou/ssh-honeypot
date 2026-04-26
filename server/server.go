package server

import (
	"log/slog"
	"net"

	"golang.org/x/crypto/ssh"

	"github.com/Am1ne-bou/ssh-honeypot/session"
)

// Options configures the SSH honeypot server.
type Options struct {
	Addr    string
	Signer  ssh.Signer
	Auth    *slog.Logger
	Session *slog.Logger
	Server  *slog.Logger
}

// Serve listens on opts.Addr and handles each SSH connection.
func Serve(opts *Options) error {
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			opts.Auth.Info("auth attempt",
				"method", "password",
				"user", c.User(),
				"password", string(pass),
				"remote", c.RemoteAddr().String(),
				"client", string(c.ClientVersion()),
				"outcome", "accepted",
			)
			return nil, nil
		},
	}
	cfg.AddHostKey(opts.Signer)

	ln, err := net.Listen("tcp", opts.Addr)
	if err != nil {
		return err
	}
	defer ln.Close()

	opts.Server.Info("listening", "addr", opts.Addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			opts.Server.Error("accept failed", "err", err)
			continue
		}
		go session.Handle(conn, cfg, opts.Session)
	}
}
