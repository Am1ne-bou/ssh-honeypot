package server

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Am1ne-bou/ssh-honeypot/session"
)

type Options struct {
	Addr    string
	MaxConn int
	Signer  ssh.Signer
	Auth    *slog.Logger
	Session *slog.Logger
	Server  *slog.Logger
}

func Serve(ctx context.Context, opts *Options) error {
	var mu sync.Mutex
	attempts := map[string]int{}

	cfg := &ssh.ServerConfig{
		MaxAuthTries: 6,
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			// key by remote addr, not session ID -- session ID is only set after
			// KEX succeeds, so a pre-KEX disconnect would never clean up the entry.
			// remote addr is available immediately and cleaned up unconditionally below.
			id := c.RemoteAddr().String()
			mu.Lock()
			attempts[id]++
			n := attempts[id]
			mu.Unlock()

			outcome := "rejected"
			if n >= 2 {
				outcome = "accepted"
			}
			opts.Auth.Info("auth attempt",
				"method", "password",
				"user", c.User(),
				"password", string(pass),
				"remote", c.RemoteAddr().String(),
				"client", string(c.ClientVersion()),
				"attempt", n,
				"outcome", outcome,
			)

			if n < 2 {
				return nil, fmt.Errorf("invalid password")
			}
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

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	sem := make(chan struct{}, opts.MaxConn)
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			opts.Server.Error("accept failed", "err", err)
			continue
		}
		select {
		case sem <- struct{}{}:
			go func() {
				defer func() { <-sem }()
				// 30s handshake deadline -- slowloris-style attackers open
				// the TCP socket then never finish KEX. cleared inside Handle.
				conn.SetReadDeadline(time.Now().Add(30 * time.Second))
				addr := conn.RemoteAddr().String()
				session.Handle(conn, cfg, opts.Session)
				mu.Lock()
				delete(attempts, addr)
				mu.Unlock()
			}()
		default:
			opts.Server.Info("connection rejected", "remote", conn.RemoteAddr().String(), "reason", "max_conn")
			conn.Close()
		}
	}
}
