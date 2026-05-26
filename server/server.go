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
		MaxAuthTries: 20,
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			// key by IP only, not IP:port -- bots open a fresh TCP connection per
			// guess so the source port changes every time. IP:port would reset the
			// counter on each connection and nobody would ever reach the threshold.
			host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
			mu.Lock()
			attempts[host]++
			n := attempts[host]
			mu.Unlock()

			outcome := "rejected"
			if n >= 10 {
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

			if n < 10 {
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
				host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
				session.Handle(conn, cfg, opts.Session)
				mu.Lock()
				// only reset after the bot reached the shell -- deleting on every
				// connection close would wipe the counter and keep n stuck at 1
				if attempts[host] >= 10 {
					delete(attempts, host)
				}
				mu.Unlock()
			}()
		default:
			opts.Server.Info("connection rejected", "remote", conn.RemoteAddr().String(), "reason", "max_conn")
			conn.Close()
		}
	}
}
