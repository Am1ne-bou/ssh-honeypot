package session

import (
	"crypto/rand"
	"fmt"
	"log/slog"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

func newSID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func Handle(conn net.Conn, cfg *ssh.ServerConfig, log *slog.Logger) {
	defer conn.Close()

	log = log.With("sid", newSID())

	sconn, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		log.Info("handshake failed",
			"remote", conn.RemoteAddr().String(),
			"err", err,
		)
		return
	}
	conn.SetReadDeadline(time.Time{}) // handshake done, drop the deadline
	defer sconn.Close()

	log.Info("handshake ok",
		"remote", sconn.RemoteAddr().String(),
		"user", sconn.User(),
		"client", string(sconn.ClientVersion()),
	)

	go ssh.DiscardRequests(reqs)

	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			newCh.Reject(ssh.UnknownChannelType, "only session channels supported")
			continue
		}
		ch, chReqs, err := newCh.Accept()
		if err != nil {
			log.Error("channel accept failed", "err", err)
			continue
		}
		go handleChannel(ch, chReqs, log)
	}
}

// RFC 4254 6.2 -- pty-req payload
type ptyReq struct {
	Term     string
	Cols     uint32
	Rows     uint32
	WidthPx  uint32
	HeightPx uint32
	Modes    string
}

type execReq struct{ Command string }
type envReq struct{ Name, Value string }
type subsystemReq struct{ Name string }

func handleChannel(ch ssh.Channel, reqs <-chan *ssh.Request, log *slog.Logger) {
	for req := range reqs {
		logRequest(req, log)
		switch req.Type {
		case "shell":
			if req.WantReply {
				req.Reply(true, nil)
			}
			go drainRequests(reqs, log)
			runShell(ch, log)
			return
		case "exec":
			var p execReq
			if err := ssh.Unmarshal(req.Payload, &p); err != nil {
				if req.WantReply {
					req.Reply(false, nil)
				}
				continue
			}
			if req.WantReply {
				req.Reply(true, nil)
			}
			go drainRequests(reqs, log)
			runExec(ch, p.Command, log)
			return
		case "pty-req", "env":
			if req.WantReply {
				req.Reply(true, nil)
			}
		default:
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}
	ch.Close()
}

func drainRequests(reqs <-chan *ssh.Request, log *slog.Logger) {
	for req := range reqs {
		logRequest(req, log)
		if req.WantReply {
			req.Reply(false, nil)
		}
	}
}

func logRequest(req *ssh.Request, log *slog.Logger) {
	switch req.Type {
	case "pty-req":
		var p ptyReq
		if err := ssh.Unmarshal(req.Payload, &p); err != nil {
			log.Info("channel request", "type", req.Type, "parse_err", err)
			return
		}
		log.Info("channel request",
			"type", req.Type,
			"term", p.Term,
			"cols", p.Cols,
			"rows", p.Rows,
		)
	case "exec":
		var p execReq
		if err := ssh.Unmarshal(req.Payload, &p); err != nil {
			log.Info("channel request", "type", req.Type, "parse_err", err)
			return
		}
		log.Info("channel request", "type", req.Type, "command", p.Command)
	case "env":
		var p envReq
		if err := ssh.Unmarshal(req.Payload, &p); err != nil {
			log.Info("channel request", "type", req.Type, "parse_err", err)
			return
		}
		log.Info("channel request", "type", req.Type, "name", p.Name, "value", p.Value)
	case "subsystem":
		var p subsystemReq
		if err := ssh.Unmarshal(req.Payload, &p); err != nil {
			log.Info("channel request", "type", req.Type, "parse_err", err)
			return
		}
		log.Info("channel request", "type", req.Type, "name", p.Name)
	case "shell":
		log.Info("channel request", "type", req.Type)
	default:
		log.Info("channel request", "type", req.Type, "payload_len", len(req.Payload))
	}
}
