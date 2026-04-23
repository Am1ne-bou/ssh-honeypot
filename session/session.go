package session

import (
	"log/slog"
	"net"

	"golang.org/x/crypto/ssh"
)

// Handle performs the SSH handshake and manages the resulting session.
func Handle(conn net.Conn, cfg *ssh.ServerConfig, log *slog.Logger) {
	defer conn.Close()

	sconn, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		log.Info("handshake failed",
			"remote", conn.RemoteAddr().String(),
			"err", err,
		)
		return
	}
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

// ptyReq matches RFC 4254 §6.2.
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

// handleChannel logs each request on an accepted channel and rejects it.
func handleChannel(ch ssh.Channel, reqs <-chan *ssh.Request, log *slog.Logger) {
	defer ch.Close()
	for req := range reqs {
		logRequest(req, log)
		if req.WantReply {
			req.Reply(false, nil)
		}
	}
}

// logRequest parses known request payloads and logs structured fields.
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
