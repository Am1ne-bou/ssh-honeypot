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

// handleChannel rejects all requests on an accepted channel.
func handleChannel(ch ssh.Channel, reqs <-chan *ssh.Request, log *slog.Logger) {
	defer ch.Close()
	for req := range reqs {
		log.Info("channel request", "type", req.Type)
		if req.WantReply {
			req.Reply(false, nil)
		}
	}
}
