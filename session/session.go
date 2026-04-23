package session

import (
	"log/slog"
	"net"
)

// Handle logs the connection and closes it.
func Handle(conn net.Conn, log *slog.Logger) {
	defer conn.Close()
	log.Info("connection", "remote", conn.RemoteAddr().String())
}
