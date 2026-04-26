package session

import (
	"encoding/binary"
	"log/slog"

	"golang.org/x/crypto/ssh"
)

// runExec executes a one-shot command, writes canned output, sends exit-status, closes.
func runExec(ch ssh.Channel, cmd string, log *slog.Logger) {
	defer ch.Close()

	out := dispatch(cmd)
	if _, err := ch.Write([]byte(out)); err != nil {
		log.Error("exec write failed", "err", err)
		return
	}

	status := make([]byte, 4)
	binary.BigEndian.PutUint32(status, 0)
	if _, err := ch.SendRequest("exit-status", false, status); err != nil {
		log.Error("exit-status send failed", "err", err)
	}
}
