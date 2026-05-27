package session

import (
	"encoding/binary"
	"log/slog"
	"time"

	"golang.org/x/crypto/ssh"
)

func runExec(ch ssh.Channel, cmd string, log *slog.Logger) {
	defer ch.Close()

	// if the client opens then stops reading, our Write blocks forever. 2min cap.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		t := time.NewTimer(2 * time.Minute)
		defer t.Stop()
		select {
		case <-t.C:
			log.Info("exec", "event", "write_timeout")
			ch.Close()
		case <-stop:
		}
	}()

	log.Info("exec", "command", cmd)

	// SCP receive needs raw channel access for the wire protocol -- can't go through dispatch
	if isSCPReceive(cmd) {
		runSCPReceive(ch, cmd, log)
		return
	}

	out, exit := dispatch(cmd)
	if _, err := ch.Write([]byte(out)); err != nil {
		log.Error("exec write failed", "err", err)
		return
	}

	status := make([]byte, 4)
	binary.BigEndian.PutUint32(status, exit)
	if _, err := ch.SendRequest("exit-status", false, status); err != nil {
		log.Error("exit-status send failed", "err", err)
	}
}
