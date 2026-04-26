package session

import (
	"encoding/binary"
	"io"
	"log/slog"
	"strings"

	"golang.org/x/crypto/ssh"
)

const prompt = "root@ubuntu:~# "

// runShell serves a fake interactive shell on ch with manual echo and line editing.
func runShell(ch ssh.Channel, log *slog.Logger) {
	defer ch.Close()

	if _, err := ch.Write([]byte(prompt)); err != nil {
		return
	}

	buf := make([]byte, 0, 256)
	one := make([]byte, 1)

	for {
		n, err := ch.Read(one)
		if err != nil {
			if err != io.EOF {
				log.Info("shell read", "err", err)
			}
			return
		}
		if n == 0 {
			continue
		}

		b := one[0]

		switch {
		case b == '\r' || b == '\n':
			if _, err := ch.Write([]byte("\r\n")); err != nil {
				return
			}
			cmd := string(buf)
			buf = buf[:0]
			log.Info("shell", "command", cmd)

			if cmd == "exit" || cmd == "logout" {
				status := make([]byte, 4)
				binary.BigEndian.PutUint32(status, 0)
				ch.SendRequest("exit-status", false, status)
				return
			}

			out := dispatch(cmd)
			out = strings.ReplaceAll(out, "\n", "\r\n")
			if _, err := ch.Write([]byte(out)); err != nil {
				return
			}
			if _, err := ch.Write([]byte(prompt)); err != nil {
				return
			}

		case b == 0x7f || b == 0x08:
			if len(buf) == 0 {
				continue
			}
			buf = buf[:len(buf)-1]
			if _, err := ch.Write([]byte("\b \b")); err != nil {
				return
			}

		case b == 0x03:
			if _, err := ch.Write([]byte("^C\r\n" + prompt)); err != nil {
				return
			}
			buf = buf[:0]

		case b == 0x04:
			if len(buf) == 0 {
				status := make([]byte, 4)
				binary.BigEndian.PutUint32(status, 0)
				ch.SendRequest("exit-status", false, status)
				return
			}

		case b >= 0x20 && b < 0x7f:
			buf = append(buf, b)
			if _, err := ch.Write(one); err != nil {
				return
			}
		}
	}
}
