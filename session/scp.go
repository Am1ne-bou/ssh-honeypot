package session

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// isSCPReceive reports whether cmd is an scp server-side receive invocation.
// When a client runs `scp file user@host:/path`, it SSHes to the host and
// exec's `scp -t /path` -- that's the receive (target) side we need to handle.
func isSCPReceive(cmd string) bool {
	fields := strings.Fields(cmd)
	if len(fields) == 0 || fields[0] != "scp" {
		return false
	}
	for _, f := range fields[1:] {
		if f == "-t" {
			return true
		}
	}
	return false
}

// runSCPReceive fakes the server side of an SCP upload.
// We speak just enough of the protocol to make the client think the transfer
// worked, then exit 0. The bot will proceed to chmod + execute the "payload"
// and we capture that next step in session.log.
//
// SCP wire protocol (receive mode):
//   server -> \x00          ready
//   client -> C<mode> <size> <name>\n   file header (or D for directory)
//   server -> \x00          ready for data
//   client -> <size bytes>  file data
//   client -> \x00          end of data
//   server -> \x00          ack
func runSCPReceive(ch ssh.Channel, cmd string, log *slog.Logger) {
	defer ch.Close()

	log.Info("scp receive", "command", cmd)

	// the client blocks here waiting for us to signal ready
	if _, err := ch.Write([]byte{0x00}); err != nil {
		log.Error("scp ready byte", "err", err)
		return
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		r := bufio.NewReader(ch)
		for {
			line, err := r.ReadString('\n')
			line = strings.TrimRight(line, "\r\n\x00")
			if line != "" {
				switch {
				case strings.HasPrefix(line, "C"):
					// file entry -- parse so we can drain exactly the right number of bytes
					var mode string
					var size int64
					var name string
					fmt.Sscanf(line, "%s %d %s", &mode, &size, &name)
					log.Info("scp file", "name", name, "size", size, "mode", mode)
					ch.Write([]byte{0x00}) // ack header, client sends data now
					if size > 0 {
						n, _ := io.Copy(io.Discard, io.LimitReader(r, size))
						log.Info("scp data drained", "name", name, "bytes", n)
					}
					r.ReadByte()           // trailing null after file data
					ch.Write([]byte{0x00}) // ack file received
				case strings.HasPrefix(line, "D"):
					// directory entry -- no data follows, just ack
					log.Info("scp dir", "header", line)
					ch.Write([]byte{0x00})
				case line == "E":
					// end of directory
					log.Info("scp", "event", "end_dir")
					ch.Write([]byte{0x00})
				default:
					log.Info("scp", "raw", line)
				}
			}
			if err != nil {
				return
			}
		}
	}()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		log.Info("scp", "event", "timeout")
	}

	// exit 0 -- bot thinks the upload succeeded, will try chmod+exec next
	status := make([]byte, 4)
	binary.BigEndian.PutUint32(status, 0)
	ch.SendRequest("exit-status", false, status)
}
