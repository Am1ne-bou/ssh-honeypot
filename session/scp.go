package session

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

const maxPayloadBytes = 50 << 20 // 50 MB -- anything bigger is almost certainly not a dropper

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
// savePayload writes the incoming bytes to quarantineDir/<sha256>-<name>.bin.
// Falls back to io.Discard on any error so the SCP protocol stays intact.
func savePayload(dir, name string, size int64, r io.Reader, log *slog.Logger) int64 {
	if size > maxPayloadBytes {
		log.Info("scp payload too large, discarding", "name", name, "size", size)
		n, _ := io.Copy(io.Discard, io.LimitReader(r, size))
		return n
	}
	base := filepath.Base(name) // attacker could send "../../etc/passwd" as filename
	tmp := filepath.Join(dir, fmt.Sprintf("%d-%s.tmp", time.Now().UnixNano(), base))
	dst, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o400)
	if err != nil {
		// dir not writable or something -- drain so protocol doesn't break
		n, _ := io.Copy(io.Discard, io.LimitReader(r, size))
		log.Error("scp quarantine open failed", "err", err)
		return n
	}
	h := sha256.New()
	n, _ := io.Copy(io.MultiWriter(dst, h), io.LimitReader(r, size))
	dst.Close()
	hash := hex.EncodeToString(h.Sum(nil))
	final := filepath.Join(dir, hash+"-"+base+".bin")
	if err := os.Rename(tmp, final); err != nil {
		log.Error("scp quarantine rename", "err", err)
		os.Remove(tmp)
	} else {
		log.Info("scp payload saved", "file", final, "sha256", hash, "bytes", n)
	}
	return n
}

// scpTargetDir extracts the target directory from "scp -t [-r] /path/".
func scpTargetDir(cmd string) string {
	fields := strings.Fields(cmd)
	for _, f := range fields[1:] {
		if !strings.HasPrefix(f, "-") {
			return f
		}
	}
	return "/tmp"
}

func runSCPReceive(ch ssh.Channel, cmd string, log *slog.Logger, quarantineDir string, sess *Session) {
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
						var n int64
						if quarantineDir != "" {
							n = savePayload(quarantineDir, name, size, r, log)
						} else {
							n, _ = io.Copy(io.Discard, io.LimitReader(r, size))
						}
						// mark file in session FS so subsequent ls/cat see it
						targetDir := scpTargetDir(cmd)
						sess.fs[filepath.Join(targetDir, name)] = []byte{}
						sess.dirs[targetDir] = true
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
