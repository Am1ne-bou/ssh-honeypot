package server

import (
	"fmt"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Am1ne-bou/ssh-honeypot/hostkey"
)

// fakeConn implements ssh.ConnMetadata for unit testing the callback directly.
type fakeConn struct {
	sid  []byte
	addr net.Addr
}

func (f *fakeConn) User() string          { return "root" }
func (f *fakeConn) SessionID() []byte     { return f.sid }
func (f *fakeConn) ClientVersion() []byte { return []byte("SSH-2.0-test") }
func (f *fakeConn) ServerVersion() []byte { return []byte("SSH-2.0-test") }
func (f *fakeConn) RemoteAddr() net.Addr  { return f.addr }
func (f *fakeConn) LocalAddr() net.Addr   { return &net.TCPAddr{} }

func tcpAddr(s string) net.Addr {
	a, _ := net.ResolveTCPAddr("tcp", s)
	return a
}

// makeCallback mirrors the PasswordCallback closure in Serve (keyed by RemoteAddr).
func makeCallback(threshold int) (func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error), *[]int) {
	var mu sync.Mutex
	counts := map[string]int{}
	log := &[]int{}
	cb := func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
		id := c.RemoteAddr().String()
		mu.Lock()
		counts[id]++
		n := counts[id]
		*log = append(*log, n)
		mu.Unlock()
		if n < threshold {
			return nil, fmt.Errorf("bad password")
		}
		return nil, nil
	}
	return cb, log
}

func TestCallbackRejectsFirst1Accepts2nd(t *testing.T) {
	cb, logged := makeCallback(2)
	fc := &fakeConn{addr: tcpAddr("10.0.0.1:5000")}

	_, err := cb(fc, []byte("pass1"))
	if err == nil {
		t.Error("attempt 1: want rejection, got acceptance")
	}
	_, err = cb(fc, []byte("pass2"))
	if err != nil {
		t.Errorf("attempt 2: want acceptance, got %v", err)
	}
	if len(*logged) != 2 {
		t.Errorf("want 2 logged, got %d: %v", len(*logged), *logged)
	}
}

func TestCallbackIsolatesByRemoteAddr(t *testing.T) {
	cb, _ := makeCallback(2)
	fc1 := &fakeConn{addr: tcpAddr("10.0.0.1:5001")}
	fc2 := &fakeConn{addr: tcpAddr("10.0.0.2:5001")}

	// fc1 gets its first attempt accepted on 2nd -- so do one attempt first
	cb(fc1, []byte("pass"))
	// fc2 is a fresh connection, attempt 1 should reject
	_, err := cb(fc2, []byte("pass"))
	if err == nil {
		t.Error("fc2 attempt 1: want rejection (fresh counter), got acceptance")
	}
}

// Integration test. Uses real TCP + real SSH handshake.
// ssh.Password() with multiple entries doesn't retry -- the client marks
// "password" exhausted after the first server rejection. Use
// RetryableAuthMethod + PasswordCallback to cycle through passwords.
func TestIntegrationAuthAcceptsOnSecondAttempt(t *testing.T) {
	signer, err := hostkey.LoadOrGenerate(filepath.Join(t.TempDir(), "host.key"))
	if err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	counts := map[string]int{}
	logged := &[]int{}

	cfg := &ssh.ServerConfig{
		MaxAuthTries: 6,
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			id := c.RemoteAddr().String()
			mu.Lock()
			counts[id]++
			n := counts[id]
			*logged = append(*logged, n)
			mu.Unlock()
			if n < 2 {
				return nil, fmt.Errorf("bad password")
			}
			return nil, nil
		},
	}
	cfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	type srvRes struct {
		sconn *ssh.ServerConn
		err   error
	}
	done := make(chan srvRes, 1)
	go func() {
		conn, e := ln.Accept()
		ln.Close()
		if e != nil {
			done <- srvRes{err: e}
			return
		}
		sconn, _, _, e := ssh.NewServerConn(conn, cfg)
		done <- srvRes{sconn: sconn, err: e}
	}()

	passwords := []string{"p1", "p2"}
	idx := 0
	auth := ssh.RetryableAuthMethod(
		ssh.PasswordCallback(func() (string, error) {
			if idx >= len(passwords) {
				return "", fmt.Errorf("no more passwords")
			}
			p := passwords[idx]
			idx++
			return p, nil
		}),
		len(passwords),
	)

	rawConn, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	cc, _, _, err := ssh.NewClientConn(rawConn, ln.Addr().String(), &ssh.ClientConfig{
		User:            "root",
		Auth:            []ssh.AuthMethod{auth},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	cc.Close()

	r := <-done
	if r.err != nil {
		t.Fatalf("server: %v", r.err)
	}
	r.sconn.Close()

	if len(*logged) != 2 {
		t.Errorf("want 2 attempts logged, got %d: %v", len(*logged), *logged)
	}
}
