package server

import (
	"context"
	"fmt"
	"io"
	"log/slog"
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

// makeCallback mirrors the PasswordCallback + goroutine cleanup in Serve.
// returns the callback, a cleanup func (call after each simulated connection close),
// and a log of n values seen per call.
func makeCallback(threshold int) (
	cb func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error),
	cleanup func(addr string),
	logged *[]int,
) {
	var mu sync.Mutex
	counts := map[string]int{}
	log := &[]int{}

	cb = func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
		host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
		mu.Lock()
		counts[host]++
		n := counts[host]
		*log = append(*log, n)
		mu.Unlock()
		if n < threshold {
			return nil, fmt.Errorf("bad password")
		}
		return nil, nil
	}

	// mirrors the goroutine cleanup in Serve: only delete when threshold reached
	cleanup = func(addr string) {
		host, _, _ := net.SplitHostPort(addr)
		mu.Lock()
		if counts[host] >= threshold {
			delete(counts, host)
		}
		mu.Unlock()
	}

	return cb, cleanup, log
}

// TestCallbackRejectsFirst1Accepts2nd: basic threshold within one connection.
func TestCallbackRejectsFirst1Accepts2nd(t *testing.T) {
	cb, _, logged := makeCallback(2)
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

// TestCallbackIsolatesByIP: different source IPs must not share a counter.
func TestCallbackIsolatesByIP(t *testing.T) {
	cb, _, _ := makeCallback(2)
	fc1 := &fakeConn{addr: tcpAddr("10.0.0.1:5001")}
	fc2 := &fakeConn{addr: tcpAddr("10.0.0.2:5001")}

	cb(fc1, []byte("pass"))
	_, err := cb(fc2, []byte("pass"))
	if err == nil {
		t.Error("fc2 attempt 1: want rejection (separate IP counter), got acceptance")
	}
}

// TestCallbackAccumulatesAcrossConnections: the core bug fix.
// same IP, different source ports (one fresh TCP connection per guess) -- counter must accumulate.
// before the fix this returned n=1 every time because the key included the port.
func TestCallbackAccumulatesAcrossConnections(t *testing.T) {
	cb, _, logged := makeCallback(10)

	for i := 1; i <= 10; i++ {
		fc := &fakeConn{addr: tcpAddr(fmt.Sprintf("10.0.0.1:%d", 5000+i))}
		_, err := cb(fc, []byte(fmt.Sprintf("pass%d", i)))
		if i < 10 && err == nil {
			t.Errorf("attempt %d: want rejection, got acceptance", i)
		}
		if i == 10 && err != nil {
			t.Errorf("attempt 10: want acceptance, got %v", err)
		}
	}

	// n must have gone 1,2,3,...,10 -- not 1,1,1,...,1
	for i, n := range *logged {
		if n != i+1 {
			t.Errorf("logged[%d] = %d, want %d -- counter did not accumulate across ports", i, n, i+1)
		}
	}
}

// TestCallbackResetsOnlyAfterAccept: counter must persist through rejected connections
// and reset only when threshold is reached.
func TestCallbackResetsOnlyAfterAccept(t *testing.T) {
	cb, cleanup, _ := makeCallback(10)

	// 5 rejected connections with cleanup after each -- counter must NOT reset
	for i := 1; i <= 5; i++ {
		addr := fmt.Sprintf("10.0.0.1:%d", 5000+i)
		cb(&fakeConn{addr: tcpAddr(addr)}, []byte("pass"))
		cleanup(addr)
	}

	// attempt 6 must be n=6, not n=1
	_, err := cb(&fakeConn{addr: tcpAddr("10.0.0.1:6006")}, []byte("pass"))
	if err == nil {
		t.Fatal("attempt 6 after 5 rejected+cleanup: want rejection, counter should be at 6 not 1")
	}
	cleanup("10.0.0.1:6006")

	// 3 more to reach 9
	for i := 7; i <= 9; i++ {
		addr := fmt.Sprintf("10.0.0.1:%d", 6000+i)
		cb(&fakeConn{addr: tcpAddr(addr)}, []byte("pass"))
		cleanup(addr)
	}

	// attempt 10: accepted
	_, err = cb(&fakeConn{addr: tcpAddr("10.0.0.1:7000")}, []byte("pass10"))
	if err != nil {
		t.Fatalf("attempt 10: want acceptance, got %v", err)
	}
	cleanup("10.0.0.1:7000") // n >= 10, should delete

	// after reset: next attempt must be n=1 (rejected)
	_, err = cb(&fakeConn{addr: tcpAddr("10.0.0.1:8000")}, []byte("pass11"))
	if err == nil {
		t.Error("after accept+cleanup: want rejection (counter was reset), got acceptance")
	}
}

// TestIntegrationThresholdAcrossConnections: end-to-end test using the real Serve().
// each iteration opens a fresh TCP connection (different source port) with one password --
// exactly what bots do. connections 1-9 must be rejected, connection 10 must be accepted.
func TestIntegrationThresholdAcrossConnections(t *testing.T) {
	signer, err := hostkey.LoadOrGenerate(filepath.Join(t.TempDir(), "host.key"))
	if err != nil {
		t.Fatal(err)
	}

	discard := slog.New(slog.NewJSONHandler(io.Discard, nil))

	// grab a free port then release it -- Serve() will rebind
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go Serve(ctx, &Options{
		Addr:    addr,
		MaxConn: 20,
		Signer:  signer,
		Auth:    discard,
		Session: discard,
		Server:  discard,
	})

	// wait for the listener to be ready
	for i := 0; i < 30; i++ {
		c, e := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if e == nil {
			c.Close()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	clientCfg := &ssh.ClientConfig{
		User:            "root",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	// connections 1-9: fresh TCP connection per attempt, expect rejection
	for i := 1; i <= 9; i++ {
		clientCfg.Auth = []ssh.AuthMethod{ssh.Password(fmt.Sprintf("pass%d", i))}
		raw, e := net.DialTimeout("tcp", addr, 5*time.Second)
		if e != nil {
			t.Fatalf("dial %d: %v", i, e)
		}
		_, _, _, e = ssh.NewClientConn(raw, addr, clientCfg)
		if e == nil {
			t.Errorf("connection %d: want rejection, got acceptance", i)
		}
	}

	// connection 10: must be accepted
	clientCfg.Auth = []ssh.AuthMethod{ssh.Password("pass10")}
	raw, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial 10: %v", err)
	}
	cc, _, _, err := ssh.NewClientConn(raw, addr, clientCfg)
	if err != nil {
		t.Fatalf("connection 10: want acceptance, got %v", err)
	}
	cc.Close()
}

// TestIntegrationAuthAcceptsOnSecondAttempt: kept -- tests within-connection retry,
// a different scenario from cross-connection accumulation.
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
