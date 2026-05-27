// Simulates the dropper bot SCP upload against a live honeypot.
// Loops until accepted (handles unknown counter state), then speaks
// the SCP wire protocol to upload a test file.
//
// Usage: go run ./verify/dropper_sim.go [host:port]
//   default: VPS_IP:2222
package main

import (
	"fmt"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	defaultTarget = "VPS_IP:2222"
	testUser      = "root"
	scpDir        = "/tmp/droptest/"
	fileContent   = "#!/bin/sh\necho scp_test_ok\n"
	fileName      = "scp_test_payload.sh"
)

func dialSSH(target, user, pass string) (*ssh.Client, error) {
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(pass)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	return ssh.Dial("tcp", target, cfg)
}

func main() {
	target := defaultTarget
	if len(os.Args) > 1 {
		target = os.Args[1]
	}
	fmt.Printf("target: %s\n", target)

	// loop until accepted -- counter state on server is unknown
	fmt.Println("sending attempts until accepted...")
	var client *ssh.Client
	for i := 1; i <= 30; i++ {
		c, err := dialSSH(target, testUser, fmt.Sprintf("pass%d", i))
		if err == nil {
			client = c
			fmt.Printf("  attempt %d: ACCEPTED\n", i)
			break
		}
		fmt.Printf("  attempt %d: rejected\n", i)
		if i == 30 {
			fmt.Fprintln(os.Stderr, "FAIL: not accepted after 30 attempts")
			os.Exit(1)
		}
	}
	defer client.Close()

	// open a session and exec scp -t
	sess, err := client.NewSession()
	if err != nil {
		fmt.Fprintf(os.Stderr, "new session: %v\n", err)
		os.Exit(1)
	}
	defer sess.Close()

	stdin, err := sess.StdinPipe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "stdin pipe: %v\n", err)
		os.Exit(1)
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "stdout pipe: %v\n", err)
		os.Exit(1)
	}

	cmd := fmt.Sprintf("scp -t -r %s", scpDir)
	fmt.Printf("exec: %s\n", cmd)
	if err := sess.Start(cmd); err != nil {
		fmt.Fprintf(os.Stderr, "exec start: %v\n", err)
		os.Exit(1)
	}

	ready := make([]byte, 1)

	// server sends \x00 (ready)
	stdout.Read(ready)
	if ready[0] != 0x00 {
		fmt.Fprintf(os.Stderr, "FAIL: expected ready byte 0x00, got 0x%02x\n", ready[0])
		os.Exit(1)
	}
	fmt.Println("  got ready byte")

	// send file header
	header := fmt.Sprintf("C0755 %d %s\n", len(fileContent), fileName)
	stdin.Write([]byte(header))
	fmt.Printf("  sent header: %s", header)

	// server acks header
	stdout.Read(ready)
	if ready[0] != 0x00 {
		fmt.Fprintf(os.Stderr, "FAIL: no ack for header (got 0x%02x)\n", ready[0])
		os.Exit(1)
	}
	fmt.Println("  got ack for header")

	// send file data + trailing null
	stdin.Write([]byte(fileContent))
	stdin.Write([]byte{0x00})
	fmt.Printf("  sent %d bytes\n", len(fileContent))

	// server acks data
	stdout.Read(ready)
	if ready[0] != 0x00 {
		fmt.Fprintf(os.Stderr, "FAIL: no ack for data (got 0x%02x)\n", ready[0])
		os.Exit(1)
	}
	fmt.Println("  got ack for data")

	stdin.Close()
	if err := sess.Wait(); err != nil {
		if exitErr, ok := err.(*ssh.ExitError); ok && exitErr.ExitStatus() == 0 {
			// exit 0 wrapped in ExitError is fine
		} else {
			fmt.Fprintf(os.Stderr, "FAIL: session wait: %v\n", err)
			os.Exit(1)
		}
	}

	fmt.Println()
	fmt.Printf("PASS -- SCP receive completed, exit 0\n")
	fmt.Printf("check session.log for: msg=scp file name=%s\n", fileName)
}
