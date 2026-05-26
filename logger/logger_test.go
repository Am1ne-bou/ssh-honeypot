package logger

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewCreatesFiles(t *testing.T) {
	dir := t.TempDir()
	l, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	for _, name := range []string{"auth.log", "session.log", "server.log"} {
		if _, e := os.Stat(filepath.Join(dir, name)); e != nil {
			t.Errorf("%s not created: %v", name, e)
		}
	}
}

func TestCloseNoError(t *testing.T) {
	l, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestLogWritesToFile(t *testing.T) {
	dir := t.TempDir()
	l, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	l.Auth.Info("test-marker", "k", "v")
	l.Close()

	data, err := os.ReadFile(filepath.Join(dir, "auth.log"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "test-marker") {
		t.Fatalf("log entry missing from auth.log, got: %s", data)
	}
}
