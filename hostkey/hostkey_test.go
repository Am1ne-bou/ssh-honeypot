package hostkey

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrGenerateCreatesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "host.key")
	s, err := LoadOrGenerate(path)
	if err != nil {
		t.Fatal(err)
	}
	if s == nil {
		t.Fatal("signer is nil")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("key file not on disk: %v", err)
	}
}

func TestLoadOrGenerateReloads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "host.key")
	s1, err := LoadOrGenerate(path)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := LoadOrGenerate(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(s1.PublicKey().Marshal(), s2.PublicKey().Marshal()) {
		t.Fatal("reloaded key differs from generated key")
	}
}
