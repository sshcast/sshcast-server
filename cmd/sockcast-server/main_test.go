package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAcquireStandaloneListenerUnixAndTCP(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "run", "server.sock")

	unixLn, err := acquireStandaloneListener("unix:" + sockPath)
	if err != nil {
		t.Fatalf("acquireStandaloneListener unix failed: %v", err)
	}
	defer unixLn.Close()

	if unixLn.Addr().Network() != "unix" {
		t.Fatalf("expected unix network, got %q", unixLn.Addr().Network())
	}
	if _, err := os.Stat(sockPath); err != nil {
		t.Fatalf("expected socket file at %s: %v", sockPath, err)
	}

	tcpLn, err := acquireStandaloneListener("127.0.0.1:0")
	if err != nil {
		t.Fatalf("acquireStandaloneListener tcp failed: %v", err)
	}
	defer tcpLn.Close()

	if tcpLn.Addr().Network() != "tcp" {
		t.Fatalf("expected tcp network, got %q", tcpLn.Addr().Network())
	}
}
