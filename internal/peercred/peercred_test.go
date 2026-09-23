package peercred

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

// TestFromConnSelfConnect verifies SO_PEERCRED against this very process:
// dialing our own listening Unix socket must report our own PID/UID/GID,
// since both ends of the connection are this test binary.
func TestFromConnSelfConnect(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "peercred-test.sock")

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close() //nolint:errcheck

	acceptedCh := make(chan Peer, 1)
	errCh := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close() //nolint:errcheck
		peer, err := FromConn(conn.(*net.UnixConn))
		if err != nil {
			errCh <- err
			return
		}
		acceptedCh <- peer
	}()

	client, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close() //nolint:errcheck

	select {
	case peer := <-acceptedCh:
		if int(peer.UID) != os.Getuid() {
			t.Fatalf("UID = %d, want %d (our own euid)", peer.UID, os.Getuid())
		}
		if int(peer.GID) != os.Getgid() {
			t.Fatalf("GID = %d, want %d", peer.GID, os.Getgid())
		}
		if int(peer.PID) != os.Getpid() {
			t.Fatalf("PID = %d, want %d (both ends are this test binary)", peer.PID, os.Getpid())
		}
	case err := <-errCh:
		t.Fatalf("accept/FromConn: %v", err)
	}
}
