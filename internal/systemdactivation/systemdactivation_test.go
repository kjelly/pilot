package systemdactivation

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestListenerNotActivated verifies the "not socket-activated" error path
// (no env vars set) — the common case for a plain `go run` / vm-target
// local test invocation.
func TestListenerNotActivated(t *testing.T) {
	os.Unsetenv("LISTEN_PID")
	os.Unsetenv("LISTEN_FDS")
	if _, err := Listener(); err == nil {
		t.Fatalf("expected an error when LISTEN_PID/LISTEN_FDS are unset")
	}
}

// TestListenerInheritedSocket verifies the real systemd socket-activation
// contract end-to-end: a child process is started with a pre-bound Unix
// listener passed as fd 3 (via os/exec's ExtraFiles, the same mechanism
// systemd itself uses) and LISTEN_PID/LISTEN_FDS set to match, mirroring
// exactly what pilot-access-gateway.socket does. This is the standard
// Go "TestHelperProcess" subprocess-testing pattern (as used by the
// os/exec package's own tests), not a mock.
func TestListenerInheritedSocket(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "activated.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	unixLn := ln.(*net.UnixListener)
	f, err := unixLn.File()
	if err != nil {
		t.Fatalf("File: %v", err)
	}
	defer f.Close()

	cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcessSystemdActivation", "--")
	cmd.Env = append(os.Environ(), "GO_WANT_HELPER_PROCESS=1", "LISTEN_FDS=1")
	cmd.ExtraFiles = []*os.File{f} // becomes fd 3 in the child
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helper process failed: %v\n%s", err, out)
	}
	if got := string(out); got != "OK\n" {
		t.Fatalf("helper process output = %q, want \"OK\\n\"", got)
	}
}

// TestHelperProcessSystemdActivation is not a real test — it is re-exec'd
// as a subprocess by TestListenerInheritedSocket above (the standard Go
// idiom), guarded by GO_WANT_HELPER_PROCESS so `go test` never runs it as
// itself.
func TestHelperProcessSystemdActivation(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	os.Setenv("LISTEN_PID", fmt.Sprint(os.Getpid()))
	ln, err := Listener()
	if err != nil {
		fmt.Println("ERROR:", err)
		os.Exit(1)
	}
	defer ln.Close()
	if _, ok := ln.(*net.UnixListener); !ok {
		fmt.Printf("ERROR: listener is %T, want *net.UnixListener\n", ln)
		os.Exit(1)
	}
	fmt.Println("OK")
	os.Exit(0)
}
