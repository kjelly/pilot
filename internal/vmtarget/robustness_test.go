package vmtarget

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// stuckVirsh is a target that boots but never acquires an IP: domifaddr
// returns nothing and net-dhcp-leases shows only a header. Used to drive
// the waitForIP timeout deterministically.
const stuckVirsh = `  dominfo)            exit 1 ;;
  domifaddr)          exit 0 ;;
  net-dhcp-leases)    echo " Expiry Time  MAC address  Protocol  IP address  Hostname" ; exit 0 ;;
  net-dumpxml)        echo "<network><ip><dhcp><range start='192.168.122.2' end='192.168.122.254'/></dhcp></ip></network>" ; exit 0 ;;
  net-update)         exit 0 ;;
  domstate)           echo "running" ; exit 0 ;;
  define)             exit 0 ;;
  start)              exit 0 ;;
  destroy)            exit 0 ;;
  undefine)           exit 0 ;;
  snapshot-create-as) exit 0 ;;
  snapshot-revert)    exit 0 ;;
  *)                  exit 0 ;;`

// TestUp_BootTimeoutOverrideHonoredWithoutMutatingManager is the regression
// guard for two coupled bugs:
//   - Fix 1: Options.BootTimeout must actually bound the wait (it used to be
//     dropped on the floor when Up ignored the field).
//   - Fix 2: honouring it must NOT write back onto the shared Manager, or a
//     later Up/wait that reuses the Manager would inherit the override.
func TestUp_BootTimeoutOverrideHonoredWithoutMutatingManager(t *testing.T) {
	m, base := newTestManager(t, stuckVirsh)
	// Manager default is deliberately LARGE; the per-call override is tiny.
	// If Up honours the override we fail in ~40ms; if it ignored it we'd
	// block on the 30s field instead.
	m.bootTimeout = 30 * time.Second
	m.sshTimeout = 30 * time.Second
	m.pollInterval = 5 * time.Millisecond

	start := time.Now()
	_, err := m.Up(context.Background(), Options{
		Name:        "stuck",
		BaseImage:   base,
		BootTimeout: 40 * time.Millisecond,
	})
	elapsed := time.Since(start)

	if err == nil || !strings.Contains(err.Error(), "timed out waiting") {
		t.Fatalf("want boot-timeout error, got %v", err)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("Up ignored BootTimeout override (took %s, expected ~40ms)", elapsed)
	}
	// The override must not have leaked onto the Manager.
	if m.bootTimeout != 30*time.Second {
		t.Errorf("BootTimeout override leaked onto Manager: m.bootTimeout=%s, want 30s", m.bootTimeout)
	}
	if m.sshTimeout != 30*time.Second {
		t.Errorf("Manager sshTimeout unexpectedly changed: %s", m.sshTimeout)
	}
}

// assertNoDownloadTmp fails if any leftover ".download-*.tmp" file remains in
// dir — the atomic download must clean up its temp file on every path.
func assertNoDownloadTmp(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir %s: %v", dir, err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".download-") && strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("leftover temp download file: %s", e.Name())
		}
	}
}

func TestDownloadFile_AtomicOnSuccess(t *testing.T) {
	dir := t.TempDir()
	payload := []byte("this-is-a-fake-cloud-image-payload")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(payload)
	}))
	defer srv.Close()

	dest := filepath.Join(dir, "img.qcow2")
	if err := downloadFile(context.Background(), srv.URL, dest); err != nil {
		t.Fatalf("downloadFile: %v", err)
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read dest: %v", err)
	}
	if string(got) != string(payload) {
		t.Errorf("dest content = %q, want %q", got, payload)
	}
	assertNoDownloadTmp(t, dir)
}

// TestDownloadFile_InterruptedLeavesNoDest is the core atomicity guard: a
// transfer that dies mid-stream must never leave a (truncated) file at dest,
// because the next run would Stat it and trust it as a complete image. We
// simulate the interruption by declaring a Content-Length larger than the
// body we actually send, so the client sees an early EOF.
func TestDownloadFile_InterruptedLeavesNoDest(t *testing.T) {
	dir := t.TempDir()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100000")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("only-a-handful-of-bytes"))
		// handler returns without sending the promised 100000 bytes →
		// the server closes the connection and the client's read fails.
	}))
	defer srv.Close()

	dest := filepath.Join(dir, "img.qcow2")
	if err := downloadFile(context.Background(), srv.URL, dest); err == nil {
		t.Fatal("want error on interrupted/short download, got nil")
	}
	if _, statErr := os.Stat(dest); !os.IsNotExist(statErr) {
		t.Error("a partial download must NOT be left at dest")
	}
	assertNoDownloadTmp(t, dir)
}

func TestDownloadFile_BadStatusLeavesNoDest(t *testing.T) {
	dir := t.TempDir()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	dest := filepath.Join(dir, "img.qcow2")
	if err := downloadFile(context.Background(), srv.URL, dest); err == nil {
		t.Fatal("want error on bad status, got nil")
	}
	if _, statErr := os.Stat(dest); !os.IsNotExist(statErr) {
		t.Error("no file should be created on a bad status code")
	}
	assertNoDownloadTmp(t, dir)
}

// TestWithNetworkLock_SerializesCriticalSection proves the cross-process
// network lock actually provides mutual exclusion. Many goroutines each open
// the same lock file (distinct fds) and do an un-synchronised
// read-modify-write of a shared counter inside the critical section; if the
// flock did not serialize them, we'd see lost updates and/or two goroutines
// inside at once. Run under -race for the strongest signal.
func TestWithNetworkLock_SerializesCriticalSection(t *testing.T) {
	dir := t.TempDir()
	m, err := NewManager(filepath.Join(dir, "state"), filepath.Join(dir, "vmdir"))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	const N = 24
	var counter int
	var inside int32
	var wg sync.WaitGroup
	errCh := make(chan error, N)

	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e := m.withNetworkLock(func() error {
				if atomic.AddInt32(&inside, 1) != 1 {
					return fmt.Errorf("two goroutines inside the network lock at once")
				}
				c := counter
				time.Sleep(time.Millisecond) // widen the race window
				counter = c + 1
				atomic.AddInt32(&inside, -1)
				return nil
			})
			if e != nil {
				errCh <- e
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for e := range errCh {
		t.Fatal(e)
	}
	if counter != N {
		t.Errorf("counter = %d, want %d (lost updates → lock not mutually exclusive)", counter, N)
	}
}
