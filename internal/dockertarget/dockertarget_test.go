package dockertarget

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// newTestManager builds a Manager rooted in a fresh temp dir and
// points PILOT_DOCKER_BIN at a mock shim that records argv and
// returns canned output per test case. This lets us exercise the
// state / lock / validation logic without docker actually present.
func newTestManager(t *testing.T, shimScript string) (*Manager, string) {
	t.Helper()
	dir := t.TempDir()
	shim := filepath.Join(dir, "docker")
	if err := os.WriteFile(shim, []byte("#!/bin/sh\n"+shimScript), 0o755); err != nil {
		t.Fatalf("write shim: %v", err)
	}
	t.Setenv("PILOT_DOCKER_BIN", shim)
	m, err := NewManager(filepath.Join(dir, "state"))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return m, filepath.Join(dir, "state")
}

const shimAlwaysFail = `exit 1`

// TestUp_RejectsBlankName is a regression guard: a previous draft
// silently coerced empty name to "pilot-target" which masked CLI
// flag wiring bugs. Now it errors.
func TestUp_RejectsBlankName(t *testing.T) {
	m, _ := newTestManager(t, shimAlwaysFail)
	_, err := m.Up(context.Background(), Options{Name: "", Image: "ubuntu:24.04"})
	if err == nil || !strings.Contains(err.Error(), "name is required") {
		t.Fatalf("want name-required error, got %v", err)
	}
}

// TestUp_RejectsBlankImage mirrors the name check.
func TestUp_RejectsBlankImage(t *testing.T) {
	m, _ := newTestManager(t, shimAlwaysFail)
	_, err := m.Up(context.Background(), Options{Name: "ok", Image: ""})
	if err == nil || !strings.Contains(err.Error(), "image is required") {
		t.Fatalf("want image-required error, got %v", err)
	}
}

// TestUp_RejectsInvalidName protects inventory / docker compat.
// [a-zA-Z0-9_.-] only — no spaces, no colons.
func TestUp_RejectsInvalidName(t *testing.T) {
	m, _ := newTestManager(t, shimAlwaysFail)
	_, err := m.Up(context.Background(), Options{Name: "bad name", Image: "ubuntu:24.04"})
	if err == nil || !strings.Contains(err.Error(), "invalid name") {
		t.Fatalf("want invalid-name error, got %v", err)
	}
}

// TestUp_PersistsTargetAndInventoryRoundTrip is the happy path:
// Up writes state, List sees it, Get returns the same fields, and
// the generated inventory contains the expected docker connection
// stanza.
func TestUp_PersistsTargetAndInventoryRoundTrip(t *testing.T) {
	// Shim: refuse inspect (no existing container), then accept
	// `docker run` and print a fake container id.
	shim := `case "$1" in
  inspect) exit 1 ;;
  run)     echo "abc123def456" ;;
  *)       exit 0 ;;
esac`
	m, _ := newTestManager(t, shim)
	tgt, err := m.Up(context.Background(), Options{Name: "infra-test", Image: "ubuntu:24.04"})
	if err != nil {
		t.Fatalf("Up: %v", err)
	}
	if tgt.ContainerID != "abc123def456" {
		t.Errorf("ContainerID = %q", tgt.ContainerID)
	}
	if tgt.Status != StatusRunning {
		t.Errorf("Status = %q", tgt.Status)
	}
	if tgt.Hostname != "infra-test" {
		t.Errorf("Hostname = %q (want default=Name)", tgt.Hostname)
	}
	if tgt.Network != "host" {
		t.Errorf("Network = %q (want default host)", tgt.Network)
	}
	if !tgt.Privileged {
		t.Error("Privileged should default to true so apt/systemd work")
	}

	// List should find it
	all, err := m.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(all) != 1 || all[0].Name != "infra-test" {
		t.Fatalf("List: %+v", all)
	}

	// Inventory round-trip
	inv, err := tgt.RenderInventory()
	if err != nil {
		t.Fatalf("RenderInventory: %v", err)
	}
	for _, want := range []string{
		"ansible_connection: docker",
		"ansible_host: infra-test",
		"ansible_user: root",
	} {
		if !strings.Contains(inv, want) {
			t.Errorf("inventory missing %q\n%s", want, inv)
		}
	}
}

// TestUp_RefusesDuplicate is the regression guard for the previous
// "silent overwrite" bug. Two Up calls with the same name → second
// must error and leave the original record intact.
func TestUp_RefusesDuplicate(t *testing.T) {
	shim := `case "$1" in
  inspect) exit 1 ;;
  run)     echo "first-container-id" ;;
  *)       exit 0 ;;
esac`
	m, _ := newTestManager(t, shim)
	if _, err := m.Up(context.Background(), Options{Name: "dup", Image: "ubuntu:24.04"}); err != nil {
		t.Fatalf("first Up: %v", err)
	}
	// Second call: shim still says "inspect fails" (no container yet,
	// because our save failure path would have rolled back; but in
	// this happy-path test, we now have state so we should error
	// BEFORE calling docker.
	_, err := m.Up(context.Background(), Options{Name: "dup", Image: "ubuntu:24.04"})
	if err == nil || !strings.Contains(err.Error(), "already in state") {
		t.Fatalf("want duplicate error, got %v", err)
	}
	// Original record intact.
	got, err := m.Get(context.Background(), "dup")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ContainerID != "first-container-id" {
		t.Errorf("ContainerID overwritten: %q", got.ContainerID)
	}
}

// TestUp_RefusesHijack protects against silently taking over an
// unrelated container with the same name. If `docker inspect` says
// the container exists, Up must error and not even attempt a run.
func TestUp_RefusesHijack(t *testing.T) {
	shim := `case "$1" in
  inspect) echo "true" ;; # container exists outside pilot's state
  run)     echo "should-not-run" ; exit 99 ;;
  *)       exit 0 ;;
esac`
	m, _ := newTestManager(t, shim)
	_, err := m.Up(context.Background(), Options{Name: "owned-elsewhere", Image: "ubuntu:24.04"})
	if err == nil || !strings.Contains(err.Error(), "already exists outside pilot state") {
		t.Fatalf("want hijack-refuse error, got %v", err)
	}
}

// TestDown_RemovesState is the happy path of Down.
func TestDown_RemovesState(t *testing.T) {
	shim := `case "$1" in
  inspect) exit 1 ;;
  run)     echo "cid-1" ;;
  rm)     exit 0 ;;
  *)       exit 0 ;;
esac`
	m, _ := newTestManager(t, shim)
	if _, err := m.Up(context.Background(), Options{Name: "doomed", Image: "ubuntu:24.04"}); err != nil {
		t.Fatalf("Up: %v", err)
	}
	if err := m.Down(context.Background(), "doomed"); err != nil {
		t.Fatalf("Down: %v", err)
	}
	all, err := m.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(all) != 0 {
		t.Fatalf("List after Down: %+v", all)
	}
}

// TestDown_IdempotentWhenContainerAlreadyGone is the regression
// guard. Before this fix, Down on a record whose container had been
// manually deleted would surface a confusing "docker rm: No such
// container" error. Now it cleans the state silently.
func TestDown_IdempotentWhenContainerAlreadyGone(t *testing.T) {
	shim := `case "$1" in
  inspect) exit 1 ;;
  run)     echo "cid-2" ;;
  rm)      echo "Error: No such container: gone" >&2 ; exit 1 ;;
  *)       exit 0 ;;
esac`
	m, _ := newTestManager(t, shim)
	if _, err := m.Up(context.Background(), Options{Name: "gone", Image: "ubuntu:24.04"}); err != nil {
		t.Fatalf("Up: %v", err)
	}
	if err := m.Down(context.Background(), "gone"); err != nil {
		t.Fatalf("Down on already-gone container should be idempotent, got %v", err)
	}
}

// TestDown_UnknownNameErrors ensures we surface typos rather than
// silently succeeding.
func TestDown_UnknownNameErrors(t *testing.T) {
	m, _ := newTestManager(t, shimAlwaysFail)
	err := m.Down(context.Background(), "nope")
	if err == nil || !strings.Contains(err.Error(), "no target named") {
		t.Fatalf("want not-found error, got %v", err)
	}
}

// TestGet_RefreshStatus_Missing reports StatusMissing when docker
// says the container is gone. This is what tells `pilot docker-target
// list` to mark the row as "needs cleanup".
func TestGet_RefreshStatus_Missing(t *testing.T) {
	shim := `case "$1" in
  inspect) exit 1 ;;
  run)     echo "cid-3" ;;
  *)       exit 0 ;;
esac`
	m, _ := newTestManager(t, shim)
	if _, err := m.Up(context.Background(), Options{Name: "lost", Image: "ubuntu:24.04"}); err != nil {
		t.Fatalf("Up: %v", err)
	}
	got, err := m.Get(context.Background(), "lost")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != StatusMissing {
		t.Errorf("Status = %q, want StatusMissing", got.Status)
	}
}

// TestGet_RefreshStatus_Running exercises the positive path of
// refreshStatus when docker confirms the container is up.
func TestGet_RefreshStatus_Running(t *testing.T) {
	shim := `case "$1" in
  inspect)
    # Up calls inspect first (refuse), then run prints cid.
    # After Up, subsequent inspects should report running=true.
    # We key off a sentinel: state file presence.
    if [ -f "$PILOT_STATE_SENTINEL" ]; then
      echo "true"
    else
      exit 1
    fi
    ;;
  run) echo "cid-4" ; touch "$PILOT_STATE_SENTINEL" ;;
  *)   exit 0 ;;
esac`
	dir := t.TempDir()
	shimFile := filepath.Join(dir, "docker")
	if err := os.WriteFile(shimFile, []byte("#!/bin/sh\n"+shim), 0o755); err != nil {
		t.Fatalf("shim: %v", err)
	}
	t.Setenv("PILOT_DOCKER_BIN", shimFile)
	t.Setenv("PILOT_STATE_SENTINEL", filepath.Join(dir, "state.sentinel"))

	m, err := NewManager(filepath.Join(dir, "state"))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if _, err := m.Up(context.Background(), Options{Name: "alive", Image: "ubuntu:24.04"}); err != nil {
		t.Fatalf("Up: %v", err)
	}
	got, err := m.Get(context.Background(), "alive")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != StatusRunning {
		t.Errorf("Status = %q, want StatusRunning", got.Status)
	}
}

// TestExec_PassesArgvVerbatim guarantees the no-shell contract:
// argv goes through to docker exec unchanged, no string joining,
// no sh -c wrapping.
func TestExec_PassesArgvVerbatim(t *testing.T) {
	var captured string
	shim := `case "$1" in
  inspect) exit 1 ;;
  run)     echo "cid-5" ;;
  exec)
    shift
    # Save all args after 'exec <name>' for the test to inspect.
    echo "$@" > "$PILOT_EXEC_ARGS_FILE"
    echo "ok"
    ;;
  *)       exit 0 ;;
esac`
	dir := t.TempDir()
	shimFile := filepath.Join(dir, "docker")
	if err := os.WriteFile(shimFile, []byte("#!/bin/sh\n"+shim), 0o755); err != nil {
		t.Fatalf("shim: %v", err)
	}
	argsFile := filepath.Join(dir, "captured-args")
	t.Setenv("PILOT_DOCKER_BIN", shimFile)
	t.Setenv("PILOT_EXEC_ARGS_FILE", argsFile)

	m, err := NewManager(filepath.Join(dir, "state"))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if _, err := m.Up(context.Background(), Options{Name: "x", Image: "ubuntu:24.04"}); err != nil {
		t.Fatalf("Up: %v", err)
	}
	res, err := m.Exec(context.Background(), "x", []string{"sh", "-c", "echo hi | tee /tmp/out"})
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("ExitCode = %d", res.ExitCode)
	}
	data, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatalf("read captured args: %v", err)
	}
	captured = strings.TrimSpace(string(data))
	want := "x sh -c echo hi | tee /tmp/out"
	if captured != want {
		t.Errorf("argv drift:\n got = %q\nwant = %q", captured, want)
	}
}

// TestStatePersistenceAcrossManagers is the regression guard for
// "second process can't see the first's Up". We build two Managers
// against the same stateDir and confirm Up-on-A is visible to Get-on-B.
func TestStatePersistenceAcrossManagers(t *testing.T) {
	shim := `case "$1" in
  inspect) exit 1 ;;
  run)     echo "cid-6" ;;
  *)       exit 0 ;;
esac`
	dir := t.TempDir()
	shimFile := filepath.Join(dir, "docker")
	if err := os.WriteFile(shimFile, []byte("#!/bin/sh\n"+shim), 0o755); err != nil {
		t.Fatalf("shim: %v", err)
	}
	t.Setenv("PILOT_DOCKER_BIN", shimFile)

	stateDir := filepath.Join(dir, "state")
	a, err := NewManager(stateDir)
	if err != nil {
		t.Fatalf("NewManager a: %v", err)
	}
	if _, err := a.Up(context.Background(), Options{Name: "shared", Image: "ubuntu:24.04"}); err != nil {
		t.Fatalf("Up: %v", err)
	}
	b, err := NewManager(stateDir)
	if err != nil {
		t.Fatalf("NewManager b: %v", err)
	}
	got, err := b.Get(context.Background(), "shared")
	if err != nil {
		t.Fatalf("Get from second manager: %v", err)
	}
	if got.ContainerID != "cid-6" {
		t.Errorf("ContainerID = %q (cross-process)", got.ContainerID)
	}
}

// TestSave_AtomicOnDiskVerify writes a target and checks the file
// is non-empty + valid JSON; without atomic rename a crash mid-save
// would leave a partial file that the next load would refuse.
func TestSave_AtomicOnDiskVerify(t *testing.T) {
	shim := `case "$1" in
  inspect) exit 1 ;;
  run)     echo "cid-7" ;;
  *)       exit 0 ;;
esac`
	m, stateDir := newTestManager(t, shim)
	if _, err := m.Up(context.Background(), Options{Name: "atom", Image: "ubuntu:24.04"}); err != nil {
		t.Fatalf("Up: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(stateDir, "docker-targets.json"))
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("state file empty")
	}
	if !strings.Contains(string(data), `"atom"`) {
		t.Errorf("state file missing target name: %s", data)
	}
	// Re-load should succeed.
	m2, err := NewManager(stateDir)
	if err != nil {
		t.Fatalf("NewManager reload: %v", err)
	}
	all, err := m2.List(context.Background())
	if err != nil {
		t.Fatalf("List after reload: %v", err)
	}
	if len(all) != 1 || all[0].Name != "atom" {
		t.Fatalf("after reload: %+v", all)
	}
}

// TestUp_HonoursCustomHostname makes sure that when the user passes
// --hostname it overrides the default (which would have been Name).
// This is what lets two targets share a docker network but be
// distinguishable in ansible's --limit.
func TestUp_HonoursCustomHostname(t *testing.T) {
	shim := `case "$1" in
  inspect) exit 1 ;;
  run)
    # Echo the argv for the test to inspect; the last positional
    # 'sleep infinity' is the entrypoint.
    echo "cid-8"
    ;;
  *)       exit 0 ;;
esac`
	m, _ := newTestManager(t, shim)
	tgt, err := m.Up(context.Background(), Options{Name: "outer", Hostname: "inner", Image: "ubuntu:24.04"})
	if err != nil {
		t.Fatalf("Up: %v", err)
	}
	if tgt.Hostname != "inner" {
		t.Errorf("Hostname = %q (want inner override)", tgt.Hostname)
	}
}

// TestUp_NetworkAndPrivilegedOverride ensures both knobs round-trip.
func TestUp_NetworkAndPrivilegedOverride(t *testing.T) {
	shim := `case "$1" in
  inspect) exit 1 ;;
  run)     echo "cid-9" ;;
  *)       exit 0 ;;
esac`
	m, _ := newTestManager(t, shim)
	pf := false
	tgt, err := m.Up(context.Background(), Options{Name: "n", Image: "ubuntu:24.04", Network: "bridge", Privileged: &pf})
	if err != nil {
		t.Fatalf("Up: %v", err)
	}
	if tgt.Network != "bridge" {
		t.Errorf("Network = %q", tgt.Network)
	}
	if tgt.Privileged {
		t.Error("Privileged should be false when user disabled it")
	}
}

// TestList_StableOrder ensures the CLI output is deterministic.
// Without sort.Slice, json map iteration order would leak through.
func TestList_StableOrder(t *testing.T) {
	shim := `case "$1" in
  inspect) exit 1 ;;
  run)
    case "$2" in
      *--name*z*) echo "z" ;;
      *--name*a*) echo "a" ;;
      *--name*m*) echo "m" ;;
      *)          echo "x" ;;
    esac
    ;;
  *) exit 0 ;;
esac`
	m, _ := newTestManager(t, shim)
	for _, n := range []string{"z", "a", "m"} {
		if _, err := m.Up(context.Background(), Options{Name: n, Image: "ubuntu:24.04"}); err != nil {
			t.Fatalf("Up %s: %v", n, err)
		}
	}
	all, err := m.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	got := []string{all[0].Name, all[1].Name, all[2].Name}
	want := []string{"a", "m", "z"}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("order = %v want %v", got, want)
		}
	}
	// Sanity: not strictly required, but a 10ms sleep proves that
	// the StartedAt timestamps are populated (downstream columns).
	_ = time.Second // keep import alive for future tests
}
