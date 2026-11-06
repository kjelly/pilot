package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/sshdial"
)

// Each refusal of the Go apply on its own row (AGENTS.md §5.12; the ledger of
// reconcile_golang_ledger_test.go ties the gate ids to the code): the message, the exit code, and
// how little had happened by then. The run's own outcomes are in TestReconcileGolangApplyEndToEnd.
func TestReconcileGolangApplyRefusals(t *testing.T) {
	for _, tc := range []struct {
		name   string
		gate   string
		args   []string
		groups map[string][]string
		setup  func(t *testing.T, e *applyEnv, dir string)
		want   string
		// connected: whether the run was allowed to get as far as the tunnel.
		connected bool
		// locked: whether the lock was asked for (and so given back).
		locked bool
	}{
		{name: "a bad --timeout", gate: "apply-timeout-parse", args: applyArgs("--timeout", "soon"), want: "--timeout 不是合法的 duration"},
		{name: "a prod host without --stage prod", gate: "stage-gate,apply-preflight", args: applyArgs(), want: "在 prod group",
			groups: map[string][]string{"prod": {"ipa-1"}}},
		{name: "the inventory cannot give the lock", gate: "apply-lock-precheck", args: applyArgs(), want: "取鎖前檢查沒有通過",
			setup: func(t *testing.T, e *applyEnv, _ string) {
				e.lock.PrecheckErr = errors.New("ansible_connection=docker")
			}},
		{name: "the lock is busy", gate: "apply-lock-acquire", args: applyArgs("--lock-wait", "0"), want: "沒有取得鎖，沒有任何寫入", locked: true,
			setup: func(t *testing.T, e *applyEnv, _ string) {
				e.lock.Err = fmt.Errorf("busy: %w", sshdial.ErrLockBusy)
			}},
		{name: "the delivery store cannot be opened", gate: "apply-store", args: applyArgs(), want: "open deployment evidence store", connected: true, locked: true,
			setup: func(t *testing.T, e *applyEnv, _ string) {
				// history.db is a directory, so the store cannot open it
				if err := os.MkdirAll(filepath.Join(dataDir, "history.db"), 0o700); err != nil {
					t.Fatal(err)
				}
			}},
		{name: "the --result-out path exists", gate: "output-exists,apply-result-out", want: "已存在；不覆寫",
			args: applyArgs("--result-out", "EXISTING"),
			setup: func(t *testing.T, e *applyEnv, dir string) {
				writePrivateFile(t, filepath.Join(dir, "EXISTING"), "keep")
			}},
		{name: "the --result-out directory does not exist", gate: "output-dir", want: "上層目錄", args: applyArgs("--result-out", "missing/result.json")},
		{name: "the tunnel cannot be made (the FQDN is unreadable)", gate: "fqdn-read,apply-connect,apply-before-first-read", args: applyArgs(), want: "讀取 ipa-1 的 FQDN", connected: true, locked: true,
			setup: func(t *testing.T, e *applyEnv, _ string) {
				golangDialerFaults.fqdnErr = errors.New("synthetic hostname -f failure")
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("gate: %s", tc.gate)
			e := newApplyEnvWith(t, rosterWithNewUser(), tc.groups)
			if tc.setup != nil {
				tc.setup(t, e, e.dir)
			}
			args := tc.args
			for i, a := range args {
				if a == "EXISTING" {
					args[i] = filepath.Join(e.dir, "EXISTING")
				}
			}
			out, err := runReconcileCLI(t, args...)
			if err == nil || !strings.Contains(err.Error(), tc.want) || processExitCode(err) != 1 {
				t.Fatalf("err = %v (exit %d), want %q and exit 1\n%s", err, processExitCode(err), tc.want, out)
			}
			if len(e.a.writeMethods()) != 0 {
				t.Fatalf("a write was sent: %v", e.a.writeMethods())
			}
			if !tc.connected {
				assertNoLogin(t, e.f)
			}
			if tc.locked {
				if evs := readEvents(t, e.events); len(e.lock.Requests()) != 1 && tc.name != "the lock is busy" || (evs != nil && evs[len(evs)-1] != "release ipa-1") {
					t.Fatalf("lock requests %d, events %v: a lock that was taken must be given back", len(e.lock.Requests()), evs)
				}
			}
			assertNoSecretAnywhere(t, err, out, "")
		})
	}
}

// reserveOutput and commitOutput on rows of their own: the two gates no command row can reach,
// since a flag value cannot hold a NUL and a file that was just created cannot be made to fail
// to take its bytes from the command line.
func TestOutputFileGates(t *testing.T) {
	for _, tc := range []struct {
		name string
		gate string
		run  func(t *testing.T) error
		want string
	}{
		{name: "a path the file system refuses", gate: "output-create", want: "--result-out", run: func(t *testing.T) error {
			_, err := reserveOutput("--result-out", filepath.Join(t.TempDir(), "bad\x00name"))
			return err
		}},
		{name: "a write that fails removes the file", gate: "output-write", want: "--result-out", run: func(t *testing.T) error {
			path := filepath.Join(t.TempDir(), "r.json")
			o, err := reserveOutput("--result-out", path)
			if err != nil {
				t.Fatal(err)
			}
			_ = o.f.Close() // the next write fails
			err = commitOutput(o, []byte("data"))
			if _, serr := os.Stat(path); serr == nil {
				t.Fatal("a file that could not be written was left behind (#274)")
			}
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("gate: %s", tc.gate)
			if err := tc.run(t); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want one holding %q", err, tc.want)
			}
		})
	}
}
