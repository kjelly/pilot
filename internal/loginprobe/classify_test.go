package loginprobe

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// captureCase loads one real capture from testdata/capture/<name>: the
// unmodified `ssh -v` stderr and the exit code recorded next to it
// (2026-10-13, four-node vm-target topology, AGENTS.md §5.6).
func captureCase(t *testing.T, name string) RawResult {
	t.Helper()
	dir := filepath.Join("testdata", "capture", name)
	stderr, err := os.ReadFile(filepath.Join(dir, "stderr"))
	if err != nil {
		t.Fatalf("read capture %s: %v", name, err)
	}
	meta, err := os.ReadFile(filepath.Join(dir, "meta"))
	if err != nil {
		t.Fatalf("read capture %s meta: %v", name, err)
	}
	rc := -100
	for _, line := range strings.Split(string(meta), "\n") {
		if v, ok := strings.CutPrefix(line, "rc="); ok {
			rc, err = strconv.Atoi(strings.TrimSpace(v))
			if err != nil {
				t.Fatalf("capture %s: bad rc %q", name, v)
			}
		}
	}
	if rc == -100 {
		t.Fatalf("capture %s has no rc", name)
	}
	return RawResult{ExitCode: rc, Stderr: string(stderr)}
}

// Every capture must land in exactly the stage the injected fault belongs
// to. Because each expectation is a single stage, every case is at once a
// "should classify as X" and a "must not classify as anything else" case
// (AGENTS.md §5.12).
var captureExpectations = map[string]Stage{
	"ok-ubuntu":                           StageOK,
	"ok-el":                               StageOK,
	"ok-ip-address":                       StageOK,
	"ok-ipa-server-stopped":               StageOK, // SSSD offline cache keeps logins working
	"session-command-exit-1":              StageSession,
	"session-command-not-found":           StageSession,
	"auth-unknown-user-ubuntu":            StageAuth,
	"auth-unknown-user-el":                StageAuth,
	"auth-key-not-published-ubuntu":       StageAuth,
	"auth-key-not-published-el":           StageAuth,
	"account-hbac-disabled-ubuntu":        StageAccount,
	"account-hbac-disabled-el":            StageAccount,
	"account-user-disabled-ubuntu":        StageAccount,
	"account-user-disabled-el":            StageAccount,
	"timeout-sssd-be-frozen-ubuntu":       StageTimeout,
	"timeout-sssd-be-frozen-el":           StageTimeout,
	"timeout-sssd-pam-frozen-ubuntu":      StageTimeout,
	"timeout-sssd-nss-frozen-ubuntu":      StageTimeout,
	"timeout-sssd-service-stopped-ubuntu": StageTimeout,
	"hostkey-rekeyed-ubuntu":              StageHostKey,
	"hostkey-not-enrolled":                StageHostKey,
	"transport-sshd-stopped-ubuntu":       StageTransport,
	"transport-sshd-stopped-el":           StageTransport,
	"transport-port-rejected":             StageTransport,
	"transport-port-dropped":              StageTransport,
	"transport-unresolvable":              StageTransport,
}

func TestClassify_RealCaptures(t *testing.T) {
	entries, err := os.ReadDir(filepath.Join("testdata", "capture"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(captureExpectations) {
		t.Errorf("testdata/capture has %d captures, expectations cover %d — every capture needs an expected stage", len(entries), len(captureExpectations))
	}
	for name, want := range captureExpectations {
		t.Run(name, func(t *testing.T) {
			got, why := Classify(captureCase(t, name))
			if got != want {
				t.Errorf("Classify = %s (%s), want %s", got, why, want)
			}
			if got != StageOK && why == "" {
				t.Error("a failure must carry a reason")
			}
		})
	}
}

// Each stage has at least one capture that triggers it and at least one
// that must not — so no stage's matcher can silently never fire or always
// fire.
func TestClassify_EveryStageIsBothTriggeredAndRejected(t *testing.T) {
	triggered := map[Stage]bool{}
	for _, want := range captureExpectations {
		triggered[want] = true
	}
	for _, s := range AllStages {
		if !triggered[s] {
			t.Errorf("no real capture triggers stage %s", s)
		}
	}
	if len(triggered) < 2 {
		t.Fatal("captures must cover more than one stage")
	}
}

func TestClassify_RemoteOutputCannotForgeAStage(t *testing.T) {
	ok := captureCase(t, "ok-ubuntu")
	// A remote command (or motd) printing a failure marker after the login
	// must not turn a completed login into auth/hostkey.
	forged := ok
	forged.Stderr += "pilot-login-canary@x: Permission denied (publickey).\nHost key verification failed.\n"
	if got, _ := Classify(forged); got != StageOK {
		t.Errorf("forged markers after a completed login: got %s, want ok", got)
	}
	// A mid-line occurrence of the success phrase must not count.
	denied := captureCase(t, "account-hbac-disabled-ubuntu")
	denied.Stderr = "banner: Authenticated to everything using \"publickey\".\n" + denied.Stderr
	if got, _ := Classify(denied); got != StageAccount {
		t.Errorf("mid-line success phrase: got %s, want account", got)
	}
}

func TestClassify_SyntheticRunnerOutcomes(t *testing.T) {
	cases := []struct {
		name string
		in   RawResult
		want Stage
	}{
		{"total timeout wins over any output", RawResult{TimedOut: true, ExitCode: -1, Stderr: captureCase(t, "ok-ubuntu").Stderr}, StageTimeout},
		{"ssh could not start", RawResult{ExitCode: -1, StartErr: errors.New("start /usr/bin/ssh: no such file")}, StageTransport},
		{"session dropped after login", RawResult{ExitCode: 255, Stderr: captureCase(t, "ok-ubuntu").Stderr}, StageSession},
		{"exit 0 without an authentication record", RawResult{ExitCode: 0, Stderr: "debug1: Exit status 0\n"}, StageSession},
		{"empty output, non-zero exit", RawResult{ExitCode: 255}, StageTransport},
	}
	for _, c := range cases {
		if got, _ := Classify(c.in); got != c.want {
			t.Errorf("%s: got %s, want %s", c.name, got, c.want)
		}
	}
}
