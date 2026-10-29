package cmd

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"regexp"
	"runtime/debug"
	"strings"
	"testing"
	"time"
)

// isolatedCaseEnv, set to a test's name in a re-executed test binary's
// environment, makes runIsolated run that test's body there.
const isolatedCaseEnv = "PILOT_TEST_ISOLATED_CASE"

// runIsolated runs body in a child process of this test binary and fails t
// when the child does not pass within timeout. A stack overflow is a fatal
// error no recover catches and a hang cannot be cancelled, so a test of
// input that may do either must not run in the test process: a failing run
// would take every other test of the package down with it. t must be a test
// or subtest whose name is a safe -test.run pattern after quoting.
func runIsolated(t *testing.T, timeout time.Duration, body func(t *testing.T)) {
	t.Helper()
	if os.Getenv(isolatedCaseEnv) == t.Name() {
		// A runaway recursion then ends at 64 MiB instead of 1 GB.
		debug.SetMaxStack(64 << 20)
		body(t)
		return
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	var pattern []string
	for _, elem := range strings.Split(t.Name(), "/") {
		pattern = append(pattern, "^"+regexp.QuoteMeta(elem)+"$")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "-test.run="+strings.Join(pattern, "/"), "-test.v", "-test.count=1")
	cmd.Env = append(os.Environ(), isolatedCaseEnv+"="+t.Name())
	out, err := cmd.CombinedOutput()
	text := string(out)
	if len(text) > 1500 {
		text = text[:1500] + "\n... (output cut)"
	}
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		t.Fatalf("child did not finish within %s (hang)\n%s", timeout, text)
	case err != nil:
		t.Fatalf("child failed: %v\n%s", err, text)
	case !strings.Contains(string(out), "--- PASS: "+t.Name()):
		// A pattern that matched nothing "passes" with no test run.
		t.Fatalf("child did not run %s\n%s", t.Name(), text)
	}
}
