package cmd

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Exercise GNU make's actual scheduling: declaring the suites as prerequisites
// would race under -j even though an ordinary make invocation appears ordered.
func TestCompleteTestSuitesRunSequentially(t *testing.T) {
	makePath, err := exec.LookPath("make")
	if err != nil {
		t.Skip("make not installed")
	}
	// CI exports a shard; this harness intentionally exercises both full suites.
	t.Setenv("GO_TEST_PACKAGES", "./internal/evidence")
	t.Setenv("GO_TEST_REPORT_DIR", filepath.Join(t.TempDir(), "must-not-report"))
	t.Setenv("GO_TEST_JSON", "1")
	t.Setenv("GO_TEST_RUN_REGEX", "^TestMustNotFilterCompleteSuites$")
	t.Setenv("CI_SHARD_INDEX", "0")
	root := repoRootForTest(t)
	for _, failNormal := range []bool{false, true} {
		name := "success"
		if failNormal {
			name = "normal failure stops race"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			stub := `#!/bin/sh
set -eu
mode=normal
case " $* " in *" -race "*) mode=race;; esac
[ "$*" = "test -count=1 -timeout 45m ./..." ] || [ "$*" = "test -race -count=1 -timeout 45m ./..." ]
printf '%s start\n' "$mode" >> "$PILOT_SUITE_EVENTS"
if [ "$mode" = normal ]; then
    if [ "$PILOT_FAIL_NORMAL" = 1 ]; then exit 7; fi
    sleep 0.1
    touch "$PILOT_SUITE_FINISHED"
else
    [ -f "$PILOT_SUITE_FINISHED" ] || exit 8
fi
printf '%s finish\n' "$mode" >> "$PILOT_SUITE_EVENTS"
`
			if err := os.WriteFile(filepath.Join(dir, "go"), []byte(stub), 0o700); err != nil {
				t.Fatal(err)
			}
			eventsPath := filepath.Join(dir, "events")
			failValue := "0"
			if failNormal {
				failValue = "1"
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, makePath, "--no-print-directory", "-j8", "test-all")
			command.Dir = root
			command.Env = append(os.Environ(), "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"),
				"PILOT_SUITE_EVENTS="+eventsPath, "PILOT_SUITE_FINISHED="+filepath.Join(dir, "normal-finished"),
				"PILOT_FAIL_NORMAL="+failValue, "MAKEFLAGS=", "MFLAGS=")
			out, runErr := command.CombinedOutput()
			if (runErr != nil) != failNormal {
				t.Fatalf("make error = %v, normal failure = %v\n%s", runErr, failNormal, out)
			}
			events, err := os.ReadFile(eventsPath)
			if err != nil {
				t.Fatalf("read suite events: %v\n%s", err, out)
			}
			want := "normal start\nnormal finish\nrace start\nrace finish\n"
			if failNormal {
				want = "normal start\n"
			}
			if string(events) != want {
				t.Fatalf("suite execution = %q, want %q\n%s", strings.TrimSpace(string(events)), strings.TrimSpace(want), out)
			}
		})
	}
}

// Command-line variables flow through MAKEOVERRIDES, beyond env -u's reach.
func TestCompleteTestSuitesIgnoreCommandLineSelector(t *testing.T) {
	makePath, err := exec.LookPath("make")
	if err != nil {
		t.Skip("make not installed")
	}
	dir := t.TempDir()
	stub := `#!/bin/sh
set -eu
[ "$*" = "test -count=1 -timeout 45m ./..." ] || [ "$*" = "test -race -count=1 -timeout 45m ./..." ]
`
	if err := os.WriteFile(filepath.Join(dir, "go"), []byte(stub), 0o700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, makePath, "--no-print-directory", "test-all",
		"GO_TEST_RUN_REGEX=^TestSubset$", "GO_TEST_JSON=1", "GO_TEST_REPORT_DIR=must-not-report", "CI_SHARD_INDEX=0")
	command.Dir = repoRootForTest(t)
	command.Env = append(os.Environ(), "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"), "MAKEFLAGS=", "MFLAGS=")
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("full suites inherited a command-line filter: %v\n%s", err, out)
	}
}

func TestRaceSuiteRetainsShardSelection(t *testing.T) {
	makePath, err := exec.LookPath("make")
	if err != nil {
		t.Skip("make not installed")
	}
	command := exec.Command(makePath, "--no-print-directory", "--dry-run", "test-race", "GO_TEST_PACKAGES=./internal/evidence")
	command.Dir = repoRootForTest(t)
	command.Env = append(os.Environ(), "MAKEFLAGS=", "MFLAGS=", "GO_TEST_REPORT_DIR=", "GO_TEST_JSON=")
	out, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("make test-race: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "go test -race -count=1 -timeout 45m ./internal/evidence") || strings.Contains(string(out), "./...") {
		t.Fatalf("direct race target lost shard selection: %s", out)
	}
}
