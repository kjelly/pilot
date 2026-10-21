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
[ "$*" = "test -count=1 -timeout 30m ./..." ] || [ "$*" = "test -race -count=1 -timeout 30m ./..." ]
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
