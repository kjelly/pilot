package cmd

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// resolvePatternHosts parses what `ansible <pattern> --list-hosts` prints, and tells an
// empty match from a failure by its exit code and its message. The tests that existed
// replayed an `ansible` somebody wrote from memory (deploy_test.go); this one replays
// what the real ansible-core 2.19 printed on the disposable FreeIPA lab, captured for
// Phase 2 P2-3 (K16): stdout, stderr and the exit code of an empty match, a limit that
// leaves nothing, a limit naming no host, one host and two (AGENTS.md §5.6).
func TestResolvePatternHostsAgainstRealListHostsOutput(t *testing.T) {
	captures := filepath.Join("..", "..", "..", "internal", "identityreconcile", "testdata", "authcache")
	replay := func(t *testing.T, name string, alter func(stderr string) string) {
		t.Helper()
		read := func(ext string) string {
			b, err := os.ReadFile(filepath.Join(captures, name+"."+ext))
			if err != nil {
				t.Fatal(err)
			}
			return string(b)
		}
		stderr := read("stderr")
		if alter != nil {
			stderr = alter(stderr)
		}
		bin := t.TempDir()
		for ext, body := range map[string]string{"stdout": read("stdout"), "stderr": stderr} {
			if err := os.WriteFile(filepath.Join(bin, ext), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		script := "#!/bin/sh\ncat '" + filepath.Join(bin, "stdout") + "'\ncat '" + filepath.Join(bin, "stderr") + "' >&2\nexit " + strings.TrimSpace(read("rc")) + "\n"
		if err := os.WriteFile(filepath.Join(bin, "ansible"), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
		t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	}

	for _, tc := range []struct {
		capture string
		limit   string
		want    []string
	}{
		// without --limit an empty match is a warning and exit 0, with "hosts (0):"
		{"k16-listhosts-empty-group", "", []string{}},
		// with --limit it is an error and exit 1, which is the same empty match
		{"k16-listhosts-empty-limit", "client-1", []string{}},
		{"k16-listhosts-unknown-limit", "no-such-host", []string{}},
		{"k16-listhosts-one", "", []string{"ipa-1"}},
		{"k16-listhosts-multi", "", []string{"client-1", "ipa-1"}},
		{"k16-listhosts-multi-limited-to-one", "ipa-1", []string{"ipa-1"}},
	} {
		t.Run(tc.capture, func(t *testing.T) {
			replay(t, tc.capture, nil)
			got, err := resolvePatternHosts(context.Background(), "inventory.yml", "freeipa-server", tc.limit)
			if err != nil || !slices.Equal(got, tc.want) {
				t.Fatalf("resolvePatternHosts = %v, %v; want %v", got, err, tc.want)
			}
		})
	}

	// The same exit 1 is an empty match only because of what it says and because a limit
	// was given: another message, or no limit, is a failure that must not read as "no
	// hosts" (a play that then runs against nothing would report success).
	t.Run("the real error with another message is a failure", func(t *testing.T) {
		replay(t, "k16-listhosts-empty-limit", func(s string) string {
			return strings.ReplaceAll(s, "leaves us with no hosts to target", "could not read the inventory")
		})
		if got, err := resolvePatternHosts(context.Background(), "inventory.yml", "freeipa-server", "client-1"); err == nil {
			t.Fatalf("an unknown failure was taken for an empty match: %v", got)
		}
	})
	t.Run("the real error without a limit is a failure", func(t *testing.T) {
		replay(t, "k16-listhosts-empty-limit", nil)
		if got, err := resolvePatternHosts(context.Background(), "inventory.yml", "freeipa-server", ""); err == nil {
			t.Fatalf("exit 1 without a limit was taken for an empty match: %v", got)
		}
	})
}
