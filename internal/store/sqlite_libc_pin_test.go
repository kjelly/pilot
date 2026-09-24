// sqlite_libc_pin_test.go guards a version pairing that go.mod cannot
// express on its own. modernc.org/sqlite is SQLite transpiled against one
// exact modernc.org/libc release, and its docs require downstream modules
// to pin that same libc version (https://gitlab.com/cznic/sqlite/-/issues/177).
// Minimal version selection only guarantees "at least" that version, so
// any other requirement, or a blanket `go get -u ./...`, can move libc
// past the one sqlite was built for without an error. This repo shipped
// sqlite v1.34.4 (built for libc v1.55.3) with libc v1.73.4 from its first
// commit until this test was added.
package store

import (
	"errors"
	"os/exec"
	"strings"
	"testing"
)

const (
	sqliteModule = "modernc.org/sqlite"
	libcModule   = "modernc.org/libc"
)

// TestModerncLibcMatchesSQLitePin asserts that the selected
// modernc.org/libc version is exactly the one the selected
// modernc.org/sqlite version requires.
func TestModerncLibcMatchesSQLitePin(t *testing.T) {
	selected := goCommand(t, "list", "-m", "-f", "{{.Path}} {{.Version}}", sqliteModule, libcModule)
	versions := map[string]string{}
	for line := range strings.SplitSeq(strings.TrimSpace(selected), "\n") {
		path, version, ok := strings.Cut(line, " ")
		if !ok {
			t.Fatalf("unexpected `go list -m` line %q", line)
		}
		versions[path] = version
	}
	sqliteVersion, libcVersion := versions[sqliteModule], versions[libcModule]
	if sqliteVersion == "" || libcVersion == "" {
		t.Fatalf("could not resolve selected versions from `go list -m`:\n%s", selected)
	}

	required := libcRequiredBy(goCommand(t, "mod", "graph"), sqliteModule+"@"+sqliteVersion)
	if required == "" {
		t.Fatalf("`go mod graph` has no %s requirement for %s@%s", libcModule, sqliteModule, sqliteVersion)
	}
	if libcVersion != required {
		t.Fatalf("%s is %s, but %s@%s was built for %s@%s; pin it with `go get %s@%s`",
			libcModule, libcVersion, sqliteModule, sqliteVersion, libcModule, required, libcModule, required)
	}
}

// libcRequiredBy returns the modernc.org/libc version that module (as
// "path@version") requires in `go mod graph` output, or "" if none.
func libcRequiredBy(graph, module string) string {
	for line := range strings.SplitSeq(graph, "\n") {
		from, to, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok || from != module {
			continue
		}
		if version, ok := strings.CutPrefix(to, libcModule+"@"); ok {
			return version
		}
	}
	return ""
}

func TestLibcRequiredBy(t *testing.T) {
	graph := strings.Join([]string{
		"github.com/kjelly/pilot modernc.org/libc@v1.73.4",
		"modernc.org/sqlite@v1.34.4 modernc.org/libc@v1.55.3",
		"modernc.org/sqlite@v1.34.4 modernc.org/mathutil@v1.6.0",
		"modernc.org/sqlite@v1.59.0 modernc.org/libc@v1.75.7",
		"",
	}, "\n")
	cases := map[string]string{
		"modernc.org/sqlite@v1.34.4": "v1.55.3",
		"modernc.org/sqlite@v1.59.0": "v1.75.7",
		"modernc.org/sqlite@v1.0.0":  "",
	}
	for module, want := range cases {
		if got := libcRequiredBy(graph, module); got != want {
			t.Errorf("libcRequiredBy(%q) = %q, want %q", module, got, want)
		}
	}
}

func goCommand(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.CommandContext(t.Context(), "go", args...).Output()
	if err != nil {
		var stderr string
		if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
			stderr = string(exitErr.Stderr)
		}
		t.Fatalf("go %s: %v\n%s", strings.Join(args, " "), err, stderr)
	}
	return string(out)
}
