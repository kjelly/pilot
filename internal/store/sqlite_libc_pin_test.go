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
	"os"
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
//
// It reads the requirement from sqlite's own go.mod rather than from
// `go mod graph`: the graph needs the go.mod of every module in the build
// list, including ones no package build ever downloads (for example the
// Windows-only mousetrap), so it fails offline or under GOPROXY=off even
// after `go test ./...` has compiled everything. sqlite's go.mod is always
// in the module cache once the store package builds.
func TestModerncLibcMatchesSQLitePin(t *testing.T) {
	selected := goCommand(t, "list", "-m", "-f", "{{.Path}} {{.Version}} {{.GoMod}}", sqliteModule, libcModule)
	type module struct{ version, goMod string }
	modules := map[string]module{}
	for line := range strings.SplitSeq(strings.TrimSpace(selected), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 {
			t.Fatalf("unexpected `go list -m` line %q", line)
		}
		modules[fields[0]] = module{version: fields[1], goMod: fields[2]}
	}
	sqlite, libc := modules[sqliteModule], modules[libcModule]
	if sqlite.version == "" || sqlite.goMod == "" || libc.version == "" {
		t.Fatalf("could not resolve selected versions from `go list -m`:\n%s", selected)
	}

	goMod, err := os.ReadFile(sqlite.goMod)
	if err != nil {
		t.Fatalf("read %s@%s go.mod: %v", sqliteModule, sqlite.version, err)
	}
	required := libcRequiredIn(string(goMod))
	if required == "" {
		t.Fatalf("%s has no %s requirement", sqlite.goMod, libcModule)
	}
	if libc.version != required {
		t.Fatalf("%s is %s, but %s@%s was built for %s@%s; pin it with `go get %s@%s`",
			libcModule, libc.version, sqliteModule, sqlite.version, libcModule, required, libcModule, required)
	}
}

// libcRequiredIn returns the modernc.org/libc version that a go.mod file
// requires, in either the block or the single-line require form, or "" if
// it has none.
func libcRequiredIn(goMod string) string {
	inBlock := false
	for line := range strings.SplitSeq(goMod, "\n") {
		line, _, _ = strings.Cut(line, "//")
		fields := strings.Fields(line)
		switch {
		case len(fields) == 0:
			continue
		case inBlock && fields[0] == ")":
			inBlock = false
			continue
		case fields[0] == "require" && len(fields) == 2 && fields[1] == "(":
			inBlock = true
			continue
		case fields[0] == "require":
			fields = fields[1:]
		case !inBlock:
			continue
		}
		if len(fields) == 2 && fields[0] == libcModule {
			return fields[1]
		}
	}
	return ""
}

// The go.mod excerpts below are copied from the module cache
// (cache/download/modernc.org/sqlite/@v/<version>.mod).
func TestLibcRequiredIn(t *testing.T) {
	cases := map[string]struct{ goMod, want string }{
		"sqlite v1.34.4": {want: "v1.55.3", goMod: `module modernc.org/sqlite

go 1.21

require (
	github.com/google/pprof v0.0.0-20240409012703-83162a5b38cd
	golang.org/x/sys v0.22.0
	modernc.org/fileutil v1.3.0
	modernc.org/gc/v3 v3.0.0-20240107210532-573471604cb6
	modernc.org/libc v1.55.3
	modernc.org/mathutil v1.6.0
)
`},
		"sqlite v1.59.0": {want: "v1.75.7", goMod: `module modernc.org/sqlite

go 1.25.0

require (
	github.com/google/pprof v0.0.0-20260802141513-ef3492d7dac3
	golang.org/x/sys v0.47.0
	modernc.org/fileutil v1.4.0
	modernc.org/libc v1.75.7
	modernc.org/mathutil v1.7.1
)

require (
	github.com/dustin/go-humanize v1.0.1 // indirect
	modernc.org/memory v1.12.1 // indirect
)

retract v1.42.0 // Accidentaly broken, reverting to v1.41.0 state
`},
		"single-line require":                 {want: "v1.2.3", goMod: "module example.com/m\n\nrequire modernc.org/libc v1.2.3 // indirect\n"},
		"libc only mentioned outside require": {want: "", goMod: "module example.com/m\n\n// modernc.org/libc v9.9.9\nreplace modernc.org/libc v1.0.0 => ../libc\n"},
		"no libc":                             {want: "", goMod: "module example.com/m\n\nrequire (\n\tmodernc.org/mathutil v1.7.1\n)\n"},
	}
	for name, tc := range cases {
		if got := libcRequiredIn(tc.goMod); got != tc.want {
			t.Errorf("%s: libcRequiredIn() = %q, want %q", name, got, tc.want)
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
