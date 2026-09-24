package spec

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// An OpenSSH ControlPath is a Unix socket path, so it must fit in 108 bytes,
// and ssh appends a 17-byte temporary suffix while creating a master. A
// template that embeds the host (%h, usually as %r@%h:%p) grows with every
// FQDN, and one rooted under a configurable directory grows with that
// directory too. f469407 fixed this for MCP diagnose only; pilot deploy
// (cmd/pilot/cmd/deploy.go), ansible.cfg and the vm-target inventory kept
// %r@%h:%p until a deep --data-dir made every deploy preflight UNREACHABLE
// ("ControlPath too long"). Every template now uses %C, OpenSSH's
// fixed-length hash of the connection tuple.
var (
	// hostTupleIdiom matches the %r@%h:%p idiom anywhere, including where
	// Go code builds the path on a line without the word ControlPath.
	// %% covers fmt format strings.
	hostTupleIdiom = regexp.MustCompile(`%{1,2}r@%{1,2}h`)
	// controlPathWithHost matches a ControlPath setting whose value
	// embeds %h.
	controlPathWithHost = regexp.MustCompile(`(?i)control_?path[=:\s"']+\S*%{1,2}h`)
)

// unboundedControlPath reports whether line contains a ControlPath template
// whose length depends on the host name.
func unboundedControlPath(line string) bool {
	return hostTupleIdiom.MatchString(line) || controlPathWithHost.MatchString(line)
}

var controlPathLintExtensions = map[string]bool{
	".go": true, ".cfg": true, ".yml": true, ".yaml": true, ".sh": true,
	".j2": true, ".py": true, ".conf": true, ".toml": true,
}

func TestRegression_SSHControlPathTemplatesAreBounded(t *testing.T) {
	root := filepath.Join("..", "..")
	skipDirs := map[string]bool{".git": true, "tmp": true, ".verification": true, "node_modules": true, "docs": true}
	var offenders []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDirs[d.Name()] && path != root {
				return filepath.SkipDir
			}
			return nil
		}
		if !controlPathLintExtensions[filepath.Ext(path)] || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close() //nolint:errcheck
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for n := 1; scanner.Scan(); n++ {
			if unboundedControlPath(scanner.Text()) {
				rel, _ := filepath.Rel(root, path)
				offenders = append(offenders, fmt.Sprintf("%s:%d: %s", rel, n, strings.TrimSpace(scanner.Text())))
			}
		}
		return scanner.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(offenders) > 0 {
		t.Fatalf("SSH ControlPath templates must not embed the host (use %%C):\n%s", strings.Join(offenders, "\n"))
	}
}

func TestUnboundedControlPath(t *testing.T) {
	cases := map[string]bool{
		`ssh_args = -o ControlMaster=auto -o ControlPath=~/.ansible/cp/pilot-%r@%h:%p -o ControlPersist=60s`: true,
		`fmt.Fprintf(&sb, "-o ControlPath=~/.ansible/cp/pilot-%%r@%%h:%%p -o ControlPersist=60s")`:           true,
		`strconv.Quote(filepath.Join(sshControl, "pilot-%r@%h:%p"))`:                                         true,
		`    ControlPath ~/.ssh/cm-%h`: true,
		`ssh_args = -o ControlMaster=auto -o ControlPath=~/.ansible/cp/pilot-%C -o ControlPersist=60s`: false,
		`fmt.Fprintf(&sb, "-o ControlPath=~/.ansible/cp/pilot-%%C")`:                                   false,
		`strconv.Quote(filepath.Join(sshControl, "%C"))`:                                               false,
		`    ControlPath ~/.pilot-e2e/cm-%C`:                                                           false,
		`// ControlPath is unique to this one diagnose tool call.`:                                     false,
	}
	for line, want := range cases {
		if got := unboundedControlPath(line); got != want {
			t.Errorf("unboundedControlPath(%q) = %v, want %v", line, got, want)
		}
	}
}
