package cmd

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// scripts/topology-checkmode-test.sh provisions a topology, installs an EXIT
// trap that runs `topology down` on the same spec, and then tests it. vm-target
// is shared by every clone and session on the host, so two things must hold or
// the trap destroys a VM the script did not create:
//
//   - the topology is provisioned with `up --fresh`, which refuses a name that
//     already exists. Plain `up` adopts a running VM that has a declared name.
//   - the trap is installed only after that `up --fresh` has succeeded. A
//     failed `up --fresh` tears down what it created itself; a trap installed
//     before it would also run `topology down` on names it refused, which
//     belong to another session. `set -e` is what stops the script at a failed
//     `up --fresh` before it reaches the trap.
//
// Nothing else may run between the two lines: anything that runs there could
// create a VM before the trap exists to remove it.

var (
	checkmodeUpRE      = regexp.MustCompile(`^\s*\S*pilot\S*\s+vm-target\s+topology\s+up(\s|$)`)
	checkmodeTrapRE    = regexp.MustCompile(`^\s*trap\s+\S+\s+EXIT(\s|$)`)
	checkmodeErrexitRE = regexp.MustCompile(`^\s*set\s+-[a-zA-Z]*e[a-zA-Z]*(\s|$)`)
	checkmodeFuncRE    = regexp.MustCompile(`^\s*[A-Za-z_][A-Za-z0-9_]*\(\)\s*\{\s*$`)
)

// checkmodeScriptProblems returns what is wrong with the order of
// provisioning, `set -e` and the EXIT trap in script; empty means it is right.
func checkmodeScriptProblems(script string) []string {
	type line struct {
		no   int
		text string
	}
	var code []line // executable lines: no blanks, no comments
	for i, l := range strings.Split(script, "\n") {
		if t := strings.TrimSpace(l); t != "" && !strings.HasPrefix(t, "#") {
			code = append(code, line{i + 1, l})
		}
	}
	var ups, traps, errexits []int // indexes into code
	for i, l := range code {
		switch {
		case checkmodeUpRE.MatchString(l.text):
			ups = append(ups, i)
		case checkmodeTrapRE.MatchString(l.text):
			traps = append(traps, i)
		case checkmodeErrexitRE.MatchString(l.text):
			errexits = append(errexits, i)
		}
	}
	var problems []string
	if len(ups) != 1 {
		problems = append(problems, "want exactly one `pilot vm-target topology up` invocation, found "+strconv.Itoa(len(ups)))
	}
	if len(traps) != 1 {
		problems = append(problems, "want exactly one `trap ... EXIT`, found "+strconv.Itoa(len(traps)))
	}
	if len(ups) != 1 || len(traps) != 1 {
		return problems
	}
	up, trap := ups[0], traps[0]
	if !slices.Contains(strings.Fields(code[up].text), "--fresh") {
		problems = append(problems, "line "+strconv.Itoa(code[up].no)+": topology up must pass --fresh, or it adopts a VM another session owns and the EXIT trap destroys it")
	}
	if len(errexits) == 0 || errexits[0] > up {
		problems = append(problems, "set -e must come before the topology up line, or a failed `up --fresh` does not stop the script")
	}
	if trap < up {
		problems = append(problems, "line "+strconv.Itoa(code[trap].no)+": the EXIT trap is installed before `topology up --fresh` succeeded; it would destroy names that command refused")
		return problems
	}
	// Only a function definition may sit between the two: its body does not run.
	for i := up + 1; i < trap; i++ {
		if checkmodeFuncRE.MatchString(code[i].text) {
			for i++; i < trap && !strings.HasPrefix(code[i].text, "}"); i++ {
			}
			continue
		}
		problems = append(problems, "line "+strconv.Itoa(code[i].no)+": "+strings.TrimSpace(code[i].text)+" runs between `topology up --fresh` and the EXIT trap, where it could create a VM nothing removes")
	}
	return problems
}

func readCheckmodeScript(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRootForTest(t), "scripts", "topology-checkmode-test.sh"))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestTopologyCheckmodeScriptInstallsItsTrapOnlyAfterUpFresh(t *testing.T) {
	if problems := checkmodeScriptProblems(readCheckmodeScript(t)); len(problems) > 0 {
		t.Fatalf("scripts/topology-checkmode-test.sh:\n  %s", strings.Join(problems, "\n  "))
	}
}

// TestTopologyCheckmodeScriptCheckerCatchesRegressions runs the checker on the
// real script with one regression applied each, so it is known to fail for the
// reason it names and not to pass on any script with the same words in it.
func TestTopologyCheckmodeScriptCheckerCatchesRegressions(t *testing.T) {
	real := readCheckmodeScript(t)
	const (
		up   = `./pilot vm-target topology up --fresh --topology "$TOPOLOGY"`
		trap = "trap cleanup EXIT\n"
	)
	for _, line := range []string{up, trap, "set -euo pipefail"} {
		if strings.Count(real, line) != 1 {
			t.Fatalf("the script no longer has exactly one %q; update this test with it:\n%s", line, real)
		}
	}
	cases := []struct {
		name   string
		mutate func(string) string
		want   string
	}{
		{"plain up adopts an existing VM", func(s string) string {
			return strings.Replace(s, up, `./pilot vm-target topology up --topology "$TOPOLOGY"`, 1)
		}, "must pass --fresh"},
		{"trap installed before up", func(s string) string {
			return strings.Replace(strings.Replace(s, trap, "", 1), up, trap+up, 1)
		}, "installed before"},
		{"a command between up and the trap", func(s string) string {
			return strings.Replace(s, up, up+"\n./pilot vm-target up --name extra --base-image rocky9", 1)
		}, "runs between"},
		{"no set -e to stop at a failed up", func(s string) string {
			return strings.Replace(s, "set -euo pipefail", "set -uo pipefail", 1)
		}, "set -e must come before"},
		{"a second, plain up", func(s string) string {
			return s + "\n./pilot vm-target topology up --topology other.yaml\n"
		}, "exactly one"},
		{"no trap at all", func(s string) string { return strings.Replace(s, trap, "", 1) }, "exactly one `trap"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mutated := tc.mutate(real)
			if mutated == real {
				t.Fatal("the mutation changed nothing")
			}
			problems := strings.Join(checkmodeScriptProblems(mutated), "\n")
			if !strings.Contains(problems, tc.want) {
				t.Fatalf("want a problem containing %q, got:\n%s", tc.want, problems)
			}
		})
	}
}
