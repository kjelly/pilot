// ansible_core_pin_consistency_test.go keeps the ansible-core version that
// images/Dockerfile.pilot-cli bakes into the delivery image and the one the
// CI playbook jobs install on the same pinned series. Both used to
// install an unpinned ansible-core; on 2026-10-12 a cache-missed image build
// pulled 2.21.5 while every Ansible behaviour AGENTS.md documents was
// verified on 2.19.2. An unpinned install, or two different pins, lets CI
// lint the playbooks against a different ansible-core than operators run.
//
// The same drift hit the Go test job on 2026-11-26 (kjelly/pilot#455): only
// the spec group installed the pin, the cmd and rest groups used the Ansible
// the runner image carries, and runner image 20261122.9 moved that to 2.22.0,
// which prints $REDACTED$ for every vault value; one run mixed 2.21.x and
// 2.22.0 shards. The pin check above never noticed: it read the install
// command and ignored the step's `if:`, the step order and the collections
// path. The second half of this file therefore checks, on the parsed
// workflow, that every Go test group gets the pinned toolchain before the
// first step that runs Go tests, that a step asserts what ended up on PATH
// (and that the assertion, run against stand-in tools, rejects any other
// series), and that CI installs collections into the path the image uses.
package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
)

// ansibleCoreRequirementRE matches an ansible-core requirement token in a
// pip/uv install command, capturing any version specifier after it.
var ansibleCoreRequirementRE = regexp.MustCompile(`(?:^|[\s"'])ansible-core([<>=!~][^\s"'\\]*)?(?:[\s"'\\]|$)`)

// ansibleCoreRequirements returns the version specifier of every
// ansible-core requirement on a non-comment line ("" for an
// unpinned requirement).
func ansibleCoreRequirements(content string) []string {
	var specs []string
	for line := range strings.SplitSeq(content, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		for _, m := range ansibleCoreRequirementRE.FindAllStringSubmatch(line, -1) {
			specs = append(specs, m[1])
		}
	}
	return specs
}

func TestAnsibleCorePinMatchesBetweenImageAndCI(t *testing.T) {
	root := repoRootForTest(t)
	image, err := os.ReadFile(filepath.Join(root, "images", "Dockerfile.pilot-cli"))
	if err != nil {
		t.Fatal(err)
	}
	if err := checkAnsibleCorePins(string(image), readCIYAML(t)); err != nil {
		t.Fatal(err)
	}
}

func TestAnsibleCoreRequirementsDetectUnpinnedInstall(t *testing.T) {
	content := "# ansible-core is mentioned in a comment\n" +
		"RUN uv pip install --system \\\n" +
		"        ansible-core \\\n" +
		"        docker\n" +
		"RUN pip install \"ansible-core==2.19.*\" ansible-lint\n"
	got := ansibleCoreRequirements(content)
	want := []string{"", "==2.19.*"}
	if !slices.Equal(got, want) {
		t.Fatalf("ansibleCoreRequirements = %q, want %q", got, want)
	}
}

// joinShellContinuations drops the comment lines of a script and joins
// backslash continuations, so one command is one line.
func joinShellContinuations(content string) string {
	var lines []string
	for line := range strings.SplitSeq(content, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		lines = append(lines, line)
	}
	return strings.ReplaceAll(strings.Join(lines, "\n"), "\\\n", " ")
}

// galaxyCollections returns the collections named by every
// `ansible-galaxy collection install` command on non-comment lines of the
// script, following backslash continuations and skipping options.
func galaxyCollections(content string) []string {
	joined := joinShellContinuations(content)
	var collections []string
	for line := range strings.SplitSeq(joined, "\n") {
		_, rest, ok := strings.Cut(line, "ansible-galaxy collection install")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		for i := 0; i < len(fields); i++ {
			f := fields[i]
			if f == "&&" || f == ";" || f == "|" {
				break
			}
			if f == "-p" || f == "--collections-path" {
				i++
				continue
			}
			if strings.HasPrefix(f, "-") {
				continue
			}
			collections = append(collections, f)
		}
	}
	slices.Sort(collections)
	return collections
}

// TestAnsibleCollectionsMatchBetweenImageAndCI: each CI playbook job must
// run against the collections the delivery image ships.
// The image added community.general on 2026-07-31 and CI never did, so a
// community.general module used directly in a playbook failed CI's
// syntax-check while the image ran it (PR #79, community.general.sefcontext
// in log-server's rescue, 2026-10-15).
func TestAnsibleCollectionsMatchBetweenImageAndCI(t *testing.T) {
	root := repoRootForTest(t)
	image, err := os.ReadFile(filepath.Join(root, "images", "Dockerfile.pilot-cli"))
	if err != nil {
		t.Fatal(err)
	}
	if err := checkAnsibleCollections(string(image), readCIYAML(t)); err != nil {
		t.Fatal(err)
	}
}

type ciAnsibleToolchain struct {
	core        []string
	collections []string
}

// CI jobs run on separate hosts: one job's dependencies cannot satisfy another.
// Always include both required consumers, even when their installs (or whole
// jobs) are removed, and discover any additional installers from step.run.
func ciAnsibleToolchains(ciYAML string) (map[string]ciAnsibleToolchain, error) {
	var wf struct {
		Jobs map[string]struct {
			Steps []struct{ Run string }
		}
	}
	if err := yaml.Unmarshal([]byte(ciYAML), &wf); err != nil {
		return nil, fmt.Errorf("parse CI workflow: %w", err)
	}
	jobs := map[string]ciAnsibleToolchain{
		"playbook-lint":        {},
		"playbook-integration": {},
	}
	for name, job := range wf.Jobs {
		var toolchain ciAnsibleToolchain
		installsGalaxy := false
		for _, step := range job.Steps {
			toolchain.core = append(toolchain.core, ansibleCoreRequirements(step.Run)...)
			toolchain.collections = append(toolchain.collections, galaxyCollections(step.Run)...)
			for line := range strings.SplitSeq(step.Run, "\n") {
				if !strings.HasPrefix(strings.TrimSpace(line), "#") && strings.Contains(line, "ansible-galaxy collection install") {
					installsGalaxy = true
				}
			}
		}
		_, required := jobs[name]
		if required || len(toolchain.core) > 0 || installsGalaxy {
			slices.Sort(toolchain.collections)
			jobs[name] = toolchain
		}
	}
	return jobs, nil
}

func checkAnsibleCorePins(image, ciYAML string) error {
	pins := ansibleCoreRequirements(image)
	if len(pins) != 1 {
		return fmt.Errorf("images/Dockerfile.pilot-cli: found %d ansible-core install requirements %q, want exactly 1", len(pins), pins)
	}
	if !strings.HasPrefix(pins[0], "==") || len(pins[0]) == 2 {
		return fmt.Errorf("images/Dockerfile.pilot-cli installs ansible-core without an == pin (%q)", pins[0])
	}
	jobs, err := ciAnsibleToolchains(ciYAML)
	if err != nil {
		return err
	}
	for _, name := range sortedCIAnsibleJobs(jobs) {
		got := jobs[name].core
		if len(got) != 1 {
			return fmt.Errorf("CI job %s: found %d ansible-core install requirements %q, want exactly 1 matching image pin %q", name, len(got), got, pins[0])
		}
		if got[0] != pins[0] {
			return fmt.Errorf("CI job %s: ansible-core pin %q differs from image pin %q", name, got[0], pins[0])
		}
	}
	return nil
}

func checkAnsibleCollections(image, ciYAML string) error {
	want := galaxyCollections(image)
	if len(want) == 0 {
		return fmt.Errorf("found no ansible-galaxy collection install in images/Dockerfile.pilot-cli")
	}
	jobs, err := ciAnsibleToolchains(ciYAML)
	if err != nil {
		return err
	}
	for _, name := range sortedCIAnsibleJobs(jobs) {
		if got := jobs[name].collections; !slices.Equal(want, got) {
			return fmt.Errorf("CI job %s: collections differ: image installs %v, job installs %v", name, want, got)
		}
	}
	return nil
}

func sortedCIAnsibleJobs(jobs map[string]ciAnsibleToolchain) []string {
	names := make([]string, 0, len(jobs))
	for name := range jobs {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

func TestAnsibleToolchainChecksCatchPerJobDrift(t *testing.T) {
	const install = "python3 -m pip install \"ansible-core==2.19.*\" ansible-lint\n" +
		"ansible-galaxy collection install ansible.posix community.docker community.postgresql community.general"
	job := func(name, run string) string {
		return "  " + name + ":\n    steps:\n      - run: |\n          " + strings.ReplaceAll(run, "\n", "\n          ") + "\n"
	}
	lint := job("playbook-lint", install)
	integration := job("playbook-integration", install)
	workflow := "jobs:\n" + lint + integration
	for _, tc := range []struct {
		name            string
		ci              string
		wantCore        string
		wantCollections string
	}{
		{name: "two matching jobs", ci: workflow},
		{name: "second job wrong pin", ci: "jobs:\n" + lint + job("playbook-integration", strings.ReplaceAll(install, "2.19.*", "2.21.*")), wantCore: "CI job playbook-integration: ansible-core pin \"==2.21.*\""},
		{name: "second job unpinned", ci: "jobs:\n" + lint + job("playbook-integration", strings.ReplaceAll(install, "==2.19.*", "")), wantCore: "CI job playbook-integration: ansible-core pin \"\""},
		{name: "second job missing collection", ci: "jobs:\n" + lint + job("playbook-integration", strings.ReplaceAll(install, " community.general", "")), wantCollections: "CI job playbook-integration: collections differ"},
		{name: "second install removed", ci: "jobs:\n" + lint + job("playbook-integration", "make integration"), wantCore: "CI job playbook-integration: found 0", wantCollections: "CI job playbook-integration: collections differ"},
		{name: "second job removed", ci: "jobs:\n" + lint, wantCore: "CI job playbook-integration: found 0", wantCollections: "CI job playbook-integration: collections differ"},
		{name: "first install removed", ci: "jobs:\n" + job("playbook-lint", "make playbook-lint") + integration, wantCore: "CI job playbook-lint: found 0", wantCollections: "CI job playbook-lint: collections differ"},
		{name: "first job removed", ci: "jobs:\n" + integration, wantCore: "CI job playbook-lint: found 0", wantCollections: "CI job playbook-lint: collections differ"},
		{name: "second duplicate core install", ci: "jobs:\n" + lint + job("playbook-integration", install+"\npython3 -m pip install ansible-core==2.19.*"), wantCore: "CI job playbook-integration: found 2"},
		{name: "third matching installer", ci: workflow + job("third", install)},
		{name: "third installer wrong pin", ci: workflow + job("third", strings.ReplaceAll(install, "2.19.*", "2.21.*")), wantCore: "CI job third: ansible-core pin \"==2.21.*\""},
		{name: "third installer missing collection", ci: workflow + job("third", strings.ReplaceAll(install, " community.general", "")), wantCollections: "CI job third: collections differ"},
		{name: "third core only", ci: workflow + job("third", "pip install ansible-core==2.19.*"), wantCollections: "CI job third: collections differ"},
		{name: "third collections only", ci: workflow + job("third", strings.Split(install, "\n")[1]), wantCore: "CI job third: found 0"},
		{name: "third empty galaxy install", ci: workflow + job("third", "ansible-galaxy collection install"), wantCore: "CI job third: found 0", wantCollections: "CI job third: collections differ"},
		{name: "non installing job ignored", ci: workflow + job("third", "# pip install ansible-core\n# ansible-galaxy collection install\nmake build")},
		{name: "malformed workflow", ci: "jobs: [", wantCore: "parse CI workflow", wantCollections: "parse CI workflow"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, check := range []struct {
				name string
				run  func(string, string) error
				want string
			}{
				{"core", checkAnsibleCorePins, tc.wantCore},
				{"collections", checkAnsibleCollections, tc.wantCollections},
			} {
				t.Run(check.name, func(t *testing.T) {
					err := check.run(install, tc.ci)
					if check.want == "" {
						if err != nil {
							t.Fatal(err)
						}
					} else if err == nil || !strings.Contains(err.Error(), check.want) {
						t.Fatalf("got %v, want error containing %q", err, check.want)
					}
				})
			}
		})
	}
}

func TestAnsibleToolchainChecksKeepImageRequirements(t *testing.T) {
	for _, tc := range []struct {
		name, image, want string
	}{
		{"missing", "RUN pip install docker", "found 0"},
		{"unpinned", "RUN pip install ansible-core", "without an == pin"},
		{"empty pin", "RUN pip install ansible-core==", "without an == pin"},
		{"duplicate", "RUN pip install ansible-core==2.19.*\nRUN pip install ansible-core==2.19.*", "found 2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkAnsibleCorePins(tc.image, "jobs: {}")
			if err == nil || !strings.Contains(err.Error(), "images/Dockerfile.pilot-cli") || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want image error containing %q", err, tc.want)
			}
		})
	}
	if err := checkAnsibleCollections("# no collections installed", "jobs: {}"); err == nil || !strings.Contains(err.Error(), "found no ansible-galaxy collection install in images/Dockerfile.pilot-cli") {
		t.Fatalf("got %v, want missing image collections error", err)
	}
}

// ---------------------------------------------------------------------------
// The Ansible toolchain of every Go test group (kjelly/pilot#455).
//
// The checks above read install commands. These read the parsed workflow: the
// step's `if:`, the order of the steps, the assertion step and the collections
// path. The workflow is the only place the groups' toolchain is decided, so
// every check takes the workflow text, and the Makefile, image and shard
// config as plain inputs; the tests below run them against the real files and
// against synthetic workflows that break exactly one thing.
// ---------------------------------------------------------------------------

// ansibleToolchainAssertStepName names the step that asserts the toolchain
// that is on PATH after the install. The step is found by this name and not by
// position or content, so removing it, renaming it or turning it into
// something else is a loud failure of its own ("no step named ...") and not a
// different step silently taking its place; where the step may sit is checked
// separately (after the install, before the first step that runs Go tests).
const ansibleToolchainAssertStepName = "Assert the pinned Ansible toolchain"

// ansibleToolchainTools are the Ansible entry points the Go tests start
// (LookPath in internal/spec, internal/inventory and cmd, `ansible-config` in
// the cmd tests). They come from one pip install, but the runner image's own
// copies are on the same PATH, so the assertion has to look at every one.
var ansibleToolchainTools = []string{"ansible", "ansible-config", "ansible-galaxy", "ansible-inventory", "ansible-playbook", "ansible-vault"}

// ansibleToolchainNotNeededByGoJobs lists the CI jobs that run Go tests
// without installing the pinned Ansible, with the reason each does not need
// it. An entry that stops being true (the job is gone, no longer runs Go
// tests, or installs the pin) fails, so the list cannot rot. The list used to
// have mcp-remote: its pilot_diagnose_delivery test starts `ansible` and
// `ansible-inventory`, so the job installs the pin and asserts it, as `test` does.
var ansibleToolchainNotNeededByGoJobs = map[string]string{
	"root-tests": "make root-test runs only the roster ownership tests of internal/inventory under sudo; the only Ansible they touch is ansible-vault encrypting, decrypting and viewing a roster file, which does not change with the series",
	"skills":     "runs the Python skill unit tests, the agent skill layout test and two repo-wide lints that read files; none of them starts Ansible",
}

type ansibleToolchainStep struct {
	Name            string    `yaml:"name"`
	If              string    `yaml:"if"`
	Run             string    `yaml:"run"`
	Uses            string    `yaml:"uses"`
	ContinueOnError yaml.Node `yaml:"continue-on-error"`
	Env             yaml.Node `yaml:"env"`
}

type ansibleToolchainJob struct {
	Strategy struct {
		Matrix yaml.Node `yaml:"matrix"`
	} `yaml:"strategy"`
	ContinueOnError yaml.Node              `yaml:"continue-on-error"`
	Env             yaml.Node              `yaml:"env"`
	Steps           []ansibleToolchainStep `yaml:"steps"`
}

func parseAnsibleToolchainJobs(ciYAML string) (map[string]ansibleToolchainJob, error) {
	var wf struct {
		Jobs map[string]ansibleToolchainJob `yaml:"jobs"`
	}
	if err := yaml.Unmarshal([]byte(ciYAML), &wf); err != nil {
		return nil, fmt.Errorf("parse CI workflow: %w", err)
	}
	return wf.Jobs, nil
}

// installSteps returns the indexes of the steps that install ansible-core.
func (j ansibleToolchainJob) installSteps() []int {
	var idx []int
	for i, step := range j.Steps {
		if len(ansibleCoreRequirements(step.Run)) > 0 {
			idx = append(idx, i)
		}
	}
	return idx
}

// assertSteps returns the indexes of the steps named ansibleToolchainAssertStepName.
func (j ansibleToolchainJob) assertSteps() []int {
	var idx []int
	for i, step := range j.Steps {
		if step.Name == ansibleToolchainAssertStepName {
			idx = append(idx, i)
		}
	}
	return idx
}

// goTestRE finds a `go test` command; `go test -c` counts, it builds the
// binary a later step runs.
var goTestRE = regexp.MustCompile(`(?:^|[\s;&|(@])go test(?:\s|$)`)

// runsGoTests reports whether a step runs Go tests: a `go test` command on a
// non-comment line, or a `make <target>` line whose recipe in the Makefile
// contains one. A make target chosen by a variable (`make "$TARGET"`) is not
// followed.
func (s ansibleToolchainStep) runsGoTests(t *testing.T, makefile string) bool {
	t.Helper()
	for line := range strings.SplitSeq(joinShellContinuations(s.Run), "\n") {
		line = strings.TrimSpace(line)
		if goTestRE.MatchString(line) {
			return true
		}
		if m := makeStepRE.FindStringSubmatch(line); m != nil {
			for _, recipeLine := range makeTargetRecipe(t, makefile, m[1]) {
				if goTestRE.MatchString(recipeLine) {
					return true
				}
			}
		}
	}
	return false
}

// firstGoTestStep returns the index of the first step that runs Go tests, or -1.
func (j ansibleToolchainJob) firstGoTestStep(t *testing.T, makefile string) int {
	t.Helper()
	for i, step := range j.Steps {
		if step.runsGoTests(t, makefile) {
			return i
		}
	}
	return -1
}

// goTestGroupsFromShardConfig returns the Go test groups (spec, cmd, rest)
// the CI matrix is generated from.
func goTestGroupsFromShardConfig(t *testing.T, root string) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, "scripts", "ci-go-test-shards.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Groups map[string]json.RawMessage `json:"groups"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("scripts/ci-go-test-shards.json: %v", err)
	}
	groups := slices.Sorted(maps.Keys(cfg.Groups))
	if len(groups) == 0 {
		t.Fatal("scripts/ci-go-test-shards.json defines no Go test group")
	}
	return groups
}

// legs returns the matrix.group values a job's steps run under: the Go test
// groups when the job's matrix is the generated Go test matrix, otherwise one
// leg with no group.
func (j ansibleToolchainJob) legs(goTestGroups []string) []string {
	if j.Strategy.Matrix.Kind == yaml.ScalarNode && strings.Contains(j.Strategy.Matrix.Value, "go_test_matrix") {
		return goTestGroups
	}
	return []string{""}
}

func ansibleToolchainLegLabel(group string) string {
	if group == "" {
		return "(the job's only leg)"
	}
	return group
}

// ciIfValue is a value of a GitHub Actions `if:` expression: a string or a
// boolean.
type ciIfValue struct {
	isBool bool
	b      bool
	s      string
}

func (v ciIfValue) truthy() bool {
	if v.isBool {
		return v.b
	}
	return v.s != ""
}

type ciIfToken struct {
	kind string // "op", "str" or "ident"
	text string
}

func ciIfTokens(expr string) ([]ciIfToken, error) {
	var toks []ciIfToken
	for i := 0; i < len(expr); {
		c := expr[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case strings.HasPrefix(expr[i:], "||") || strings.HasPrefix(expr[i:], "&&") ||
			strings.HasPrefix(expr[i:], "==") || strings.HasPrefix(expr[i:], "!="):
			toks = append(toks, ciIfToken{"op", expr[i : i+2]})
			i += 2
		case c == '!' || c == '(' || c == ')':
			toks = append(toks, ciIfToken{"op", string(c)})
			i++
		case c == '\'':
			var lit strings.Builder
			j := i + 1
			for {
				if j >= len(expr) {
					return nil, fmt.Errorf("unterminated string literal")
				}
				if expr[j] == '\'' {
					if j+1 < len(expr) && expr[j+1] == '\'' {
						lit.WriteByte('\'')
						j += 2
						continue
					}
					break
				}
				lit.WriteByte(expr[j])
				j++
			}
			toks = append(toks, ciIfToken{"str", lit.String()})
			i = j + 1
		case c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z':
			j := i
			for j < len(expr) && (expr[j] == '_' || expr[j] == '.' || expr[j] == '-' ||
				expr[j] >= 'a' && expr[j] <= 'z' || expr[j] >= 'A' && expr[j] <= 'Z' || expr[j] >= '0' && expr[j] <= '9') {
				j++
			}
			toks = append(toks, ciIfToken{"ident", expr[i:j]})
			i = j
		default:
			return nil, fmt.Errorf("unexpected character %q", c)
		}
	}
	return toks, nil
}

type ciIfParser struct {
	toks  []ciIfToken
	pos   int
	group string
}

func (p *ciIfParser) peekOp(op string) bool {
	return p.pos < len(p.toks) && p.toks[p.pos].kind == "op" && p.toks[p.pos].text == op
}

func (p *ciIfParser) or() (ciIfValue, error) {
	v, err := p.and()
	if err != nil {
		return v, err
	}
	for p.peekOp("||") {
		p.pos++
		r, err := p.and()
		if err != nil {
			return v, err
		}
		v = ciIfValue{isBool: true, b: v.truthy() || r.truthy()}
	}
	return v, nil
}

func (p *ciIfParser) and() (ciIfValue, error) {
	v, err := p.comparison()
	if err != nil {
		return v, err
	}
	for p.peekOp("&&") {
		p.pos++
		r, err := p.comparison()
		if err != nil {
			return v, err
		}
		v = ciIfValue{isBool: true, b: v.truthy() && r.truthy()}
	}
	return v, nil
}

// comparison is == or != between two unary operands: as in GitHub Actions,
// ! binds tighter than the comparison, so `!a == b` is `(!a) == b`.
func (p *ciIfParser) comparison() (ciIfValue, error) {
	left, err := p.unary()
	if err != nil {
		return left, err
	}
	for _, op := range []string{"==", "!="} {
		if !p.peekOp(op) {
			continue
		}
		p.pos++
		right, err := p.unary()
		if err != nil {
			return left, err
		}
		if left.isBool != right.isBool {
			return left, fmt.Errorf("compares a string with a boolean")
		}
		equal := left.b == right.b
		if !left.isBool {
			// GitHub Actions compares strings case-insensitively.
			equal = strings.EqualFold(left.s, right.s)
		}
		return ciIfValue{isBool: true, b: equal == (op == "==")}, nil
	}
	return left, nil
}

func (p *ciIfParser) unary() (ciIfValue, error) {
	if p.peekOp("!") {
		p.pos++
		v, err := p.unary()
		return ciIfValue{isBool: true, b: !v.truthy()}, err
	}
	return p.primary()
}

func (p *ciIfParser) primary() (ciIfValue, error) {
	if p.pos >= len(p.toks) {
		return ciIfValue{}, fmt.Errorf("the expression ends early")
	}
	tok := p.toks[p.pos]
	p.pos++
	switch {
	case tok.kind == "op" && tok.text == "(":
		v, err := p.or()
		if err != nil {
			return v, err
		}
		if !p.peekOp(")") {
			return v, fmt.Errorf("missing )")
		}
		p.pos++
		return v, nil
	case tok.kind == "str":
		return ciIfValue{s: tok.text}, nil
	case tok.kind == "ident" && tok.text == "matrix.group":
		return ciIfValue{s: p.group}, nil
	case tok.kind == "ident" && (tok.text == "true" || tok.text == "false"):
		return ciIfValue{isBool: true, b: tok.text == "true"}, nil
	}
	return ciIfValue{}, fmt.Errorf("%q is not something this check evaluates", tok.text)
}

// ciStepRunsForGroup evaluates a step's `if:` for one matrix.group value. An
// empty `if:` runs. Only what a group condition needs is understood
// (matrix.group, string literals, true/false, ==, !=, !, &&, ||, parentheses);
// anything else is an error, so an `if:` this check cannot read fails the
// check instead of being assumed harmless.
func ciStepRunsForGroup(cond, group string) (bool, error) {
	expr := strings.TrimSpace(cond)
	if expr == "" {
		return true, nil
	}
	if inner, ok := strings.CutPrefix(expr, "${{"); ok {
		if inner, ok = strings.CutSuffix(inner, "}}"); ok {
			expr = inner
		}
	}
	toks, err := ciIfTokens(expr)
	if err == nil {
		p := &ciIfParser{toks: toks, group: group}
		var v ciIfValue
		if v, err = p.or(); err == nil && p.pos != len(toks) {
			err = fmt.Errorf("%q follows a complete expression", toks[p.pos].text)
		}
		if err == nil {
			return v.truthy(), nil
		}
	}
	return false, fmt.Errorf("cannot evaluate `if: %s` (%v): this check reads only matrix.group comparisons built from ==, !=, !, && and ||", cond, err)
}

// checkAnsibleToolchainReachesEveryGroup fails when an install step of the
// pinned Ansible has an `if:` that skips it for any Go test group. The Go
// groups that skip it run the runner image's Ansible, which floats.
func checkAnsibleToolchainReachesEveryGroup(ciYAML string, goTestGroups []string) error {
	jobs, err := parseAnsibleToolchainJobs(ciYAML)
	if err != nil {
		return err
	}
	for _, name := range slices.Sorted(maps.Keys(jobs)) {
		job := jobs[name]
		for _, i := range job.installSteps() {
			step := job.Steps[i]
			var skipped []string
			for _, group := range job.legs(goTestGroups) {
				runs, err := ciStepRunsForGroup(step.If, group)
				if err != nil {
					return fmt.Errorf("CI job %s, step %q: %w", name, step.Name, err)
				}
				if !runs {
					skipped = append(skipped, ansibleToolchainLegLabel(group))
				}
			}
			if len(skipped) > 0 {
				return fmt.Errorf("CI job %s: step %q has `if: %s`, which skips the pinned Ansible install for group(s): %s; "+
					"those groups run the runner image's Ansible, which floats (kjelly/pilot#455)",
					name, step.Name, step.If, strings.Join(skipped, ", "))
			}
		}
	}
	return nil
}

// checkEveryGoTestJobInstallsTheToolchain fails when a CI job runs Go tests
// without installing the pinned Ansible and is not in notNeeded, or when a
// notNeeded entry no longer holds.
func checkEveryGoTestJobInstallsTheToolchain(t *testing.T, ciYAML, makefile string, notNeeded map[string]string) error {
	t.Helper()
	jobs, err := parseAnsibleToolchainJobs(ciYAML)
	if err != nil {
		return err
	}
	for _, name := range slices.Sorted(maps.Keys(jobs)) {
		job := jobs[name]
		runsGo := job.firstGoTestStep(t, makefile) >= 0
		installs := len(job.installSteps()) > 0
		_, listed := notNeeded[name]
		switch {
		case runsGo && !installs && !listed:
			return fmt.Errorf("CI job %s runs Go tests without installing the pinned Ansible, so its tests use the runner image's, which floats (kjelly/pilot#455): "+
				"add the install and the %q step as job `test` has them, or, if its tests never start Ansible, list the job in ansibleToolchainNotNeededByGoJobs with the reason", name, ansibleToolchainAssertStepName)
		case listed && runsGo && installs:
			return fmt.Errorf("ansibleToolchainNotNeededByGoJobs lists %s, but the job installs the pinned Ansible now: remove the entry", name)
		case listed && !runsGo:
			return fmt.Errorf("ansibleToolchainNotNeededByGoJobs lists %s, but the job runs no Go tests (or is gone): remove the entry", name)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(notNeeded)) {
		if _, ok := jobs[name]; !ok {
			return fmt.Errorf("ansibleToolchainNotNeededByGoJobs lists %s, but ci.yml has no such job: remove the entry", name)
		}
	}
	return nil
}

// checkAnsibleToolchainIsAssertedBeforeGoTests: in every job that installs the
// pinned Ansible and runs Go tests, the install and the assertion step come
// before the first step that runs Go tests, in that order, and the assertion
// runs for every group.
func checkAnsibleToolchainIsAssertedBeforeGoTests(t *testing.T, ciYAML, makefile string) error {
	t.Helper()
	jobs, err := parseAnsibleToolchainJobs(ciYAML)
	if err != nil {
		return err
	}
	for _, name := range slices.Sorted(maps.Keys(jobs)) {
		job := jobs[name]
		installs := job.installSteps()
		goTest := job.firstGoTestStep(t, makefile)
		if len(installs) == 0 || goTest < 0 {
			continue
		}
		asserts := job.assertSteps()
		if len(asserts) != 1 {
			return fmt.Errorf("CI job %s installs the pinned Ansible and runs Go tests, so it needs exactly one step named %q that asserts what is on PATH; it has %d", name, ansibleToolchainAssertStepName, len(asserts))
		}
		assertIdx := asserts[0]
		assert := job.Steps[assertIdx]
		first := job.Steps[goTest].Name
		for _, i := range installs {
			if i > goTest {
				return fmt.Errorf("CI job %s: install step %q comes after step %q, the first step that runs Go tests", name, job.Steps[i].Name, first)
			}
			if i > assertIdx {
				return fmt.Errorf("CI job %s: step %q comes before the install step %q: it would assert the runner image's Ansible", name, assert.Name, job.Steps[i].Name)
			}
		}
		if assertIdx > goTest {
			return fmt.Errorf("CI job %s: step %q comes after step %q, the first step that runs Go tests", name, assert.Name, first)
		}
		if assert.If != "" {
			return fmt.Errorf("CI job %s: step %q has `if: %s`; it must run for every group, with no condition", name, assert.Name, assert.If)
		}
		if strings.TrimSpace(assert.Run) == "" {
			return fmt.Errorf("CI job %s: step %q has no run script", name, assert.Name)
		}
		if reqs := ansibleCoreRequirements(assert.Run); len(reqs) > 0 {
			return fmt.Errorf("CI job %s: step %q names ansible-core, which checkAnsibleCorePins counts as a second install requirement: refer to the tools by their entry-point names", name, assert.Name)
		}
	}
	return nil
}

// ansibleToolchainPlainFalse reports whether a `continue-on-error` node is
// absent or the literal false. A truthy value, a quoted "false" and a
// `${{ }}` expression are not: the step's or job's failure could then be
// ignored.
func ansibleToolchainPlainFalse(n yaml.Node) bool {
	return n.Kind == 0 || n.Kind == yaml.ScalarNode && n.Tag == "!!bool" && strings.EqualFold(n.Value, "false")
}

// ansibleToolchainYAMLText shows a `continue-on-error` value; a string that
// only looks like a boolean is marked, so the message does not read as if the
// value were fine.
func ansibleToolchainYAMLText(n yaml.Node) string {
	switch {
	case n.Kind == yaml.ScalarNode && n.Tag == "!!bool":
		return n.Value
	case n.Kind == yaml.ScalarNode:
		return n.Value + " (a string, not a boolean)"
	}
	return "(not a plain value)"
}

// ansibleToolchainEnvSetsPath reports whether an `env:` node sets PATH, or is
// not a mapping this check can read (an expression): either could put another
// Ansible first on PATH after the install.
func ansibleToolchainEnvSetsPath(n yaml.Node) bool {
	switch n.Kind {
	case 0:
		return false
	case yaml.ScalarNode:
		return n.Tag != "!!null" // `env:` with nothing under it sets nothing
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			if strings.EqualFold(n.Content[i].Value, "PATH") {
				return true
			}
		}
		return false
	}
	return true
}

// checkAnsibleToolchainCannotBeDisarmed: in every job that installs the pinned
// Ansible and runs Go tests, a failure of an install step or of the assertion
// step must fail the job, and nothing may change PATH between the install and
// the tests. So neither those steps nor the job set `continue-on-error` to
// anything but the literal false, and neither sets PATH in `env:` (a job-level
// PATH reaches every step, a step-level one reaches that step: either could
// make the assertion look at one Ansible and the tests run another).
func checkAnsibleToolchainCannotBeDisarmed(t *testing.T, ciYAML, makefile string) error {
	t.Helper()
	jobs, err := parseAnsibleToolchainJobs(ciYAML)
	if err != nil {
		return err
	}
	for _, name := range slices.Sorted(maps.Keys(jobs)) {
		job := jobs[name]
		installs := job.installSteps()
		if len(installs) == 0 || job.firstGoTestStep(t, makefile) < 0 {
			continue
		}
		if !ansibleToolchainPlainFalse(job.ContinueOnError) {
			return fmt.Errorf("CI job %s has `continue-on-error: %s`: a failed toolchain install or assertion would not fail the workflow", name, ansibleToolchainYAMLText(job.ContinueOnError))
		}
		if ansibleToolchainEnvSetsPath(job.Env) {
			return fmt.Errorf("CI job %s sets PATH in its `env:`: the tests could run another Ansible than the one the assertion step checked", name)
		}
		for _, i := range append(slices.Clone(installs), job.assertSteps()...) {
			step := job.Steps[i]
			if !ansibleToolchainPlainFalse(step.ContinueOnError) {
				return fmt.Errorf("CI job %s: step %q has `continue-on-error: %s`: its failure must fail the job", name, step.Name, ansibleToolchainYAMLText(step.ContinueOnError))
			}
			if ansibleToolchainEnvSetsPath(step.Env) {
				return fmt.Errorf("CI job %s: step %q sets PATH in its `env:`: the install and the assertion must see the PATH the tests run with", name, step.Name)
			}
		}
	}
	return nil
}

// galaxyInstallPaths returns one entry for every `ansible-galaxy collection
// install` command in the script: its collections path (-p /
// --collections-path; the last one, as the command takes), or "" when it has
// none or the option has no value. A command without a path must show, so a
// job that installs into the system-wide path once and into the default home
// once does not look like one that installs only into the former.
func galaxyInstallPaths(content string) []string {
	var paths []string
	for line := range strings.SplitSeq(joinShellContinuations(content), "\n") {
		_, rest, ok := strings.Cut(line, "ansible-galaxy collection install")
		if !ok {
			continue
		}
		path := ""
		fields := strings.Fields(rest)
		for i := 0; i < len(fields); i++ {
			f := fields[i]
			if f == "&&" || f == ";" || f == "|" {
				break
			}
			switch {
			case f == "-p" || f == "--collections-path":
				path = ""
				if i+1 < len(fields) {
					path = fields[i+1]
					i++
				}
			case strings.HasPrefix(f, "--collections-path="):
				path = strings.TrimPrefix(f, "--collections-path=")
			}
		}
		paths = append(paths, path)
	}
	return paths
}

func TestAnsibleToolchainGalaxyInstallPaths(t *testing.T) {
	for _, tc := range []struct {
		name, script string
		want         []string
	}{
		{"short option", "ansible-galaxy collection install -p /srv/collections a.b c.d", []string{"/srv/collections"}},
		{"long option", "ansible-galaxy collection install --collections-path /srv/c a.b", []string{"/srv/c"}},
		{"long option with =", "ansible-galaxy collection install --collections-path=/srv/c a.b", []string{"/srv/c"}},
		{"no option", "ansible-galaxy collection install a.b c.d", []string{""}},
		{"the last path of one command wins", "ansible-galaxy collection install -p /one a.b --collections-path /two", []string{"/two"}},
		{"a second install without a path", "ansible-galaxy collection install -p /one a.b\nansible-galaxy collection install c.d", []string{"/one", ""}},
		{"no install at all", "echo nothing", nil},
		{"continuation lines", "RUN x \\\n    && ansible-galaxy collection install -p /srv/c \\\n        a.b \\\n        c.d", []string{"/srv/c"}},
		{"comment lines are not commands", "# ansible-galaxy collection install -p /nowhere a.b\nansible-galaxy collection install a.b", []string{""}},
		{"option after the next command is not ours", "ansible-galaxy collection install a.b && tool -p /elsewhere", []string{""}},
		{"option without a value", "ansible-galaxy collection install a.b -p", []string{""}},
		{"two commands", "ansible-galaxy collection install -p /one a.b\nansible-galaxy collection install -p /two c.d", []string{"/one", "/two"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := galaxyInstallPaths(tc.script); !slices.Equal(got, tc.want) {
				t.Fatalf("galaxyInstallPaths = %q, want %q", got, tc.want)
			}
		})
	}
}

// checkAnsibleCollectionsPathMatchesImage: a job that runs Go tests with the
// pinned Ansible installs the collections where the delivery image does. The
// image installs into the system-wide path because pilot gives every run its
// own ANSIBLE_HOME, which hides ~/.ansible/collections; a CI job that installs
// into the default home runs the tests that go through that runtime (the
// identity reconcile tests, TestDiagnoseRunWire_*) without the collections.
func checkAnsibleCollectionsPathMatchesImage(t *testing.T, image, ciYAML, makefile string) error {
	t.Helper()
	want := galaxyInstallPaths(image)
	if len(want) != 1 || want[0] == "" {
		return fmt.Errorf("images/Dockerfile.pilot-cli: want one `ansible-galaxy collection install -p <system-wide path>`, found paths %q", want)
	}
	jobs, err := parseAnsibleToolchainJobs(ciYAML)
	if err != nil {
		return err
	}
	for _, name := range slices.Sorted(maps.Keys(jobs)) {
		job := jobs[name]
		if len(job.installSteps()) == 0 || job.firstGoTestStep(t, makefile) < 0 {
			continue
		}
		var script strings.Builder
		for _, step := range job.Steps {
			script.WriteString(step.Run + "\n")
		}
		if got := galaxyInstallPaths(script.String()); !slices.Equal(want, got) {
			return fmt.Errorf("CI job %s installs collections into %q, the delivery image into %q: pilot gives every run its own ANSIBLE_HOME, "+
				"which hides the default home path, so the Go tests that go through that runtime would not find the collections", name, got, want)
		}
	}
	return nil
}

// ansibleStandIns describes the Ansible tools the assertion step finds when it
// runs in a test: version maps a tool to the version its `--version` prints,
// and a tool that is not in the map is not installed. pingExit is the status of
// `ansible ... -m ping`.
type ansibleStandIns struct {
	version  map[string]string
	pingExit int
}

// ansibleStandInsAt returns stand-ins for every tool at one version.
func ansibleStandInsAt(version string) ansibleStandIns {
	m := map[string]string{}
	for _, tool := range ansibleToolchainTools {
		m[tool] = version
	}
	return ansibleStandIns{version: m}
}

// with returns a copy with one tool at another version, or without it when
// version is "".
func (s ansibleStandIns) with(tool, version string) ansibleStandIns {
	m := maps.Clone(s.version)
	if version == "" {
		delete(m, tool)
	} else {
		m[tool] = version
	}
	return ansibleStandIns{version: m, pingExit: s.pingExit}
}

// ansibleStandInScript is the stand-in for one tool. `--version` prints the
// first line the real tool prints (`<tool> [core X.Y.Z]`) and a second line;
// the `ansible` stand-in also records how `-m ping` was called and exits with
// pingExit. It uses shell builtins only.
func ansibleStandInScript(tool, version, pingLog string, pingExit int) string {
	var b strings.Builder
	b.WriteString("#!/bin/sh\n")
	if tool == "ansible" {
		fmt.Fprintf(&b, `for arg in "$@"; do
  if [ "$arg" = ping ]; then
    {
      printf 'args=%%s\n' "$*"
      printf 'ANSIBLE_HOME=%%s\n' "$ANSIBLE_HOME"
      printf 'ANSIBLE_STDOUT_CALLBACK=%%s\n' "$ANSIBLE_STDOUT_CALLBACK"
      printf 'ANSIBLE_LOAD_CALLBACK_PLUGINS=%%s\n' "$ANSIBLE_LOAD_CALLBACK_PLUGINS"
      printf 'HOME=%%s\n' "$HOME"
    } > '%s'
    exit %d
  fi
done
`, pingLog, pingExit)
	}
	fmt.Fprintf(&b, "case \"$1\" in\n--version)\n  printf '%%s\\n' '%s [core %s]' '  config file = None'\n  exit 0 ;;\nesac\nexit 0\n", tool, version)
	return b.String()
}

// ansibleAssertionRun is what running the assertion step's script produced.
type ansibleAssertionRun struct {
	exit   int
	output string
	ping   map[string]string // what `ansible ... -m ping` saw; nil when it was never called
}

// runAnsibleAssertion runs the assertion step's own script against the
// stand-ins. The environment is built from scratch: PATH is a directory of
// stand-ins plus a directory holding only the two programs the script
// needs (sed, mktemp), never the host's PATH: a developer machine has real
// ansible binaries on it, and they must not be found. bash runs with -e, as
// GitHub Actions does for a step that sets no shell.
func runAnsibleAssertion(t *testing.T, script string, standIns ansibleStandIns) ansibleAssertionRun {
	t.Helper()
	dir := t.TempDir()
	shims, tools, tmp, home := filepath.Join(dir, "shims"), filepath.Join(dir, "tools"), filepath.Join(dir, "tmp"), filepath.Join(dir, "home")
	for _, d := range []string{shims, tools, tmp, home} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	pingLog := filepath.Join(dir, "ping.log")
	if strings.ContainsAny(pingLog, "'\n") {
		t.Fatalf("temp dir %q cannot be quoted into a stand-in script", dir)
	}
	for tool, version := range standIns.version {
		body := ansibleStandInScript(tool, version, pingLog, standIns.pingExit)
		if err := os.WriteFile(filepath.Join(shims, tool), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"sed", "mktemp"} {
		hostPath, err := exec.LookPath(name)
		if err != nil {
			t.Fatalf("the assertion step needs %s: %v", name, err)
		}
		if err := os.Symlink(hostPath, filepath.Join(tools, name)); err != nil {
			t.Fatal(err)
		}
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, bash, "-e", "-c", script)
	cmd.Dir = dir
	cmd.Env = []string{"PATH=" + shims + string(os.PathListSeparator) + tools, "HOME=" + home, "TMPDIR=" + tmp, "LC_ALL=C"}
	out, err := cmd.CombinedOutput()
	run := ansibleAssertionRun{output: string(out)}
	var exitErr *exec.ExitError
	switch {
	case errors.As(err, &exitErr):
		run.exit = exitErr.ExitCode()
	case err != nil:
		t.Fatalf("run the assertion step: %v\n%s", err, out)
	}
	if raw, err := os.ReadFile(pingLog); err == nil {
		run.ping = map[string]string{}
		for line := range strings.SplitSeq(strings.TrimSpace(string(raw)), "\n") {
			if k, v, ok := strings.Cut(line, "="); ok {
				run.ping[k] = v
			}
		}
	}
	return run
}

var ansibleSeriesPinRE = regexp.MustCompile(`^==(\d+\.\d+)\.\*$`)

// ansibleSeriesOfImagePin returns the series of the image's pin with a
// trailing dot ("2.19." for ==2.19.*): the value the assertion step has to
// accept and nothing else.
func ansibleSeriesOfImagePin(image string) (string, error) {
	pins := ansibleCoreRequirements(image)
	if len(pins) != 1 {
		return "", fmt.Errorf("images/Dockerfile.pilot-cli: found %d ansible-core install requirements, want exactly 1", len(pins))
	}
	m := ansibleSeriesPinRE.FindStringSubmatch(pins[0])
	if m == nil {
		return "", fmt.Errorf("images/Dockerfile.pilot-cli pins ansible-core as %q; the assertion step needs an ==X.Y.* series pin to derive the series it asserts", pins[0])
	}
	return m[1] + ".", nil
}

// ansibleAssertionTail is the last lines of the assertion step's output, on one line.
func ansibleAssertionTail(s string) string {
	s = strings.TrimSpace(s)
	lines := strings.Split(s, "\n")
	if len(lines) > 6 {
		lines = lines[len(lines)-6:]
	}
	return strings.Join(lines, " | ")
}

// checkAnsibleToolchainAssertionRejectsOtherSeries runs the assertion step of
// every job that installs the pin and runs Go tests, as written in ci.yml,
// against stand-in tools: the pinned series passes; any one tool on another
// series (2.22.0, the 2026-11 runner image; 2.21.6; 2.20.1) or missing fails
// and the output names the tool; a failing `ansible ... -m ping` under an
// isolated ANSIBLE_HOME fails the step; and the ping is made the way pilot
// makes it. The series is the image's pin, so changing the pin without the
// step (or the step without the pin) fails here.
func checkAnsibleToolchainAssertionRejectsOtherSeries(t *testing.T, ciYAML, image, makefile string) error {
	t.Helper()
	series, err := ansibleSeriesOfImagePin(image)
	if err != nil {
		return err
	}
	jobs, err := parseAnsibleToolchainJobs(ciYAML)
	if err != nil {
		return err
	}
	goodVersions := []string{series + "15", series + "2"}
	var badVersions []string
	for _, v := range []string{"2.22.0", "2.21.6", "2.20.1"} {
		if !strings.HasPrefix(v, series) {
			badVersions = append(badVersions, v)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(jobs)) {
		job := jobs[name]
		if len(job.installSteps()) == 0 || job.firstGoTestStep(t, makefile) < 0 {
			continue
		}
		asserts := job.assertSteps()
		if len(asserts) != 1 {
			return fmt.Errorf("CI job %s has no single step named %q to run", name, ansibleToolchainAssertStepName)
		}
		script := job.Steps[asserts[0]].Run
		for i, good := range goodVersions {
			run := runAnsibleAssertion(t, script, ansibleStandInsAt(good))
			if run.exit != 0 {
				return fmt.Errorf("CI job %s: the assertion step rejected a toolchain whose tools are all at %s, which is on the image's pinned series %s*: exit %d: %s", name, good, series, run.exit, ansibleAssertionTail(run.output))
			}
			if i > 0 {
				continue
			}
			if run.ping == nil {
				return fmt.Errorf("CI job %s: the assertion step never ran `ansible ... -m ping`: collections that are only reachable through the default home would go unnoticed", name)
			}
			if !strings.Contains(run.ping["args"], "-m ping") || !strings.Contains(run.ping["args"], "localhost") {
				return fmt.Errorf("CI job %s: the assertion step ran ansible with %q, want a ping of localhost", name, run.ping["args"])
			}
			if home := run.ping["ANSIBLE_HOME"]; home == "" || home == filepath.Join(run.ping["HOME"], ".ansible") {
				return fmt.Errorf("CI job %s: the assertion step's ping ran with ANSIBLE_HOME=%q: pilot gives every run an isolated one, which is what the ping has to reproduce", name, home)
			}
			if run.ping["ANSIBLE_STDOUT_CALLBACK"] != "ansible.posix.json" || run.ping["ANSIBLE_LOAD_CALLBACK_PLUGINS"] != "1" {
				return fmt.Errorf("CI job %s: the assertion step's ping did not load the ansible.posix.json stdout callback the way pilot does (ANSIBLE_STDOUT_CALLBACK=%q, ANSIBLE_LOAD_CALLBACK_PLUGINS=%q)", name, run.ping["ANSIBLE_STDOUT_CALLBACK"], run.ping["ANSIBLE_LOAD_CALLBACK_PLUGINS"])
			}
		}
		good := ansibleStandInsAt(goodVersions[0])
		for _, tool := range ansibleToolchainTools {
			for _, bad := range badVersions {
				run := runAnsibleAssertion(t, script, good.with(tool, bad))
				if run.exit == 0 {
					return fmt.Errorf("CI job %s: the assertion step accepted a toolchain whose %s is %s, outside the image's pinned series %s*", name, tool, bad, series)
				}
				if !strings.Contains(run.output, tool) {
					return fmt.Errorf("CI job %s: the assertion step failed on %s at %s without naming the tool: %s", name, tool, bad, ansibleAssertionTail(run.output))
				}
			}
			run := runAnsibleAssertion(t, script, good.with(tool, ""))
			if run.exit == 0 {
				return fmt.Errorf("CI job %s: the assertion step accepted a toolchain with no %s on PATH", name, tool)
			}
			if !strings.Contains(run.output, tool) {
				return fmt.Errorf("CI job %s: the assertion step failed on a missing %s without naming it: %s", name, tool, ansibleAssertionTail(run.output))
			}
		}
		failingPing := good
		failingPing.pingExit = 3
		if run := runAnsibleAssertion(t, script, failingPing); run.exit == 0 {
			return fmt.Errorf("CI job %s: the assertion step ignored a failing `ansible localhost -m ping` under an isolated ANSIBLE_HOME", name)
		}
	}
	return nil
}

// ansibleToolchainInputs are the files the toolchain checks read.
type ansibleToolchainInputs struct {
	ci, makefile, image string
	groups              []string
}

func readAnsibleToolchainInputs(t *testing.T) ansibleToolchainInputs {
	t.Helper()
	root := repoRootForTest(t)
	read := func(parts ...string) string {
		raw, err := os.ReadFile(filepath.Join(append([]string{root}, parts...)...))
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	return ansibleToolchainInputs{
		ci:       readCIYAML(t),
		makefile: read("Makefile"),
		image:    read("images", "Dockerfile.pilot-cli"),
		groups:   goTestGroupsFromShardConfig(t, root),
	}
}

// ansibleToolchainCheck is one check on the Go test groups' toolchain.
// runsAssertionScript marks the check that executes the assertion step's
// script (slower, and covered by its own test on the real ci.yml).
type ansibleToolchainCheck struct {
	name                string
	runsAssertionScript bool
	run                 func(t *testing.T) error
}

// ansibleToolchainChecks returns every check, in the order they run, so a
// failure names the first thing that is wrong.
func ansibleToolchainChecks(in ansibleToolchainInputs, notNeeded map[string]string) []ansibleToolchainCheck {
	return []ansibleToolchainCheck{
		{name: "install reaches every group", run: func(t *testing.T) error { return checkAnsibleToolchainReachesEveryGroup(in.ci, in.groups) }},
		{name: "every Go test job installs it", run: func(t *testing.T) error {
			return checkEveryGoTestJobInstallsTheToolchain(t, in.ci, in.makefile, notNeeded)
		}},
		{name: "install and assertion come first", run: func(t *testing.T) error {
			return checkAnsibleToolchainIsAssertedBeforeGoTests(t, in.ci, in.makefile)
		}},
		{name: "install and assertion cannot be disarmed", run: func(t *testing.T) error {
			return checkAnsibleToolchainCannotBeDisarmed(t, in.ci, in.makefile)
		}},
		{name: "collections path matches the image", run: func(t *testing.T) error {
			return checkAnsibleCollectionsPathMatchesImage(t, in.image, in.ci, in.makefile)
		}},
		{name: "assertion rejects other series", runsAssertionScript: true, run: func(t *testing.T) error {
			return checkAnsibleToolchainAssertionRejectsOtherSeries(t, in.ci, in.image, in.makefile)
		}},
	}
}

// TestAnsibleToolchainIsPinnedForEveryGoTestGroup: on the real ci.yml,
// Makefile, image and shard config, every Go test group gets the pinned Ansible
// (no `if:` that skips a group), the install and the assertion step come
// before the first step that runs Go tests, every other job that runs Go tests
// is listed with the reason it does not need Ansible, and the collections go to
// the image's path. The assertion step's own script is run by the test below.
func TestAnsibleToolchainIsPinnedForEveryGoTestGroup(t *testing.T) {
	in := readAnsibleToolchainInputs(t)
	for _, check := range ansibleToolchainChecks(in, ansibleToolchainNotNeededByGoJobs) {
		if check.runsAssertionScript {
			continue
		}
		t.Run(check.name, func(t *testing.T) {
			if err := check.run(t); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestAnsibleToolchainAssertionRejectsOtherSeries runs the assertion step of
// the real ci.yml against stand-in tools (see
// checkAnsibleToolchainAssertionRejectsOtherSeries).
func TestAnsibleToolchainAssertionRejectsOtherSeries(t *testing.T) {
	in := readAnsibleToolchainInputs(t)
	if err := checkAnsibleToolchainAssertionRejectsOtherSeries(t, in.ci, in.image, in.makefile); err != nil {
		t.Fatal(err)
	}
}

func TestAnsibleToolchainStepConditionEvaluator(t *testing.T) {
	for _, tc := range []struct {
		cond  string
		group string
		want  bool
	}{
		{"", "spec", true},
		{"   ", "rest", true},
		{"matrix.group == 'spec'", "spec", true},
		{"matrix.group == 'spec'", "cmd", false},
		{"matrix.group != 'rest'", "rest", false},
		{"matrix.group != 'rest'", "cmd", true},
		{"matrix.group == 'spec' || matrix.group == 'cmd'", "cmd", true},
		{"matrix.group == 'spec' || matrix.group == 'cmd'", "rest", false},
		{"matrix.group == 'rest' && true", "rest", true},
		{"matrix.group == 'rest' && false", "rest", false},
		{"!(matrix.group == 'spec')", "spec", false},
		{"!(matrix.group == 'spec')", "cmd", true},
		{"${{ matrix.group == 'cmd' }}", "cmd", true},
		{"matrix.group == 'SPEC'", "spec", true}, // GitHub compares strings case-insensitively
		// ! binds tighter than ==: `!x == y` is `(!x) == y`, not `!(x == y)`.
		{"!(matrix.group == 'spec') == true", "spec", false},
		{"!(matrix.group == 'spec') == true", "cmd", true},
		{"!(matrix.group == 'spec') == false", "spec", true},
		{"!matrix.group == true", "spec", false},
		{"!matrix.group == true", "", true},
		{"!!matrix.group == true", "spec", true},
		{"!(matrix.group == 'spec') != true", "spec", true},
		{"true", "", true},
		{"false", "spec", false},
		{"matrix.group == 'it''s'", "it's", true},
		{"matrix.group", "spec", true},
		{"matrix.group", "", false},
	} {
		t.Run(fmt.Sprintf("%s/%s", tc.cond, tc.group), func(t *testing.T) {
			got, err := ciStepRunsForGroup(tc.cond, tc.group)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("ciStepRunsForGroup(%q, %q) = %v, want %v", tc.cond, tc.group, got, tc.want)
			}
		})
	}
	for _, cond := range []string{
		"always()",
		"contains(fromJSON('[\"spec\"]'), matrix.group)",
		"github.event_name == 'push'",
		"matrix.group ==",
		"matrix.group == 'spec",
		"(matrix.group == 'spec'",
		"matrix.group 'spec'",
		"matrix.group == true",
		"matrix.group = 'spec'",
		"!matrix.group == 'spec'", // (!matrix.group) == 'spec' compares a boolean with a string; not guessed
		"matrix.group == 'spec' == true",
	} {
		t.Run("unreadable/"+cond, func(t *testing.T) {
			if got, err := ciStepRunsForGroup(cond, "spec"); err == nil || !strings.Contains(err.Error(), "cannot evaluate") {
				t.Fatalf("ciStepRunsForGroup(%q) = %v, %v; want a \"cannot evaluate\" error", cond, got, err)
			}
		})
	}
}

// mustReplaceOnce replaces old by new in s and fails when old is not there
// exactly once: a negative control whose mutation silently did nothing would
// pass for the wrong reason.
func mustReplaceOnce(t *testing.T, s, old, new string) string {
	t.Helper()
	if n := strings.Count(s, old); n != 1 {
		t.Fatalf("mutation target %q occurs %d times, want 1: the control would not test anything", old, n)
	}
	return strings.Replace(s, old, new, 1)
}

var ciJobHeaderRE = regexp.MustCompile(`\n  [A-Za-z0-9_-]+:\n`)

// mutateRealJob applies mutate to the text of one job of ci.yml (from its
// `  name:` line to the next job's), so a control can break one job of the real
// workflow although the same step text appears in another job.
func mutateRealJob(t *testing.T, ci, job string, mutate func(region string) string) string {
	t.Helper()
	header := "\n  " + job + ":\n"
	start := strings.Index(ci, header)
	if start < 0 || strings.Count(ci, header) != 1 {
		t.Fatalf("ci.yml must have exactly one job %q", job)
	}
	start++
	end := len(ci)
	if loc := ciJobHeaderRE.FindStringIndex(ci[start:]); loc != nil {
		end = start + loc[0] + 1
	}
	return ci[:start] + mutate(ci[start:end]) + ci[end:]
}

// withoutStep removes the step with the given name from a job's text, up to
// the next step.
func withoutStep(t *testing.T, region, name string) string {
	t.Helper()
	head := "      - name: " + name + "\n"
	start := strings.Index(region, head)
	if start < 0 || strings.Count(region, head) != 1 {
		t.Fatalf("the job must have exactly one step named %q", name)
	}
	end := len(region)
	if next := strings.Index(region[start+1:], "\n      - "); next >= 0 {
		end = start + 1 + next + 1
	}
	return region[:start] + region[end:]
}

// afterStepName inserts lines (already indented) right after a step's name line.
func afterStepName(t *testing.T, region, name, lines string) string {
	t.Helper()
	head := "      - name: " + name + "\n"
	return mustReplaceOnce(t, region, head, head+lines)
}

// ansibleToolchainJobYAML renders one job of a synthetic workflow. goMatrix
// gives it the generated Go test matrix.
func ansibleToolchainJobYAML(name string, goMatrix bool, steps ...ansibleToolchainStep) string {
	var b strings.Builder
	fmt.Fprintf(&b, "  %s:\n", name)
	if goMatrix {
		b.WriteString("    strategy:\n      matrix: ${{ fromJSON(needs.changes.outputs.go_test_matrix) }}\n")
	}
	b.WriteString("    steps:\n")
	for _, s := range steps {
		fmt.Fprintf(&b, "      - name: %s\n", strconv.Quote(s.Name))
		if s.If != "" {
			fmt.Fprintf(&b, "        if: %s\n", strconv.Quote(s.If))
		}
		if s.Run == "" {
			continue
		}
		b.WriteString("        run: |\n")
		for line := range strings.SplitSeq(strings.TrimRight(s.Run, "\n"), "\n") {
			if line == "" {
				b.WriteString("\n")
			} else {
				b.WriteString("          " + line + "\n")
			}
		}
	}
	return b.String()
}

// TestAnsibleToolchainGuardCatchesDrift is the negative control of the checks
// above. The steps of the synthetic workflows are the real ones read from
// ci.yml, so a case that must pass proves the real text passes and a case that
// must fail breaks exactly one thing and names it. Every mutation is applied
// with mustReplaceOnce, so none can silently be a no-op.
func TestAnsibleToolchainGuardCatchesDrift(t *testing.T) {
	in := readAnsibleToolchainInputs(t)
	jobs, err := parseAnsibleToolchainJobs(in.ci)
	if err != nil {
		t.Fatal(err)
	}
	realJob, ok := jobs["test"]
	if !ok || len(realJob.installSteps()) != 1 || len(realJob.assertSteps()) != 1 {
		t.Fatalf("ci.yml job `test` must have one step installing the pinned Ansible and one step named %q", ansibleToolchainAssertStepName)
	}
	installRun, assertRun := realJob.Steps[realJob.installSteps()[0]].Run, realJob.Steps[realJob.assertSteps()[0]].Run

	install := ansibleToolchainStep{Name: "Install the toolchain", Run: installRun}
	assert := ansibleToolchainStep{Name: ansibleToolchainAssertStepName, Run: assertRun}
	vet := ansibleToolchainStep{Name: "go vet", Run: "go vet ./..."}
	gotest := ansibleToolchainStep{Name: "go test", Run: "make test-race"}
	withIf := func(s ansibleToolchainStep, cond string) ansibleToolchainStep { s.If = cond; return s }
	withRun := func(s ansibleToolchainStep, run string) ansibleToolchainStep { s.Run = run; return s }
	workflow := func(jobs ...string) string { return "jobs:\n" + strings.Join(jobs, "") }
	testJob := func(steps ...ansibleToolchainStep) string { return ansibleToolchainJobYAML("test", true, steps...) }
	good := testJob(install, assert, vet, gotest)
	droppedLine := func(run, containing string) string {
		var kept []string
		for line := range strings.SplitSeq(run, "\n") {
			if !strings.Contains(line, containing) {
				kept = append(kept, line)
			}
		}
		if len(kept) != len(strings.Split(run, "\n"))-1 {
			t.Fatalf("%q must be on exactly one line of the assertion step", containing)
		}
		return strings.Join(kept, "\n")
	}
	notAnsible := ansibleToolchainStep{Name: "lint", Run: "golangci-lint run ./..."}
	withExtraGroup := append(slices.Clone(in.groups), "extra")
	const specCmdRest = "matrix.group == 'spec' || matrix.group == 'cmd' || matrix.group == 'rest'"
	const installP = "-p /usr/share/ansible/collections"
	const installName = "Install Ansible toolchain and PyYAML (pinned like the delivery image)"
	// inRealJob mutates one job of the real ci.yml.
	inRealJob := func(job string, mutate func(region string) string) string {
		return mutateRealJob(t, in.ci, job, mutate)
	}
	realStepLines := func(job, step, lines string) string {
		return inRealJob(job, func(r string) string { return afterStepName(t, r, step, lines) })
	}
	realJobLines := func(job, lines string) string {
		return inRealJob(job, func(r string) string {
			return mustReplaceOnce(t, r, "    timeout-minutes:", lines+"    timeout-minutes:")
		})
	}

	for _, tc := range []struct {
		name      string
		ci        string
		image     string // in.image when empty
		groups    []string
		notNeeded map[string]string
		want      string // "" = every check must pass
	}{
		// Must pass.
		{name: "the real workflow", ci: in.ci, notNeeded: ansibleToolchainNotNeededByGoJobs},
		{name: "the same steps in a synthetic workflow", ci: workflow(good)},
		{name: "a third job with a matching install and the assertion", ci: workflow(good, ansibleToolchainJobYAML("third", false, install, assert, ansibleToolchainStep{Name: "go test", Run: "go test ./x/"}))},
		{name: "a job that runs no Go tests needs nothing", ci: workflow(good, ansibleToolchainJobYAML("lint", false, notAnsible))},
		{name: "a job that runs Go tests and is listed with a reason", ci: workflow(good, ansibleToolchainJobYAML("listed", false, ansibleToolchainStep{Name: "t", Run: "go test ./x/"})), notNeeded: map[string]string{"listed": "no Ansible"}},
		{name: "continue-on-error: false on the assertion step", ci: realStepLines("test", ansibleToolchainAssertStepName, "        continue-on-error: false\n"), notNeeded: ansibleToolchainNotNeededByGoJobs},

		// The install must reach every group.
		{name: "the spec-only if is back", ci: workflow(testJob(withIf(install, "matrix.group == 'spec'"), assert, vet, gotest)), want: "group(s): cmd, rest"},
		{name: "spec or cmd", ci: workflow(testJob(withIf(install, "matrix.group == 'spec' || matrix.group == 'cmd'"), assert, vet, gotest)), want: "group(s): rest"},
		{name: "a fourth group behind a group-list if", ci: workflow(testJob(withIf(install, specCmdRest), assert, vet, gotest)), groups: withExtraGroup, want: "group(s): extra"},
		{name: "the same list while the groups are the three", ci: workflow(testJob(withIf(install, specCmdRest), assert, vet, gotest))},
		{name: "an if the check cannot read", ci: workflow(testJob(withIf(install, "always()"), assert, vet, gotest)), want: "cannot evaluate"},
		{name: "an if on the install of a job with no groups", ci: workflow(good, ansibleToolchainJobYAML("third", false, withIf(install, "matrix.group == 'spec'"), assert, gotest)), want: "CI job third"},

		// The assertion step.
		{name: "the assertion step is gone", ci: workflow(testJob(install, vet, gotest)), want: "exactly one step named"},
		{name: "the assertion step has an if", ci: workflow(testJob(install, withIf(assert, "matrix.group == 'spec'"), vet, gotest)), want: "no condition"},
		{name: "the assertion step moved after the go test step", ci: workflow(testJob(install, vet, gotest, assert)), want: `step "` + ansibleToolchainAssertStepName + `" comes after step "go test"`},
		{name: "the assertion step is before the install", ci: workflow(testJob(assert, install, vet, gotest)), want: "comes before the install step"},
		{name: "the install moved after the go test step", ci: workflow(testJob(assert, vet, gotest, install)), want: `install step "Install the toolchain" comes after`},
		{name: "the assertion step names the package it checks", ci: workflow(testJob(install, withRun(assert, assertRun+"echo ansible-core ok\n"), vet, gotest)), want: "second install requirement"},
		{name: "the assertion asserts another series", ci: workflow(testJob(install, withRun(assert, mustReplaceOnce(t, assertRun, `*"[core 2.19."*`, `*"[core 2.21."*`)), vet, gotest)), want: "rejected a toolchain whose tools are all at 2.19"},
		{name: "the assertion only echoes", ci: workflow(testJob(install, withRun(assert, droppedLine(assertRun, `case "$version" in`)), vet, gotest)), want: "accepted a toolchain whose ansible is 2.22.0"},
		{name: "the assertion forgets ansible-vault", ci: workflow(testJob(install, withRun(assert, mustReplaceOnce(t, assertRun, " ansible-vault; do", "; do")), vet, gotest)), want: "whose ansible-vault is 2.22.0"},
		{name: "the assertion forgets ansible-inventory", ci: workflow(testJob(install, withRun(assert, mustReplaceOnce(t, assertRun, " ansible-inventory ", " ")), vet, gotest)), want: "whose ansible-inventory is 2.22.0"},
		{name: "the assertion has no ping", ci: workflow(testJob(install, withRun(assert, droppedLine(assertRun, "-m ping")), vet, gotest)), want: "never ran `ansible ... -m ping`"},
		{name: "the assertion ignores a failing ping", ci: workflow(testJob(install, withRun(assert, mustReplaceOnce(t, assertRun, ">/dev/null", ">/dev/null || true")), vet, gotest)), want: "ignored a failing"},
		{name: "the ping does not isolate ANSIBLE_HOME", ci: workflow(testJob(install, withRun(assert, mustReplaceOnce(t, assertRun, `ANSIBLE_HOME="$(mktemp -d)" `, "")), vet, gotest)), want: "ping ran with ANSIBLE_HOME"},
		{name: "the ping does not load the json callback", ci: workflow(testJob(install, withRun(assert, mustReplaceOnce(t, assertRun, "ANSIBLE_STDOUT_CALLBACK=ansible.posix.json ", "")), vet, gotest)), want: "ansible.posix.json stdout callback"},

		// Every job that runs Go tests has the toolchain or a reason.
		{name: "a new job runs go test without the pin", ci: workflow(good, ansibleToolchainJobYAML("extra", false, ansibleToolchainStep{Name: "t", Run: "go test ./x/"})), want: "CI job extra runs Go tests without installing the pinned Ansible"},
		{name: "a new job runs a make target that runs go test", ci: workflow(good, ansibleToolchainJobYAML("extra", false, gotest)), want: "CI job extra runs Go tests without installing the pinned Ansible"},
		{name: "the test job lost the install", ci: workflow(testJob(vet, gotest)), want: "CI job test runs Go tests without installing the pinned Ansible"},
		{name: "a listed job is gone", ci: workflow(good), notNeeded: map[string]string{"ghost": "x"}, want: "has no such job"},
		{name: "a listed job runs no Go tests", ci: workflow(good, ansibleToolchainJobYAML("lint", false, notAnsible)), notNeeded: map[string]string{"lint": "x"}, want: "runs no Go tests"},
		{name: "a listed job installs the pin now", ci: workflow(good, ansibleToolchainJobYAML("third", false, install, assert, gotest)), notNeeded: map[string]string{"third": "x"}, want: "installs the pinned Ansible now"},

		// The collections path.
		{name: "collections go to the default home", ci: workflow(testJob(withRun(install, mustReplaceOnce(t, installRun, installP, "-p ~/.ansible/collections")), assert, vet, gotest)), want: "installs collections into"},
		{name: "collections go to the default path with no -p", ci: workflow(testJob(withRun(install, mustReplaceOnce(t, installRun, installP+" ", "")), assert, vet, gotest)), want: "installs collections into"},
		{name: "the image installs collections with no -p", ci: good, image: mustReplaceOnce(t, in.image, installP+" ", ""), want: "images/Dockerfile.pilot-cli: want one"},

		{name: "a second install into the default path", ci: workflow(testJob(withRun(install, installRun+"ansible-galaxy collection install community.general\n"), assert, vet, gotest)), want: `installs collections into ["/usr/share/ansible/collections" ""]`},

		// Jobs of the real ci.yml that start Ansible (mcp-remote: pilot_diagnose_delivery runs ansible and ansible-inventory).
		{name: "mcp-remote loses its assertion step", ci: inRealJob("mcp-remote", func(r string) string { return withoutStep(t, r, ansibleToolchainAssertStepName) }), notNeeded: ansibleToolchainNotNeededByGoJobs,
			want: "CI job mcp-remote installs the pinned Ansible and runs Go tests, so it needs exactly one step named"},
		{name: "mcp-remote loses its install step", ci: inRealJob("mcp-remote", func(r string) string { return withoutStep(t, r, installName) }), notNeeded: ansibleToolchainNotNeededByGoJobs,
			want: "CI job mcp-remote runs Go tests without installing the pinned Ansible"},
		{name: "mcp-remote's install has a group if", ci: realStepLines("mcp-remote", installName, "        if: matrix.group == 'spec'\n"), notNeeded: ansibleToolchainNotNeededByGoJobs,
			want: "CI job mcp-remote: step"},
		{name: "mcp-remote is listed as not needing it again", ci: in.ci, notNeeded: map[string]string{"mcp-remote": "x", "root-tests": "x", "skills": "x"},
			want: "lists mcp-remote, but the job installs the pinned Ansible now"},

		// A failure of the install or the assertion has to fail the job, and PATH has to stay what the install made it.
		{name: "continue-on-error on the assertion step", ci: realStepLines("test", ansibleToolchainAssertStepName, "        continue-on-error: true\n"), notNeeded: ansibleToolchainNotNeededByGoJobs,
			want: `step "` + ansibleToolchainAssertStepName + `" has ` + "`continue-on-error: true`"},
		{name: "continue-on-error on mcp-remote's assertion step", ci: realStepLines("mcp-remote", ansibleToolchainAssertStepName, "        continue-on-error: true\n"), notNeeded: ansibleToolchainNotNeededByGoJobs,
			want: "CI job mcp-remote: step"},
		{name: "continue-on-error on the install step", ci: realStepLines("test", installName, "        continue-on-error: true\n"), notNeeded: ansibleToolchainNotNeededByGoJobs,
			want: `step "` + installName + `" has ` + "`continue-on-error: true`"},
		{name: "continue-on-error is an expression", ci: realStepLines("test", ansibleToolchainAssertStepName, "        continue-on-error: ${{ matrix.group == 'cmd' }}\n"), notNeeded: ansibleToolchainNotNeededByGoJobs,
			want: "continue-on-error: ${{ matrix.group == 'cmd' }} (a string, not a boolean)"},
		{name: "continue-on-error is the string false", ci: realStepLines("test", ansibleToolchainAssertStepName, "        continue-on-error: \"false\"\n"), notNeeded: ansibleToolchainNotNeededByGoJobs,
			want: "continue-on-error: false (a string, not a boolean)"},
		{name: "continue-on-error on the job", ci: realJobLines("test", "    continue-on-error: true\n"), notNeeded: ansibleToolchainNotNeededByGoJobs,
			want: "CI job test has `continue-on-error: true`"},
		{name: "PATH set in the env of the assertion step", ci: realStepLines("test", ansibleToolchainAssertStepName, "        env:\n          PATH: /opt/pipx_bin:${{ env.PATH }}\n"), notNeeded: ansibleToolchainNotNeededByGoJobs,
			want: `step "` + ansibleToolchainAssertStepName + `" sets PATH in its ` + "`env:`"},
		{name: "PATH set in the env of the job", ci: realJobLines("test", "    env:\n      PATH: /opt/pipx_bin\n"), notNeeded: ansibleToolchainNotNeededByGoJobs,
			want: "CI job test sets PATH in its `env:`"},
		{name: "an env that is an expression", ci: realStepLines("test", ansibleToolchainAssertStepName, "        env: ${{ fromJSON(needs.changes.outputs.profile) }}\n"), notNeeded: ansibleToolchainNotNeededByGoJobs,
			want: "sets PATH in its `env:`"},

		{name: "a malformed workflow", ci: "jobs: [", want: "parse CI workflow"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inputs := in
			inputs.ci = tc.ci
			if tc.image != "" {
				inputs.image = tc.image
			}
			if tc.groups != nil {
				inputs.groups = tc.groups
			}
			var err error
			for _, check := range ansibleToolchainChecks(inputs, tc.notNeeded) {
				if err = check.run(t); err != nil {
					break
				}
			}
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("want every check to pass, got: %v", err)
			case tc.want != "" && err == nil:
				t.Fatalf("want an error containing %q, every check passed", tc.want)
			case tc.want != "" && !strings.Contains(err.Error(), tc.want):
				t.Fatalf("want an error containing %q, got: %v", tc.want, err)
			case tc.want != "":
				t.Logf("rejected: %v", err)
			}
		})
	}
}
