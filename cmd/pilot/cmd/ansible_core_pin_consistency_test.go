// ansible_core_pin_consistency_test.go keeps the ansible-core version that
// images/Dockerfile.pilot-cli bakes into the delivery image and the one the
// CI playbook jobs install on the same pinned series. Both used to
// install an unpinned ansible-core; on 2026-10-12 a cache-missed image build
// pulled 2.21.5 while every Ansible behaviour AGENTS.md documents was
// verified on 2.19.2. An unpinned install, or two different pins, lets CI
// lint the playbooks against a different ansible-core than operators run.
package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

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

// galaxyCollections returns the collections named by every
// `ansible-galaxy collection install` command on non-comment lines of the
// script, following backslash continuations and skipping options.
func galaxyCollections(content string) []string {
	var lines []string
	for line := range strings.SplitSeq(content, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		lines = append(lines, line)
	}
	joined := strings.ReplaceAll(strings.Join(lines, "\n"), "\\\n", " ")
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
