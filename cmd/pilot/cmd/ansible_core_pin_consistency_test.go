// ansible_core_pin_consistency_test.go keeps the ansible-core version that
// images/Dockerfile.pilot-cli bakes into the delivery image and the one the
// CI playbook-lint job installs on the same pinned series. Both used to
// install an unpinned ansible-core; on 2026-10-12 a cache-missed image build
// pulled 2.21.5 while every Ansible behaviour AGENTS.md documents was
// verified on 2.19.2. An unpinned install, or two different pins, lets CI
// lint the playbooks against a different ansible-core than operators run.
package cmd

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// ansibleCoreRequirementRE matches an ansible-core requirement token in a
// pip/uv install command, capturing any version specifier after it.
var ansibleCoreRequirementRE = regexp.MustCompile(`(?:^|[\s"'])ansible-core([<>=!~][^\s"'\\]*)?(?:[\s"'\\]|$)`)

// ansibleCoreRequirements returns the version specifier of every
// ansible-core requirement on a non-comment line of the file ("" for an
// unpinned requirement).
func ansibleCoreRequirements(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var specs []string
	for line := range strings.SplitSeq(string(data), "\n") {
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
	files := []string{
		filepath.Join("images", "Dockerfile.pilot-cli"),
		filepath.Join(".github", "workflows", "ci.yml"),
	}

	pins := make(map[string]string)
	for _, rel := range files {
		specs := ansibleCoreRequirements(t, filepath.Join(root, rel))
		if len(specs) != 1 {
			t.Fatalf("%s: found %d ansible-core install requirements %q, want exactly 1", rel, len(specs), specs)
		}
		if !strings.HasPrefix(specs[0], "==") {
			t.Errorf("%s installs ansible-core without an == pin (%q); pin it to the series the playbooks were verified on", rel, specs[0])
		}
		pins[rel] = specs[0]
	}

	if pins[files[0]] != pins[files[1]] {
		t.Errorf("ansible-core pins differ: %s has %q, %s has %q; CI must lint against the ansible-core the image ships",
			files[0], pins[files[0]], files[1], pins[files[1]])
	}
}

func TestAnsibleCoreRequirementsDetectUnpinnedInstall(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Dockerfile")
	content := "# ansible-core is mentioned in a comment\n" +
		"RUN uv pip install --system \\\n" +
		"        ansible-core \\\n" +
		"        docker\n" +
		"RUN pip install \"ansible-core==2.19.*\" ansible-lint\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	got := ansibleCoreRequirements(t, path)
	want := []string{"", "==2.19.*"}
	if !slices.Equal(got, want) {
		t.Fatalf("ansibleCoreRequirements = %q, want %q", got, want)
	}
}

// galaxyCollections returns the collections named by every
// `ansible-galaxy collection install` command on non-comment lines of the
// file, following backslash continuations and skipping options.
func galaxyCollections(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for line := range strings.SplitSeq(string(data), "\n") {
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

// TestAnsibleCollectionsMatchBetweenImageAndCI: the CI playbook-lint job is
// meant to syntax-check against the collections the delivery image ships.
// The image added community.general on 2026-07-31 and CI never did, so a
// community.general module used directly in a playbook failed CI's
// syntax-check while the image ran it (PR #79, community.general.sefcontext
// in log-server's rescue, 2026-10-15).
func TestAnsibleCollectionsMatchBetweenImageAndCI(t *testing.T) {
	root := repoRootForTest(t)
	image := galaxyCollections(t, filepath.Join(root, "images", "Dockerfile.pilot-cli"))
	ci := galaxyCollections(t, filepath.Join(root, ".github", "workflows", "ci.yml"))
	if len(image) == 0 {
		t.Fatal("found no ansible-galaxy collection install in images/Dockerfile.pilot-cli")
	}
	if !slices.Equal(image, ci) {
		t.Errorf("collections differ: the image installs %v, CI's playbook-lint installs %v", image, ci)
	}
}
