// dockerfile_artifact_consistency_test.go guards the invariant behind a
// real incident (2026-09-15): a component's group_vars example declares a
// controller-local build artifact under dist/ (e.g.
// pilot_binary_path: "dist/pilot-linux-amd64"), its apply playbook asserts
// that file exists on the controller before doing anything else, but
// images/Dockerfile.pilot-cli — the one artifact that actually ships as
// "the controller" for every operator following DELIVERY.md's documented
// (and only) delivery path — never built or copied it in. This was
// invisible for as long as pilot-access-gateway was single-component-only,
// and surfaced the moment it became reachable via a plain site-wide
// deploy: the very first real site-wide run against it failed the
// "Gate: pilot binary exists" assert and aborted the whole delivery
// transaction on a real production host.
//
// This test prevents the CAUSE from ever landing unnoticed again: any new
// dist/-relative group_vars default must have a matching COPY destination
// in the Dockerfile, checked at test time rather than the next time
// someone happens to run a live deploy against it.
package cmd

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

var dockerfileCopyDistDestRE = regexp.MustCompile(`(?m)^\s*COPY\s+(?:--from=\S+\s+)?\S+\s+/pilot/(dist/\S+)\s*$`)

// dockerfileBakedDistArtifacts returns every dist/-relative path
// images/Dockerfile.pilot-cli's runtime stage actually COPYs into the
// final image, keyed by that relative path (e.g. "dist/pilot-linux-amd64").
func dockerfileBakedDistArtifacts(root string) (map[string]bool, error) {
	path := filepath.Join(root, "images", "Dockerfile.pilot-cli")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	baked := make(map[string]bool)
	for _, match := range dockerfileCopyDistDestRE.FindAllStringSubmatch(string(data), -1) {
		baked[match[1]] = true
	}
	return baked, nil
}

// exampleGroupVarsDistDefaults walks every group_vars/*.example.yml file's
// top-level values (recursing into nested maps) and collects every string
// value that looks like a repo-root-relative dist/ artifact path, along
// with the file:key it came from for error reporting.
func exampleGroupVarsDistDefaults(root string) (map[string]string, error) {
	matches, err := filepath.Glob(filepath.Join(root, "group_vars", "*.example.yml"))
	if err != nil {
		return nil, err
	}
	found := make(map[string]string)
	for _, path := range matches {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var doc map[string]any
		if err := yaml.Unmarshal(data, &doc); err != nil {
			return nil, err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			rel = path
		}
		collectDistDefaults(doc, rel, found)
	}
	return found, nil
}

func collectDistDefaults(node any, source string, found map[string]string) {
	switch v := node.(type) {
	case map[string]any:
		for key, val := range v {
			if s, ok := val.(string); ok && strings.HasPrefix(s, "dist/") {
				found[s] = source + ":" + key
				continue
			}
			collectDistDefaults(val, source, found)
		}
	}
}

func TestDockerfileBakesEveryDistArtifactGroupVarsExpects(t *testing.T) {
	root := repoRootForTest(t)

	baked, err := dockerfileBakedDistArtifacts(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(baked) == 0 {
		t.Fatal("found zero dist/ COPY destinations in images/Dockerfile.pilot-cli — regex likely broken, or the Dockerfile stopped baking any dist/ artifact")
	}

	expected, err := exampleGroupVarsDistDefaults(root)
	if err != nil {
		t.Fatal(err)
	}

	for distPath, source := range expected {
		if !baked[distPath] {
			t.Errorf(
				"%s defaults to %q, a controller-local dist/ artifact, but images/Dockerfile.pilot-cli "+
					"never builds+COPYs it to /pilot/%s — every operator following DELIVERY.md's documented "+
					"docker-image delivery path will fail this component's \"binary exists\" gate the first "+
					"time it actually runs (see this file's header comment for the 2026-09-15 incident this "+
					"exact drift caused)",
				source, distPath, distPath)
		}
	}
}
