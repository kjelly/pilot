package contract

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateLocalDiskPaths(t *testing.T) {
	c := minimalValidContract()
	c.Resources = Resources{MinDiskGiB: 50, DiskPaths: []string{"/var/lib/docker", "/opt/pilot/wazuh-docker", "/var/lib/pilot-session-store"}}
	if err := validateLocal(c); err != nil {
		t.Fatalf("validateLocal: %v", err)
	}

	for _, path := range []string{
		"var/lib/docker",        // relative
		"/",                     // / is the default already
		"/var/lib/docker/",      // not clean
		"/var/lib/../docker",    // not clean
		"/var/./lib",            // not clean
		"/var/lib/my data",      // needs shell quoting
		"/var/lib/x'; rm -rf /", // shell injection
		"/var/lib/$HOME",        // shell expansion
	} {
		c.Resources = Resources{MinDiskGiB: 50, DiskPaths: []string{path}}
		if err := validateLocal(c); err == nil || !strings.Contains(err.Error(), "resources.diskPaths entry") {
			t.Fatalf("diskPaths %q: err=%v", path, err)
		}
	}

	c.Resources = Resources{MinDiskGiB: 50, DiskPaths: []string{"/var/lib/docker", "/var/lib/docker"}}
	if err := validateLocal(c); err == nil || !strings.Contains(err.Error(), "duplicate resources.diskPaths") {
		t.Fatalf("duplicate: err=%v", err)
	}

	c.Resources = Resources{DiskPaths: []string{"/var/lib/docker"}}
	if err := validateLocal(c); err == nil || !strings.Contains(err.Error(), "positive minDiskGiB") {
		t.Fatalf("no minimum: err=%v", err)
	}
}

// dockerDataRoot is where the Docker Engine the docker component installs
// keeps images and named volumes. No apply playbook names it, so a component
// may declare it only when it is docker or runs on docker.
const dockerDataRoot = "/var/lib/docker"

// TestContractDiskPathsMatchApplyPlaybooks keeps every diskPaths entry tied to
// where the component really writes: the path must appear in its apply
// playbook, so moving a data directory there without updating the contract
// fails here instead of silently measuring the old location.
func TestContractDiskPathsMatchApplyPlaybooks(t *testing.T) {
	t.Parallel()

	root := contractRepoRoot(t)
	loader, err := NewLoader(root)
	if err != nil {
		t.Fatal(err)
	}
	contracts, err := loader.LoadDir(DefaultDirectory)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range contracts {
		if len(c.Resources.DiskPaths) == 0 {
			continue
		}
		playbook, err := os.ReadFile(filepath.Join(root, c.Playbooks.Apply))
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range c.Resources.DiskPaths {
			if path == dockerDataRoot {
				if !runsOnDocker(c) {
					t.Errorf("contract %s declares diskPaths %s but neither is docker nor depends on it", c.ID, path)
				}
				continue
			}
			if !strings.Contains(string(playbook), path) {
				t.Errorf("contract %s declares diskPaths %s, which %s never mentions", c.ID, path, c.Playbooks.Apply)
			}
		}
	}
}

func runsOnDocker(c Contract) bool {
	if c.ID == "docker" {
		return true
	}
	for _, dependency := range c.Dependencies {
		if dependency.Component == "docker" && dependency.Required {
			return true
		}
	}
	return false
}
