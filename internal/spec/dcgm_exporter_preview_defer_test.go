package spec

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// A --check preview does not install docker, so on a host that has never had it
// the dcgm-exporter install + container block must wait for the real apply
// (the first one to fail was Step 2's restart: "Could not find the requested
// service docker"). That only holds for hosts pilot installs docker on, i.e.
// hosts in the `docker` inventory group; docker may be installed and operated
// outside pilot (contracts/dcgm-exporter.yaml), and a host outside the group
// with no docker.service still fails the real apply, so its preview must keep
// running the block (and failing). Everywhere else the block runs as before.
//
// This runs the real probe, the real defer fact and the real block `when` with
// real ansible-playbook, with the block's body swapped for a marker, a fake
// systemctl that says whether docker.service exists, and an inventory that
// puts the host inside or outside the `docker` group.
func TestDcgmExporterPreviewDefersTheBlockOnlyWithoutDocker(t *testing.T) {
	ansible, err := exec.LookPath("ansible-playbook")
	if err != nil {
		t.Skip("ansible-playbook not installed")
	}
	raw, err := os.ReadFile("../../playbooks/apply/dcgm-exporter-apply.yml")
	if err != nil {
		t.Fatal(err)
	}
	var plays []map[string]any
	if err := yaml.Unmarshal(raw, &plays); err != nil {
		t.Fatal(err)
	}
	byName := map[string]map[string]any{}
	for _, play := range plays {
		for _, section := range []string{"pre_tasks", "tasks"} {
			list, _ := play[section].([]any)
			for _, task := range list {
				if m, ok := task.(map[string]any); ok {
					if name, _ := m["name"].(string); name != "" {
						byName[name] = m
					}
				}
			}
		}
	}
	var tasks []any
	for _, name := range []string{
		"Check whether docker.service exists yet",
		"Determine whether this preview must defer the install (docker not installed yet, and pilot installs it)",
		"dcgm-exporter install + container",
	} {
		task, ok := byName[name]
		if !ok {
			t.Fatalf("dcgm-exporter-apply.yml has no task named %q", name)
		}
		if name == "dcgm-exporter install + container" {
			// Only whether the block runs matters here, not what is in it.
			delete(task, "rescue")
			task["block"] = []any{map[string]any{"name": "marker", "ansible.builtin.debug": map[string]any{"msg": "INSTALL-BLOCK-RAN"}}}
		}
		tasks = append(tasks, task)
	}

	for _, tt := range []struct {
		name          string
		check         bool
		dockerPresent bool
		inDockerGroup bool
		gpu           bool
		occupied      bool
		wantRuns      bool
	}{
		{"preview, no docker.service, host in docker group: deferred", true, false, true, true, false, false},
		{"preview, no docker.service, host NOT in docker group: runs (pilot will not install docker)", true, false, false, true, false, true},
		{"preview, docker installed, host in docker group: runs", true, true, true, true, false, true},
		{"preview, docker installed, host NOT in docker group: runs", true, true, false, true, false, true},
		{"real apply, no docker.service, host in docker group: runs (docker-apply installs it first)", false, false, true, true, false, true},
		{"real apply, no docker.service, host NOT in docker group: runs", false, false, false, true, false, true},
		{"real apply, docker installed: runs", false, true, true, true, false, true},
		{"no GPU: never runs", true, true, true, false, false, false},
		{"no GPU, no docker, in docker group: never runs", true, false, true, false, false, false},
		{"port served by something else: never runs", false, true, true, true, true, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			// Not t.TempDir(): it embeds the subtest name (with commas), and
			// ansible cannot parse an inventory whose path contains one.
			dir, err := os.MkdirTemp("", "dcgm-defer-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(dir) })
			fake := filepath.Join(dir, "bin")
			if err := os.Mkdir(fake, 0o755); err != nil {
				t.Fatal(err)
			}
			rc := "1"
			if tt.dockerPresent {
				rc = "0"
			}
			if err := os.WriteFile(filepath.Join(fake, "systemctl"), []byte("#!/bin/sh\nexit "+rc+"\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			play := []any{map[string]any{
				"hosts": "localhost", "connection": "local", "gather_facts": false,
				"vars": map[string]any{
					"dcgm_exporter_gpu_present":            tt.gpu,
					"dcgm_exporter_port_occupied_by_other": tt.occupied,
				},
				"tasks": tasks,
			}}
			out, err := yaml.Marshal(play)
			if err != nil {
				t.Fatal(err)
			}
			playbook := filepath.Join(dir, "play.yml")
			if err := os.WriteFile(playbook, out, 0o600); err != nil {
				t.Fatal(err)
			}
			group := "other"
			if tt.inDockerGroup {
				group = "docker"
			}
			inventory := filepath.Join(dir, "hosts.ini")
			if err := os.WriteFile(inventory, []byte("["+group+"]\nlocalhost ansible_connection=local\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			args := []string{"-i", inventory, playbook}
			if tt.check {
				args = append(args, "--check")
			}
			cmd := exec.Command(ansible, args...)
			cmd.Env = append(os.Environ(), "PATH="+fake+":"+os.Getenv("PATH"), "ANSIBLE_NOCOLOR=1", "ANSIBLE_LOCALHOST_WARNING=False")
			log, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("ansible-playbook: %v\n%s", err, log)
			}
			// A silently unparsed inventory would fall back to the implicit
			// localhost, which is in no group, and make the group cases vacuous.
			if strings.Contains(string(log), "No inventory was parsed") || strings.Contains(string(log), "Failed to parse inventory") {
				t.Fatalf("inventory was not parsed\n%s", log)
			}
			if ran := strings.Contains(string(log), "INSTALL-BLOCK-RAN"); ran != tt.wantRuns {
				t.Fatalf("install block ran = %v, want %v\n%s", ran, tt.wantRuns, log)
			}
		})
	}
}

// A --check preview does not write the NVIDIA apt key or repo list, so the
// toolkit install's scoped APT refresh cannot find the .list file; the install
// must be skipped in check mode (same as wazuh-fim's third-party repo).
func TestDcgmExporterToolkitInstallIsSkippedInCheckMode(t *testing.T) {
	raw, err := os.ReadFile("../../playbooks/apply/dcgm-exporter-apply.yml")
	if err != nil {
		t.Fatal(err)
	}
	var plays []map[string]any
	if err := yaml.Unmarshal(raw, &plays); err != nil {
		t.Fatal(err)
	}
	const name = "Step 1: Install nvidia-container-toolkit (spec C1)"
	for _, play := range plays {
		tasks, _ := play["tasks"].([]any)
		for _, task := range tasks {
			block, _ := task.(map[string]any)["block"].([]any)
			for _, inner := range block {
				m, _ := inner.(map[string]any)
				if m["name"] != name {
					continue
				}
				if when, _ := m["when"].(string); strings.TrimSpace(when) != "not ansible_check_mode" {
					t.Fatalf("%q has when %v, want `not ansible_check_mode`", name, m["when"])
				}
				return
			}
		}
	}
	t.Fatalf("dcgm-exporter-apply.yml has no task named %q", name)
}
