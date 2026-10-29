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
// service docker"). Everywhere else the block must run exactly as before.
//
// This runs the real probe, the real defer fact and the real block `when` with
// real ansible-playbook, with the block's body swapped for a marker, and a
// fake systemctl that says whether docker.service exists.
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
		"Determine whether this preview must defer the install (docker not installed yet)",
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
		gpu           bool
		occupied      bool
		wantRuns      bool
	}{
		{"preview, docker not installed yet: deferred", true, false, true, false, false},
		{"preview, docker installed: runs", true, true, true, false, true},
		{"real apply, docker not installed yet: runs (docker is installed first)", false, false, true, false, true},
		{"real apply, docker installed: runs", false, true, true, false, true},
		{"no GPU: never runs", true, true, false, false, false},
		{"port served by something else: never runs", false, true, true, true, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
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
			args := []string{"-i", "localhost,", playbook}
			if tt.check {
				args = append(args, "--check")
			}
			cmd := exec.Command(ansible, args...)
			cmd.Env = append(os.Environ(), "PATH="+fake+":"+os.Getenv("PATH"), "ANSIBLE_NOCOLOR=1", "ANSIBLE_LOCALHOST_WARNING=False")
			log, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("ansible-playbook: %v\n%s", err, log)
			}
			if ran := strings.Contains(string(log), "INSTALL-BLOCK-RAN"); ran != tt.wantRuns {
				t.Fatalf("install block ran = %v, want %v\n%s", ran, tt.wantRuns, log)
			}
		})
	}
}
