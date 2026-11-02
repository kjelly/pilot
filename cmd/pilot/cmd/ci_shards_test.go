package cmd

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
)

func TestCIGoShardsCoverAllPackagesExactlyOnce(t *testing.T) {
	root := repoRootForTest(t)
	run := func(command string, args ...string) string {
		t.Helper()
		cmd := exec.Command(command, args...)
		cmd.Dir = root
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("%s %v: %v\n%s", command, args, err, out)
		}
		return string(out)
	}
	all := strings.Fields(run("go", "list", "./..."))
	var got []string
	for _, shard := range []string{"spec", "cmd", "rest"} {
		packages := strings.Fields(run("bash", "scripts/ci-go-test-packages.sh", shard))
		if len(packages) == 0 {
			t.Fatalf("empty shard %s", shard)
		}
		if shard != "rest" && len(packages) != 1 {
			t.Fatalf("%s: %v", shard, packages)
		}
		got = append(got, packages...)
	}
	slices.Sort(got)
	slices.Sort(all)
	if !slices.Equal(got, all) {
		t.Fatalf("shards %v != all packages %v", got, all)
	}
	var wf struct {
		Jobs map[string]struct {
			Strategy struct{ Matrix struct{ Shard []string } }
			If       string
		}
	}
	if err := yaml.Unmarshal([]byte(readCIYAML(t)), &wf); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(wf.Jobs["test"].Strategy.Matrix.Shard, []string{"spec", "cmd", "rest"}) {
		t.Fatal("CI must run all three package shards")
	}
	if wf.Jobs["test"].If != "needs.changes.outputs.evidence_only != 'true'" {
		t.Fatal("Go suite skip must depend only on evidence diff")
	}
}

func TestCIIntegrationSuitesRemainParallelAndBlocking(t *testing.T) {
	var wf struct {
		Jobs map[string]struct {
			Needs    any
			If       string
			Timeout  int `yaml:"timeout-minutes"`
			Strategy struct {
				FailFast bool `yaml:"fail-fast"`
				Matrix   struct{ Target []string }
			}
			Steps []struct{ Run string }
		}
	}
	if err := yaml.Unmarshal([]byte(readCIYAML(t)), &wf); err != nil {
		t.Fatal(err)
	}
	job := wf.Jobs["playbook-integration"]
	want := []string{"alert-rules-test", "identity-noop-test", "identity-ssh-cache-test", "identity-secret-test", "freeipa-server-pool-test"}
	if !slices.Equal(job.Strategy.Matrix.Target, want) || job.Strategy.FailFast {
		t.Fatal("each required runtime suite must run in its own non-fail-fast matrix job")
	}
	if job.If != "needs.changes.outputs.evidence_only != 'true'" || !slices.Contains(ciNeedsList(job.Needs), "changes") {
		t.Fatal("runtime reuse must depend on candidate validation")
	}
	mk, err := os.ReadFile(filepath.Join(repoRootForTest(t), "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range want {
		if time.Duration(job.Timeout)*time.Minute < makeTargetTimeoutCaps(t, string(mk), target)+ciGoTestSetupMargin {
			t.Fatalf("integration job budget does not cover %s and setup", target)
		}
		for _, step := range wf.Jobs["playbook-lint"].Steps {
			if strings.Contains(step.Run, target) {
				t.Fatalf("%s is still serialized in lint", target)
			}
		}
	}
	found := false
	for _, step := range job.Steps {
		if step.Run == `make "$TARGET"` {
			found = true
		}
	}
	if !found {
		t.Fatal("matrix target must actually execute")
	}
	if !slices.Contains(ciNeedsList(wf.Jobs["image"].Needs), "playbook-integration") {
		t.Fatal("image must wait for integration")
	}
	if !slices.Contains(ciNeedsList(wf.Jobs["ci-receipt"].Needs), "image") {
		t.Fatal("receipt must wait for full image validation")
	}
}
