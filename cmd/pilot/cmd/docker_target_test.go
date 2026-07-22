package cmd

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/dockertarget"
)

// newImageShim writes a fake `docker` that logs argv to PILOT_CALLS_LOG
// and dispatches on the given script body, then points PILOT_DOCKER_BIN
// at it. Returns the calls-log path.
func newImageShim(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	shim := filepath.Join(dir, "docker")
	log := filepath.Join(dir, "calls.log")
	script := "#!/bin/sh\necho \"$@\" >> \"$PILOT_CALLS_LOG\"\n" + body
	if err := os.WriteFile(shim, []byte(script), 0o755); err != nil {
		t.Fatalf("write shim: %v", err)
	}
	t.Setenv("PILOT_DOCKER_BIN", shim)
	t.Setenv("PILOT_CALLS_LOG", log)
	return log
}

func newImageTestManager(t *testing.T) *dockertarget.Manager {
	t.Helper()
	m, err := dockertarget.NewManager(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return m
}

// TestEnsurePilotImage_BuildsWhenMissing is the headline behaviour:
// `docker image inspect` says the tag is missing, so ensurePilotImage
// must shell out to `docker build` with the right tag.
func TestEnsurePilotImage_BuildsWhenMissing(t *testing.T) {
	log := newImageShim(t, `case "$1" in
  image) exit 1 ;;   # image inspect -> missing
  build) exit 0 ;;
  *)     exit 0 ;;
esac`)
	m := newImageTestManager(t)
	var buf bytes.Buffer
	if err := ensurePilotImage(context.Background(), m, dockertarget.EngineDocker, "ubuntu-24.04", false, &buf); err != nil {
		t.Fatalf("ensurePilotImage: %v", err)
	}
	data, _ := os.ReadFile(log)
	if !strings.Contains(string(data), "build -t pilot-target:ubuntu-24.04") {
		t.Errorf("expected a `docker build -t pilot-target:ubuntu-24.04` call, got:\n%s", data)
	}
}

// TestEnsurePilotImage_SkipsWhenPresent: inspect exits 0 → no build.
func TestEnsurePilotImage_SkipsWhenPresent(t *testing.T) {
	log := newImageShim(t, `case "$1" in
  image) exit 0 ;;   # present
  build) exit 0 ;;
  *)     exit 0 ;;
esac`)
	m := newImageTestManager(t)
	var buf bytes.Buffer
	if err := ensurePilotImage(context.Background(), m, dockertarget.EngineDocker, "ubuntu-24.04", false, &buf); err != nil {
		t.Fatalf("ensurePilotImage: %v", err)
	}
	data, _ := os.ReadFile(log)
	if strings.Contains(string(data), "build") {
		t.Errorf("must not build when image already present, got:\n%s", data)
	}
}

// TestEnsurePilotImage_RebuildsStaleSystemdImage: the image is present
// but lacks /sbin/init (the `docker run --entrypoint test` probe exits
// non-zero), and --systemd was requested, so it must rebuild rather
// than let `docker run` fail with a cryptic OCI error.
func TestEnsurePilotImage_RebuildsStaleSystemdImage(t *testing.T) {
	log := newImageShim(t, `case "$1" in
  image) exit 0 ;;   # present
  run)   exit 1 ;;   # test -e /sbin/init -> missing (stale image)
  build) exit 0 ;;
  *)     exit 0 ;;
esac`)
	m := newImageTestManager(t)
	var buf bytes.Buffer
	if err := ensurePilotImage(context.Background(), m, dockertarget.EngineDocker, "ubuntu-24.04", true, &buf); err != nil {
		t.Fatalf("ensurePilotImage: %v", err)
	}
	data, _ := os.ReadFile(log)
	if !strings.Contains(string(data), "build -t pilot-target:ubuntu-24.04") {
		t.Errorf("stale systemd image should be rebuilt, got:\n%s", data)
	}
}

// TestEnsurePilotImage_PresentWithInitSkips: image present AND init
// probe passes → no rebuild even with --systemd.
func TestEnsurePilotImage_PresentWithInitSkips(t *testing.T) {
	log := newImageShim(t, `case "$1" in
  image) exit 0 ;;   # present
  run)   exit 0 ;;   # /sbin/init present
  build) exit 1 ;;   # must not be called
  *)     exit 0 ;;
esac`)
	m := newImageTestManager(t)
	var buf bytes.Buffer
	if err := ensurePilotImage(context.Background(), m, dockertarget.EngineDocker, "ubuntu-24.04", true, &buf); err != nil {
		t.Fatalf("ensurePilotImage: %v", err)
	}
	data, _ := os.ReadFile(log)
	if strings.Contains(string(data), "build") {
		t.Errorf("must not rebuild when /sbin/init present, got:\n%s", data)
	}
}

// TestEnsurePilotImage_UnknownVariantErrors: missing image + a variant
// we have no embedded Dockerfile for → a helpful error (not a build of
// nothing, not a doomed registry pull).
func TestEnsurePilotImage_UnknownVariantErrors(t *testing.T) {
	newImageShim(t, `case "$1" in
  image) exit 1 ;;   # missing
  *)     exit 0 ;;
esac`)
	m := newImageTestManager(t)
	var buf bytes.Buffer
	err := ensurePilotImage(context.Background(), m, dockertarget.EngineDocker, "fedora-99", false, &buf)
	if err == nil || !strings.Contains(err.Error(), "no built-in Dockerfile") {
		t.Fatalf("want unknown-variant error, got %v", err)
	}
}

// TestDockerTargetCmdRegistered is the regression guard for "I added
// the subcommand but forgot to rootCmd.AddCommand(dockerTargetCmd)".
// Without the registration, `pilot docker-target` errors out and the
// CI smoke test catches it.
func TestDockerTargetCmdRegistered(t *testing.T) {
	root := rootCmd
	var found bool
	for _, c := range root.Commands() {
		if c.Name() == "docker-target" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("docker-target subcommand not registered on rootCmd")
	}
}

// TestDockerTargetSubCommandsAllRegistered walks the seven
// subcommands we promised in the parent Long doc and ensures each
// one is wired. If anyone refactors and drops one, this trips.
func TestDockerTargetSubCommandsAllRegistered(t *testing.T) {
	want := []string{
		"up",
		"down",
		"list",
		"show-inventory",
		"run",
		"verify",
		"exec",
	}
	var have []string
	for _, c := range dockerTargetCmd.Commands() {
		have = append(have, c.Name())
	}
	for _, w := range want {
		ok := false
		for _, h := range have {
			if h == w {
				ok = true
				break
			}
		}
		if !ok {
			t.Errorf("subcommand %q missing; have %v", w, have)
		}
	}
}

// TestRunDtUp_RequiresName is the regression guard for the previous
// "accepts empty --name and silently picked default" bug — which
// produced a target named "" that broke ansible inventory keys.
func TestRunDtUp_RequiresName(t *testing.T) {
	dtName = ""
	dtImage = ""
	rootCmd.SetArgs([]string{"docker-target", "up"})
	rootCmd.SetOut(&bytes.Buffer{})
	rootCmd.SetErr(&bytes.Buffer{})
	err := rootCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "--name is required") {
		t.Fatalf("want --name-required error, got %v", err)
	}
}

// TestRunDtUp_RequiresImage mirrors the name check.
func TestRunDtUp_RequiresImage(t *testing.T) {
	dtName = ""
	dtImage = ""
	rootCmd.SetArgs([]string{"docker-target", "up", "--name", "x"})
	rootCmd.SetOut(&bytes.Buffer{})
	rootCmd.SetErr(&bytes.Buffer{})
	err := rootCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "--image or --image-pilot is required") {
		t.Fatalf("want --image-or-image-pilot-required error, got %v", err)
	}
}

// TestRunDtDown_RequiresName is the matching guard.
func TestRunDtDown_RequiresName(t *testing.T) {
	dtName = ""
	rootCmd.SetArgs([]string{"docker-target", "down"})
	rootCmd.SetOut(&bytes.Buffer{})
	rootCmd.SetErr(&bytes.Buffer{})
	err := rootCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "--name is required") {
		t.Fatalf("want --name-required error, got %v", err)
	}
}

// TestRunDtUp_RejectsInvalidEngine guards the --engine flag: only
// "docker" (default) and "podman" are accepted, so a typo doesn't
// silently fall through to whichever engine parseEngine's zero value
// happens to resolve to.
func TestRunDtUp_RejectsInvalidEngine(t *testing.T) {
	dtName = ""
	dtImage = ""
	dtImagePilot = ""
	defer func() { dtEngine = "docker" }()
	rootCmd.SetArgs([]string{"docker-target", "up", "--name", "x", "--image", "u", "--engine", "lxc"})
	rootCmd.SetOut(&bytes.Buffer{})
	rootCmd.SetErr(&bytes.Buffer{})
	err := rootCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "--engine") {
		t.Fatalf("want --engine validation error, got %v", err)
	}
}

// TestShortCID_MatchesDockerFormat ensures our 12-char prefix matches
// what `docker ps --format "{{.ID}}"` prints, so users can paste the
// value into other docker commands without surprise.
func TestShortCID_MatchesDockerFormat(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"abc123def456789012345678901234567890", "abc123def456"},
		{"short", "short"},
		{"", ""},
	}
	for _, tc := range cases {
		if got := shortCID(tc.in); got != tc.want {
			t.Errorf("shortCID(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestResolveDataDir_RespectsFlag covers the precedence rule:
// --data-dir flag wins over the default $HOME/.local/share/pilot.
func TestResolveDataDir_RespectsFlag(t *testing.T) {
	t.Setenv("HOME", "/tmp/fake-home")
	old := dataDir
	dataDir = "/tmp/explicit-data"
	defer func() { dataDir = old }()
	got := resolveDataDir()
	if got != "/tmp/explicit-data" {
		t.Errorf("resolveDataDir = %q, want /tmp/explicit-data", got)
	}
}

// TestRunDtUp_ImageAndImagePilotExclusive is the regression guard:
// the previous "both flags accepted" silently picked the last one
// bound, masking CLI flag wiring bugs.
func TestRunDtUp_ImageAndImagePilotExclusive(t *testing.T) {
	dtName = ""
	dtImage = ""
	dtImagePilot = ""
	rootCmd.SetArgs([]string{"docker-target", "up", "--name", "x", "--image", "u", "--image-pilot", "u"})
	rootCmd.SetOut(&bytes.Buffer{})
	rootCmd.SetErr(&bytes.Buffer{})
	err := rootCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("want mutex error, got %v", err)
	}
}

// TestRunDtUp_RequiresImageOrImagePilot mirrors the name check.
func TestRunDtUp_RequiresImageOrImagePilot(t *testing.T) {
	dtName = ""
	dtImage = ""
	dtImagePilot = ""
	rootCmd.SetArgs([]string{"docker-target", "up", "--name", "x"})
	rootCmd.SetOut(&bytes.Buffer{})
	rootCmd.SetErr(&bytes.Buffer{})
	err := rootCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "--image or --image-pilot is required") {
		t.Fatalf("want image-required error, got %v", err)
	}
}

// TestDockerTargetSubCommandsAllRegistered_AfterSnapshotRollback
// walks the new command set. If anyone refactors and drops
// snapshot / rollback, this trips.
func TestDockerTargetSubCommandsAllRegistered_AfterSnapshotRollback(t *testing.T) {
	want := []string{
		"up", "down", "list", "show-inventory",
		"run", "verify", "exec",
		"snapshot", "rollback",
	}
	var have []string
	for _, c := range dockerTargetCmd.Commands() {
		have = append(have, c.Name())
	}
	for _, w := range want {
		ok := false
		for _, h := range have {
			if h == w {
				ok = true
				break
			}
		}
		if !ok {
			t.Errorf("subcommand %q missing; have %v", w, have)
		}
	}
}

// TestRunDtSnapshot_RequiresTag is the regression guard: a previous
// "snapshots to 'latest' by default" silently overwrote whatever
// 'latest' pointed at.
func TestRunDtSnapshot_RequiresTag(t *testing.T) {
	dtName = ""
	dtSnapshotTag = ""
	rootCmd.SetArgs([]string{"docker-target", "snapshot", "--name", "x"})
	rootCmd.SetOut(&bytes.Buffer{})
	rootCmd.SetErr(&bytes.Buffer{})
	err := rootCmd.Execute()
	if err == nil || (!strings.Contains(err.Error(), "--tag") && !strings.Contains(err.Error(), "required")) {
		t.Fatalf("want --tag-required error, got %v", err)
	}
}

// TestRunDtRollback_RequiresImage is the matching guard.
func TestRunDtRollback_RequiresImage(t *testing.T) {
	dtName = ""
	dtRollbackImage = ""
	rootCmd.SetArgs([]string{"docker-target", "rollback", "--name", "x"})
	rootCmd.SetOut(&bytes.Buffer{})
	rootCmd.SetErr(&bytes.Buffer{})
	err := rootCmd.Execute()
	if err == nil || (!strings.Contains(err.Error(), "--image") && !strings.Contains(err.Error(), "required")) {
		t.Fatalf("want --image-required error, got %v", err)
	}
}

// TestExtraHasTargetGroup_DetectsForms is the regression guard for the
// 3 ways a user can pass target_group: separate -e flag, joined -e target_group=...
// and the explicit -e target_group=... form.
func TestExtraHasTargetGroup_DetectsForms(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want bool
	}{
		{"plain flag", []string{"-e", "target_group=dns"}, true},
		{"joined arg", []string{"-e target_group=dns"}, true},
		{"no target_group", []string{"-e", "infra_role=dns"}, false},
		{"empty", nil, false},
		{"only -e without value", []string{"-e"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := extraHasTargetGroup(tc.in); got != tc.want {
				t.Errorf("extraHasTargetGroup(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// TestValidDockerTag_RejectsShell is the regression guard for the
// "snapshot --tag a+b" silent error path. '+' is a valid char in
// YAML/JSON but not in docker image references.
func TestValidDockerTag_RejectsShell(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"good", true},
		{"my-tag", true},
		{"registry.example.com/x:y", true},
		{"a+b", false},
		{"with space", false},
		{"semi;colon", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := validDockerTag(tc.in); got != tc.want {
			t.Errorf("validDockerTag(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// TestRunDtSnapshot_RejectsInvalidTag is the regression guard.
func TestRunDtSnapshot_RejectsInvalidTag(t *testing.T) {
	dtName = ""
	dtSnapshotTag = "bad+tag"
	rootCmd.SetArgs([]string{"docker-target", "snapshot", "--name", "x", "--tag", "bad+tag"})
	rootCmd.SetOut(&bytes.Buffer{})
	rootCmd.SetErr(&bytes.Buffer{})
	err := rootCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "--tag") {
		t.Fatalf("want --tag validation error, got %v", err)
	}
}

// TestRunDtRollback_RejectsInvalidImage is the matching guard.
func TestRunDtRollback_RejectsInvalidImage(t *testing.T) {
	dtName = ""
	dtRollbackImage = "bad+image"
	rootCmd.SetArgs([]string{"docker-target", "rollback", "--name", "x", "--image", "bad+image"})
	rootCmd.SetOut(&bytes.Buffer{})
	rootCmd.SetErr(&bytes.Buffer{})
	err := rootCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "--image") {
		t.Fatalf("want --image validation error, got %v", err)
	}
}
