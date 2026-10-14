package cmd

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/kjelly/pilot/internal/vmtarget"
)

// fakeDockerScript stands in for docker: `cp` copies into $FAKE_ROOT (the
// "container" filesystem), `exec ... ansible-playbook` runs the real
// ansible-playbook with container paths mapped into $FAKE_ROOT, and every
// other command succeeds without doing anything. `inspect` fails so the
// sandbox starts a fresh "container", and `run` prints a container ID.
const fakeDockerScript = `#!/bin/bash
echo "$*" >> "$FAKE_DOCKER_LOG"
case "$1" in
  inspect) exit 1 ;;
  run) echo 0123456789ab ;;
  cp)
    src=$2; dst=${3#*:}
    if [[ $src == */. ]]; then mkdir -p "$FAKE_ROOT$dst" && cp -a "$src" "$FAKE_ROOT$dst"
    else mkdir -p "$(dirname "$FAKE_ROOT$dst")" && cp "$src" "$FAKE_ROOT$dst"; fi
    exit $? ;;
  exec)
    shift; [[ $1 == -t ]] && shift; shift
    [[ $1 == ansible-playbook ]] || exit 0
    args=()
    for a in "$@"; do
      case "$a" in
        /tmp/pilot-*) args+=("$FAKE_ROOT$a") ;;
        @/tmp/pilot-*) args+=("@$FAKE_ROOT${a#@}") ;;
        *) args+=("$a") ;;
      esac
    done
    exec "${args[@]}" ;;
esac
exit 0
`

// `vm-target run --sandbox` copies the playbook into a container. A
// playbook under playbooks/check/ or playbooks/decommission/ includes
// ../apply/tasks/freeipa-private-ccache-*.yml (PR #72), so copying only the
// playbook's directory failed with "Could not find or access" (reproduced
// in review). This drives vtRunViaContainer, the --sandbox path of
// `vm-target run`, with a fake docker and the real ansible-playbook, and
// checks that a cross-directory include resolves inside the copy.
func TestVtRunViaContainerResolvesIncludesAcrossThePlaybooksTree(t *testing.T) {
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		t.Skipf("ansible-playbook not installed: %v", err)
	}
	repo := t.TempDir()
	write := func(rel, content string) string {
		p := filepath.Join(repo, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	playbook := write("playbooks/check/probe.yml", `- hosts: localhost
  connection: local
  gather_facts: false
  tasks:
    - ansible.builtin.include_tasks: ../apply/tasks/hello.yml
`)
	write("playbooks/apply/tasks/hello.yml", `- ansible.builtin.copy: {dest: "{{ marker }}", content: included}
`)
	inv := write("inventory.ini", "localhost ansible_connection=local\n")
	key := write("id_ed25519", "not a key\n")
	marker := filepath.Join(t.TempDir(), "marker")

	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(fakeDockerScript), 0o755); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(t.TempDir(), "docker.log")
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("FAKE_ROOT", t.TempDir())
	t.Setenv("FAKE_DOCKER_LOG", log)
	t.Setenv("ANSIBLE_LOCALHOST_WARNING", "False")
	t.Setenv("ANSIBLE_NOCOLOR", "1")

	c := &cobra.Command{}
	var out, errOut bytes.Buffer
	c.SetOut(&out)
	c.SetErr(&errOut)
	targets := []*vmtarget.Target{{Name: "sandbox-test", KeyPath: key, CreatedAt: time.Now()}}
	err := vtRunViaContainer(c, targets, playbook, inv, []string{"-i", inv, playbook, "-e", "marker=" + marker}, "pilot-test:fake", "")
	if err != nil {
		t.Fatalf("vtRunViaContainer: %v\nstdout:\n%s\nstderr:\n%s", err, out.String(), errOut.String())
	}
	if got, _ := os.ReadFile(marker); string(got) != "included" {
		t.Errorf("the include in ../apply/tasks did not run (marker %q)\n%s", got, out.String())
	}
	calls, _ := os.ReadFile(log)
	if want := "cp " + filepath.Join(repo, "playbooks") + "/. "; !strings.Contains(string(calls), want) {
		t.Errorf("docker calls do not copy the playbooks tree (%q):\n%s", want, calls)
	}
	if !strings.Contains(string(calls), "/tmp/pilot-playbook-dir/check/probe.yml") {
		t.Errorf("ansible-playbook was not pointed at check/probe.yml inside the copy:\n%s", calls)
	}
}

func TestSandboxPlaybookRoot(t *testing.T) {
	dir := t.TempDir()
	cases := []struct{ playbook, root, rel string }{
		{filepath.Join(dir, "repo/playbooks/check/x.yml"), filepath.Join(dir, "repo/playbooks"), "check/x.yml"},
		{filepath.Join(dir, "repo/playbooks/site.yml"), filepath.Join(dir, "repo/playbooks"), "site.yml"},
		{filepath.Join(dir, "repo/playbooks/test/fixtures/f.yml"), filepath.Join(dir, "repo/playbooks"), "test/fixtures/f.yml"},
		{filepath.Join(dir, "elsewhere/x.yml"), filepath.Join(dir, "elsewhere"), "x.yml"},
	}
	for _, tc := range cases {
		root, rel := sandboxPlaybookRoot(tc.playbook)
		if root != tc.root || rel != tc.rel {
			t.Errorf("sandboxPlaybookRoot(%s) = %s, %s; want %s, %s", tc.playbook, root, rel, tc.root, tc.rel)
		}
	}
}
