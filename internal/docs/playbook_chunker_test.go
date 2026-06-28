package docs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const samplePlaybook = `---
- name: Harden SSH
  hosts: all
  become: true
  tags: [security, cis]
  tasks:
    - name: Disable root SSH login
      lineinfile:
        path: /etc/ssh/sshd_config
        regexp: '^PermitRootLogin'
        line: 'PermitRootLogin no'
      notify: restart sshd

    - name: Restart sshd
      service:
        name: sshd
        state: restarted

- name: Audit config
  hosts: localhost
  tasks:
    - shell: cat /etc/audit/auditd.conf
      register: out
      changed_when: false
`

func TestParsePlaybook(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "test.yml")
	if err := os.WriteFile(tmp, []byte(samplePlaybook), 0o644); err != nil {
		t.Fatal(err)
	}
	pb, err := ParsePlaybook(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if len(pb.Plays) != 2 {
		t.Fatalf("plays: %d", len(pb.Plays))
	}
	p1 := pb.Plays[0]
	if p1.Name != "Harden SSH" {
		t.Errorf("play1 name: %s", p1.Name)
	}
	if p1.Hosts != "all" {
		t.Errorf("hosts: %s", p1.Hosts)
	}
	if len(p1.Tasks) != 2 {
		t.Errorf("play1 tasks: %d", len(p1.Tasks))
	}
	if p1.Tasks[0].Module != "lineinfile" {
		t.Errorf("task0 module: %s", p1.Tasks[0].Module)
	}
	if p1.Tasks[0].Args["path"] != "/etc/ssh/sshd_config" {
		t.Errorf("path: %v", p1.Tasks[0].Args["path"])
	}
	if !p1.Become {
		t.Error("expected become=true")
	}
	if len(p1.Tags) != 2 {
		t.Errorf("tags: %v", p1.Tags)
	}
}

func TestChunkPlaybook(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "test.yml")
	_ = os.WriteFile(tmp, []byte(samplePlaybook), 0o644)
	pb, _ := ParsePlaybook(tmp)
	chunks := ChunkPlaybook(pb)
	// 2 plays + 3 tasks = 5 chunks
	if len(chunks) != 5 {
		t.Errorf("chunks: %d", len(chunks))
	}
	for _, c := range chunks {
		if c.Source != SourcePlaybook {
			t.Errorf("source: %s", c.Source)
		}
		if !strings.HasPrefix(c.ID, "playbooks:") {
			t.Errorf("bad ID: %s", c.ID)
		}
	}
}

func TestDiscoverPlaybooks(t *testing.T) {
	tmp := t.TempDir()
	mkfile := func(name string) {
		_ = os.WriteFile(filepath.Join(tmp, name), []byte("foo"), 0o644)
	}
	mkfile("a.yml")
	mkfile("b.yaml")
	mkfile("c.txt")    // ignored
	mkfile("test.yml") // skipped
	mkfile(".hidden")  // skipped
	mkfile("a.bak")    // skipped

	got, err := DiscoverPlaybooks([]string{tmp}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Errorf("got %d files: %v", len(got), got)
	}
}

func TestDiscoverPlaybooksRecursive(t *testing.T) {
	tmp := t.TempDir()
	sub := filepath.Join(tmp, "sub")
	_ = os.MkdirAll(sub, 0o755)
	_ = os.WriteFile(filepath.Join(tmp, "a.yml"), []byte("x"), 0o644)
	_ = os.WriteFile(filepath.Join(sub, "b.yml"), []byte("x"), 0o644)

	got, err := DiscoverPlaybooks([]string{tmp}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Errorf("got %d files: %v", len(got), got)
	}
}

func TestVersionHashStable(t *testing.T) {
	a := VersionHash("2.14.5", []string{"lineinfile", "copy", "apt"})
	b := VersionHash("2.14.5", []string{"apt", "copy", "lineinfile"}) // different order
	if a != b {
		t.Errorf("hash should be order-independent: %s != %s", a, b)
	}
	c := VersionHash("2.15.0", []string{"lineinfile", "copy", "apt"})
	if a == c {
		t.Error("hash should differ for different version")
	}
}
