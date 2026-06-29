package ansible

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseDiff_BasicFile(t *testing.T) {
	stdout := `TASK [Disable root SSH login] *
--- before
+++ after
@@ -1,1 +1,1 @@
-PermitRootLogin yes
+PermitRootLogin no
TASK [Restart sshd] ******
`
	summary := ParseDiff(stdout)
	if summary.FilesTotal == 0 {
		t.Fatalf("expected at least one file, got %d", summary.FilesTotal)
	}
	d := summary.Diffs[0]
	if d.Path == "" {
		t.Errorf("path empty")
	}
	if !strings.Contains(d.After, "no") {
		t.Errorf("after missing 'no': %q", d.After)
	}
	if !strings.Contains(d.Before, "yes") {
		t.Errorf("before missing 'yes': %q", d.Before)
	}
}

func TestParseDiff_NewAndDeleted(t *testing.T) {
	stdout := `--- before
+++ after
@@ -0,0 +1,3 @@
+new line 1
+new line 2
+new line 3
--- before
+++ after
@@ -1,3 +0,0 @@
-old line 1
-old line 2
-old line 3
`
	s := ParseDiff(stdout)
	if s.FilesTotal < 2 {
		t.Fatalf("expected ≥2 files, got %d", s.FilesTotal)
	}
	// We don't get a clean Path, but the body should be parsed.
	foundNew := false
	for _, d := range s.Diffs {
		if strings.Contains(d.After, "new line 1") {
			foundNew = true
		}
	}
	if !foundNew {
		t.Errorf("new-file diff not captured")
	}
}

func TestParseDiff_SensitiveRedacted(t *testing.T) {
	stdout := `--- before: /etc/shadow
+++ after: /etc/shadow
@@ -1,1 +1,1 @@
-root:$y$j9T$OLD...
+root:$y$j9T$NEW...
`
	summary := ParseDiff(stdout)
	if summary.FilesTotal == 0 {
		t.Fatalf("expected at least one file, got %d", summary.FilesTotal)
	}
	d := summary.Diffs[0]
	if d.Path != "/etc/shadow" {
		t.Errorf("expected path '/etc/shadow', got %q", d.Path)
	}
	if !d.IsSensitive {
		t.Errorf("expected file to be marked sensitive")
	}
	if strings.Contains(d.Before, "OLD") || !strings.Contains(d.Before, "REDACTED") {
		t.Errorf("before not redacted: %q", d.Before)
	}
	if strings.Contains(d.After, "NEW") || !strings.Contains(d.After, "REDACTED") {
		t.Errorf("after not redacted: %q", d.After)
	}
}

func TestParseDiff_SensitiveSSHKeyGlob(t *testing.T) {
	// Direct: we test isSensitivePath, which is path-driven.
	// Override the first diff path detection is not directly possible,
	// so we synthesise via extractPath and isSensitivePath.
	cases := []struct {
		path string
		want bool
	}{
		{"/etc/ssh/ssh_host_ed25519_key", true},
		{"/etc/ssh/ssh_host_rsa_key", true},
		{"/home/alice/.ssh/id_rsa", true},
		{"/home/bob/.ssh/authorized_keys", true},
		{"/home/alice/.aws/credentials", true},
		{"/etc/ssh/sshd_config", false},
		{"/var/log/syslog", false},
	}
	for _, c := range cases {
		if got := isSensitivePath(c.path); got != c.want {
			t.Errorf("isSensitivePath(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestParseDiff_CapsFileCount(t *testing.T) {
	var b strings.Builder
	for i := 0; i < diffMaxFiles+10; i++ {
		b.WriteString("--- before\n+++ after\n@@ -1,1 +1,1 @@\n-a\n+b\n")
	}
	s := ParseDiff(b.String())
	if !s.Truncated {
		t.Errorf("expected truncated=true when more than %d files", diffMaxFiles)
	}
}

func TestDiffSummary_JSONRoundTrip(t *testing.T) {
	s := DiffSummary{
		Diffs: []FileDiff{
			{Path: "/etc/ssh/sshd_config", Before: "x", After: "y"},
		},
		FilesTotal: 1, FilesChanged: 1,
	}
	b, _ := json.Marshal(s)
	var back DiffSummary
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.Diffs[0].Path != "/etc/ssh/sshd_config" {
		t.Errorf("path lost")
	}
}

func TestRenderMarkdown_HumanFriendly(t *testing.T) {
	s := DiffSummary{
		Diffs: []FileDiff{
			{Path: "/etc/ssh/sshd_config", Before: "PermitRootLogin yes", After: "PermitRootLogin no"},
			{Path: "/etc/shadow", Before: "x", After: "y", IsSensitive: true},
		},
		FilesTotal: 2, FilesChanged: 1,
	}
	md := s.RenderMarkdown()
	if !strings.Contains(md, "Diff summary") {
		t.Errorf("missing header: %s", md)
	}
	if !strings.Contains(md, "sshd_config") {
		t.Errorf("missing file: %s", md)
	}
	if !strings.Contains(strings.ToLower(md), "redact") {
		t.Errorf("sensitive file not marked: %s", md)
	}
}

func TestGlobToRegex(t *testing.T) {
	re := globToRegex("/home/*/.ssh/id_")
	if re == nil {
		t.Fatal("nil regex")
	}
	if !re.MatchString("/home/alice/.ssh/id_rsa") {
		t.Errorf("did not match alice: %v", re)
	}
	if !re.MatchString("/home/bob/.ssh/id_ed25519") {
		t.Errorf("did not match bob: %v", re)
	}
	if re.MatchString("/etc/ssh/id_rsa") {
		t.Errorf("matched wrong prefix")
	}
}
