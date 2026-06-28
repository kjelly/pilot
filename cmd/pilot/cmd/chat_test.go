package cmd

import (
	"strings"
	"testing"
)

func TestAppendSessionDefaults_BothSet(t *testing.T) {
	out := appendSessionDefaults("base prompt", "/etc/ansible/hosts", "web*")
	if !strings.HasPrefix(out, "base prompt\n\n## Session defaults") {
		t.Errorf("should preserve base prompt + add section header, got: %q", out)
	}
	if !strings.Contains(out, "Default inventory file") || !strings.Contains(out, "/etc/ansible/hosts") {
		t.Errorf("missing inventory line: %q", out)
	}
	if !strings.Contains(out, "Default --limit host pattern") || !strings.Contains(out, "web*") {
		t.Errorf("missing limit line: %q", out)
	}
	if !strings.Contains(out, "Use these defaults unless") {
		t.Errorf("missing usage hint: %q", out)
	}
}

func TestAppendSessionDefaults_OnlyInventory(t *testing.T) {
	out := appendSessionDefaults("base", "/inv.ini", "")
	if !strings.Contains(out, "Default inventory file") {
		t.Errorf("inventory line missing: %q", out)
	}
	if strings.Contains(out, "Default --limit") {
		t.Errorf("limit line should be absent: %q", out)
	}
	if !strings.Contains(out, "Use these defaults unless") {
		t.Errorf("usage hint should still appear: %q", out)
	}
}

func TestAppendSessionDefaults_OnlyLimit(t *testing.T) {
	out := appendSessionDefaults("base", "", "db")
	if strings.Contains(out, "Default inventory file") {
		t.Errorf("inventory line should be absent: %q", out)
	}
	if !strings.Contains(out, "Default --limit host pattern") {
		t.Errorf("limit line missing: %q", out)
	}
}

func TestAppendSessionDefaults_NeitherSet(t *testing.T) {
	// When both are empty the appender should be a no-op — return
	// the base prompt unchanged. (Defensive: chat.go doesn't call
	// appendSessionDefaults in this case, but the helper itself
	// must not emit the section header for empty input.)
	out := appendSessionDefaults("base prompt", "", "")
	if out != "base prompt" {
		t.Errorf("no defaults → no change, got: %q", out)
	}
}
