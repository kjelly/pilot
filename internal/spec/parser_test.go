package spec

import (
	"strings"
	"testing"
)

const sampleSpec = `# Verification Spec — bastion-host

> 版本：v1.0
> 對齊規範：CIS Ubuntu 22.04 §5.2.x
> 維護者：infra-team

## 1. 目標系統

| 項目 | 值 |
|------|----|

## 2. Checklist

| ID  | Category | Check                                | Expected                   | Command |
|-----|----------|--------------------------------------|----------------------------|---------|
| C1  | file     | /etc/ssh/sshd_config                 | present                    | ` + "`test -f /etc/ssh/sshd_config`" + ` |
| C2  | file     | PermitRootLogin                      | ` + "`^PermitRootLogin\\\\s+no$`" + ` | ` + "`grep -E '^PermitRootLogin\\\\s+no$' /etc/ssh/sshd_config`" + ` |
| C3  | sysctl   | net.ipv4.ip_forward                  | "0"                        | ` + "`sysctl -n net.ipv4.ip_forward`" + ` |
| C4  | service  | sshd.service state                   | active                     | ` + "`systemctl is-active sshd`" + ` |
| C5  | package  | fail2ban installed                   | present                    | ` + "`dpkg -s fail2ban`" + ` |
`

func TestParseReader_OK(t *testing.T) {
	s, err := ParseReader(strings.NewReader(sampleSpec))
	if err != nil {
		t.Fatalf("ParseReader: %v", err)
	}
	if s.Title != "Verification Spec — bastion-host" {
		t.Errorf("title=%q", s.Title)
	}
	if s.Version != "v1.0" {
		t.Errorf("version=%q", s.Version)
	}
	if s.Alignment != "CIS Ubuntu 22.04 §5.2.x" {
		t.Errorf("alignment=%q", s.Alignment)
	}
	if len(s.Rows) != 5 {
		t.Fatalf("rows=%d want=5", len(s.Rows))
	}
	if s.Rows[0].ID != "C1" || s.Rows[0].Command != "test -f /etc/ssh/sshd_config" {
		t.Errorf("row0=%+v", s.Rows[0])
	}
	// backticks should be stripped from Command cells
	for _, r := range s.Rows {
		if strings.HasPrefix(r.Command, "`") || strings.HasSuffix(r.Command, "`") {
			t.Errorf("row %s still has backticks: %q", r.ID, r.Command)
		}
	}
}

func TestParseReader_MissingTitle(t *testing.T) {
	body := "## 2. Checklist\n| ID | Cat | Check | Exp | Cmd |\n|----|-----|------|-----|-----|\n| C1 | x | y | z | w |\n"
	if _, err := ParseReader(strings.NewReader(body)); err == nil {
		t.Fatal("expected error for missing title")
	}
}

func TestParseReader_NoRows(t *testing.T) {
	body := "# Verification Spec — empty\n\n## 1. target\n\n## 2. Checklist\n\n| (no rows) |\n"
	if _, err := ParseReader(strings.NewReader(body)); err == nil {
		t.Fatal("expected error for empty checklist")
	}
}

func TestSplitRow(t *testing.T) {
	got := splitRow("| C1 | file | sshd | present | `test -f /etc/ssh/sshd_config` |")
	want := []string{"C1", "file", "sshd", "present", "`test -f /etc/ssh/sshd_config`"}
	if len(got) != len(want) {
		t.Fatalf("len=%d want=%d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("[%d] got=%q want=%q", i, got[i], want[i])
		}
	}
}
