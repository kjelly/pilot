package spec

import (
	"os"
	"strings"
	"testing"
)

// TestRegression_ResticBackupSpec locks the declarative contract of the
// cross-cutting S3-backed restic backup role.
func TestRegression_ResticBackupSpec(t *testing.T) {
	const specPath = "../../docs/verification/restic-backup.md"
	s, err := Parse(specPath)
	if err != nil {
		t.Fatalf("parse %s: %v", specPath, err)
	}

	wantIDs := []string{"C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9", "C10"}
	if len(s.Rows) != len(wantIDs) {
		t.Fatalf("rows=%d want=%d", len(s.Rows), len(wantIDs))
	}
	cmd := map[string]string{}
	expected := map[string]string{}
	for i, id := range wantIDs {
		if s.Rows[i].ID != id {
			t.Errorf("row[%d] id=%q want=%q", i, s.Rows[i].ID, id)
		}
	}
	for _, row := range s.Rows {
		cmd[row.ID] = row.Command
		expected[row.ID] = strings.TrimSpace(row.Expected)
		switch strings.ToLower(expected[row.ID]) {
		case "ok", "normal", "reasonable", "sufficient", "合理", "正常", "足夠":
			t.Errorf("row %s uses vague expected %q", row.ID, row.Expected)
		}
	}

	for _, id := range wantIDs {
		if id == "C3" {
			continue
		}
		if expected[id] != "0" {
			t.Errorf("%s expected must be rc-based 0, got %q", id, expected[id])
		}
	}
	if expected["C3"] != "600" || strings.HasPrefix(expected["C3"], "~") || strings.HasPrefix(expected["C3"], "0") {
		t.Errorf("C3 expected must be bare numeric mode 600, got %q", expected["C3"])
	}
	for _, row := range s.Rows {
		if strings.EqualFold(strings.TrimSpace(row.Expected), "~active") {
			t.Errorf("row %s uses ~active (matches inactive); use rc-based systemctl is-active", row.ID)
		}
	}

	for _, id := range []string{"C4", "C5", "C6"} {
		if !strings.Contains(cmd[id], ". /etc/pilot/restic-env") {
			t.Errorf("%s must source /etc/pilot/restic-env before invoking restic, got %q", id, cmd[id])
		}
	}
	if !strings.Contains(cmd["C4"], "restic snapshots") {
		t.Errorf("C4 must check restic snapshots succeeds, got %q", cmd["C4"])
	}
	for _, id := range []string{"C5", "C6"} {
		if !strings.Contains(cmd[id], "--retry-lock 120s") {
			t.Errorf("%s must wait safely for concurrent shared-repository access, got %q", id, cmd[id])
		}
	}
	if !strings.Contains(cmd["C6"], "restic check") {
		t.Errorf("C6 must run restic check, got %q", cmd["C6"])
	}
	if !strings.Contains(cmd["C10"], "s3-backup-server") {
		t.Errorf("C10 must reference the site-independent s3-backup-server alias, got %q", cmd["C10"])
	}

	findings := Lint(s)
	if HasErrors(findings) {
		t.Errorf("Lint produced errors:\n%s", joinFindings(findings))
	}
	pb, err := Generate(s, GenerateOptions{IncludeRaw: true})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	covered := map[string]bool{}
	for _, task := range pb.Tasks {
		for _, id := range task.SourceIDs {
			covered[id] = true
		}
	}
	for _, id := range wantIDs {
		if !covered[id] {
			t.Errorf("spec row %s is not covered by any generated task", id)
		}
	}

	playbookRaw, err := os.ReadFile("../../playbooks/apply/restic-backup-apply.yml")
	if err != nil {
		t.Fatalf("read restic-backup-apply.yml: %v", err)
	}
	apply := string(playbookRaw)
	for _, secret := range []string{"restic_aws_access_key_id", "restic_aws_secret_access_key", "restic_password"} {
		if strings.Contains(apply, secret+": \"\"") || strings.Contains(apply, secret+": ''") {
			t.Errorf("playbook must not default %s to an empty string", secret)
		}
	}
	for _, want := range []string{
		"restic_aws_access_key_id is defined and restic_aws_access_key_id | length > 0",
		"restic_password is defined and restic_password | length > 0",
		"Gate: backup destination must be resolvable",
		`restic_backup_paths: ["/etc"]`,
		"restic_backup_paths | join",
		"restic_backup_timer_persistent: false",
		"restic_backup_randomized_delay: 1h",
		"RandomizedDelaySec={{ restic_backup_randomized_delay }}",
		"restic backup --retry-lock \"${RESTIC_LOCK_RETRY}\"",
		"--retry-lock \"${RESTIC_LOCK_RETRY}\"",
		"--keep-daily",
	} {
		if !strings.Contains(apply, want) {
			t.Errorf("restic-backup-apply.yml missing %q", want)
		}
	}
	if strings.Contains(apply, "Run one backup now if needed") ||
		strings.Contains(apply, "name: restic-backup.service\n            state: started") {
		t.Fatal("apply must not synchronously start restic-backup.service")
	}
}
