package spec

import (
	"os"
	"strings"
	"testing"
)

// TestRegression_ResticBackupSpec locks the structure of
// docs/verification/restic-backup.md (v1.0 — cross-cutting restic backup to
// S3, default destination the repo's own seaweedfs-s3 gateway, switchable to
// an external S3 via restic_repository, per-host configurable scope via
// restic_backup_paths/restic_backup_pre_hook):
//
//	C1      restic installed
//	C2/C3   secrets env file present + 0600 permissions
//	C4      repository reachable + initialized (restic snapshots succeeds)
//	C5      at least one snapshot exists
//	C6      restic check integrity passes
//	C7      backup script contains the retention flag (--keep-daily)
//	C8/C9   restic-backup.timer enabled + active
//	C10     s3-backup-server alias pinned in /etc/hosts (only applicable
//	        when restic_s3_target_host was provided — see spec §5)
//
// Cross-row invariants locked below:
//
//   - C1-C10 must all use positive-logic rc per
//     verification-spec-template.md trap 1.
//   - C3 must be a numeric (not ~-prefixed) permission expected value, per
//     the template's "file permission rows use numbers" rule.
//   - C9 must NOT use ~active (matches inactive as a substring).
//   - restic_aws_access_key_id / restic_aws_secret_access_key /
//     restic_password must all be mandatory (no hardcoded default) — a
//     backup feature with a silently-defaulted encryption password is a
//     security hole, not a convenience.
//   - the apply playbook must gate on the "no destination configured"
//     combination (restic_s3_target_host empty AND restic_repository still
//     the default alias) — unlike siem_forward_host/wazuh_manager_host,
//     skipping the destination leaves the whole feature non-functional, not
//     a smaller-but-useful subset, so this must be a hard pre_tasks assert,
//     not a silent skip.
//   - restic_backup_paths must be a templated list (Jinja join), not a
//     hardcoded path, so it's genuinely overridable per-host (host_vars).
//   - the apply playbook must actually trigger one backup run during apply
//     (not just install the timer) so C4-C6 can pass immediately after a
//     fresh apply without waiting for the schedule.
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
	exp := map[string]string{}
	for i, id := range wantIDs {
		if s.Rows[i].ID != id {
			t.Errorf("row[%d] id=%q want=%q", i, s.Rows[i].ID, id)
		}
	}
	for _, r := range s.Rows {
		cmd[r.ID] = r.Command
		exp[r.ID] = strings.TrimSpace(r.Expected)
		switch strings.ToLower(exp[r.ID]) {
		case "ok", "normal", "reasonable", "sufficient", "合理", "正常", "足夠":
			t.Errorf("row %s uses vague expected %q", r.ID, r.Expected)
		}
	}

	// All rows except C3 (a literal file-mode number) are rc-based `0`.
	for _, id := range wantIDs {
		if id == "C3" {
			continue
		}
		if exp[id] != "0" {
			t.Errorf("%s expected must be rc-based `0`, got %q", id, exp[id])
		}
	}
	if exp["C3"] != "600" {
		t.Errorf("C3 expected must be the numeric file mode `600`, got %q", exp["C3"])
	}
	if strings.HasPrefix(exp["C3"], "~") || strings.HasPrefix(exp["C3"], "0") {
		t.Errorf("C3 must be the bare numeric mode `600` (stat -c '%%a' has no leading 0), got %q", exp["C3"])
	}

	// No row anywhere may use ~active (false-positives on "inactive").
	for _, r := range s.Rows {
		if strings.EqualFold(strings.TrimSpace(r.Expected), "~active") {
			t.Errorf("row %s uses ~active (matches inactive); use rc-based systemctl is-active", r.ID)
		}
	}

	// C4/C5/C6 must source the env file and use positive-logic rc.
	for _, id := range []string{"C4", "C5", "C6"} {
		if !strings.Contains(cmd[id], ". /etc/pilot/restic-env") {
			t.Errorf("%s must source /etc/pilot/restic-env before invoking restic, got %q", id, cmd[id])
		}
	}
	if !strings.Contains(cmd["C4"], "restic snapshots") {
		t.Errorf("C4 must check `restic snapshots` succeeds, got %q", cmd["C4"])
	}
	if !strings.Contains(cmd["C6"], "restic check") {
		t.Errorf("C6 must run `restic check`, got %q", cmd["C6"])
	}
	if !strings.Contains(cmd["C6"], "--retry-lock 120s") {
		t.Errorf("C6 must wait safely for concurrent shared-repository checks, got %q", cmd["C6"])
	}

	// C10 must reference the site-independent s3-backup-server alias.
	if !strings.Contains(cmd["C10"], "s3-backup-server") {
		t.Errorf("C10 must reference the s3-backup-server alias, got %q", cmd["C10"])
	}

	fs := Lint(s)
	if HasErrors(fs) {
		t.Errorf("Lint produced errors:\n%s", joinFindings(fs))
	}

	pb, err := Generate(s, GenerateOptions{IncludeRaw: true})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	covered := map[string]bool{}
	for _, tk := range pb.Tasks {
		for _, id := range tk.SourceIDs {
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
	applyRaw := string(playbookRaw)

	// The three secrets must be mandatory: no default value anywhere that
	// would let a backup silently run with a guessable/shared credential or
	// encryption password.
	for _, secret := range []string{"restic_aws_access_key_id", "restic_aws_secret_access_key", "restic_password"} {
		if strings.Contains(applyRaw, secret+": \"\"") || strings.Contains(applyRaw, secret+": ''") {
			t.Errorf("restic-backup-apply.yml must not default %s to an empty string; it must be a required (mandatory) secret", secret)
		}
	}
	if !strings.Contains(applyRaw, "restic_aws_access_key_id is defined and restic_aws_access_key_id | length > 0") {
		t.Errorf("restic-backup-apply.yml must assert restic_aws_access_key_id is provided before any mutation")
	}
	if !strings.Contains(applyRaw, "restic_password is defined and restic_password | length > 0") {
		t.Errorf("restic-backup-apply.yml must assert restic_password is provided before any mutation")
	}

	// The "no reachable destination" combination must be hard-gated, not
	// silently skipped — this is the key design difference from
	// siem_forward_host/wazuh_manager_host called out in spec §1.5.
	if !strings.Contains(applyRaw, "Gate: backup destination must be resolvable") {
		t.Errorf("restic-backup-apply.yml must hard-gate the case where restic_s3_target_host is empty and restic_repository is still the default alias")
	}

	// restic_backup_paths must be genuinely templated (host-overridable),
	// not a hardcoded literal list baked into the script.
	if !strings.Contains(applyRaw, `restic_backup_paths: ["/etc"]`) {
		t.Errorf("restic-backup-apply.yml must default restic_backup_paths to [\"/etc\"]")
	}
	if !strings.Contains(applyRaw, "RESTIC_BACKUP_PATHS | join") && !strings.Contains(applyRaw, "restic_backup_paths | join") {
		t.Errorf("restic-backup-apply.yml must render the backup path list via a Jinja join over restic_backup_paths (per-host overridable), not a hardcoded path")
	}

	// The playbook must trigger a real backup run during apply (not just
	// install the timer) so C4-C6 can pass right after a fresh apply.
	if !strings.Contains(applyRaw, "name: restic-backup.service") || !strings.Contains(applyRaw, "state: started") {
		t.Errorf("restic-backup-apply.yml must start restic-backup.service during apply to produce an immediate snapshot for verify")
	}
	if !strings.Contains(applyRaw, "--keep-daily") {
		t.Errorf("restic-backup-apply.yml's backup script must include a --keep-daily retention flag (spec C7)")
	}
}
