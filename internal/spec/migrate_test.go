package spec

import (
	"strings"
	"testing"
)

const migrationV1Fixture = `# Verification Spec — migrated fixture

> 版本：v1.2
> 對齊規範：migration-test
> 維護者：sre

## 1. Targets

| Hostname | Group |
|----------|-------|
| host-a | docker |

## 2. Checklist

| ID | Category | Check | Expected | Command |
|----|----------|-------|----------|---------|
| C1 | service | active | present | systemctl is-active docker |
| C2 | output | ready | ~ready | printf ready |
`

func TestMigrateV1ProducesParseableReviewedDraft(t *testing.T) {
	legacy, err := ParseReader(strings.NewReader(migrationV1Fixture))
	if err != nil {
		t.Fatal(err)
	}
	draft, report, err := MigrateV1("fixture.md", []byte(migrationV1Fixture), legacy, MigrationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !report.HasFindings() {
		t.Fatal("missing review findings")
	}
	migrated, err := ParseReader(strings.NewReader(string(draft)))
	if err != nil {
		t.Fatalf("parse migrated draft: %v\n%s", err, draft)
	}
	if migrated.SchemaVersion != 2 || len(migrated.Rows) != 2 || !migrated.Rows[0].VerifyOnly {
		t.Fatalf("migrated=%+v", migrated)
	}
	if !HasErrors(Lint(migrated)) || len(migrated.Rows[0].NeedsReview) == 0 {
		t.Fatalf("review gate missing: %+v", migrated.Rows[0])
	}
	if !strings.Contains(string(draft), "> # Verification Spec — migrated fixture") {
		t.Fatal("original prose was not retained as quoted migration context")
	}
}

func TestMigrateV1ExplicitDecisionsCanBeLintClean(t *testing.T) {
	legacy, err := ParseReader(strings.NewReader(migrationV1Fixture))
	if err != nil {
		t.Fatal(err)
	}
	draft, report, err := MigrateV1("fixture.md", []byte(migrationV1Fixture), legacy, MigrationOptions{DefaultAction: "readOnly", TagPrefix: "docker"})
	if err != nil {
		t.Fatal(err)
	}
	if report.HasFindings() {
		t.Fatalf("findings=%+v", report.Findings)
	}
	migrated, err := ParseReader(strings.NewReader(string(draft)))
	if err != nil {
		t.Fatal(err)
	}
	if HasErrors(Lint(migrated)) || migrated.Rows[0].Tags[0] != "docker-C1" {
		t.Fatalf("rows=%+v findings=%+v", migrated.Rows, Lint(migrated))
	}
}

func TestMigrateV1MarksAmbiguityAndApplicability(t *testing.T) {
	raw := strings.Replace(migrationV1Fixture, "~ready", "1", 1)
	raw = strings.Replace(raw, "printf ready", "echo '{{ value }}'", 1)
	raw += "\nOptional dependency: this row is not applicable when disabled.\n"
	legacy, err := ParseReader(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	_, report, err := MigrateV1("fixture.md", []byte(raw), legacy, MigrationOptions{DefaultAction: "readOnly", TagPrefix: "docker"})
	if err != nil {
		t.Fatal(err)
	}
	codes := make(map[string]bool)
	for _, finding := range report.Findings {
		codes[finding.Code] = true
	}
	for _, code := range []string{"v1-int-ambiguous", "jinja-template-risk", "applicability-unknown"} {
		if !codes[code] {
			t.Fatalf("missing %s in %+v", code, report.Findings)
		}
	}
}
