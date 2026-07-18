package spec

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// MigrationOptions supplies the explicit human decisions that a v1 document
// does not contain. Empty options deliberately produce review findings rather
// than guessing deployment safety or playbook traceability.
type MigrationOptions struct {
	DefaultAction string
	TagPrefix     string
}

// MigrationFinding records one decision that must be made before a migrated
// document can be treated as a production verification contract.
type MigrationFinding struct {
	RowID       string   `json:"rowId,omitempty"`
	Code        string   `json:"code"`
	Message     string   `json:"message"`
	Original    string   `json:"original,omitempty"`
	Suggestions []string `json:"suggestions,omitempty"`
}

// MigrationReport is persisted beside a migrated draft. It intentionally
// contains no secret values: only v1 document metadata and migration choices.
type MigrationReport struct {
	Source        string             `json:"source"`
	SchemaVersion int                `json:"schemaVersion"`
	Findings      []MigrationFinding `json:"findings"`
}

// HasFindings reports whether the migration requires a reviewer decision.
func (r MigrationReport) HasFindings() bool { return len(r.Findings) != 0 }

// MigrateV1 translates a parsed v1 spec into a valid, review-gated v2 draft.
// original is retained verbatim in the markdown body so prose and historical
// context are never silently dropped by a format conversion.
func MigrateV1(source string, original []byte, legacy *Spec, options MigrationOptions) ([]byte, MigrationReport, error) {
	if legacy == nil || legacy.SchemaVersion != 1 {
		return nil, MigrationReport{}, fmt.Errorf("spec migrate: input must be a v1 spec")
	}
	if options.DefaultAction != "" && options.DefaultAction != "readOnly" {
		return nil, MigrationReport{}, fmt.Errorf("spec migrate: default action must be readOnly")
	}
	report := MigrationReport{Source: source, SchemaVersion: 2}
	roles := migrationRoles(legacy)
	maintainer := legacy.Maintainer
	if maintainer == "" {
		maintainer = "unassigned"
		report.Findings = append(report.Findings, MigrationFinding{Code: "maintainer-unknown", Message: "v1 metadata has no maintainer; replace unassigned before production use"})
	}
	if options.DefaultAction == "" {
		report.Findings = append(report.Findings, MigrationFinding{Code: "action-unknown", Message: "v1 has no declarative verification action; choose readOnly only after review", Suggestions: []string{"rerun with --default-action=readOnly after action inventory review"}})
	}
	if options.TagPrefix == "" {
		report.Findings = append(report.Findings, MigrationFinding{Code: "traceability-unknown", Message: "v1 does not declare a ComponentContract tag strategy", Suggestions: []string{"rerun with --tag-prefix=<role> or map tags manually"}})
	}
	applicabilityRisk := DetectApplicabilityRisk(original)
	if applicabilityRisk {
		report.Findings = append(report.Findings, MigrationFinding{Code: "applicability-unknown", Message: "v1 prose mentions optional, expected-fail, or not-applicable behavior; model appliesWhen explicitly"})
	}

	var out strings.Builder
	out.WriteString("---\n")
	out.WriteString("schemaVersion: 2\n")
	out.WriteString("compatibility: {minPilotVersion: \"0.9\"}\n")
	out.WriteString("intent:\n")
	out.WriteString("  summary: ")
	out.WriteString(yamlScalar(migrationSummary(legacy.Title)))
	out.WriteString("\n  source: ")
	out.WriteString(yamlScalar(migrationSource(legacy)))
	out.WriteString("\n  maintainer: ")
	out.WriteString(yamlScalar(maintainer))
	out.WriteString("\ntargets:\n  roles:\n")
	for _, role := range roles {
		out.WriteString("    - ")
		out.WriteString(yamlScalar(role))
		out.WriteByte('\n')
	}
	if len(legacy.Hosts) > 0 {
		out.WriteString("  hosts:\n")
		for _, host := range legacy.Hosts {
			out.WriteString("    - hostname: ")
			out.WriteString(yamlScalar(host.Hostname))
			out.WriteString("\n      group: ")
			out.WriteString(yamlScalar(host.Group))
			out.WriteByte('\n')
		}
	}
	out.WriteString("inputs: []\ntraceability: {components: []}\ndefaults:\n  become: false\n  action: {mode: readOnly}\n---\n\n")
	out.WriteString("# Verification Spec — ")
	out.WriteString(migrationSummary(legacy.Title))
	out.WriteString("\n\n## Migrated v1 context\n\n")
	out.WriteString("The original v1 document is retained below for review. The v2 checks at the end are authoritative after all `needsReview` findings are resolved.\n\n")
	out.WriteString(quoteMigrationContext(original))
	checks := make([]map[string]any, 0, len(legacy.Rows))
	for _, row := range legacy.Rows {
		check, findings := migrateRow(row, options, applicabilityRisk)
		report.Findings = append(report.Findings, findings...)
		checks = append(checks, check)
	}
	encodedChecks, err := yaml.Marshal(checks)
	if err != nil {
		return nil, MigrationReport{}, fmt.Errorf("spec migrate checks: %w", err)
	}
	out.WriteString("\n## Checks\n\n```yaml\n")
	out.Write(encodedChecks)
	out.WriteString("```\n")
	return []byte(out.String()), report, nil
}

func migrateRow(row Row, options MigrationOptions, applicabilityRisk bool) (map[string]any, []MigrationFinding) {
	check := map[string]any{
		"id":       row.ID,
		"category": row.Category,
		"check":    row.Check,
		"probe":    row.Command,
		"become":   NeedsBecome(row),
	}
	needsReview := make([]string, 0, 3)
	findings := make([]MigrationFinding, 0, 3)
	expected := strings.TrimSpace(row.Expected)
	switch {
	case expected == "" || expected == "present":
		check["expect"] = map[string]any{"exitCode": 0}
	case strings.HasPrefix(expected, "^"):
		check["expect"] = map[string]any{"stdout": map[string]any{"regex": expected}}
	case isV1Integer(expected):
		check["expect"] = map[string]any{"exitCode": legacyV1Atoi(expected)}
		needsReview = append(needsReview, "v1-int-ambiguous")
		findings = append(findings, MigrationFinding{RowID: row.ID, Code: "v1-int-ambiguous", Original: row.Expected, Message: "v1 integer matcher preferred rc echoed in stdout; exitCode is only a review draft", Suggestions: []string{"confirm exitCode", "replace with stdout matcher"}})
	case strings.HasPrefix(expected, "~"):
		value := strings.TrimPrefix(expected, "~")
		check["expect"] = map[string]any{"stdout": map[string]any{"contains": value}}
		if len(value) < 3 {
			needsReview = append(needsReview, "weak-matcher")
			findings = append(findings, MigrationFinding{RowID: row.ID, Code: "weak-matcher", Original: row.Expected, Message: "short v1 contains matcher is weak", Suggestions: []string{"use stdout.equals", "use a more specific contains value"}})
		}
	default:
		check["expect"] = map[string]any{"stdout": map[string]any{"equals": row.Expected}}
	}
	if strings.Contains(row.Command, "{{") {
		needsReview = append(needsReview, "jinja-template-risk")
		findings = append(findings, MigrationFinding{RowID: row.ID, Code: "jinja-template-risk", Original: row.Command, Message: "v2 probes must not use Jinja template syntax"})
	}
	if applicabilityRisk {
		needsReview = append(needsReview, "applicability-unknown")
		findings = append(findings, MigrationFinding{RowID: row.ID, Code: "applicability-unknown", Message: "document prose requires an explicit appliesWhen decision"})
	}
	if options.DefaultAction == "" {
		needsReview = append(needsReview, "action-unknown")
	}
	if options.TagPrefix == "" {
		check["verifyOnly"] = true
		needsReview = append(needsReview, "traceability-unknown")
	} else {
		check["tags"] = []string{options.TagPrefix + "-" + row.ID}
	}
	if len(needsReview) > 0 {
		check["needsReview"] = needsReview
	}
	return check, findings
}

func migrationRoles(s *Spec) []string {
	set := make(map[string]struct{})
	for _, host := range s.Hosts {
		if host.Group != "" {
			set[host.Group] = struct{}{}
		}
	}
	if len(set) == 0 {
		return []string{"all"}
	}
	roles := make([]string, 0, len(set))
	for role := range set {
		roles = append(roles, role)
	}
	sort.Strings(roles)
	return roles
}

func migrationSummary(title string) string {
	title = strings.TrimSpace(strings.TrimPrefix(title, "Verification Spec —"))
	if title == "" {
		return "migrated verification"
	}
	return title
}

func migrationSource(s *Spec) string {
	parts := make([]string, 0, 2)
	if s.Alignment != "" {
		parts = append(parts, s.Alignment)
	}
	if s.Version != "" {
		parts = append(parts, "v1 version "+s.Version)
	}
	if len(parts) == 0 {
		return "migrated from v1"
	}
	return strings.Join(parts, "; ")
}

func yamlScalar(value string) string {
	encoded, err := yaml.Marshal(value)
	if err != nil {
		panic(err)
	}
	return strings.TrimSpace(string(encoded))
}

func quoteMigrationContext(original []byte) string {
	if len(original) == 0 {
		return ""
	}
	lines := strings.Split(strings.TrimSuffix(string(original), "\n"), "\n")
	for i, line := range lines {
		lines[i] = "> " + line
	}
	return strings.Join(lines, "\n") + "\n"
}

var migrationOptionalProse = regexp.MustCompile(`(?i)(expected\s+fail|not[ -]?applicable|optional|選填|預期失敗|不適用)`)

// DetectApplicabilityRisk returns true for prose that needs a human to model
// applicability. It is exported so the CLI can add a document-level finding
// without pretending to know which v1 row it belongs to.
func DetectApplicabilityRisk(original []byte) bool { return migrationOptionalProse.Match(original) }

// MarshalMigrationReport writes stable, indented JSON for a sidecar file.
func MarshalMigrationReport(report MigrationReport) ([]byte, error) {
	return json.MarshalIndent(report, "", "  ")
}
