package inventory

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// ansibleLoadsAsString is, for each plain (unquoted) scalar, whether
// Ansible's vars-file loader reads it as a string — captured from
// ansible-core 2.19.2 with TestYAML11NonStringMatchesAnsible's playbook.
// The keys only name the values.
var ansibleLoadsAsString = map[string]struct {
	plain  string
	string bool
}{
	"leading zero, not octal": {"012345678", true},
	"exponent, no dot":        {"1e10", true},
	"0o octal":                {"0o12345670", true},
	"base 60 int":             {"190:20:30", false},
	"date":                    {"2024-01-01", false},
	"exponent letters":        {"84e12345", true},
	"int":                     {"12345678", false},
	"float":                   {"1234.5678", false},
	"true":                    {"true", false},
	"yes":                     {"yes", false},
	"on":                      {"on", false},
	"off":                     {"off", false},
	"no":                      {"no", false},
	"hex":                     {"0x1F", false},
	"binary":                  {"0b101", false},
	"octal":                   {"0755", false},
	"underscored int":         {"1_000", false},
	"inf":                     {".inf", false},
	"nan":                     {".nan", false},
	"base 60 float":           {"1:30.5", false},
	"timestamp":               {"2024-01-01T10:00:00Z", false},
	"password":                {"Old-pass_1", true},
	"two dots":                {"1.2.3", true},
	"not hex":                 {"0x1G", true},
	"signed int":              {"+12", false},
	"signed float":            {"-0.5", false},
	"signed exponent":         {"1.5e+3", false},
	"Y":                       {"Y", true},
	"n":                       {"n", true},
	"NULL":                    {"NULL", false},
	"dangling exponent":       {"12e", true},
	"trailing dot":            {"0.", false},
	"leading dot":             {".5", false},
	"short time":              {"2024-1-1 1:2:3", true},
	"exponent with sign":      {"1e+10", true},
	"octal 007":               {"007", false},
}

// yaml11NonString agrees with Ansible's loader on every captured value;
// with ansible-playbook installed (always in `make identity-secret-test`,
// which CI runs with Ansible), the capture is checked against the real
// loader in one run (PR #148 re-review: pilot judged 190:20:30 current
// while the gate compared a number, and refused 012345678 that Ansible
// keeps as a string).
func TestYAML11NonStringMatchesAnsible(t *testing.T) {
	for name, tt := range ansibleLoadsAsString {
		if got := !yaml11NonString.MatchString(tt.plain); got != tt.string {
			t.Errorf("%s (%s): yaml11NonString says string=%v, Ansible says %v", name, tt.plain, got, tt.string)
		}
	}

	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		if os.Getenv("PILOT_REQUIRE_CONTAINER_TESTS") == "1" {
			t.Fatalf("required ansible-playbook not installed: %v", err)
		}
		t.Skipf("ansible-playbook not installed; checked the captured values only: %v", err)
	}
	dir := t.TempDir()
	keys := make([]string, 0, len(ansibleLoadsAsString))
	for name := range ansibleLoadsAsString {
		keys = append(keys, name)
	}
	sort.Strings(keys)
	var vals strings.Builder
	vals.WriteString("vals:\n")
	for i, name := range keys {
		fmt.Fprintf(&vals, "  v%03d: %s\n", i, ansibleLoadsAsString[name].plain)
	}
	play := `- hosts: localhost
  connection: local
  gather_facts: false
  vars_files: [vals.yml]
  tasks:
    - debug:
        msg: "{{ vals | dict2items | selectattr('value', 'string') | map(attribute='key') | list }}"
`
	for name, body := range map[string]string{"vals.yml": vals.String(), "play.yml": play} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("ansible-playbook", "-i", "localhost,", "play.yml")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "ANSIBLE_STDOUT_CALLBACK=json", "ANSIBLE_NOCOLOR=1",
		"ANSIBLE_LOCALHOST_WARNING=False", "ANSIBLE_INVENTORY_UNPARSED_WARNING=False")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("ansible-playbook: %v\n%s", err, out)
	}
	var result struct {
		Plays []struct {
			Tasks []struct {
				Hosts map[string]struct {
					Msg []string `json:"msg"`
				} `json:"hosts"`
			} `json:"tasks"`
		} `json:"plays"`
	}
	if err := json.Unmarshal(out, &result); err != nil || len(result.Plays) != 1 || len(result.Plays[0].Tasks) != 1 {
		t.Fatalf("unexpected ansible-playbook output (%v):\n%s", err, out)
	}
	strs := result.Plays[0].Tasks[0].Hosts["localhost"].Msg
	for i, name := range keys {
		key := fmt.Sprintf("v%03d", i)
		if got := slices.Contains(strs, key); got != ansibleLoadsAsString[name].string {
			t.Errorf("%s (%s): Ansible now loads it as string=%v; the capture says %v", name, ansibleLoadsAsString[name].plain, got, ansibleLoadsAsString[name].string)
		}
	}
}

// yaml12NonString reports whether yaml.v3 (YAML 1.2) reads plain as
// anything but a string.
func yaml12NonString(t *testing.T, plain string) bool {
	t.Helper()
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte("x: "+plain+"\n"), &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Content[0].Content[1].ShortTag() != "!!str"
}

// A password written so that either YAML version may read it as anything
// but a string is "quote it" on both sides — never judged current, never
// synced, never skipped — and quoting it makes it an ordinary password
// (PR #148 re-review).
func TestAdminPasswordsAYAMLLoaderMayTypeNeedQuoting(t *testing.T) {
	for name, tt := range ansibleLoadsAsString {
		t.Run(name, func(t *testing.T) {
			plain := writeRoster(t, strings.Replace(rosterAdminFixture, "%s", tt.plain, 1))
			quoted := writeRoster(t, strings.Replace(rosterAdminFixture, "%s", `"`+tt.plain+`"`, 1))
			vaultPlain := []byte("ipa_admin_password: " + tt.plain + "\n")
			nullish := tt.plain == "NULL"
			typed := !tt.string || yaml12NonString(t, tt.plain)

			got, err := CompareRosterAdminPassword(plain, tt.plain)
			switch {
			case err != nil:
				t.Fatal(err)
			case nullish && got != RosterAdminNotLiteral:
				t.Errorf("roster %s: %v, want no password (RosterAdminNotLiteral)", tt.plain, got)
			case !nullish && typed && got != RosterAdminNotString:
				t.Errorf("roster %s: %v, want RosterAdminNotString", tt.plain, got)
			case !nullish && !typed && got != RosterAdminCurrent:
				t.Errorf("roster %s: %v, want RosterAdminCurrent", tt.plain, got)
			}
			if !nullish && VaultAdminPasswordNotString(vaultPlain) != typed {
				t.Errorf("vault %s: VaultAdminPasswordNotString = %v, want %v", tt.plain, !typed, typed)
			}
			if typed && VaultAdminPassword(vaultPlain) != "" {
				t.Errorf("vault %s: VaultAdminPassword compares a value a loader may type", tt.plain)
			}
			if typed && !nullish {
				if result, err := SyncRosterAdminPassword(plain, tt.plain, "New-pass_2"); err != nil || result != RosterAdminNotString {
					t.Errorf("sync of roster %s = %v, %v; want RosterAdminNotString", tt.plain, result, err)
				}
			}
			if got, err := CompareRosterAdminPassword(quoted, tt.plain); err != nil || got != RosterAdminCurrent {
				t.Errorf("quoted roster %q: %v, %v; want RosterAdminCurrent", tt.plain, got, err)
			}
			if VaultAdminPasswordNotString([]byte("ipa_admin_password: \"" + tt.plain + "\"\n")) {
				t.Errorf("quoted vault %q reported as not a string", tt.plain)
			}
		})
	}
}

// taggedLiteralForms are password forms ansibleScalarKind calls literal
// although a bare reading would not: an !unsafe value (even holding a Jinja
// delimiter), an explicit !!str, and quoted values YAML would otherwise
// type. Each is the text it maps to.
var taggedLiteralForms = []struct{ scalar, text string }{
	{`!unsafe "Pass-1"`, "Pass-1"},
	{`!unsafe "Pa{{ss"`, "Pa{{ss"},
	{`!!str 012345678`, "012345678"},
	{`!!str yes`, "yes"},
	{`"190:20:30"`, "190:20:30"},
	{`'2024-01-01'`, "2024-01-01"},
}

// Each tagged or quoted form the classifier calls literal is, to Ansible, a
// string equal to its text — what the drift gate's comparison sees — so
// pilot judging it current against that text is right. Checked against
// the real loader in one playbook run, in `make identity-secret-test`
// (PR #148 re-review, round 4).
func TestAnsibleTagsMatchTheClassifier(t *testing.T) {
	var vals strings.Builder
	vals.WriteString("vals:\n")
	var checks []string
	for i, form := range taggedLiteralForms {
		var doc yaml.Node
		if err := yaml.Unmarshal([]byte("x: "+form.scalar+"\n"), &doc); err != nil {
			t.Fatal(err)
		}
		if value := doc.Content[0].Content[1]; ansibleScalarKind(value) != scalarLiteral || value.Value != form.text {
			t.Errorf("%s: classifier says %v %q, want literal %q", form.scalar, ansibleScalarKind(value), value.Value, form.text)
		}
		fmt.Fprintf(&vals, "  v%03d: %s\n", i, form.scalar)
		// The expected text, spelled so no "{{" appears in the template.
		want := "'" + strings.ReplaceAll(form.text, "{", "' ~ '{' ~ '") + "'"
		checks = append(checks, fmt.Sprintf("(vals.v%03d is string) and (vals.v%03d == %s)", i, i, want))
	}

	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		if os.Getenv("PILOT_REQUIRE_CONTAINER_TESTS") == "1" {
			t.Fatalf("required ansible-playbook not installed: %v", err)
		}
		t.Skipf("ansible-playbook not installed; checked the classifier only: %v", err)
	}
	dir := t.TempDir()
	play := "- hosts: localhost\n  connection: local\n  gather_facts: false\n  vars_files: [vals.yml]\n  tasks:\n" +
		"    - debug:\n        msg: \"{{ [" + strings.Join(checks, ", ") + "] }}\"\n"
	for name, body := range map[string]string{"vals.yml": vals.String(), "play.yml": play} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("ansible-playbook", "-i", "localhost,", "play.yml")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "ANSIBLE_STDOUT_CALLBACK=json", "ANSIBLE_NOCOLOR=1",
		"ANSIBLE_LOCALHOST_WARNING=False", "ANSIBLE_INVENTORY_UNPARSED_WARNING=False")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("ansible-playbook: %v\n%s", err, out)
	}
	var result struct {
		Plays []struct {
			Tasks []struct {
				Hosts map[string]struct {
					Msg []bool `json:"msg"`
				} `json:"hosts"`
			} `json:"tasks"`
		} `json:"plays"`
	}
	if err := json.Unmarshal(out, &result); err != nil || len(result.Plays) != 1 || len(result.Plays[0].Tasks) != 1 {
		t.Fatalf("unexpected ansible-playbook output (%v):\n%s", err, out)
	}
	got := result.Plays[0].Tasks[0].Hosts["localhost"].Msg
	if len(got) != len(taggedLiteralForms) {
		t.Fatalf("Ansible returned %d results for %d forms:\n%s", len(got), len(taggedLiteralForms), out)
	}
	for i, ok := range got {
		if !ok {
			t.Errorf("%s: Ansible does not load it as the string %q", taggedLiteralForms[i].scalar, taggedLiteralForms[i].text)
		}
	}
}
