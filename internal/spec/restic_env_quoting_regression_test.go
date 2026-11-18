package spec

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// Issue #360: restic-backup-apply.yml Step 4 wrote every value of
// /etc/pilot/restic-env as export NAME='<value>', and that file is a shell
// file (the backup script, Steps 10/10a and spec rows C4-C6 `.` it as root).
// A single quote in the repository password ended the string: a syntax error,
// or with a crafted value a command run by the root shell. The values now go
// through Ansible's `quote` filter.

const resticEnvTask = "Step 4: Render restic env file (spec C2, C3)"

// resticEnvVars maps each variable the env file exports to the playbook
// variable that feeds it, in file order.
var resticEnvVars = []struct{ env, input string }{
	{"AWS_ACCESS_KEY_ID", "restic_aws_access_key_id"},
	{"AWS_SECRET_ACCESS_KEY", "restic_aws_secret_access_key"},
	{"RESTIC_REPOSITORY", "restic_repository"},
	{"RESTIC_PASSWORD", "restic_password"},
	{"RESTIC_BACKUP_PATHS", "restic_backup_paths"},
	{"RESTIC_BACKUP_PRE_HOOK", "restic_backup_pre_hook"},
	{"RESTIC_LOCK_RETRY", "restic_lock_retry"},
	{"RESTIC_RETENTION_DAILY", "restic_retention_daily"},
	{"RESTIC_RETENTION_WEEKLY", "restic_retention_weekly"},
	{"RESTIC_RETENTION_MONTHLY", "restic_retention_monthly"},
}

// hostileValues are values a shell would rewrite or run if they were not
// quoted for it; %[1]s is a file that only a command run by the shell creates.
var hostileValues = []string{
	`q"uo'te\back slash`,
	`'; touch %[1]s; '`,
	"x$(touch %[1]s)y",
	"a`touch %[1]s`b",
	"$HOME and ${PATH}",
	"  spaced  ",
	"line1\nline2",
	"tab\there",
	"",
}

// renderResticEnv runs the real Step 4 task with ansible-playbook and returns
// the path of the rendered file. values[i] feeds resticEnvVars[i].
func renderResticEnv(t *testing.T, dir string, values []string) string {
	t.Helper()
	task := findNamedTask(t, loadYAML(t, filepath.Join("..", "..", "playbooks", "apply", "restic-backup-apply.yml")), resticEnvTask)
	if task["no_log"] != true {
		t.Fatalf("%s must keep no_log: true", resticEnvTask)
	}
	envPath := filepath.Join(dir, "restic-env")
	vars := map[string]any{"restic_env_path": envPath}
	for i, v := range resticEnvVars {
		// !unsafe keeps a value from being templated; Ansible reads an empty
		// !unsafe scalar as null, so "" is passed as a plain string.
		var value any = unsafeString(values[i])
		if values[i] == "" {
			value = ""
		}
		if v.input == "restic_backup_paths" {
			// A list in the inventory; the task joins it with spaces.
			value = []any{value}
		}
		vars[v.input] = value
	}
	play := []map[string]any{{
		"hosts": "localhost", "connection": "local", "gather_facts": false,
		"vars":  vars,
		"tasks": []any{task},
	}}
	body, err := yaml.Marshal(play)
	if err != nil {
		t.Fatal(err)
	}
	playbook := filepath.Join(dir, "play.yml")
	if err := os.WriteFile(playbook, body, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("ansible-playbook", "-i", "localhost,", playbook)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "ANSIBLE_NOCOLOR=1", "ANSIBLE_LOCALHOST_WARNING=False", "ANSIBLE_DEPRECATION_WARNINGS=False")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ansible-playbook: %v\n%s", err, out)
	}
	return envPath
}

func requireAnsiblePlaybook(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		if os.Getenv("PILOT_REQUIRE_CONTAINER_TESTS") == "1" {
			t.Fatalf("required ansible-playbook not installed: %v", err)
		}
		t.Skipf("ansible-playbook not installed: %v", err)
	}
}

// TestRegression_ResticEnvFileReadsBackEveryValueUnchanged renders the real
// Step 4 with hostile values and sources the result with each POSIX shell on
// this host, the way the backup script and the spec rows do.
func TestRegression_ResticEnvFileReadsBackEveryValueUnchanged(t *testing.T) {
	requireAnsiblePlaybook(t)
	var shells []string
	for _, sh := range []string{"sh", "dash", "bash"} {
		if _, err := exec.LookPath(sh); err == nil {
			shells = append(shells, sh)
		}
	}
	for i, tmpl := range hostileValues {
		t.Run(fmt.Sprintf("value-%d", i), func(t *testing.T) {
			dir := t.TempDir()
			marker := filepath.Join(dir, "pwned")
			values := make([]string, len(resticEnvVars))
			for j := range values {
				// Each variable gets its own value, so a mix-up is visible.
				values[j] = tmpl
				if strings.Contains(tmpl, "%[1]s") {
					values[j] = fmt.Sprintf(tmpl, marker)
				}
				if tmpl != "" {
					values[j] = fmt.Sprintf("%d:%s", j, values[j])
				}
			}
			envPath := renderResticEnv(t, dir, values)
			if info, err := os.Stat(envPath); err != nil || info.Mode().Perm() != 0o600 {
				t.Fatalf("env file mode = %v, %v; want 0600", info, err)
			}
			var names []string
			for _, v := range resticEnvVars {
				names = append(names, `"$`+v.env+`"`)
			}
			script := `. "$1" && printf '%s\0' ` + strings.Join(names, " ")
			for _, sh := range shells {
				out, err := exec.Command(sh, "-c", script, sh, envPath).Output()
				if err != nil {
					t.Fatalf("%s could not source the env file: %v", sh, err)
				}
				got := strings.Split(strings.TrimSuffix(string(out), "\x00"), "\x00")
				if len(got) != len(values) {
					t.Fatalf("%s read %d values, want %d: %q", sh, len(got), len(values), got)
				}
				for j, v := range resticEnvVars {
					if got[j] != values[j] {
						t.Errorf("%s: %s = %q, want %q", sh, v.env, got[j], values[j])
					}
				}
				if _, err := os.Stat(marker); err == nil {
					t.Fatalf("%s ran a command embedded in a value while sourcing the env file", sh)
				}
			}
		})
	}
}

// TestRegression_ResticUsesTheConfiguredPasswordThroughTheEnvFile backs up and
// restores with the real restic through the sourced env file, then opens the
// repository with the password given to restic directly: the password the
// file delivered is the configured one.
func TestRegression_ResticUsesTheConfiguredPasswordThroughTheEnvFile(t *testing.T) {
	requireAnsiblePlaybook(t)
	restic, err := exec.LookPath("restic")
	if err != nil {
		t.Skip("restic not installed")
	}
	dir := t.TempDir()
	marker := filepath.Join(dir, "pwned")
	password := fmt.Sprintf(`p'w"d $(touch %s) \ end`, marker)
	repo := filepath.Join(dir, "repo")
	data := filepath.Join(dir, "data")
	if err := os.MkdirAll(data, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, "file.txt"), []byte("payload\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	values := []string{"key-id", "secret", repo, password, data, "", "1m", "7", "4", "6"}
	envPath := renderResticEnv(t, dir, values)
	cache := filepath.Join(dir, "cache")
	script := `set -e; . "$1"; restic init >/dev/null; restic backup $RESTIC_BACKUP_PATHS >/dev/null; restic restore latest --target "$2" >/dev/null`
	cmd := exec.Command("bash", "-c", script, "bash", envPath, filepath.Join(dir, "out"))
	cmd.Env = append(os.Environ(), "RESTIC_CACHE_DIR="+cache, "PATH="+filepath.Dir(restic)+":"+os.Getenv("PATH"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("restic through the env file: %v\n%s", err, out)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("sourcing the env file ran a command embedded in the password")
	}
	restored, err := os.ReadFile(filepath.Join(dir, "out", data, "file.txt"))
	if err != nil || string(restored) != "payload\n" {
		t.Fatalf("restored file = %q, %v", restored, err)
	}
	direct := exec.Command(restic, "-r", repo, "snapshots", "--json")
	direct.Env = append(os.Environ(), "RESTIC_PASSWORD="+password, "RESTIC_CACHE_DIR="+cache)
	if out, err := direct.CombinedOutput(); err != nil {
		t.Fatalf("the repository does not open with the configured password, so the env file delivered another one: %v\n%s", err, out)
	}
}

// exportAssignmentRe is a shell `export NAME=<value>` line.
var exportAssignmentRe = regexp.MustCompile(`^\s*export\s+[A-Za-z_][A-Za-z0-9_]*=(.*)$`)

// quotedJinjaValueRe is a value that is one Jinja expression ending in the
// shell `quote` filter.
var quotedJinjaValueRe = regexp.MustCompile(`^\{\{[^{}]*\|\s*quote\s*\}\}$`)

// unquotedShellExports returns the `export NAME=` lines of text whose value
// contains Jinja but is not a single `{{ ... | quote }}` expression.
func unquotedShellExports(text string) []string {
	var bad []string
	for n, line := range strings.Split(text, "\n") {
		m := exportAssignmentRe.FindStringSubmatch(line)
		if m == nil || !strings.Contains(m[1], "{{") {
			continue
		}
		if !quotedJinjaValueRe.MatchString(strings.TrimSpace(m[1])) {
			bad = append(bad, fmt.Sprintf("line %d: %s", n+1, strings.TrimSpace(line)))
		}
	}
	return bad
}

// TestRegression_ShellExportsOfJinjaValuesAreQuoted keeps the #360 class out
// of every playbook: a rendered `export NAME=` line is shell, so a Jinja
// value in it must be one `{{ ... | quote }}` expression. Quotes typed around
// the expression ('{{ x }}' or "{{ x }}") are what broke Step 4.
func TestRegression_ShellExportsOfJinjaValuesAreQuoted(t *testing.T) {
	// The lint fires on the shapes #360 had and passes the fixed one.
	for line, want := range map[string]bool{
		`export RESTIC_PASSWORD='{{ restic_password }}'`:                           true,
		`export RESTIC_PASSWORD="{{ restic_password }}"`:                           true,
		`export RESTIC_PASSWORD={{ restic_password }}`:                             true,
		`export P='{{ restic_backup_paths | join(" ") }}'`:                         true,
		`export RESTIC_PASSWORD={{ restic_password | quote }}`:                     false,
		`export RESTIC_BACKUP_PATHS={{ restic_backup_paths | join(" ") | quote }}`: false,
		`export HOME=/root`: false,
	} {
		if got := len(unquotedShellExports(line)) > 0; got != want {
			t.Errorf("unquotedShellExports(%q) flagged = %v, want %v", line, got, want)
		}
	}
	files := 0
	err := filepath.WalkDir(filepath.Join("..", "..", "playbooks"), func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		switch filepath.Ext(path) {
		case ".yml", ".yaml", ".j2", ".sh":
		default:
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		files++
		for _, problem := range unquotedShellExports(string(raw)) {
			t.Errorf("%s %s: a shell export of a Jinja value must be `{{ ... | quote }}` (issue #360)", path, problem)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files < 100 {
		t.Fatalf("only %d playbook files scanned; the walk is broken", files)
	}
}
