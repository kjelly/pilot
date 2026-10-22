package spec

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// fakeIdentityPasswordAPI substitutes only the FreeIPA RPC boundary. The real
// Python adapter and Ansible command module still run. Never use this as live
// FreeIPA evidence: the double cannot prove server policy or authentication.
func fakeIdentityPasswordAPI(t *testing.T, dir string) {
	t.Helper()
	source := `import json, os
from types import SimpleNamespace
class NotFound(Exception):
    pass
class API:
    def __init__(self):
        self.connected = False
        self.Backend = SimpleNamespace(rpcclient=self)
        self.Command = SimpleNamespace(passwd=self.passwd)
    def bootstrap(self, **kwargs):
        assert kwargs == dict(context='cli', in_server=False)
    def finalize(self):
        pass
    def connect(self):
        self.connected = True
    def isconnected(self):
        return self.connected
    def disconnect(self):
        self.connected = False
        with open(os.environ['IDENTITY_API_DISCONNECT'], 'a') as f:
            f.write('disconnected\n')
    def passwd(self, principal, password, current_password):
        assert self.connected
        assert current_password == 'CHANGING_PASSWORD_FOR_ANOTHER_USER'
        cache = os.environ.get('KRB5CCNAME', '')
        with open(os.environ['IDENTITY_API_CALLS'], 'a') as f:
            f.write(json.dumps(dict(principal=principal, password=password, cache=cache)) + '\n')
        if principal == os.environ.get('IDENTITY_API_FAIL_USER'):
            # An exception may contain the supplied secret. The adapter must
            # report only its type, never its message or traceback.
            raise NotFound('secret=' + password)
        state = os.environ.get('IDENTITY_PASSWORD_STATE')
        if state:
            open(os.path.join(state, principal), 'w').close()
api = API()
`
	if err := os.WriteFile(filepath.Join(dir, "ipalib.py"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PYTHONPATH", dir)
	t.Setenv("IDENTITY_API_CALLS", filepath.Join(dir, "api-calls"))
	t.Setenv("IDENTITY_API_DISCONNECT", filepath.Join(dir, "disconnects"))
}

type identityPasswordCall struct {
	Principal string `json:"principal"`
	Password  string `json:"password"`
	Cache     string `json:"cache"`
}

func identityPasswordCalls(t *testing.T, dir string) []identityPasswordCall {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "api-calls"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var calls []identityPasswordCall
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var call identityPasswordCall
		if err := json.Unmarshal([]byte(line), &call); err != nil {
			t.Fatal(err)
		}
		calls = append(calls, call)
	}
	return calls
}

func TestRegression_IdentitySecretInputContract(t *testing.T) {
	doc := loadYAML(t, identityApplyPath)
	for _, name := range []string{"Kinit admin", identityPwSetTask} {
		task := findNamedTask(t, doc, name)
		args, ok := task["ansible.builtin.command"].(map[string]any)
		if !ok || args["stdin"] == nil || task["no_log"] != true {
			t.Fatalf("%s must use command argv/stdin and no_log", name)
		}
		argv, ok := args["argv"].([]any)
		if !ok || len(argv) == 0 {
			t.Fatalf("%s has no argv", name)
		}
		for _, arg := range argv {
			if len(secretsInText(fmt.Sprint(arg))) != 0 {
				t.Fatalf("%s puts a secret in process argv", name)
			}
		}
		if _, ok := task["ansible.builtin.shell"]; ok {
			t.Fatalf("%s still uses a shell", name)
		}
	}
}

func TestRegression_IdentitySecretCIRequiresAnsible(t *testing.T) {
	body, err := os.ReadFile("../../Makefile")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^identity-secret-test:.*\n\tPILOT_REQUIRE_CONTAINER_TESTS=1 go test .* -run '([^']+)' ./internal/spec/`).FindSubmatch(body)
	if m == nil {
		t.Fatal("identity-secret-test must require Ansible")
	}
	selected := regexp.MustCompile(strings.ReplaceAll(string(m[1]), "$$", "$"))
	for _, name := range []string{"IdentitySecretInputContract", "IdentitySecretCIRequiresAnsible", "IdentitySecretInputsRuntime", "IdentityPasswordResetFollowsRosterSchema", "IdentityPasswordLookupFailureSetsNothing", "IdentityPasswordCheckModeSetsNothing", "IdentityPasswdFailureFailsTheRun", "FreeIPAKinitTasksPassPasswordUnchanged", "NoSecretInCommandText"} {
		if !selected.MatchString("TestRegression_" + name) {
			t.Errorf("required-Ansible recipe omits %s", name)
		}
	}
	body, err = os.ReadFile("../../.github/workflows/ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	var workflow struct {
		Jobs map[string]struct {
			Steps []struct{ Run, Uses string }
		}
	}
	if err := yaml.Unmarshal(body, &workflow); err != nil {
		t.Fatal(err)
	}
	ansible, setupGo, recipe := -1, -1, -1
	for i, step := range workflow.Jobs["playbook-lint"].Steps {
		if strings.Contains(step.Run, "pip install") && strings.Contains(step.Run, "ansible-core") {
			ansible = i
		}
		if strings.HasPrefix(step.Uses, "actions/setup-go@") {
			setupGo = i
		}
		if strings.TrimSpace(step.Run) == "make identity-secret-test" {
			recipe = i
		}
	}
	if recipe < 0 || ansible < 0 || setupGo < 0 || recipe <= ansible || recipe <= setupGo {
		t.Fatalf("CI recipe must follow Ansible and Go setup: %d %d %d", ansible, setupGo, recipe)
	}
}

// Keep the production block's environment, include/always cleanup and command
// tasks. Only omit unrelated identity mutations; include paths become absolute
// because the harness writes its playbook into a temporary directory.
func identitySecretBlock(t *testing.T) map[string]any {
	t.Helper()
	doc := loadYAML(t, identityApplyPath)
	block := findNamedTask(t, doc, "FreeIPA identity reconcile with a private Kerberos cache")
	names := append([]string{"Private Kerberos cache for the tickets below (issue #69)", "Kinit admin"}, identityPasswordTaskNames...)
	names = append(names, identityPasswdGateTask)
	var tasks []any
	for _, task := range namedTasks(block["block"].([]any), names) {
		tasks = append(tasks, task)
	}
	block["block"] = tasks
	walkTaskMaps(block, func(task map[string]any) {
		if include, ok := task["ansible.builtin.include_tasks"].(map[string]any); ok {
			path, err := filepath.Abs(filepath.Join("../../playbooks/apply", include["file"].(string)))
			if err != nil {
				t.Fatal(err)
			}
			include["file"] = path
		}
	})
	return block
}

func TestRegression_IdentitySecretInputsRuntime(t *testing.T) {
	for _, mode := range []string{"success", "kinit-failure", "password-failure", "check", "tagged"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			fakeIdentityPasswordAPI(t, dir)
			defaultCache := filepath.Join(dir, "default-cache")
			if err := os.WriteFile(defaultCache, []byte("unrelated ticket"), 0o600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("KRB5CCNAME", "FILE:"+defaultCache)
			marker := filepath.Join(dir, "pwned")
			passwords := []string{
				"demo$pilot118_missing_suffix", "a`touch " + marker + "`b",
				"x$(touch " + marker + ")y", `q"uo'te\back slash`,
				"  spaced \t ", `x"; touch ` + marker + `; #`, "{{ not_jinja }}", "密碼🔐",
			}
			adminPassword := "Admin$`touch " + marker + "`$(touch " + marker + ")\"' \\ pass"
			var users []any
			for i, password := range passwords {
				user := canonicalUser(fmt.Sprintf("user%d", i), true, false)
				user["password"] = unsafeString(password)
				users = append(users, user)
			}
			// Exercise requested reset and preservation alongside initial setup.
			users = append(users, canonicalUser("reset-user", false, false), canonicalUser("preserved-user", true, true))
			state := filepath.Join(dir, "state")
			if err := os.Mkdir(state, 0o700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("IDENTITY_PASSWORD_STATE", state)
			for name, fixture := range map[string]string{"new": userShowNoKey, "pending": userShowResetPending, "changed": userShowSelfChanged} {
				body, err := os.ReadFile(fixture)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			bin := filepath.Join(dir, "bin")
			if err := os.Mkdir(bin, 0o700); err != nil {
				t.Fatal(err)
			}
			for name, script := range map[string]string{
				"kinit": `#!/bin/sh
cat > "$IDENTITY_TEST_DIR/admin-stdin"
printf '%s\n' "$@" > "$IDENTITY_TEST_DIR/admin-argv"
printf '%s' "$KRB5CCNAME" > "$IDENTITY_TEST_DIR/cache"
stat -c '%a' "${KRB5CCNAME#FILE:}" > "$IDENTITY_TEST_DIR/cache-mode"
printf ticket > "${KRB5CCNAME#FILE:}"
exit "$IDENTITY_KINIT_RC"
`,
				// Failure to kdestroy must still unlink the cache in always.
				"kdestroy": "#!/bin/sh\nprintf '%s\\n' \"$@\" >> \"$IDENTITY_TEST_DIR/destroy\"\nexit 1\n",
				"ipa": `#!/bin/sh
if [ "$1" != user-show ]; then exit 99; fi
if [ "$2" = preserved-user ]; then cat "$IDENTITY_TEST_DIR/changed"
elif [ -e "$IDENTITY_PASSWORD_STATE/$2" ]; then cat "$IDENTITY_TEST_DIR/pending"
elif [ "$2" = reset-user ]; then cat "$IDENTITY_TEST_DIR/changed"
else cat "$IDENTITY_TEST_DIR/new"; fi
`,
			} {
				if err := os.WriteFile(filepath.Join(bin, name), []byte(script), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
			t.Setenv("IDENTITY_TEST_DIR", dir)
			t.Setenv("IDENTITY_KINIT_RC", "0")
			if mode == "kinit-failure" {
				t.Setenv("IDENTITY_KINIT_RC", "1")
			}
			if mode == "password-failure" {
				t.Setenv("IDENTITY_API_FAIL_USER", "user0")
			}
			vars := map[string]any{"ipa_active_users": users, "identity_admin_password": unsafeString(adminPassword), "identity_admin_principal": "admin", "ipa_realm": "IPA.PILOT.INTERNAL"}
			args := []string{}
			switch mode {
			case "check":
				args = append(args, "--check", "--diff")
			case "tagged":
				args = append(args, "--tags", "passwords")
			}
			for run := 0; run < 2; run++ {
				forgotten := map[string]any{"name": "Cache facts were cleared", "ansible.builtin.assert": map[string]any{"that": []any{"pilot_krb5ccname == 'FILE:/nonexistent/pilot-krb5cc-not-open'", "pilot_krb5ccname_file == {}"}}, "tags": []any{"always"}}
				res := runGatewayTasks(t, dir, []any{identitySecretBlock(t), forgotten}, vars, nil, args...)
				wantFailure := mode == "kinit-failure" || mode == "password-failure"
				if (res.rc != 0) != wantFailure {
					t.Fatalf("run %d rc=%d failures=%v\n%s", run, res.rc, res.failures, res.raw)
				}
				if mode == "password-failure" && !strings.Contains(failureOf(res, identityPasswdGateTask), "user0 (rc=1: ipa: ERROR: password reset failed (NotFound))") {
					t.Fatalf("password failure did not reach the sanitized gate: %v", res.failures)
				}
				for _, secret := range append(slices.Clone(passwords), adminPassword) {
					if strings.Contains(res.raw, secret) {
						t.Fatal("Ansible output leaked a password")
					}
				}
				cache, err := os.ReadFile(filepath.Join(dir, "cache"))
				if err != nil || !strings.HasPrefix(string(cache), "FILE:") {
					t.Fatalf("missing private cache: %v", err)
				}
				if _, err := os.Stat(strings.TrimPrefix(string(cache), "FILE:")); !os.IsNotExist(err) {
					t.Fatalf("cache survived run %d: %v", run, err)
				}
				if got, _ := os.ReadFile(filepath.Join(dir, "cache-mode")); string(got) != "600\n" {
					t.Fatalf("cache was not private: %q", got)
				}
				if got, _ := os.ReadFile(filepath.Join(dir, "admin-stdin")); string(got) != adminPassword+"\n" {
					t.Fatal("kinit changed the admin password")
				}
				if got, _ := os.ReadFile(filepath.Join(dir, "admin-argv")); string(got) != "admin@IPA.PILOT.INTERNAL\n" {
					t.Fatalf("unexpected kinit argv: %q", got)
				}
				if _, err := os.Stat(marker); !os.IsNotExist(err) {
					t.Fatal("a password executed a command")
				}
				if got, _ := os.ReadFile(defaultCache); string(got) != "unrelated ticket" {
					t.Fatal("default cache was modified")
				}
				calls := identityPasswordCalls(t, dir)
				wantCalls := len(passwords) + 1
				if mode == "kinit-failure" || mode == "check" {
					wantCalls = 0
				} else if mode == "password-failure" && run == 1 {
					wantCalls++ // only the failed initializer retries
				}
				if len(calls) != wantCalls {
					t.Fatalf("run %d API calls=%d, want %d", run, len(calls), wantCalls)
				}
				for i, call := range calls {
					if i < len(passwords) && call.Password != passwords[i] {
						t.Fatalf("password %d was changed before the API", i)
					}
					if !strings.HasPrefix(call.Cache, "FILE:") || call.Cache == "FILE:"+defaultCache {
						t.Fatalf("API used a default cache: %q", call.Cache)
					}
				}
				disconnected, _ := os.ReadFile(filepath.Join(dir, "disconnects"))
				if strings.Count(string(disconnected), "disconnected\n") != len(calls) {
					t.Fatal("API connection was not closed after success/failure")
				}
				if run == 1 && !wantFailure && len(res.changed) != 0 {
					t.Fatalf("rerun changed tasks: %v", res.changed)
				}
			}
		})
	}
}
