package accessgrants

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// readCapture loads a REAL ansible-playbook capture of the drift probe from
// testdata/ansible (stdout and stderr kept apart, exactly as ansible wrote
// them; only the machine's paths were rewritten to /work, /repo and /scratch).
// The captures came from running playbooks/check/freeipa-access-drift-probe.yml
// with ansible-core 2.19.2 against a localhost inventory with a hyphenated
// group (freeipa-server, the shape pilot inventories use), as
// testdata/ansible/README documents.
func readCapture(t *testing.T, name string) (stdout, stderr string) {
	t.Helper()
	out, err := os.ReadFile(filepath.Join("testdata", "ansible", name+".stdout"))
	if err != nil {
		t.Fatal(err)
	}
	errOut, err := os.ReadFile(filepath.Join("testdata", "ansible", name+".stderr"))
	if err != nil {
		t.Fatal(err)
	}
	return string(out), string(errOut)
}

// TestSummarizeAnsibleFailure_RealCaptures runs the extraction over real
// captures of every way the probe fails, on both streams. Each case has a
// should-trigger side (the message an operator needs is shown) and a
// should-not-leak side (nothing from the vault file's content, and none of
// ansible's snippet lines, survives).
func TestSummarizeAnsibleFailure_RealCaptures(t *testing.T) {
	const sentinel = "Sup3rS3cretPw"
	for _, tc := range []struct {
		name     string
		varsFile string
		want     []string
		notWant  []string
	}{
		{
			// stdout carries the gate message, stderr only the hyphenated-group
			// warning: the message must win over the warning.
			name:    "gate_missing",
			want:    []string{"No usable FreeIPA admin password", "ipa_admin_password", "freeipa.admin.password", "Both are missing or too short"},
			notWant: []string{"Invalid characters were found in group names", "Origin:", "^ column"},
		},
		{
			// ANSIBLE_STDOUT_CALLBACK=minimal prints no `fatal:` line, so the
			// gate message is only in the [ERROR] line, whose text names
			// .vault/main.yaml: it must not be taken for a parse error.
			name:    "gate_missing_minimal",
			want:    []string{"No usable FreeIPA admin password", "Both are missing or too short"},
			notWant: []string{"could not parse", "withheld", "valid YAML", "Origin:"},
		},
		{
			// ANSIBLE_FORCE_COLOR=1: every line carries escape codes.
			name:    "gate_missing_force_color",
			want:    []string{"No usable FreeIPA admin password", "Both are missing or too short"},
			notWant: []string{"\x1b", "[0;3", "could not parse", "Origin:"},
		},
		{
			// A vars file that is a list: a real parse-class [ERROR] that is
			// not worded "YAML parsing failed".
			name:     "vault_not_mapping",
			varsFile: "/repo/.vault/main.yaml",
			want:     []string{"could not parse an input file", "/repo/.vault/main.yaml is valid YAML", "withheld"},
			notWant:  []string{"could not be made into a dictionary", "/work/main.yaml"},
		},
		{
			// {{ 1 / 0 }} as the vault value: rescued, so the gate speaks.
			name:    "vault_template_unresolvable",
			want:    []string{"No usable FreeIPA admin password", "Both are missing or too short"},
			notWant: []string{"censored", "hidden by no_log"},
		},
		{
			// The vault file is not valid YAML: ansible prints the source line.
			name:     "vault_bad_yaml",
			varsFile: "/repo/.vault/main.yaml",
			want:     []string{"could not parse /work/bad-vault.yaml:1:34", "valid YAML", "withheld"},
			notWant:  []string{sentinel, "oops", "ipa_admin_password", "Colons in unquoted values", "column 34", "raw: echo"},
		},
		{
			name:    "vault_encrypted_no_password",
			want:    []string{"Attempting to decrypt but no vault secrets found"},
			notWant: []string{"Failed to parse inventory", "<<< caused by >>>"},
		},
		{
			name:    "vault_wrong_password",
			want:    []string{"Decryption failed"},
			notWant: []string{"Failed to parse inventory", "<<< caused by >>>"},
		},
		{
			// kinit failed; the task is no_log, so ansible printed "censored".
			name:    "kinit_censored",
			want:    []string{"Kinit admin for read-only drift probe", "hidden by no_log"},
			notWant: []string{"Python interpreter", "Origin:", "Module failed"},
		},
		{
			name:    "host_unreachable",
			want:    []string{"ipa1 is unreachable", "Connection refused"},
			notWant: []string{"Origin:", "^ column"},
		},
		{
			// ansible_connection: "{{ ipa_admin_password }}" in the vault: ansible
			// puts the expanded password in the message and in the [ERROR] line.
			name:    "vault_connection_template",
			want:    []string{"ansible_connection names a connection plugin ansible does not have", "the value is withheld", "(task: Gate: drift probe input is complete)"},
			notWant: []string{sentinel, "Origin:", "connection plugin '"},
		},
		{
			// ansible_python_interpreter: "/nonexistent/{{ ipa_admin_password }}":
			// the msg, module_stderr and the [ERROR] chain all carry the value.
			name:    "vault_interpreter_template",
			want:    []string{"ansible_python_interpreter points at an interpreter that does not exist", "the value is withheld"},
			notWant: []string{sentinel, "/nonexistent", "module_stderr", "not found"},
		},
		{
			// ansible_host: "{{ ipa_admin_password }}" over ssh: the UNREACHABLE
			// msg carries the (lower-cased) value as the host name.
			name:    "vault_ssh_host_template",
			want:    []string{"ipa1 is unreachable", "Could not resolve hostname (check ansible_host)"},
			notWant: []string{sentinel, "sup3rs3cretpw", "Name or service not known"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stdout, stderr := readCapture(t, tc.name)
			got := summarizeAnsibleFailure(stdout, stderr, tc.varsFile)
			if got == "" {
				t.Fatalf("nothing extracted from a real failure\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
			}
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Errorf("summary %q does not contain %q", got, w)
				}
			}
			for _, w := range tc.notWant {
				if strings.Contains(got, w) {
					t.Errorf("summary %q must not contain %q", got, w)
				}
			}
			if strings.Contains(strings.ToLower(got), strings.ToLower(sentinel)) {
				t.Errorf("summary %q carries the vault sentinel", got)
			}
			if strings.ContainsAny(got, "\n\r") {
				t.Errorf("summary spans several lines: %q", got)
			}
		})
	}

	// The should-trigger for the leak: the real capture of a malformed vault
	// really does carry the secret, so the absence above is the extraction's
	// doing and not an empty fixture.
	t.Run("the expanded-template captures really contain the secret", func(t *testing.T) {
		for _, name := range []string{"vault_connection_template", "vault_interpreter_template", "vault_ssh_host_template"} {
			stdout, stderr := readCapture(t, name)
			if !strings.Contains(strings.ToLower(stdout+stderr), strings.ToLower(sentinel)) {
				t.Errorf("the %s capture no longer carries the expanded vault value; it can no longer prove the leak", name)
			}
		}
	})
	t.Run("the malformed-vault capture really contains the secret", func(t *testing.T) {
		_, stderr := readCapture(t, "vault_bad_yaml")
		if !strings.Contains(stderr, sentinel) {
			t.Fatalf("the vault_bad_yaml capture no longer echoes the vault line; it can no longer prove the leak:\n%s", stderr)
		}
	})
}

// TestSummarizeAnsibleFailure_NothingRecognisable: output with no failure
// message yields "", and DriftProbe then says so instead of dumping the
// transcript.
func TestSummarizeAnsibleFailure_NothingRecognisable(t *testing.T) {
	for _, tc := range []struct{ name, stdout, stderr string }{
		{"empty", "", ""},
		{"warning only", "", "[WARNING]: Invalid characters were found in group names but not replaced, use -vvvv to see details\n"},
		{"a source snippet alone", "", "1 ipa_admin_password: Sup3rS3cretPw: oops\n                                   ^ column 34\n"},
	} {
		if got := summarizeAnsibleFailure(tc.stdout, tc.stderr, ""); got != "" {
			t.Errorf("%s: summary = %q, want none", tc.name, got)
		}
	}
}

// TestRedactSecretish blanks password-shaped pairs and leaves the gate's own
// message (which names the keys but carries no value) alone.
func TestRedactSecretish(t *testing.T) {
	gate := "No usable FreeIPA admin password for the drift probe. Set ipa_admin_password (at least 8 characters) in the vault vars file, or freeipa.admin.password (at least 8 characters, not a template) in the roster."
	if got := redactSecretish(gate); got != gate {
		t.Errorf("the gate message was altered: %q", got)
	}
	for in, want := range map[string]string{
		"ipa_admin_password: Hunter2Hunter2":      "ipa_admin_password: [redacted]",
		`"ipa_admin_password": "Hunter2 Hunter2"`: `"ipa_admin_password": [redacted]`,
		"password=Hunter2Hunter2 next":            "password=[redacted] next",
		"freeipa.admin.password: 'a b c'":         "freeipa.admin.password: [redacted]",
	} {
		if got := redactSecretish(in); got != want {
			t.Errorf("redactSecretish(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestSummarizeAnsibleFailure_ParseErrorWithoutOriginHintsTheVarsFile: when
// ansible gives no Origin for a parse error, the hint names the vars file the
// probe was given and still echoes nothing from ansible's message.
func TestSummarizeAnsibleFailure_ParseErrorWithoutOriginHintsTheVarsFile(t *testing.T) {
	got := summarizeAnsibleFailure("", "[ERROR]: Syntax Error while loading YAML.\n  found Sup3rS3cretPw\n", "/ws/.vault/main.yaml")
	if !strings.Contains(got, "check that /ws/.vault/main.yaml is valid YAML") || strings.Contains(got, "Sup3rS3cretPw") || strings.Contains(got, "Syntax Error") {
		t.Fatalf("summary = %q", got)
	}
}

// TestParseErrorRE_OnlyRealParseErrors: the gate's own text names
// .vault/main.yaml and must never be classed as a parse error, while every
// real ansible-core 2.19.2 parse-error header (the YAML/JSON ones come from
// real captures: testdata/ansible/vault_bad_yaml, vault_not_mapping, and a
// tab-indented file) still is.
func TestParseErrorRE_OnlyRealParseErrors(t *testing.T) {
	for _, in := range []string{
		"YAML parsing failed: Colons in unquoted values must be followed by a non-space character.",
		"YAML parsing failed: Tabs are usually invalid in YAML.",
		"JSON parsing failed.",
		"Syntax Error while loading YAML.",
		"Invalid extra vars data supplied. '@/work/main.yaml' could not be made into a dictionary",
		"We were unable to read either as JSON nor YAML, these are the errors we got from each",
	} {
		if !parseErrorRE.MatchString(in) {
			t.Errorf("parseErrorRE must match the real parse error %q", in)
		}
	}
	for _, in := range []string{
		"Task failed: Action failed: No usable FreeIPA admin password for the drift probe. Set ipa_admin_password (at least 8 characters) in the vault vars file (default <inventory dir>/.vault/main.yaml, or --vars-file), or freeipa.admin.password in the roster. Both are missing or too short.",
		"the roster is not valid yaml",
		"Failed to parse inventory with 'yaml' plugin.",
		"Unable to parse /work/inventory.yml as an inventory source",
		"could not load the module",
		"Attempting to decrypt but no vault secrets found",
	} {
		if parseErrorRE.MatchString(in) {
			t.Errorf("parseErrorRE must not match %q", in)
		}
	}
}

// TestSummarizeAnsibleFailure_StripsAnsiEscapes: colour codes around a real
// `fatal:` and `[ERROR]:` line are removed before anything is matched.
func TestSummarizeAnsibleFailure_StripsAnsiEscapes(t *testing.T) {
	const esc = "\x1b"
	if got := ansiRE.ReplaceAllString(esc+"[0;31mred"+esc+"[0m "+esc+"[1;35mbold"+esc+"[0m plain "+esc+"[2K", ""); got != "red bold plain " {
		t.Fatalf("ansiRE left %q", got)
	}
	stdout := esc + "[0;31m[ERROR]: Task failed: Action failed: Connection refused (see .vault/main.yaml)" + esc + "[0m\n" +
		esc + "[0;31mfatal: [h1]: FAILED! => {\"msg\": \"Connection refused\"}" + esc + "[0m\n" +
		"h1 : ok=1    changed=0    unreachable=0    failed=1    skipped=0    rescued=0    ignored=0\n"
	got := summarizeAnsibleFailure(stdout, "", "")
	if !strings.Contains(got, "Connection refused") || strings.Contains(got, esc) || strings.Contains(got, "[0;31m") {
		t.Fatalf("summary = %q", got)
	}
}

// leakySentinel stands for a vault value that ansible expanded into a message.
const leakySentinel = "Sup3rS3cretPw"

// TestSummarizeAnsibleFailure_NeverCopiesAnsibleMessageText is the issue #179
// review finding: ansible's own message text is never returned, because any
// vault key can be expanded into it. Each case puts the sentinel inside prose
// that no password-key pattern can mask, through every path that used to copy
// text: a FAILED msg, an UNREACHABLE msg, the [ERROR] first line, an unknown
// task name. Each has a should-trigger twin: text that IS ours still appears.
func TestSummarizeAnsibleFailure_NeverCopiesAnsibleMessageText(t *testing.T) {
	failed := func(task, msg string) string {
		return "TASK [" + task + "] ****\nfatal: [h1]: FAILED! => {\"changed\": false, \"msg\": \"" + msg + "\"}\n" +
			"\nPLAY RECAP ****\nh1 : ok=1    changed=0    unreachable=0    failed=1    skipped=0    rescued=0    ignored=0\n"
	}
	unreachable := func(msg string) string {
		return "TASK [Kinit admin for read-only drift probe] ****\nfatal: [h1]: UNREACHABLE! => {\"changed\": false, \"msg\": \"" + msg + "\", \"unreachable\": true}\n" +
			"\nPLAY RECAP ****\nh1 : ok=1    changed=0    unreachable=1    failed=0    skipped=0    rescued=0    ignored=0\n"
	}
	for _, tc := range []struct {
		name, stdout, stderr string
		want                 []string // must appear (our text)
		notWant              []string // must not appear (ansible's text)
	}{
		{
			name:    "unknown FAILED msg is withheld",
			stdout:  failed("Kinit admin for read-only drift probe", "Something odd happened with "+leakySentinel+" in it"),
			want:    []string{"details withheld", "vault vars file", "(task: Kinit admin for read-only drift probe)"},
			notWant: []string{"odd", "happened"},
		},
		{
			name:    "a known class never reuses the surrounding text",
			stdout:  failed("Gate: drift probe input is complete", "Task failed: the connection plugin '"+leakySentinel+"' was not found"),
			want:    []string{"ansible_connection names a connection plugin ansible does not have"},
			notWant: []string{"Task failed", "'"},
		},
		{
			name:    "a gate message with a secret glued on is replaced by ours",
			stdout:  failed("Gate: a FreeIPA admin password is available (vault or roster)", "No usable FreeIPA admin password for the drift probe. "+leakySentinel+" Both are missing or too short."),
			want:    []string{"Set ipa_admin_password (at least 8 characters) in the vault vars file", "Both are missing or too short."},
			notWant: []string{" " + leakySentinel + " "},
		},
		{
			name:    "unknown UNREACHABLE msg is withheld",
			stdout:  unreachable("Task failed: Failed to connect to the host via ssh: user " + leakySentinel + " is odd"),
			want:    []string{"h1 is unreachable: details withheld"},
			notWant: []string{"user ", "odd"},
		},
		{
			name:    "a task name that is not the probe's own is dropped",
			stdout:  failed("Run as "+leakySentinel, "Something odd"),
			want:    []string{"details withheld"},
			notWant: []string{"task:", "Run as"},
		},
		{
			name:    "[ERROR] first line of an unknown error is withheld",
			stderr:  "[ERROR]: Some new ansible failure mentioning " + leakySentinel + " here\nOrigin: /w/x.yml:1:1\n",
			want:    []string{"details withheld"},
			notWant: []string{"new ansible failure", "here"},
		},
		{
			name:    "[ERROR] first line of a known class is replaced by ours",
			stderr:  "[ERROR]: Task failed: the connection plugin '" + leakySentinel + "' was not found\n",
			want:    []string{"ansible_connection names a connection plugin ansible does not have"},
			notWant: []string{"Task failed"},
		},
		{
			name:    "no_log censored output is reported as hidden",
			stdout:  "TASK [Kinit admin for read-only drift probe] ****\nfatal: [h1]: FAILED! => {\"censored\": \"the output has been hidden\", \"changed\": false}\n",
			want:    []string{"Kinit admin for read-only drift probe", "hidden by no_log"},
			notWant: []string{"the output has been hidden"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := summarizeAnsibleFailure(tc.stdout, tc.stderr, "")
			if got == "" {
				t.Fatal("nothing extracted")
			}
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Errorf("summary %q does not contain %q", got, w)
				}
			}
			for _, w := range append(tc.notWant, leakySentinel) {
				if strings.Contains(got, w) {
					t.Errorf("summary %q must not contain %q", got, w)
				}
			}
		})
	}
}

// TestClassifyMessage: the allowlisted gate messages and the failure classes
// return OUR text, and everything else is the withheld sentence.
func TestClassifyMessage(t *testing.T) {
	for _, k := range knownProbeMessages {
		if got := classifyMessage("Task failed: Action failed: " + k.marker + " " + leakySentinel); got != k.text {
			t.Errorf("gate %q -> %q, want our copy %q", k.marker, got, k.text)
		}
	}
	for _, c := range failureClasses {
		if c.text == "" || c.text == withheldText {
			t.Errorf("class %v has no text of its own", c.re)
		}
	}
	for _, in := range []string{
		"", "boom", "Something " + leakySentinel, "Module failed: " + leakySentinel,
		"Failed to connect to the host via ssh: user@" + leakySentinel,
	} {
		if got := classifyMessage(in); got != withheldText {
			t.Errorf("classifyMessage(%q) = %q, want the withheld sentence", in, got)
		}
	}
}

// probePlaybookFiles are the files whose task names and fail_msg values the
// allowlists must cover: the probe and the task files it includes.
var probePlaybookFiles = []string{
	"playbooks/check/freeipa-access-drift-probe.yml",
	"playbooks/apply/tasks/freeipa-private-ccache-open.yml",
	"playbooks/apply/tasks/freeipa-private-ccache-close.yml",
}

func loadProbeYAML(t *testing.T, rel string) yaml.Node {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", rel))
	if err != nil {
		t.Fatal(err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatalf("%s: %v", rel, err)
	}
	return doc
}

// TestProbeMessagesMatchThePlaybook: knownProbeMessages is exactly the set of
// the probe playbook's static fail_msg values (both directions, so a new gate
// without an entry fails here instead of being withheld in production, and a
// stale entry fails instead of lingering). A fail_msg with a template could
// carry a vault value, so each must be a literal.
func TestProbeMessagesMatchThePlaybook(t *testing.T) {
	var found []string
	var walk func(n *yaml.Node)
	walk = func(n *yaml.Node) {
		if n.Kind == yaml.MappingNode {
			for i := 0; i+1 < len(n.Content); i += 2 {
				if n.Content[i].Value == "fail_msg" {
					found = append(found, strings.Join(strings.Fields(n.Content[i+1].Value), " "))
				}
			}
		}
		for _, c := range n.Content {
			walk(c)
		}
	}
	for _, f := range probePlaybookFiles {
		doc := loadProbeYAML(t, f)
		walk(&doc)
	}
	if len(found) == 0 {
		t.Fatal("found no fail_msg in the probe playbook; the walker needs updating")
	}
	want := map[string]bool{}
	for _, k := range knownProbeMessages {
		want[k.text] = true
	}
	got := map[string]bool{}
	for _, m := range found {
		if strings.Contains(m, "{{") || strings.Contains(m, "{%") {
			t.Errorf("fail_msg %q is templated; it could carry a vault value", m)
		}
		got[m] = true
		if !want[m] {
			t.Errorf("playbook fail_msg is not in knownProbeMessages: %q", m)
		}
	}
	for m := range want {
		if !got[m] {
			t.Errorf("knownProbeMessages has a message the playbook does not: %q", m)
		}
	}
	for _, k := range knownProbeMessages {
		if !strings.Contains(k.text, k.marker) {
			t.Errorf("marker %q is not part of its own text", k.marker)
		}
	}
}

// TestProbeTaskNamesCoverThePlaybook: every task name in the probe (and the
// task files it includes) is in probeTaskNames and none has a template, so a
// banner naming one is static. An unlisted name is dropped from the summary,
// which is safe but loses the location.
func TestProbeTaskNamesCoverThePlaybook(t *testing.T) {
	var names []string
	var tasks func(n *yaml.Node)
	tasks = func(seq *yaml.Node) {
		for _, task := range seq.Content {
			if task.Kind != yaml.MappingNode {
				continue
			}
			for i := 0; i+1 < len(task.Content); i += 2 {
				switch task.Content[i].Value {
				case "name":
					names = append(names, task.Content[i+1].Value)
				case "block", "rescue", "always":
					tasks(task.Content[i+1])
				}
			}
		}
	}
	for _, f := range probePlaybookFiles {
		doc := loadProbeYAML(t, f)
		root := doc.Content[0]
		if root.Kind == yaml.SequenceNode {
			for _, play := range root.Content {
				for i := 0; i+1 < len(play.Content); i += 2 {
					switch play.Content[i].Value {
					case "name":
						names = append(names, play.Content[i+1].Value)
					case "pre_tasks", "tasks", "post_tasks":
						tasks(play.Content[i+1])
					}
				}
			}
		}
		if f != probePlaybookFiles[0] {
			tasks(root)
		}
	}
	if len(names) < 30 {
		t.Fatalf("collected only %d task names; the walker needs updating", len(names))
	}
	listed := map[string]bool{}
	for _, n := range names {
		listed[n] = true
		if strings.Contains(n, "{{") || strings.Contains(n, "{%") {
			t.Errorf("task name %q is templated; it could carry a vault value", n)
		}
		if !probeTaskNames[n] {
			t.Errorf("task name %q is missing from probeTaskNames", n)
		}
	}
	for n := range probeTaskNames {
		if !listed[n] {
			t.Errorf("probeTaskNames has a name the playbook no longer has: %q", n)
		}
	}
}
