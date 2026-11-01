// probe_failure.go turns a failed drift-probe ansible-playbook run into a short,
// safe diagnostic (issue #179).
//
// The probe is handed the operator's vault vars file (`-e @.vault/main.yaml`),
// so ansible's raw output can echo secret material: for a vars file that is not
// valid YAML, ansible prints the offending source line (a numbered snippet
// under "[ERROR]: YAML parsing failed", plus Origin and caret lines), and the
// vars file's content is also parsed while ansible loads the inventory. Before
// this change the probe error embedded stderr, or the whole stdout transcript,
// verbatim. It also buried the one line an operator needs: the gate message
// "No usable FreeIPA admin password" is on stdout, while stderr only carries
// ansible's `[WARNING]: Invalid characters were found in group names` noise
// (pilot inventories use hyphenated groups such as freeipa-server).
//
// Go never reads the vault file, so it cannot know which strings in ansible's
// output are secret, and ansible will expand any vault key into any message:
// a vars file with `ansible_connection: "{{ ipa_admin_password }}"` makes
// ansible fail with "the connection plugin '<the password>' was not found", and
// the same happens with ansible_python_interpreter, ssh arguments, and so on. A
// password-key regex cannot mask a value that sits inside prose. So ansible's
// own message text is NEVER copied. Only text that is OURS is ever returned:
//
//   - the probe playbook's own fixed gate messages (knownProbeMessages),
//     recognised in ansible's output and replaced by our own copy of the text;
//   - a small fixed vocabulary of failure classes (failureClasses: connection
//     refused, no vault secrets, a missing connection plugin, ...), each
//     recognised by a stable ansible phrase and replaced by our wording, never
//     by the original text;
//   - for a parse error, fixed text plus the `Origin:` file:line:column;
//   - anything else becomes a fixed "details withheld" sentence.
//
// The failing task's name is printed only when it is one of the probe's own
// task names (probeTaskNames); [WARNING] lines, numbered source snippets,
// caret lines and Origin blocks are never taken. The result still goes through
// redactSecretish as a last defence, and Health.ProbeError caps it.
package accessgrants

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

const (
	maxFailureEntries   = 3
	maxFailureEntryLen  = 500
	maxFatalPayloadRows = 200
)

var (
	// ansible's default callback task banner.
	taskBannerRE = regexp.MustCompile(`^TASK \[(.*)\] \*+\s*$`)
	// `fatal: [host]: FAILED! => {...}`; the payload may continue on later
	// lines when the callback pretty-prints it.
	fatalLineRE = regexp.MustCompile(`^fatal: \[([^\]]*)\]: (FAILED|UNREACHABLE)! => (.*)$`)
	errorLineRE = regexp.MustCompile(`^\[ERROR\]: (.*)$`)
	// recapRE is a PLAY RECAP row; a host with no failed or unreachable tasks
	// recovered from every `fatal:` line (rescue, ignore_errors).
	recapRE  = regexp.MustCompile(`^(\S+)\s*: ok=\d+\s.*\bunreachable=(\d+)\s+failed=(\d+)`)
	originRE = regexp.MustCompile(`^Origin: (/\S+)\s*$`)
	// parseErrorRE marks an [ERROR] whose ansible text may quote the file it
	// could not parse. It matches only ansible-core's real parse-error
	// phrases ("YAML parsing failed: ...", "JSON parsing failed", "Syntax
	// Error while loading YAML", "Invalid extra vars data supplied. '...'
	// could not be made into a dictionary", "unable to read either as JSON
	// nor YAML"), never a bare "yaml": the gate's own message names
	// `.vault/main.yaml`.
	parseErrorRE = regexp.MustCompile(`(?i)\b(?:yaml|json) parsing failed|syntax error while loading yaml|could not be made into a dictionary|unable to read either as json nor yaml`)
	// ansiRE matches a terminal escape sequence (colour codes).
	ansiRE = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]`)
	// secretLineRE finds a password-shaped `key: value` / `key=value` pair
	// (JSON keys too) so its value can be blanked.
	secretLineRE = regexp.MustCompile(`(?i)(pass(?:word|wd|phrase)?\w*["']?\s*[:=]\s*)("[^"]*"|'[^']*'|\S+)`)
)

// redactSecretish blanks the value of any password-shaped key: value pair. It
// is a last line of defence behind the extraction, which already never copies
// a source line.
func redactSecretish(s string) string {
	return secretLineRE.ReplaceAllString(s, "${1}[redacted]")
}

// knownProbeMessages are the probe playbook's own static `fail_msg` texts, in
// the form ansible prints them (whitespace collapsed). Each marker identifies
// one in ansible's output; the text returned is OUR copy, so nothing of
// ansible's line (which could carry a prefix or suffix) is reused.
// TestProbeMessagesMatchThePlaybook keeps this list equal to the playbook's
// fail_msg values.
var knownProbeMessages = []struct{ marker, text string }{
	{
		"No usable FreeIPA admin password",
		"No usable FreeIPA admin password for the drift probe. Set ipa_admin_password (at least 8 characters) in the vault vars file (default <inventory dir>/.vault/main.yaml, or --vars-file), or freeipa.admin.password (at least 8 characters, not a template) in the roster. Both are missing or too short.",
	},
	{
		"freeipa_roster_file and pilot_drift_output are required",
		"freeipa_roster_file and pilot_drift_output are required.",
	},
	{
		"Canonical roster (schema_version) is required",
		"Canonical roster (schema_version) is required for an authoritative drift probe.",
	},
	// The users/groups observer's error classes (freeipa-identity-object-
	// observer.py ERROR_CLASSES), one gate each in freeipa-identity-object-
	// observe.yml. TestObserverErrorClassesHaveAGateAndAMessage keeps the three
	// lists equal.
	{
		"The users/groups observer rejected its input",
		"The users/groups observer rejected its input (internal error: the desired state handed to it was malformed or carried a credential field). No complete users/groups plan is available.",
	},
	{
		"The FreeIPA Python client (ipalib and ipapython) could not be imported",
		"The FreeIPA Python client (ipalib and ipapython) could not be imported on the probed host; install the FreeIPA client packages there. No complete users/groups plan is available.",
	},
	{
		"ssh_keys value is not a valid SSH public key",
		"A roster user's ssh_keys value is not a valid SSH public key (FreeIPA would reject it on apply); fix the roster. No complete users/groups plan is available.",
	},
	{
		"The users/groups observer had no usable Kerberos credentials",
		"The users/groups observer had no usable Kerberos credentials for FreeIPA (the admin ticket was missing, expired or rejected). No complete users/groups plan is available.",
	},
	{
		"The users/groups observer could not complete a FreeIPA API call",
		"The users/groups observer could not complete a FreeIPA API call (connection or request failed; the detail is withheld). No complete users/groups plan is available.",
	},
	{
		"FreeIPA returned a truncated or inconsistent user or group search result",
		"FreeIPA returned a truncated or inconsistent user or group search result. No complete users/groups plan is available.",
	},
	{
		"FreeIPA did not report the account lock state",
		"FreeIPA did not report the account lock state (nsaccountlock) of a user, so enabled and disabled drift cannot be evaluated. No complete users/groups plan is available.",
	},
	{
		"FreeIPA returned a user or group record in an unexpected shape",
		"FreeIPA returned a user or group record in an unexpected shape (the detail is withheld). No complete users/groups plan is available.",
	},
	{
		"failed for a reason outside its fixed error classes",
		"The users/groups observer failed for a reason outside its fixed error classes (the detail is withheld). No complete users/groups plan is available.",
	},
}

// failureClasses is the fixed vocabulary for every other failure: a stable
// ansible phrase (case-insensitive regexp) mapped to OUR text. The first match
// wins; the matched ansible text is never returned.
var failureClasses = []struct {
	re   *regexp.Regexp
	text string
}{
	{regexp.MustCompile(`(?i)connection refused`), "Connection refused"},
	{regexp.MustCompile(`(?i)connection timed out|operation timed out`), "Connection timed out"},
	{regexp.MustCompile(`(?i)no route to host`), "No route to host"},
	{regexp.MustCompile(`(?i)could not resolve hostname`), "Could not resolve hostname (check ansible_host)"},
	{regexp.MustCompile(`(?i)host key verification failed`), "Host key verification failed"},
	{regexp.MustCompile(`(?i)permission denied`), "Permission denied (check ansible_user and the SSH key)"},
	{regexp.MustCompile(`(?i)connection plugin .* was not found`), "ansible_connection names a connection plugin ansible does not have (check ansible_connection in the inventory and the vault vars file; the value is withheld)"},
	{regexp.MustCompile(`(?i)module interpreter .* was not found`), "ansible_python_interpreter points at an interpreter that does not exist (the value is withheld)"},
	{regexp.MustCompile(`(?i)attempting to decrypt but no vault secrets found`), "Attempting to decrypt but no vault secrets found (an input file is ansible-vault encrypted: pass --vault-password-file)"},
	{regexp.MustCompile(`(?i)decryption failed`), "Decryption failed (the --vault-password-file does not decrypt an input file)"},
	{regexp.MustCompile(`(?i)non-zero return code`), "a command returned a non-zero return code"},
	{regexp.MustCompile(`(?i)is undefined`), "a template used an undefined variable (the name is withheld)"},
	{regexp.MustCompile(`(?i)error rendering template|finalization of task args`), "a template could not be rendered (the detail is withheld)"},
}

// withheldText is the fallback for an ansible message that matches nothing
// above.
const withheldText = "details withheld: ansible messages can echo values expanded from the vault vars file"

// probeTaskNames are the names of the tasks in the probe playbook and the
// task files it includes. A task name from ansible's banner is printed only
// when it is in this set. TestProbeTaskNamesCoverThePlaybook keeps it complete.
var probeTaskNames = map[string]bool{
	"Read the complete users/groups object model for identity drift":               true,
	"Normalize canonical users and groups (shared with apply)":                     true,
	"Reset canonical users and groups":                                             true,
	"Normalize canonical users for the compatibility reconciler":                   true,
	"Normalize canonical groups for the compatibility reconciler":                  true,
	"Project the desired users and groups for the observer":                        true,
	"Observe complete FreeIPA users and groups without credentials in output":      true,
	"Classify the users/groups observation result":                                 true,
	"Gate: the users/groups observer got well-formed input":                        true,
	"Gate: the FreeIPA Python client is installed on the probed host":              true,
	"Gate: every roster ssh_keys value is a valid SSH public key":                  true,
	"Gate: the observer had usable Kerberos credentials":                           true,
	"Gate: the observer completed its FreeIPA API calls":                           true,
	"Gate: the FreeIPA user and group searches were complete":                      true,
	"Gate: FreeIPA reported every account lock state":                              true,
	"Gate: FreeIPA user and group records had the expected shape":                  true,
	"Gate: the users/groups observation succeeded":                                 true,
	"Decode the credential-free identity observation":                              true,
	"Probe live FreeIPA access-governance state for drift inspection":              true,
	"Gate: drift probe input is complete":                                          true,
	"Load canonical roster under a namespace":                                      true,
	"Gate: canonical roster is available":                                          true,
	"Resolve the FreeIPA admin password from the vault variable":                   true,
	"Read the vault admin password":                                                true,
	"Treat an unresolvable vault admin password as missing":                        true,
	"Fall back to the roster admin password when the vault has none":               true,
	"Read the roster admin password":                                               true,
	"Treat an unresolvable roster admin password as missing":                       true,
	"Check the resolved FreeIPA admin password length":                             true,
	"Gate: a FreeIPA admin password is available (vault or roster)":                true,
	"Normalize FreeIPA probe settings":                                             true,
	"Read-only FreeIPA queries with a private Kerberos cache for the admin ticket": true,
	"Private Kerberos cache for the tickets below (issue #69)":                     true,
	"Kinit admin for read-only drift probe":                                        true,
	"List live HBAC rule names":                                                    true,
	"List live sudo rule names":                                                    true,
	"Check existence of each desired compiled HBAC rule":                           true,
	"Check existence of each desired compiled sudo rule":                           true,
	"Read live account principal expiration per user":                              true,
	"Read live authentication indicators per host":                                 true,
	"Read live group password policies (v3.2 §7/§12)":                              true,
	"Initialize drift-probe accumulators":                                          true,
	"Accumulate compiled HBAC rule existence":                                      true,
	"Accumulate compiled sudo rule existence":                                      true,
	"Accumulate live account principal expiration per user":                        true,
	"Accumulate live authentication indicators per host":                           true,
	"Accumulate live authentication types per user (v3.2 §8)":                      true,
	"Accumulate live group password policy state (v3.2 §7/§12)":                    true,
	"Normalize live group password policy fields to int-or-null":                   true,
	"Build machine-readable drift-probe result":                                    true,
	"Write drift-probe result on the Ansible controller":                           true,
	"Destroy the private Kerberos cache":                                           true,
	"Private Kerberos cache — create the cache file":                               true,
	"Private Kerberos cache — point KRB5CCNAME at it":                              true,
	"Private Kerberos cache — find caches a killed run left behind":                true,
	"Private Kerberos cache — remove them":                                         true,
	"Private Kerberos cache — destroy the tickets in it":                           true,
	"Private Kerberos cache — remove the cache file":                               true,
	"Private Kerberos cache — forget it":                                           true,
}

// knownProbeMessage returns our copy of the probe's own gate message when
// msg is one, else "".
func knownProbeMessage(msg string) string {
	for _, k := range knownProbeMessages {
		if strings.Contains(msg, k.marker) {
			return k.text
		}
	}
	return ""
}

// classifyMessage maps one ansible message to text that is ours: a gate
// message, a vocabulary class, or the withheld sentence. It never returns any
// of msg.
func classifyMessage(msg string) string {
	if t := knownProbeMessage(msg); t != "" {
		return t
	}
	for _, c := range failureClasses {
		if c.re.MatchString(msg) {
			return c.text
		}
	}
	return withheldText
}

// summarizeAnsibleFailure returns a short, secret-free description of why an
// ansible-playbook run failed, or "" when its output holds nothing recognisable.
// varsFile is the vault vars file passed with -e @file, if any: it only
// selects the hint when ansible could not parse an input file.
func summarizeAnsibleFailure(stdout, stderr, varsFile string) string {
	// ANSI colour codes (ANSIBLE_FORCE_COLOR) would break every anchored match.
	all := ansiRE.ReplaceAllString(stdout+"\n"+stderr, "")
	lines := strings.Split(strings.ReplaceAll(all, "\r\n", "\n"), "\n")

	// finalFatal is each host's latest `fatal:` entry, in first-seen order. A
	// rescued failure is also printed as `fatal:` (ansible 2.19 shows it, then
	// runs the rescue), so only a host's last one can be the failure that
	// ended its run, and only when the recap says the host failed.
	var fatalOrder []string
	finalFatal := map[string]string{}
	failedHosts := map[string]bool{}
	sawRecap := false
	var errs []string
	seen := map[string]bool{}
	clean := func(entry string) string {
		entry = strings.Join(strings.Fields(entry), " ")
		if r := []rune(entry); len(r) > maxFailureEntryLen {
			entry = string(r[:maxFailureEntryLen]) + "..."
		}
		return entry
	}
	add := func(dst *[]string, entry string) {
		if entry = clean(entry); entry != "" && !seen[entry] {
			seen[entry] = true
			*dst = append(*dst, entry)
		}
	}

	task := ""
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		if m := taskBannerRE.FindStringSubmatch(line); m != nil {
			task = m[1]
			continue
		}
		if m := fatalLineRE.FindStringSubmatch(line); m != nil {
			payload := m[3]
			// The default callback prints one line or a pretty-printed
			// block; keep reading until the JSON is complete.
			for j := i + 1; !json.Valid([]byte(payload)) && j < len(lines) && j < i+maxFatalPayloadRows; j++ {
				payload += "\n" + lines[j]
			}
			if _, ok := finalFatal[m[1]]; !ok {
				fatalOrder = append(fatalOrder, m[1])
			}
			finalFatal[m[1]] = describeFatal(m[1], m[2], task, payload)
			continue
		}
		if m := recapRE.FindStringSubmatch(line); m != nil {
			sawRecap = true
			failedHosts[m[1]] = m[2] != "0" || m[3] != "0"
			continue
		}
		if m := errorLineRE.FindStringSubmatch(line); m != nil {
			msg := strings.TrimSpace(m[1])
			if parseErrorRE.MatchString(msg) {
				origin := ""
				for j := i + 1; j < len(lines) && j <= i+2; j++ {
					if om := originRE.FindStringSubmatch(lines[j]); om != nil {
						origin = om[1]
						break
					}
				}
				msg = parseErrorText(origin, varsFile)
			} else {
				msg = classifyMessage(msg)
			}
			add(&errs, msg)
		}
	}

	var fatals []string
	for _, host := range fatalOrder {
		if sawRecap && !failedHosts[host] {
			continue
		}
		add(&fatals, finalFatal[host])
	}
	picked := fatals
	if len(picked) == 0 {
		picked = errs
	}
	if len(picked) > maxFailureEntries {
		picked = picked[:maxFailureEntries]
	}
	return redactSecretish(strings.Join(picked, "; "))
}

// parseErrorText is the fixed replacement for an ansible parse error. origin
// is the `Origin:` location ansible printed (a path with line and column),
// never any of the content.
func parseErrorText(origin, varsFile string) string {
	switch {
	case origin != "":
		return fmt.Sprintf("ansible could not parse %s (check that it is valid YAML); the parser detail is withheld because it can quote the file", origin)
	case varsFile != "":
		return fmt.Sprintf("ansible could not parse an input file (check that %s is valid YAML); the parser detail is withheld because it can quote the file", varsFile)
	}
	return "ansible could not parse an input file (check that it is valid YAML); the parser detail is withheld because it can quote the file"
}

// describeFatal renders one `fatal:` payload as our own text: the gate
// message or failure class its msg maps to (never the msg itself), plus the
// failing task when it is one of the probe's own. A payload with no msg, or a
// no_log-censored one, is reported as hidden rather than dumped.
func describeFatal(host, kind, task, payload string) string {
	var p struct {
		Msg      any    `json:"msg"`
		Censored string `json:"censored"`
	}
	if err := json.Unmarshal([]byte(payload), &p); err != nil {
		p.Msg = nil
	}
	if !probeTaskNames[task] {
		task = ""
	}
	where := ""
	if task != "" {
		where = fmt.Sprintf(" (task: %s)", task)
	}
	msg, _ := p.Msg.(string)
	switch {
	case p.Censored != "":
		if task == "" {
			return fmt.Sprintf("a task failed on %s; its output is hidden by no_log", host)
		}
		return fmt.Sprintf("task %q failed on %s; its output is hidden by no_log", task, host)
	case msg == "":
		if task == "" {
			return fmt.Sprintf("a task %s on %s; ansible gave no message", strings.ToLower(kind), host)
		}
		return fmt.Sprintf("task %q %s on %s; ansible gave no message", task, strings.ToLower(kind), host)
	case kind == "UNREACHABLE":
		return fmt.Sprintf("%s is unreachable: %s%s", host, classifyMessage(msg), where)
	}
	return classifyMessage(msg) + where
}
