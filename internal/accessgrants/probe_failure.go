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
// So only these are ever extracted, never a pass-through:
//   - the "msg" of a `fatal: [host]: FAILED!/UNREACHABLE! => {...}` payload (the
//     gate's fixed message, a module's own message), with the failing task's
//     name; a no_log result is reported as hidden;
//   - without a fatal payload, the first line of each `[ERROR]:` block, except
//     that a parse error is replaced by fixed text plus the Origin location,
//     because a parser message can quote the file;
//   - [WARNING] lines, numbered source snippets, caret lines and Origin blocks
//     are never taken.
//
// The result then goes through redactSecretish as a last defence.
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
	// could not parse.
	parseErrorRE = regexp.MustCompile(`(?i)yaml|syntax error|pars(?:e|ing)|could not (?:be )?load`)
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

// summarizeAnsibleFailure returns a short, secret-free description of why an
// ansible-playbook run failed, or "" when its output holds nothing recognisable.
// varsFile is the vault vars file passed with -e @file, if any: it only
// selects the hint when ansible could not parse an input file.
func summarizeAnsibleFailure(stdout, stderr, varsFile string) string {
	lines := strings.Split(strings.ReplaceAll(stdout+"\n"+stderr, "\r\n", "\n"), "\n")

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

// describeFatal renders one `fatal:` payload: the module's own msg plus the
// task it came from. A payload with no msg, or a no_log-censored one, is
// reported as hidden rather than dumped.
func describeFatal(host, kind, task, payload string) string {
	var p struct {
		Msg      any    `json:"msg"`
		Censored string `json:"censored"`
	}
	if err := json.Unmarshal([]byte(payload), &p); err != nil {
		p.Msg = nil
	}
	where := ""
	if task != "" {
		where = fmt.Sprintf(" (task: %s)", task)
	}
	msg, _ := p.Msg.(string)
	switch {
	case p.Censored != "":
		return fmt.Sprintf("task %q failed on %s; its output is hidden by no_log", task, host)
	case msg == "":
		return fmt.Sprintf("task %q %s on %s; ansible gave no message", task, strings.ToLower(kind), host)
	case kind == "UNREACHABLE":
		return fmt.Sprintf("%s is unreachable: %s%s", host, msg, where)
	}
	return msg + where
}
