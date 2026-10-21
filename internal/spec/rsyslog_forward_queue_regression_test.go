package spec

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Captured from /proc/<rsyslog-pid>/task/*/comm on the Ubuntu 24.04 VM
// (8.2312); the AlmaLinux 9 VM (8.2510) used the same two queue worker names.
func TestRegression_AuditQueueProbeMatchesCapturedWorkers(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not installed")
	}
	const code = `import pathlib,runpy
p=runpy.run_path('../../playbooks/files/pilot-siem-queue-check')
captured=set(pathlib.Path('testdata/rsyslog-queue-workers.txt').read_text().splitlines())
for name in ['siem_audit','siem_auth']:
    assert p['worker_name'](name) in captured, name
assert p['worker_name']('nonexistent') not in captured
`
	if out, err := exec.Command("python3", "-c", code).CombinedOutput(); err != nil {
		t.Fatalf("queue worker names: %v\n%s", err, out)
	}
}

// Forwarding actions must not silently drop whole suspension windows. Scan
// every production apply playbook, so new senders cannot copy the old @@ rule.
func TestRegression_SyslogForwardersHaveRetryQueues(t *testing.T) {
	var files []string
	for _, root := range []string{"../../playbooks/apply", "../../playbooks/templates"} {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() && (strings.HasSuffix(path, ".yml") || strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".j2")) {
				files = append(files, path)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	legacy := regexp.MustCompile(`(?m)^\s*[^#\s][^\n]*\s+@@[^\s]+`)
	omfwd := regexp.MustCompile(`\btype\s*=\s*"[^"\n]*\bom(?:fwd|relp)\b[^"\n]*"`)
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		text := string(data)
		if legacy.MatchString(text) {
			t.Errorf("%s: legacy @@ forwarding uses a direct queue; use a bounded disk-assisted action with unlimited retries", file)
		}
		seen := map[string]bool{}
		bodies, err := rsyslogActionBodies(text)
		if err != nil {
			t.Errorf("%s: %v", file, err)
			continue
		}
		for _, body := range bodies {
			if !omfwd.MatchString(body) {
				continue
			}
			for _, problem := range rsyslogRetryQueueProblems(body, seen) {
				t.Errorf("%s: %s", file, problem)
			}
		}
	}
}

// Template expressions and quoted values can contain parentheses. Keep their
// original text for the invariant checks, but skip them when finding the end.
func rsyslogActionBodies(text string) ([]string, error) {
	start := regexp.MustCompile(`\baction\(`)
	var bodies []string
	for offset := 0; offset < len(text); {
		match := start.FindStringIndex(text[offset:])
		if match == nil {
			break
		}
		begin := offset + match[1]
		depth, quote, end := 1, byte(0), -1
		for i := begin; i < len(text); i++ {
			if strings.HasPrefix(text[i:], "{{") || strings.HasPrefix(text[i:], "{%") {
				close := "}}"
				if text[i+1] == '%' {
					close = "%}"
				}
				n := strings.Index(text[i+2:], close)
				if n < 0 {
					return nil, fmt.Errorf("unterminated Jinja expression inside action")
				}
				i += n + 3
				continue
			}
			c := text[i]
			if quote != 0 {
				switch c {
				case '\\':
					i++
				case quote:
					quote = 0
				}
				continue
			}
			if c == '\'' || c == '"' {
				quote = c
			} else if c == '(' {
				depth++
			} else if c == ')' {
				depth--
				if depth == 0 {
					end = i
					break
				}
			}
		}
		if end < 0 {
			return nil, fmt.Errorf("unterminated rsyslog action")
		}
		bodies = append(bodies, text[begin:end])
		offset = end + 1
	}
	return bodies, nil
}

func rsyslogRetryQueueProblems(body string, seen map[string]bool) []string {
	var problems []string
	for _, param := range []string{`queue.type="LinkedList"`, `queue.saveOnShutdown="on"`, `action.resumeRetryCount="-1"`} {
		parts := strings.SplitN(param, "=", 2)
		pattern := regexp.MustCompile(regexp.QuoteMeta(parts[0]) + `\s*=\s*` + regexp.QuoteMeta(parts[1]))
		if !pattern.MatchString(body) {
			problems = append(problems, "forwarding action missing "+param)
		}
	}
	for _, param := range []string{"queue.filename", "queue.maxDiskSpace", "action.resumeInterval", "action.resumeIntervalMax"} {
		m := regexp.MustCompile(regexp.QuoteMeta(param) + `\s*=\s*"([^"]+)"`).FindStringSubmatch(body)
		if len(m) != 2 || m[1] == "0" {
			problems = append(problems, "forwarding action needs a nonzero "+param)
			continue
		}
		if param == "queue.filename" {
			if seen[m[1]] {
				problems = append(problems, "actions share queue filename "+m[1])
			}
			seen[m[1]] = true
		}
	}
	return problems
}

func TestRsyslogRetryQueueScannerHandlesTemplates(t *testing.T) {
	const valid = `type="{{ 'omrelp' if relp else 'omfwd' }}" target="{{ host | default('receiver(backup)') }}"
{% if engine | default('auto') == 'disk' %} queue.diskQueueType="disk" {% endif %}
queue.type="LinkedList" queue.saveOnShutdown="on" action.resumeRetryCount="-1"
queue.filename="audit" queue.maxDiskSpace="256m" action.resumeInterval="1" action.resumeIntervalMax="10"`
	for _, tc := range []struct {
		name, source string
		badSyntax    bool
		problems     int
	}{
		{"template parentheses", "action(" + valid + ")", false, 0},
		{"quoted parentheses", "action(" + strings.ReplaceAll(valid, "receiver(backup)", "receiver)backup(") + ")", false, 0},
		{"missing required queue still fails", "action(" + strings.ReplaceAll(valid, `queue.type="LinkedList"`, "") + ")", false, 1},
		{"zero disk budget still fails", "action(" + strings.ReplaceAll(valid, `queue.maxDiskSpace="256m"`, `queue.maxDiskSpace="0"`) + ")", false, 1},
		{"duplicate spool still fails", "action(" + valid + ")\naction(" + valid + ")", false, 1},
		{"unterminated action", "action(" + valid, true, 0},
		{"unterminated template", `action(type="omfwd" {% if broken)`, true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bodies, err := rsyslogActionBodies(tc.source)
			if (err != nil) != tc.badSyntax {
				t.Fatalf("syntax error=%v want %v", err, tc.badSyntax)
			}
			if err != nil {
				return
			}
			seen := map[string]bool{}
			problems := 0
			for _, body := range bodies {
				problems += len(rsyslogRetryQueueProblems(body, seen))
			}
			if len(bodies) == 0 || problems != tc.problems {
				t.Fatalf("actions=%d problems=%d want %d", len(bodies), problems, tc.problems)
			}
		})
	}
}
