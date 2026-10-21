package spec

import (
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
	actions := regexp.MustCompile(`(?s)action\(([^)]*)\)`)
	omfwd := regexp.MustCompile(`\btype\s*=\s*"omfwd"`)
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
		for _, action := range actions.FindAllStringSubmatch(text, -1) {
			body := action[1]
			if !omfwd.MatchString(body) {
				continue
			}
			for _, param := range []string{`queue.type="LinkedList"`, `queue.saveOnShutdown="on"`, `action.resumeRetryCount="-1"`} {
				parts := strings.SplitN(param, "=", 2)
				pattern := regexp.MustCompile(regexp.QuoteMeta(parts[0]) + `\s*=\s*` + regexp.QuoteMeta(parts[1]))
				if !pattern.MatchString(body) {
					t.Errorf("%s: forwarding action missing %s", file, param)
				}
			}
			for _, param := range []string{"queue.filename", "queue.maxDiskSpace", "action.resumeInterval", "action.resumeIntervalMax"} {
				m := regexp.MustCompile(regexp.QuoteMeta(param) + `\s*=\s*"([^"]+)"`).FindStringSubmatch(body)
				if len(m) != 2 || m[1] == "0" {
					t.Errorf("%s: forwarding action needs a nonzero %s", file, param)
					continue
				}
				if param == "queue.filename" {
					if seen[m[1]] {
						t.Errorf("%s: actions share queue filename %s", file, m[1])
					}
					seen[m[1]] = true
				}
			}
		}
	}
}
