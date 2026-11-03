package cmd

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Exercise the actual shell bodies with the complete production AWK payload.
// A small kernel pipe makes omitted consumption discriminating on hosts whose
// default pipe could otherwise buffer the whole input before the child exits.
// Fault executables below only supply exit statuses, not native success output.
func TestAuditLogForwardingStdinDrainPreservesEarlyExit(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRootForTest(t), "playbooks/apply/audit-log-forwarding-apply.yml"))
	if err != nil {
		t.Fatal(err)
	}
	tasks, err := step5SourceTasks(raw, true)
	if err != nil {
		t.Fatal(err)
	}
	preflight := tasks[0].(map[string]any)["ansible.builtin.shell"].(map[string]any)["cmd"].(string)
	var compute string
	step5Walk(tasks, func(task map[string]any) {
		if task["register"] == "distro_rsyslog_without_audit_path" {
			compute = task["ansible.builtin.shell"].(map[string]any)["cmd"].(string)
		}
	})
	if compute == "" {
		t.Fatal("production computed-policy shell missing")
	}
	payload, err := os.ReadFile(dropPathScript(t))
	if err != nil || len(payload) <= 4096 {
		t.Fatalf("need the full production helper larger than the pipe: %d bytes, %v", len(payload), err)
	}
	quote := func(v string) string { return "'" + strings.ReplaceAll(v, "'", "'\"'\"'") + "'" }
	cases := []struct {
		name, kind, fault string
		status            int
		counterexample    bool
	}{
		{"missing-policy", "preflight", "missing", 0, true},
		{"dangling-policy", "preflight", "dangling", 0, true},
		{"mktemp-failure", "preflight", "mktemp", 1, true},
		{"awk-early-failure", "preflight", "awk23", 23, true},
		{"real-helper-refusal", "preflight", "glob", 3, false},
		{"native-command-status", "preflight", "logrotate23", 23, false},
		{"compute-redirection-failure", "compute", "redirect", 1, true},
		{"compute-awk-early-failure", "compute", "awk37", 37, true},
	}
	for _, tc := range cases {
		variants := []bool{false}
		if tc.counterexample {
			variants = append(variants, true)
		}
		for _, omit := range variants {
			name := tc.name + "/production-drain"
			if omit {
				name = tc.name + "/omitted-drain-counterexample"
			}
			t.Run(name, func(t *testing.T) {
				dir := t.TempDir()
				tmp := filepath.Join(dir, "temporary")
				bin := filepath.Join(dir, "bin")
				for _, path := range []string{tmp, bin} {
					if err := os.Mkdir(path, 0700); err != nil {
						t.Fatal(err)
					}
				}
				policy := filepath.Join(dir, "rsyslog")
				switch tc.fault {
				case "missing":
				case "dangling":
					if err := os.Symlink(filepath.Join(dir, "absent"), policy); err != nil {
						t.Fatal(err)
					}
				default:
					content := "/var/log/syslog\n/var/log/mail.log\n{\n rotate 4\n}\n"
					if tc.fault == "glob" {
						content = "/var/log/syslog /var/log/sys* {\n rotate 4\n}\n"
					}
					writeFile(t, policy, content)
				}
				tool, result := "", ""
				switch tc.fault {
				case "mktemp":
					tool, result = "mktemp", "37"
				case "awk23", "awk37":
					tool, result = "awk", strings.TrimPrefix(tc.fault, "awk")
				case "logrotate23":
					tool, result = "logrotate", "23"
				}
				if tool != "" {
					path := filepath.Join(bin, tool)
					writeFile(t, path, "#!/bin/sh\nexit "+result+"\n")
					if err := os.Chmod(path, 0700); err != nil {
						t.Fatal(err)
					}
				}
				body := preflight
				if tc.kind == "compute" {
					body = compute
					output := filepath.Join(dir, "computed")
					if tc.fault != "redirect" {
						if err := os.Mkdir(output, 0700); err != nil {
							t.Fatal(err)
						}
					}
					body = strings.ReplaceAll(body, "{{ (distro_rsyslog_tmp.path ~ '/policy') | quote }}", quote(filepath.Join(output, "policy")))
				}
				body = strings.ReplaceAll(body, "{{ audit_syslog_path | quote }}", quote("/var/log/syslog"))
				body = strings.ReplaceAll(body, "/etc/logrotate.d/rsyslog", quote(policy))
				if omit {
					body = strings.ReplaceAll(body, "trap 'cat >/dev/null' EXIT", ":")
					body = strings.ReplaceAll(body, `trap 'cat >/dev/null; rm -rf "$d"' EXIT`, `trap 'rm -rf "$d"' EXIT`)
				}
				if strings.Contains(body, "{{") {
					t.Fatal("unrendered production shell argument")
				}
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, "/bin/bash", "-c", body)
				cmd.Env = append(os.Environ(), "TMPDIR="+tmp, "PILOT_CHECK_MODE=False", "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"))
				var stdout, stderr bytes.Buffer
				cmd.Stdout, cmd.Stderr = &stdout, &stderr
				stdin, err := cmd.StdinPipe()
				if err != nil {
					t.Fatal(err)
				}
				fd := stdin.(*os.File).Fd()
				size, _, errno := syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_SETPIPE_SZ, 4096)
				if errno != 0 || size != 4096 {
					t.Fatalf("cannot set discriminating pipe size: %d %v", size, errno)
				}
				if err := cmd.Start(); err != nil {
					t.Fatal(err)
				}
				written, writeErr := io.Copy(stdin, bytes.NewReader(payload))
				_ = stdin.Close()
				runErr := cmd.Wait()
				if ctx.Err() != nil {
					t.Fatalf("stdin consumption timed out: %s", stderr.String())
				}
				status := 0
				if runErr != nil {
					var exit *exec.ExitError
					if !errors.As(runErr, &exit) {
						t.Fatal(runErr)
					}
					status = exit.ExitCode()
				}
				if status != tc.status {
					t.Fatalf("EXIT drain replaced original status: got%d want%d: %s", status, tc.status, stderr.String())
				}
				if omit {
					if !errors.Is(writeErr, syscall.EPIPE) || written >= int64(len(payload)) {
						t.Fatalf("counterexample did not reproduce unread input: wrote%d/%d, %v", written, len(payload), writeErr)
					}
				} else if writeErr != nil || written != int64(len(payload)) {
					t.Fatalf("production did not drain complete actual input: wrote%d/%d, %v", written, len(payload), writeErr)
				}
				entries, err := os.ReadDir(tmp)
				if err != nil || len(entries) != 0 {
					t.Fatalf("preflight failed to clean its private temporary directory: %v %v", entries, err)
				}
				t.Logf("actual helper bytes=%d pipe=%d status=%d written=%d omitted-drain=%t", len(payload), size, status, written, omit)
			})
		}
	}
}
