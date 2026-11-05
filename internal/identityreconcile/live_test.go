package identityreconcile

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/freeiparpc"
	"github.com/kjelly/pilot/internal/sshdial"
)

// TestLiveGoPreviewDriver is the Phase 1 part of the Go reconcile test
// driver (spec §10.3). It runs only when PILOT_IDENTITY_ENGINE_LIVE_VM is
// set, against a disposable vm-target, and drives the built pilot binary,
// never the engine's functions:
//
//	PILOT_IDENTITY_ENGINE_LIVE_VM          vm-target name (snapshot/rollback)
//	PILOT_IDENTITY_ENGINE_LIVE_WORKSPACE   workspace whose roster the preview reads
//	PILOT_IDENTITY_ENGINE_LIVE_DRIFT_USER  an enabled roster user
//	PILOT_IDENTITY_ENGINE_LIVE_DRIFT_GROUP an authoritative roster group that
//	                                       does not declare that user
//	PILOT_IDENTITY_ENGINE_LIVE_SUMMARY     optional: where to write the summary
//	PILOT_FREEIPA_LIVE_SSH[_KEY|_OPTS], IPA_ADMIN_PASSWORD
//	                                       as for internal/freeiparpc's live tests;
//	                                       used only for the drift fixture writes
//	                                       and the server log
func TestLiveGoPreviewDriver(t *testing.T) {
	vm := os.Getenv("PILOT_IDENTITY_ENGINE_LIVE_VM")
	if vm == "" {
		t.Skip("PILOT_IDENTITY_ENGINE_LIVE_VM is not set")
	}
	workspace := mustEnv(t, "PILOT_IDENTITY_ENGINE_LIVE_WORKSPACE")
	driftUser := mustEnv(t, "PILOT_IDENTITY_ENGINE_LIVE_DRIFT_USER")
	driftGroup := mustEnv(t, "PILOT_IDENTITY_ENGINE_LIVE_DRIFT_GROUP")
	password := mustEnv(t, "IPA_ADMIN_PASSWORD")
	target := liveSSHTarget(t)
	repo, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	pilot := filepath.Join(t.TempDir(), "pilot")
	run(t, repo, "go", "build", "-o", pilot, "./cmd/pilot")
	summary := liveSummary{Revision: gitOut(t, repo, "rev-parse", "HEAD"), Tree: gitOut(t, repo, "rev-parse", "HEAD^{tree}"), VM: vm}
	step := func(name string, f func() error) {
		start := time.Now()
		err := f()
		summary.Steps = append(summary.Steps, liveStep{Name: name, Pass: err == nil, Seconds: time.Since(start).Seconds(), Error: errText(err)})
		if err != nil {
			writeSummary(t, summary)
			t.Fatalf("%s: %v", name, err)
		}
	}
	stamp := time.Now().Unix()
	// pre is the state before the test, restored at the end; baseline is
	// the state after the Ansible engine applied the roster, the one the
	// drift is rolled back to (spec §10.3 steps 1, 3 and 7).
	pre, baseline := fmt.Sprintf("go-preview-pre-%d", stamp), fmt.Sprintf("go-preview-base-%d", stamp)
	preview := func(name string) (Document, error) {
		plan := filepath.Join(t.TempDir(), name+".json")
		before, err := serverLogSize(target)
		if err != nil {
			return Document{}, err
		}
		out, err := pilotRun(pilot, repo, "reconcile", "--dir", workspace, "--component", "freeipa-identity", "--preview-only", "--engine", "golang", "--plan-out", plan)
		if err != nil {
			return Document{}, fmt.Errorf("preview: %w\n%s", err, out)
		}
		if strings.Contains(out, password) {
			return Document{}, fmt.Errorf("the preview output holds the admin password")
		}
		var doc Document
		data, err := os.ReadFile(plan)
		if err == nil {
			err = json.Unmarshal(data, &doc)
		}
		if err != nil {
			return doc, err
		}
		if writes, err := serverWritesSince(target, before); err != nil || len(writes) > 0 {
			return doc, fmt.Errorf("the server logged writes during the preview: %v %v", writes, err)
		}
		if doc.Stats.Writes != 0 {
			return doc, fmt.Errorf("the preview sent %d writes", doc.Stats.Writes)
		}
		summary.Server, summary.Previews = doc.Server, append(summary.Previews, livePreview{Name: name, Operations: len(doc.Operations), Blocked: len(doc.Blocked), Stats: doc.Stats})
		return doc, nil
	}

	snapshot := func(tag string) func() error {
		return func() error {
			out, err := pilotRun(pilot, repo, "vm-target", "snapshot", "--name", vm, "--tag", tag)
			if err != nil {
				return fmt.Errorf("%w\n%s", err, out)
			}
			return nil
		}
	}
	step("snapshot before the test", snapshot(pre))
	t.Cleanup(func() { _, _ = pilotRun(pilot, repo, "vm-target", "rollback", "--name", vm, "--tag", pre) })
	step("ansible engine apply", func() error {
		out, err := pilotRun(pilot, repo, "reconcile", "--dir", workspace, "--component", "freeipa-identity", "--force")
		if err != nil {
			return fmt.Errorf("%w\n%s", err, out)
		}
		return nil
	})
	step("snapshot the baseline", snapshot(baseline))
	step("go preview after the ansible engine: no write", func() error {
		doc, err := preview("after-apply")
		if err == nil && (len(doc.Operations) != 0 || doc.Result != ResultOK) {
			err = fmt.Errorf("result %s, operations %v", doc.Result, opKinds(doc.Operations))
		}
		return err
	})
	step("inject drift", func() error { return injectDrift(target, password, driftUser, driftGroup) })
	step("go preview sees exactly the drift", func() error {
		doc, err := preview("after-drift")
		if err != nil {
			return err
		}
		want := []string{KindUserUpdate + " " + driftUser, KindMemberUserRemove + " " + driftGroup, KindUserEnable + " " + driftUser}
		if got := opKinds(doc.Operations); !slices.Equal(got, want) {
			return fmt.Errorf("operations %v, want %v", got, want)
		}
		return nil
	})
	step("rollback to the baseline", func() error {
		out, err := pilotRun(pilot, repo, "vm-target", "rollback", "--name", vm, "--tag", baseline)
		if err != nil {
			return fmt.Errorf("%w\n%s", err, out)
		}
		return nil
	})
	step("go preview after rollback: no write", func() error {
		doc, err := preview("after-rollback")
		if err == nil && (len(doc.Operations) != 0 || doc.Result != ResultOK) {
			err = fmt.Errorf("result %s, operations %v", doc.Result, opKinds(doc.Operations))
		}
		return err
	})
	writeSummary(t, summary)
}

type liveSummary struct {
	Revision string        `json:"tested_revision"`
	Tree     string        `json:"tested_tree"`
	VM       string        `json:"vm"`
	Server   Server        `json:"server"`
	Steps    []liveStep    `json:"steps"`
	Previews []livePreview `json:"previews"`
}

type liveStep struct {
	Name    string  `json:"name"`
	Pass    bool    `json:"pass"`
	Seconds float64 `json:"seconds"`
	Error   string  `json:"error,omitempty"`
}

type livePreview struct {
	Name       string `json:"name"`
	Operations int    `json:"operations"`
	Blocked    int    `json:"blocked"`
	Stats      Stats  `json:"stats"`
}

func writeSummary(t *testing.T, s liveSummary) {
	data, _ := json.MarshalIndent(s, "", "  ")
	t.Logf("summary:\n%s", data)
	if path := os.Getenv("PILOT_IDENTITY_ENGINE_LIVE_SUMMARY"); path != "" {
		if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
			t.Error(err)
		}
	}
}

func opKinds(ops []Operation) []string {
	var out []string
	for _, op := range ops {
		out = append(out, op.Kind+" "+op.Object)
	}
	return out
}

// injectDrift changes one user's shell, adds that user as an undeclared
// direct member of a group, and disables the user: test set-up writes
// through the Phase 0 client, not the engine under test.
func injectDrift(target sshdial.Target, password, user, group string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	d := &sshdial.Dialer{Target: target}
	fqdn, err := d.FQDN(ctx)
	if err != nil {
		return err
	}
	ca, err := d.CA(ctx)
	if err != nil {
		return err
	}
	c, err := freeiparpc.New(freeiparpc.Config{FQDN: fqdn, CA: ca, DialContext: d.DialContext})
	if err != nil {
		return err
	}
	if err := c.Login(ctx, "admin", password); err != nil {
		return err
	}
	defer func() { _ = c.Logout(context.Background()) }()
	for _, cmd := range []freeiparpc.Command{
		{Method: "user_mod", Args: []any{user}, Options: map[string]any{"loginshell": "/sbin/nologin"}},
		{Method: "group_add_member", Args: []any{group}, Options: map[string]any{"user": []any{user}}},
		{Method: "user_disable", Args: []any{user}},
	} {
		raw, err := c.Call(ctx, cmd)
		if err != nil {
			return fmt.Errorf("%s: %w", cmd.Method, err)
		}
		if cmd.Method == "group_add_member" {
			if res, err := freeiparpc.DecodeMemberResult(raw, 1); err != nil || res.Completed != 1 {
				return fmt.Errorf("group_add_member: %+v %v", res, err)
			}
		}
	}
	return nil
}

// writeMethod matches a FreeIPA API log line of a command the users/groups
// engine may write with.
var writeMethod = regexp.MustCompile(`\b(user_add|user_mod|user_del|user_enable|user_disable|passwd|group_add|group_mod|group_del|group_add_member|group_remove_member)\(`)

const serverLog = "/var/log/httpd/error_log"

func serverLogSize(target sshdial.Target) (int64, error) {
	out, err := sshRun(target, "stat -c %s "+serverLog)
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(strings.TrimSpace(out), 10, 64)
}

func serverWritesSince(target sshdial.Target, offset int64) ([]string, error) {
	out, err := sshRun(target, fmt.Sprintf("tail -c +%d %s", offset+1, serverLog))
	if err != nil {
		return nil, err
	}
	var writes []string
	for _, line := range strings.Split(out, "\n") {
		if writeMethod.MatchString(line) {
			writes = append(writes, line)
		}
	}
	return writes, nil
}

func sshRun(t sshdial.Target, command string) (string, error) {
	args := []string{"-o", "BatchMode=yes"}
	if t.Port != 0 {
		args = append(args, "-p", strconv.Itoa(t.Port))
	}
	if t.IdentityFile != "" {
		args = append(args, "-i", t.IdentityFile)
	}
	for k, v := range t.Options {
		args = append(args, "-o", k+"="+v)
	}
	host := t.Host
	if t.User != "" {
		host = t.User + "@" + host
	}
	out, err := exec.Command("ssh", append(args, host, command)...).Output()
	return string(out), err
}

func liveSSHTarget(t *testing.T) sshdial.Target {
	dest := mustEnv(t, "PILOT_FREEIPA_LIVE_SSH")
	tgt := sshdial.Target{Host: dest, IdentityFile: os.Getenv("PILOT_FREEIPA_LIVE_SSH_KEY"), Options: map[string]string{}}
	if user, host, ok := strings.Cut(dest, "@"); ok {
		tgt.User, tgt.Host = user, host
	}
	for _, kv := range strings.Split(os.Getenv("PILOT_FREEIPA_LIVE_SSH_OPTS"), ",") {
		if k, v, ok := strings.Cut(kv, "="); ok {
			tgt.Options[k] = v
		}
	}
	return tgt
}

// pilotRun runs pilot from the repository root, as an operator does: the
// Ansible engine reads contracts/ and playbooks/ relative to the working
// directory, and the workspace is named by --dir.
func pilotRun(pilot, dir string, args ...string) (string, error) {
	cmd := exec.Command(pilot, args...)
	cmd.Dir = dir
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.String(), err
}

func run(t *testing.T, dir, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
}

func gitOut(t *testing.T, dir string, args ...string) string {
	t.Helper()
	out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}

func mustEnv(t *testing.T, key string) string {
	t.Helper()
	v := os.Getenv(key)
	if v == "" {
		t.Fatalf("%s is not set", key)
	}
	return v
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
