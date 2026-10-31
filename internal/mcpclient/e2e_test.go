package mcpclient

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/mcpwire"
)

// The end-to-end run of spec §13.3, against a disposable deploy node
// prepared by playbooks/test/fixtures/mcp-remote-access-setup.yml: real
// ssh, real docker, the real pilot-cli image. It runs only with
// PILOT_MCP_E2E=1; the runbook (docs/runbooks/mcp-remote-access.md) lists
// the environment it reads.

type e2eEnv struct {
	sshConfig, host, adminHost, targetIP, envRoot, image, alias, managedUser string
	networkHost                                                              bool
}

func loadE2E(t *testing.T) e2eEnv {
	t.Helper()
	if os.Getenv("PILOT_MCP_E2E") != "1" {
		t.Skip("set PILOT_MCP_E2E=1 to run against a disposable deploy node")
	}
	get := func(k string) string {
		v := os.Getenv(k)
		if v == "" {
			t.Fatalf("%s is required", k)
		}
		return v
	}
	return e2eEnv{
		sshConfig: get("PILOT_MCP_E2E_SSH_CONFIG"), host: get("PILOT_MCP_E2E_SSH_HOST"),
		adminHost: get("PILOT_MCP_E2E_ADMIN_HOST"), targetIP: get("PILOT_MCP_E2E_TARGET_IP"),
		envRoot: get("PILOT_MCP_E2E_ENV_ROOT"), image: get("PILOT_MCP_E2E_IMAGE"),
		alias: get("PILOT_MCP_E2E_IMAGE_ALIAS"), managedUser: get("PILOT_MCP_E2E_MANAGED_USER"),
		networkHost: os.Getenv("PILOT_MCP_E2E_NETWORK_HOST") == "1",
	}
}

// admin runs a command on the deploy node as its administrator.
func (e e2eEnv) admin(t *testing.T, cmd string) string {
	t.Helper()
	out, err := exec.Command("ssh", "-F", e.sshConfig, "-o", "BatchMode=yes", e.adminHost, cmd).CombinedOutput()
	if err != nil {
		t.Fatalf("admin %q: %v\n%s", cmd, err, out)
	}
	return strings.TrimSpace(string(out))
}

func (e e2eEnv) repo(t *testing.T) string {
	t.Helper()
	hosts := "vars:\n  ansible_ssh_private_key_file: \"/pilot/config/.vault/id_ed25519\"\nhosts:\n" +
		"  mcp-vm:\n    ansible_host: \"" + e.targetIP + "\"\n    ansible_user: " + e.managedUser + "\n" +
		"    roles: [docker]\n    env: prod\n    freeipa_roster_file: \"/pilot/config/freeipa-roster.yaml\"\n"
	roster := "schema_version: 1\nfreeipa: {domain: ipa.e2e.invalid}\nusers: []\ngroups:\n" +
		"  - name: access-ops\n    state: present\n    category: access\n    membership: {authoritative: true, users: [alice], groups: []}\n" +
		"hostgroups: []\nhbac:\n  rules:\n    - name: allow-ops-all\n      state: present\n      enabled: true\n" +
		"      subjects: {users: [], groups: [access-ops]}\n      targets: {hostcat: all}\n      services: [sshd]\n"
	bare, _ := makeRepo(t, map[string]string{
		"prod/hosts.yml": hosts, "prod/freeipa-roster.yaml": roster,
		"prod/group_vars/all.yml": "e2e: true\n", "prod/.gitignore": "/inventory.yml\n",
	})
	return bare
}

func (e e2eEnv) profile(repo, mode string) Profile {
	p := testProfile(repo, "prod", mode)
	p.Target = TargetConfig{SSHHost: e.host, SSHConfig: e.sshConfig, Env: "prod", EnvRoot: e.envRoot,
		Image: e.image, Docker: "docker", NetworkHost: e.networkHost}
	p.Timeouts.StartupSeconds = 180
	return p
}

// sessionContainer is the one container running the e2e image.
func (e e2eEnv) sessionContainer(t *testing.T) string {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for {
		ids := strings.Fields(e.admin(t, "docker ps -q --filter ancestor="+e.image))
		if len(ids) == 1 {
			return ids[0]
		}
		if time.Now().After(deadline) {
			t.Fatalf("want one session container, have %v", ids)
		}
		time.Sleep(time.Second)
	}
}

func (e e2eEnv) waitNoContainer(t *testing.T, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for e.admin(t, "docker ps -q --filter ancestor="+e.image) != "" {
		if time.Now().After(deadline) {
			t.Fatalf("a session container is still running %s later", within)
		}
		time.Sleep(time.Second)
	}
}

func TestE2EDoctorBothModesAndBothTags(t *testing.T) {
	e := loadE2E(t)
	allowLocalRepos(t)
	repo := e.repo(t)
	for _, c := range []struct{ mode, image string }{{mcpwire.ModeObserve, ""}, {mcpwire.ModeEdit, ""}, {mcpwire.ModeObserve, e.alias}} {
		o := &Options{ProfileName: "e2e", Profile: e.profile(repo, c.mode), Image: c.image, Stderr: io.Discard,
			CacheDir: t.TempDir(), StatePath: filepath.Join(t.TempDir(), "s.jsonl"), ClientVersion: "e2e"}
		rep := Doctor(context.Background(), o)
		data, _ := json.MarshalIndent(rep, "", "  ")
		if !rep.OK() {
			t.Fatalf("doctor %s %s:\n%s", c.mode, c.image, data)
		}
		t.Logf("doctor %s %s:\n%s", c.mode, rep.Image, data)
	}
	o := &Options{ProfileName: "e2e", Profile: e.profile(repo, mcpwire.ModeObserve), Image: "pilot-cli:does-not-exist",
		Stdin: strings.NewReader(""), Stdout: io.Discard, Stderr: io.Discard, CacheDir: t.TempDir()}
	if err := Connect(context.Background(), o); !hasCode(err, CodeDockerFailed) {
		t.Fatalf("missing tag: %v", err)
	}
}

func TestE2EObserveSessionOnTheRealImage(t *testing.T) {
	e := loadE2E(t)
	allowLocalRepos(t)
	ls := connectLive(t, e.profile(e.repo(t), mcpwire.ModeObserve), "e2e-observe")

	// Container facts while the session runs: one environment mounted,
	// .vault read-only, no log driver, all capabilities dropped, and only
	// the image's own environment variables plus HOSTNAME and HOME.
	id := e.sessionContainer(t)
	if got := e.admin(t, "docker inspect -f '{{.HostConfig.LogConfig.Type}} {{json .HostConfig.CapDrop}} {{json .HostConfig.CapAdd}}' "+id); got != `none ["ALL"] null` {
		t.Errorf("host config = %s", got)
	}
	var mounts []struct {
		Source, Destination string
		RW                  bool
	}
	if err := json.Unmarshal([]byte(e.admin(t, "docker inspect -f '{{json .Mounts}}' "+id)), &mounts); err != nil {
		t.Fatal(err)
	}
	for _, m := range mounts {
		if strings.Contains(m.Source, "/staging/") || (m.Destination == mcpwire.ContainerVaultDir && m.RW) {
			t.Errorf("mount %+v", m)
		}
	}
	if len(mounts) != 2 {
		t.Errorf("mounts = %+v, want the .vault and .pilot-data of prod only", mounts)
	}
	var imageEnv []string
	if err := json.Unmarshal([]byte(e.admin(t, "docker image inspect -f '{{json .Config.Env}}' "+e.image)), &imageEnv); err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{"HOSTNAME": true, "HOME": true}
	for _, kv := range imageEnv {
		k, _, _ := strings.Cut(kv, "=")
		allowed[k] = true
	}
	for _, kv := range strings.Split(e.admin(t, "docker exec "+id+" env"), "\n") {
		if k, _, _ := strings.Cut(kv, "="); k != "" && !allowed[k] {
			t.Errorf("container environment has %s, not from the image", k)
		}
	}

	if err := mcpwire.CheckTools(mcpwire.ModeObserve, toolNames(t, ls.mcp)); err != nil {
		t.Fatal(err)
	}
	// I15: Ansible reaches the managed host with the key named by its
	// /pilot/config/.vault path (two symlinks deep) ...
	dns := callTool(t, ls.mcp, "pilot_diagnose_dns", map[string]any{"host": "mcp-vm"})
	if dns.IsError || strings.Contains(resultText(dns), `"unreachable":true`) {
		t.Fatalf("pilot_diagnose_dns = %s", resultText(dns))
	}
	// ... and reads the roster named by its /pilot/config path.
	login := callTool(t, ls.mcp, "pilot_diagnose_login", map[string]any{"host": "mcp-vm", "users": []any{"alice"}})
	if login.IsError || !strings.Contains(resultText(login), `\"roster_available\":true`) && structured(t, login)["roster_available"] != true {
		t.Fatalf("pilot_diagnose_login = %.2000s", resultText(login))
	}
	// The delivery tools load the catalog and the data dir.
	delivery := callTool(t, ls.mcp, "pilot_diagnose_delivery", map[string]any{"host": "mcp-vm", "component": "docker"})
	if delivery.IsError {
		t.Fatalf("pilot_diagnose_delivery = %s", resultText(delivery))
	}
	ls.end(t)
	e.waitNoContainer(t, 30*time.Second)
	if out := e.admin(t, "ls "+e.envRoot+"/prod/.pilot-data/mcp/sessions 2>/dev/null | wc -l"); out != "0" {
		t.Errorf("observe session left %s entries", out)
	}
}

func TestE2EEditChangesAndAStrandedSession(t *testing.T) {
	e := loadE2E(t)
	allowLocalRepos(t)
	repo := e.repo(t)
	p := e.profile(repo, mcpwire.ModeEdit)

	edit := func(ls *liveSession, ip string) {
		rev := structured(t, callTool(t, ls.mcp, "pilot_edit_inspect", map[string]any{}))["workspace_revision"].(string)
		plan := callTool(t, ls.mcp, "pilot_edit_plan", map[string]any{"base_revision": rev, "scenario": map[string]any{
			"version": 1, "title": "e2e", "steps": []any{
				map[string]any{"action": "set_host_field", "host": "mcp-vm", "field": "ansible_host", "value": ip},
				map[string]any{"action": "save_hosts"},
			}}})
		if plan.IsError {
			t.Fatalf("plan = %s", resultText(plan))
		}
		apply := callTool(t, ls.mcp, "pilot_edit_apply", map[string]any{"plan_id": structured(t, plan)["plan_id"].(string), "expected_revision": rev})
		if apply.IsError || structured(t, apply)["result"] != "applied" {
			t.Fatalf("apply = %s", resultText(apply))
		}
	}

	// A normal edit session, exported with changes.
	ls := connectLive(t, p, "e2e-edit")
	edit(ls, "192.0.2.21")
	ls.end(t)
	first := sessionIDFrom(t, ls.stderr.String())
	clone := t.TempDir()
	git(t, clone, "clone", "--quiet", repo, ".")
	o := &Options{ProfileName: "e2e-edit", Profile: p, Stderr: io.Discard, CacheDir: t.TempDir()}
	res, err := Changes(context.Background(), o, first, clone)
	if err != nil {
		t.Fatalf("changes: %v", err)
	}
	if strings.Join(res.Written, ",") != "prod/hosts.yml" {
		t.Fatalf("changes = %+v", res)
	}

	// A session whose container is killed stays "serving" until the next
	// edit request reclaims it as ended, so its edit is not lost.
	ls2 := connectLive(t, p, "e2e-edit")
	edit(ls2, "192.0.2.22")
	second := sessionIDFrom(t, ls2.stderr.String())
	e.admin(t, "docker kill "+e.sessionContainer(t))
	select {
	case err := <-ls2.done:
		var ce *Error
		if err != nil && !errors.As(err, &ce) {
			t.Fatalf("Connect after kill: %v", err)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("Connect did not return after the container was killed")
	}
	state := e.admin(t, "cat "+e.envRoot+"/prod/.pilot-data/mcp/sessions/"+second+"/session.json")
	if !strings.Contains(state, `"serving"`) {
		t.Fatalf("killed session state = %s", state)
	}
	clone2 := t.TempDir()
	git(t, clone2, "clone", "--quiet", repo, ".")
	res2, err := Changes(context.Background(), o, second, clone2)
	if err != nil {
		t.Fatalf("changes of the stranded session: %v", err)
	}
	hosts, _ := os.ReadFile(filepath.Join(clone2, "prod", "hosts.yml"))
	if strings.Join(res2.Written, ",") != "prod/hosts.yml" || !strings.Contains(string(hosts), "192.0.2.22") {
		t.Fatalf("stranded session changes = %+v\n%s", res2, hosts)
	}
}

func TestE2EKilledClientEndsTheContainer(t *testing.T) {
	e := loadE2E(t)
	allowLocalRepos(t)
	p := e.profile(e.repo(t), mcpwire.ModeObserve)
	opts, err := json.Marshal(Options{ProfileName: "k", Profile: p, CacheDir: t.TempDir(), StatePath: filepath.Join(t.TempDir(), "s.jsonl")})
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(os.Args[0])
	child.Env = append(os.Environ(), "PILOT_MCP_RUN_CONNECT="+string(opts))
	stdin, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdin.Close()
	var stderr lockedBuffer
	child.Stderr = &stderr
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(180 * time.Second)
	for !strings.Contains(stderr.String(), "pilot-mcp: session ") {
		if time.Now().After(deadline) {
			t.Fatalf("session did not start:\n%s", stderr.String())
		}
		time.Sleep(200 * time.Millisecond)
	}
	e.sessionContainer(t)
	if err := child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = child.Wait()
	e.waitNoContainer(t, 30*time.Second)
}
