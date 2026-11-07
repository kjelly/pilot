package identityreconcile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/kjelly/pilot/internal/freeiparpc"
	"github.com/kjelly/pilot/internal/livehooks"
	"github.com/kjelly/pilot/internal/sshdial"
)

// The lab of TestLiveGoApplyDriver (spec §10.2): what the driver needs of two disposable VMs, a
// FreeIPA server and an enrolled client, and of the pilot binaries it builds and runs. Every
// function here is test set-up or observation; none is the engine under test. Secrets stay in
// memory and in 0600 files of the run's temporary directory: a password is read from a file or
// generated, handed to pilot through the roster or the vault file of a workspace, and to ssh
// through an askpass script, never in an argument and never in the summary.

// labEnv is the driver's world.
type labEnv struct {
	t    *testing.T
	repo string

	pilot      string // the binary as released: no stop points
	pilotHooks string // built with the identity_live_hooks tag

	srvVM, cliVM string
	srv, cli     sshdial.Target
	baseTag      string // the snapshot both VMs are reverted to for an arm

	template  string // the workspace the arms' workspaces are made from
	vaultPass string // the file ansible-vault reads the vault password from
	adminPW   string
	tmp       string
	cp        string // PILOT_SSH_CONTROL_BASE: short, private, ours to clean
	arm       int    // a counter for names
	cliFQDN   string
	key       string // the private key of the roster users' ssh_keys (the client login oracle)
	pub       string
}

// pilotEnv is the environment of every pilot and ansible process the driver starts.
func (lv *labEnv) pilotEnv(extra ...string) []string {
	cache, err := os.MkdirTemp(lv.tmp, "fact-cache-")
	if err != nil {
		lv.t.Fatal(err)
	}
	env := append(os.Environ(),
		"ANSIBLE_VAULT_PASSWORD_FILE="+lv.vaultPass,
		"ANSIBLE_PYTHON_INTERPRETER=/usr/bin/python3",
		"ANSIBLE_CACHE_PLUGIN_CONNECTION="+cache,
		"PILOT_SSH_CONTROL_BASE="+lv.cp,
		"IPA_ADMIN_PASSWORD=",
	)
	return append(env, extra...)
}

// ---- running pilot ----

// pilotResult is a finished pilot run.
type pilotResult struct {
	Out      string
	ExitCode int
	Seconds  float64
}

// runPilot runs binary to the end with its own data directory, as an operator does from the repository.
func (lv *labEnv) runPilot(binary, dataDir string, args []string, extraEnv ...string) pilotResult {
	lv.t.Helper()
	cmd := exec.Command(binary, append([]string{"--data-dir", dataDir}, args...)...)
	cmd.Dir = lv.repo
	cmd.Env = lv.pilotEnv(extraEnv...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	start := time.Now()
	err := cmd.Run()
	return pilotResult{Out: out.String(), ExitCode: exitCodeOf(err), Seconds: time.Since(start).Seconds()}
}

func exitCodeOf(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
}

// vmTarget runs `pilot vm-target <args>` against the default data directory, where the VMs are known.
func (lv *labEnv) vmTarget(args ...string) error {
	lv.t.Helper()
	cmd := exec.Command(lv.pilot, append([]string{"vm-target"}, args...)...)
	cmd.Dir = lv.repo
	cmd.Env = lv.pilotEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("vm-target %v: %w\n%s", args, err, out)
	}
	return nil
}

// proc is a pilot the driver started and talks to while it runs (the stop points).
type proc struct {
	lv    *labEnv
	cmd   *exec.Cmd
	out   *syncBuffer
	hooks string // the directory of the stop-point files
	done  chan struct{}
	exit  int
	start time.Time
}

// startPilot starts the binary with hooks built in and the stop points named, and returns at once.
func (lv *labEnv) startPilot(dataDir string, args []string, points ...string) *proc {
	lv.t.Helper()
	hooks, err := os.MkdirTemp(lv.tmp, "hooks-")
	if err != nil {
		lv.t.Fatal(err)
	}
	cmd := exec.Command(lv.pilotHooks, append([]string{"--data-dir", dataDir}, args...)...)
	cmd.Dir = lv.repo
	cmd.Env = lv.pilotEnv(livehooks.EnvDir+"="+hooks, livehooks.EnvPoints+"="+strings.Join(points, ","), "PILOT_W_TEST_TOKEN=lab-token")
	p := &proc{lv: lv, cmd: cmd, out: &syncBuffer{}, hooks: hooks, done: make(chan struct{}), start: time.Now()}
	cmd.Stdout, cmd.Stderr = p.out, p.out
	if err := cmd.Start(); err != nil {
		lv.t.Fatal(err)
	}
	go func() {
		err := cmd.Wait()
		p.exit = exitCodeOf(err)
		close(p.done)
	}()
	return p
}

// waitNotify waits for pilot to be stopped at point and returns the number of the stop.
func (p *proc) waitNotify(point string, within time.Duration) (int, error) {
	end := time.Now().Add(within)
	for time.Now().Before(end) {
		if data, err := os.ReadFile(filepath.Join(p.hooks, "notify")); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				var n int
				var got string
				if _, err := fmt.Sscanf(line, "%d %s", &n, &got); err == nil && got == point {
					return n, nil
				}
			}
		}
		select {
		case <-p.done:
			return 0, fmt.Errorf("pilot ended (exit %d) before it stopped at %s:\n%s", p.exit, point, p.out.String())
		case <-time.After(20 * time.Millisecond):
		}
	}
	return 0, fmt.Errorf("pilot did not stop at %s within %s:\n%s", point, within, p.out.String())
}

// answer releases stop n: "resume", or "drop" for an after_send stop.
func (p *proc) answer(n int, what string) {
	_ = os.WriteFile(filepath.Join(p.hooks, fmt.Sprintf("go.%d", n)), []byte(what+"\n"), 0o600)
}

func (p *proc) signal(sig syscall.Signal) { _ = p.cmd.Process.Signal(sig) }

func (p *proc) kill() { _ = p.cmd.Process.Kill() }

// wait returns the result when pilot has ended.
func (p *proc) wait(within time.Duration) (pilotResult, error) {
	select {
	case <-p.done:
		return pilotResult{Out: p.out.String(), ExitCode: p.exit, Seconds: time.Since(p.start).Seconds()}, nil
	case <-time.After(within):
		return pilotResult{Out: p.out.String(), ExitCode: -1}, fmt.Errorf("pilot did not end within %s:\n%s", within, p.out.String())
	}
}

// children are pilot's child processes with their command lines: the tunnel's ssh -W and the lock's ssh.
func (p *proc) children() map[int]string {
	out, err := exec.Command("ps", "-o", "pid=,args=", "--ppid", strconv.Itoa(p.cmd.Process.Pid)).Output()
	if err != nil {
		return nil
	}
	res := map[int]string{}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if pid, rest, ok := strings.Cut(line, " "); ok {
			if n, err := strconv.Atoi(pid); err == nil {
				res[n] = rest
			}
		}
	}
	return res
}

// childWith returns the pid of the child whose command line matches re.
func (p *proc) childWith(re string) (int, bool) {
	rx := regexp.MustCompile(re)
	for pid, args := range p.children() {
		if rx.MatchString(args) {
			return pid, true
		}
	}
	return 0, false
}

// syncBuffer is a bytes.Buffer safe for a process writing while the driver reads.
type syncBuffer struct {
	mu  chan struct{}
	buf bytes.Buffer
}

func (b *syncBuffer) lock() func() {
	if b.mu == nil {
		b.mu = make(chan struct{}, 1)
	}
	b.mu <- struct{}{}
	return func() { <-b.mu }
}

func (b *syncBuffer) Write(p []byte) (int, error) { defer b.lock()(); return b.buf.Write(p) }
func (b *syncBuffer) String() string              { defer b.lock()(); return b.buf.String() }

// ---- the two VMs ----

// rollback reverts both VMs to tag and makes them usable again: the guest clocks are set from the
// controller (vm-target does it, this checks), and every ssh control connection of ours is dropped.
func (lv *labEnv) rollback(tag string) error {
	for _, vm := range []string{lv.srvVM, lv.cliVM} {
		if err := lv.vmTarget("rollback", "--name", vm, "--tag", tag); err != nil {
			return err
		}
	}
	_ = os.RemoveAll(lv.cp)
	if err := os.MkdirAll(lv.cp, 0o700); err != nil {
		return err
	}
	now := strconv.FormatInt(time.Now().Unix(), 10)
	for _, t := range []sshdial.Target{lv.srv, lv.cli} {
		var last error
		for i := 0; i < 24; i++ {
			if _, last = sshRun(t, "date -u -s @"+now+" >/dev/null"); last == nil {
				break
			}
			time.Sleep(5 * time.Second)
		}
		if last != nil {
			return fmt.Errorf("cannot set the clock of a VM: %w", last)
		}
		out, err := sshRun(t, "date -u +%s")
		if err != nil {
			return err
		}
		got, _ := strconv.ParseInt(strings.TrimSpace(out), 10, 64)
		if skew := time.Now().Unix() - got; skew > 5 || skew < -5 {
			return fmt.Errorf("a guest clock is %d s off after the rollback", skew)
		}
	}
	return nil
}

func (lv *labEnv) snapshot(tag string) error {
	for _, vm := range []string{lv.srvVM, lv.cliVM} {
		if err := lv.vmTarget("snapshot", "--name", vm, "--tag", tag); err != nil {
			return err
		}
	}
	return nil
}

func (lv *labEnv) deleteSnapshot(tag string) {
	for _, vm := range []string{lv.srvVM, lv.cliVM} {
		_ = exec.Command("virsh", "-c", "qemu:///system", "snapshot-delete", vm, tag).Run()
	}
}

// onServer runs a command on the server as root.
func (lv *labEnv) onServer(command string) (string, error) { return sshRun(lv.srv, command) }

// onClient runs a command on the client as root.
func (lv *labEnv) onClient(command string) (string, error) { return sshRun(lv.cli, command) }

// ipaCLI runs an ipa command on the server with an admin ticket in a private cache (test set-up).
func (lv *labEnv) ipaCLI(command string) (string, error) {
	const cc = "FILE:/tmp/p26driver.ccache"
	cmd := exec.Command("ssh", append(sshArgs(lv.srv), sshHost(lv.srv), "export KRB5CCNAME="+cc+"; kinit admin >/dev/null && "+command+"; rc=$?; kdestroy -c "+cc+" 2>/dev/null; exit $rc")...)
	cmd.Stdin = strings.NewReader(lv.adminPW + "\n")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func sshArgs(t sshdial.Target) []string {
	args := []string{"-o", "BatchMode=yes", "-o", "ConnectTimeout=20"}
	if t.Port != 0 {
		args = append(args, "-p", strconv.Itoa(t.Port))
	}
	if t.IdentityFile != "" {
		args = append(args, "-i", t.IdentityFile)
	}
	keys := make([]string, 0, len(t.Options))
	for k := range t.Options {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		args = append(args, "-o", k+"="+t.Options[k])
	}
	return args
}

func sshHost(t sshdial.Target) string {
	if t.User != "" {
		return t.User + "@" + t.Host
	}
	return t.Host
}

// journal is the authorization cache journal of the server: its bytes' hash and the obligation it holds.
type journalState struct {
	Exists  bool
	Pending bool
	Hash    string
}

const journalPath = "/var/lib/pilot-identity/ssh-cache.json"

func (lv *labEnv) journal() journalState {
	lv.t.Helper()
	out, err := lv.onServer("cat " + journalPath + " 2>/dev/null")
	if err != nil || strings.TrimSpace(out) == "" {
		return journalState{Exists: false, Pending: true}
	}
	var j map[string]any
	if json.Unmarshal([]byte(out), &j) != nil {
		return journalState{Exists: true, Pending: true}
	}
	sum := sha256.Sum256([]byte(out))
	pending := true
	if v, ok := j["auth_pending"].(bool); ok {
		pending = v
	}
	return journalState{Exists: true, Pending: pending, Hash: hex.EncodeToString(sum[:8])}
}

// writeCount is how many write commands the server logged since offset, by method.
func (lv *labEnv) writesSince(offset int64) (map[string]int, error) {
	lines, err := serverWritesSince(lv.srv, offset)
	if err != nil {
		return nil, err
	}
	out := map[string]int{}
	for _, l := range lines {
		// A batched write is logged twice: once as "batch: <method>(...)" for the command and once as
		// the outer "batch(<method>(...))" session line. Count the command line only.
		if strings.Contains(l, "batch(") {
			continue
		}
		if m := writeMethod.FindStringSubmatch(l); m != nil {
			out[m[1]]++
		}
	}
	return out, nil
}

// ---- external writes: the drift and the mid-run changes of the arms ----

// ipa builds a FreeIPA client for set-up writes: a disposable server, written through the Phase 0
// client rather than the engine under test, with the gate open (there is no lock to ask).
func (lv *labEnv) ipa(principal, password string) (*freeiparpc.Client, func(), error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	d := &sshdial.Dialer{Target: lv.srv}
	fqdn, err := d.FQDN(ctx)
	if err != nil {
		d.Close()
		return nil, nil, err
	}
	ca, err := d.CA(ctx)
	if err != nil {
		d.Close()
		return nil, nil, err
	}
	c, err := freeiparpc.New(freeiparpc.Config{FQDN: fqdn, CA: ca, DialContext: d.DialContext, WriteGate: func(context.Context, string) error { return nil }})
	if err != nil {
		d.Close()
		return nil, nil, err
	}
	if err := c.Login(ctx, principal, password); err != nil {
		d.Close()
		return nil, nil, err
	}
	return c, func() { _ = c.Logout(context.Background()); c.CloseIdleConnections(); d.Close() }, nil
}

// ipaDo sends commands as the admin and fails on the first error.
func (lv *labEnv) ipaDo(cmds ...freeiparpc.Command) error {
	c, closeFn, err := lv.ipa("admin", lv.adminPW)
	if err != nil {
		return err
	}
	defer closeFn()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	for _, cmd := range cmds {
		if _, err := c.Call(ctx, cmd); err != nil {
			return fmt.Errorf("%s: %w", cmd.Method, err)
		}
	}
	return nil
}

// ---- the client: the allow and deny oracle K20 defined ----

// clientView is what a revocation looks like on the client, by the two oracles of K20: the cache
// view (root, no login: what SSSD holds) and a fresh login (which refreshes the user's entry, so it
// follows the server at once).
type clientView struct {
	IDResolves, InSudoGroup, SudoListsRule bool
}

func (lv *labEnv) cacheView(user, group, command string) clientView {
	g, gerr := lv.onClient("id -nG " + user + " 2>/dev/null")
	s, _ := lv.onClient("sudo -l -U " + user + " 2>&1")
	return clientView{
		IDResolves:    gerr == nil && strings.TrimSpace(g) != "",
		InSudoGroup:   slicesContains(strings.Fields(g), group),
		SudoListsRule: strings.Contains(s, command),
	}
}

func slicesContains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// loginKey reports whether a fresh ssh login of user with the oracle key, running command, succeeds.
func (lv *labEnv) loginKey(user, command string) bool {
	args := append([]string{"-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR", "-o", "ConnectTimeout=20", "-o", "BatchMode=yes",
		"-i", lv.key, "-o", "IdentitiesOnly=yes", "-o", "PreferredAuthentications=publickey"}, user+"@"+lv.cli.Host, command)
	return exec.Command("ssh", args...).Run() == nil
}

// ---- workspaces and rosters ----

// rosterDoc is a roster as YAML-able maps.
type rosterDoc map[string]any

func (r rosterDoc) yaml() []byte {
	data, err := yaml.Marshal(map[string]any(r))
	if err != nil {
		panic(err)
	}
	return data
}

// copyWorkspace makes a workspace for an arm from the template: its inventory files with the roster
// path pointed at the copy, the vault, and the roster written plaintext 0600. A non-empty vaultPW
// replaces the vault with a plaintext one holding that admin password (an arm whose login is
// another principal).
func (lv *labEnv) copyWorkspace(roster rosterDoc, vaultPW string, groupVars map[string]string) string {
	lv.t.Helper()
	lv.arm++
	dst := filepath.Join(lv.tmp, fmt.Sprintf("ws-%02d", lv.arm))
	for _, d := range []string{dst, filepath.Join(dst, ".vault"), filepath.Join(dst, "group_vars")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			lv.t.Fatal(err)
		}
	}
	copyFile := func(name string, mod func(string) string) {
		data, err := os.ReadFile(filepath.Join(lv.template, name))
		if err != nil {
			lv.t.Fatal(err)
		}
		text := strings.ReplaceAll(string(data), lv.template, dst)
		if mod != nil {
			text = mod(text)
		}
		if err := os.WriteFile(filepath.Join(dst, name), []byte(text), 0o600); err != nil {
			lv.t.Fatal(err)
		}
	}
	copyFile("hosts.yml", nil)
	copyFile("inventory.yml", nil)
	copyFile("group_vars/freeipa.yml", func(s string) string {
		for k, v := range groupVars {
			// A key the file already sets is replaced: a second line of it is an invalid mapping.
			re := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(k) + `:.*$`)
			if re.MatchString(s) {
				s = re.ReplaceAllLiteralString(s, k+": "+v)
				continue
			}
			s += "\n" + k + ": " + v + "\n"
		}
		return s
	})
	if vaultPW != "" {
		if err := os.WriteFile(filepath.Join(dst, ".vault", "main.yaml"), []byte("ipa_admin_password: "+strconv.Quote(vaultPW)+"\n"), 0o600); err != nil {
			lv.t.Fatal(err)
		}
	} else {
		copyFile(".vault/main.yaml", nil)
	}
	if err := os.WriteFile(filepath.Join(dst, ".vault", "ipa-identity.yaml"), roster.yaml(), 0o600); err != nil {
		lv.t.Fatal(err)
	}
	return dst
}

// setRoster rewrites the roster of a workspace.
func (lv *labEnv) setRoster(ws string, roster rosterDoc) {
	lv.t.Helper()
	if err := os.WriteFile(filepath.Join(ws, ".vault", "ipa-identity.yaml"), roster.yaml(), 0o600); err != nil {
		lv.t.Fatal(err)
	}
}

// readApplyResult reads the result file of a run.
func readApplyResult(path string) (ApplyDocument, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return ApplyDocument{}, err
	}
	return ParseApplyDocument(data)
}

// opLines are the operations of the plan a run executed, as "kind object", in order.
func opLines(plan Plan) []string {
	var out []string
	for _, op := range plan.Operations {
		out = append(out, op.Kind+" "+op.Object)
	}
	return out
}

// executedPlan is Plan₂ when the run got that far, else Plan₁.
func executedPlan(d ApplyDocument) Plan {
	if d.Plan2 != nil {
		return *d.Plan2
	}
	return d.Plan1
}

// regenerateInventory renders inventory.yml from hosts.yml again, as pilot inventory generate does, after the
// arm changed a connection variable in hosts.yml (the Go engine refuses an inventory that is not current with it).
func (lv *labEnv) regenerateInventory(ws string) error {
	r := lv.runPilot(lv.pilot, filepath.Join(lv.tmp, "data-inventory"), []string{"inventory", "generate", "--dir", ws, "--no-vault", "--no-group-vars", "--no-host-vars", "--no-nfs-roster"})
	if r.ExitCode != 0 {
		return fmt.Errorf("inventory generate exited %d:\n%s", r.ExitCode, r.Out)
	}
	return nil
}
