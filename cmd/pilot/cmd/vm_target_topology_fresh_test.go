package cmd

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/sshcontrol"
	"github.com/kjelly/pilot/internal/statefile"
	"github.com/kjelly/pilot/internal/vmtarget"
)

// The tests in this file drive the real cobra commands (`vm-target topology
// up --fresh`, `topology down`, `topology test --ephemeral`) through the real
// vmtarget.Manager against shim virsh/ssh/qemu-img/cloud-localds/ssh-keygen
// binaries, a temp data dir and a libvirt network name no other pilot uses.
// Nothing here touches libvirt, the shared vm-target state or the network.
//
// Boundary: the shims stand in for libvirt and sshd. They prove which VMs pilot
// creates, keeps and tears down (the shim's virsh log and pilot's state file
// are the oracle); they do not prove a real VM boots. The libvirt-QEMU ACL grant
// and the Ansible fact-cache cleanup are replaced through vmtarget.HostSeams
// because both depend on the machine running the test.

const (
	freshForeign = "foreign-vm" // another session's VM; named in no topology
	freshBad     = "bad-node"   // fails to provision: its base image is missing
	freshGood    = "good-node"  // provisions and boots
	freshRacer   = "racer-node" // another session claims this name mid-run
)

// freshHost is one hermetic vm-target host for a test.
type freshHost struct {
	t        *testing.T
	dir      string
	base     string // base image that exists
	missing  string // base image that does not
	network  string
	virshLog string
	sshLog   string
	dropped  *nameLog // hosts whose Ansible fact cache pilot was about to drop
	granted  *nameLog // targets whose QEMU overlay ACL pilot was about to grant
}

type nameLog struct {
	mu    sync.Mutex
	names []string
}

func (l *nameLog) add(names ...string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.names = append(l.names, names...)
}

func (l *nameLog) has(name string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, n := range l.names {
		if n == name {
			return true
		}
	}
	return false
}

// newFreshHost isolates every package variable `topology up/down/test` reads,
// installs the shims and seeds the pilot state with a foreign VM (freshForeign)
// that belongs to no topology. wiringFails makes the ssh shim refuse the
// /etc/hosts wiring command (but not the readiness probe), so a node boots
// and then fails to wire.
func newFreshHost(t *testing.T, wiringFails bool) *freshHost {
	t.Helper()
	isolateDataDirInputs(t)
	h := &freshHost{t: t, dir: t.TempDir(), dropped: &nameLog{}, granted: &nameLog{}}
	dataDir = filepath.Join(h.dir, "data")

	oldVMDir, oldSpec, oldFresh, oldSeams := vtVMDir, vtTopoSpecPath, vtTopoUpFresh, vtManagerHostSeams
	oldPlaybook, oldVerify, oldSkipLint, oldSkipCheck := vtTopoTestPlaybook, vtTopoTestVerify, vtTopoTestSkipLint, vtTopoTestSkipCheckmode
	oldNoRollback, oldEphemeral, oldKeep, oldVerifyTimeout := vtTopoTestNoRollback, vtTopoTestEphemeral, vtTopoTestKeepOnFailure, vtTopoTestVerifyTimeout
	t.Cleanup(func() {
		vtVMDir, vtTopoSpecPath, vtTopoUpFresh, vtManagerHostSeams = oldVMDir, oldSpec, oldFresh, oldSeams
		vtTopoTestPlaybook, vtTopoTestVerify, vtTopoTestSkipLint, vtTopoTestSkipCheckmode = oldPlaybook, oldVerify, oldSkipLint, oldSkipCheck
		vtTopoTestNoRollback, vtTopoTestEphemeral, vtTopoTestKeepOnFailure, vtTopoTestVerifyTimeout = oldNoRollback, oldEphemeral, oldKeep, oldVerifyTimeout
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
		rootCmd.SetArgs(nil)
	})
	vtVMDir = filepath.Join(h.dir, "vmdir")
	vtManagerHostSeams = &vmtarget.HostSeams{
		GrantQEMUOverlayAccess: func(_ context.Context, overlayPath string) error {
			h.granted.add(filepath.Base(filepath.Dir(overlayPath)))
			return nil
		},
		DropFacts: func(_ context.Context, hosts []string) error {
			h.dropped.add(hosts...)
			return nil
		},
	}
	// Manager.Up and Down print progress straight to os.Stderr.
	captureStderr(t)

	// A unique network name keeps the cross-process network lock file
	// (/tmp/pilot-vmtarget-network-<name>.lock) away from every real network.
	h.network = fmt.Sprintf("pilot-ut-%d-%d", os.Getpid(), time.Now().UnixNano())
	lock := filepath.Join("/tmp", "pilot-vmtarget-network-"+h.network+".lock")
	t.Cleanup(func() { _ = os.Remove(lock) })
	// Teardown removes each target's SSH control directory.
	sshBase, err := os.MkdirTemp("/tmp", "pilot-ut-ssh-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sshBase) })
	t.Setenv(sshcontrol.BaseEnv, sshBase)

	h.base = filepath.Join(h.dir, "base.qcow2")
	if err := os.WriteFile(h.base, []byte("fake-qcow2"), 0o644); err != nil {
		t.Fatal(err)
	}
	h.missing = filepath.Join(h.dir, "no-such-base.qcow2")
	h.virshLog = filepath.Join(h.dir, "virsh.log")
	h.sshLog = filepath.Join(h.dir, "ssh.log")
	h.installShims(wiringFails)

	saveVMTargetState(t, dataDir, freshForeign)
	return h
}

func (h *freshHost) shim(name, envKey, body string) {
	h.t.Helper()
	p := filepath.Join(h.dir, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		h.t.Fatal(err)
	}
	h.t.Setenv(envKey, p)
}

func (h *freshHost) racerMarker(name string) string { return filepath.Join(h.dir, "racer."+name) }

func (h *freshHost) installShims(wiringFails bool) {
	h.t.Helper()
	// No domain exists before pilot defines it; every defined one is running
	// and has an address. For the racer, `dominfo` blocks until the test has
	// put another session's record for that name into pilot's state.
	h.shim("virsh", "PILOT_VIRSH_BIN", fmt.Sprintf(`echo "$@" >> '%s'
case "$1" in
  dominfo)
    if [ "$2" = %q ] && [ -e '%s' ]; then
      : > '%s'
      i=0
      while [ ! -e '%s' ] && [ "$i" -lt 1000 ]; do sleep 0.01; i=$((i+1)); done
    fi
    exit 1 ;;
  domstate)        echo running ;;
  domifaddr)       echo " vnet0      52:54:00:aa:bb:cc    ipv4         192.168.122.42/24" ;;
  net-dumpxml)     echo "<network><ip><dhcp><range start='192.168.122.2' end='192.168.122.254'/></dhcp></ip></network>" ;;
  net-dhcp-leases) echo " Expiry Time           MAC address         Protocol   IP address           Hostname" ;;
esac
exit 0`, h.virshLog, freshRacer, h.racerMarker("enabled"), h.racerMarker("waiting"), h.racerMarker("go")))
	h.shim("qemu-img", "PILOT_QEMU_IMG_BIN", "exit 0")
	h.shim("cloud-localds", "PILOT_CLOUD_LOCALDS_BIN", `: > "$1"; exit 0`)
	h.shim("ssh-keygen", "PILOT_SSH_KEYGEN_BIN", `f=""
while [ $# -gt 0 ]; do
  if [ "$1" = "-f" ]; then f="$2"; fi
  shift
done
echo "fake-private-key" > "$f"
echo "ssh-ed25519 AAAAFAKEKEY pilot" > "$f.pub"
exit 0`)
	refuse := ""
	if wiringFails {
		refuse = `case "$*" in *"sed -i"*) echo "wiring refused by the shim" >&2; exit 3 ;; esac`
	}
	h.shim("ssh", "PILOT_SSH_BIN", fmt.Sprintf(`echo "$@" >> '%s'
%s
exit 0`, h.sshLog, refuse))
}

// enableRacer arms the race: the first `virsh dominfo racer-node` blocks until
// the returned function-owned goroutine has recorded another session's VM
// named racer-node in pilot's state. That is the window between the absent
// check and Manager.Up's reservation, in which a second pilot can claim a name.
func (h *freshHost) enableRacer() {
	h.t.Helper()
	if err := os.WriteFile(h.racerMarker("enabled"), nil, 0o644); err != nil {
		h.t.Fatal(err)
	}
	store := h.store()
	done := make(chan struct{})
	h.t.Cleanup(func() { <-done })
	go func() {
		defer close(done)
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := os.Stat(h.racerMarker("waiting")); err == nil {
				err := store.Mutate(func(ts []vmtarget.Target) ([]vmtarget.Target, error) {
					return append(ts, vmtarget.Target{Name: freshRacer, Status: vmtarget.StatusRunning}), nil
				})
				if err != nil {
					h.t.Errorf("record the racing session's VM: %v", err)
				}
				if err := os.WriteFile(h.racerMarker("go"), nil, 0o644); err != nil {
					h.t.Errorf("release the shim: %v", err)
				}
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		h.t.Errorf("provisioning never reached `virsh dominfo %s`", freshRacer)
	}()
}

func (h *freshHost) store() *statefile.Store[vmtarget.Target] {
	h.t.Helper()
	store, err := statefile.New[vmtarget.Target](dataDir, "vm-targets.json", 1, "vmtarget")
	if err != nil {
		h.t.Fatal(err)
	}
	return store
}

// stateNames is the sorted set of VM names in pilot's state.
func (h *freshHost) stateNames() []string {
	h.t.Helper()
	targets, err := h.store().Load()
	if err != nil {
		h.t.Fatal(err)
	}
	names := make([]string, 0, len(targets))
	for _, tg := range targets {
		names = append(names, tg.Name)
	}
	sort.Strings(names)
	return names
}

func (h *freshHost) wantState(want ...string) {
	h.t.Helper()
	sort.Strings(want)
	if got := h.stateNames(); strings.Join(got, ",") != strings.Join(want, ",") {
		h.t.Errorf("pilot state holds %v, want %v", got, want)
	}
}

// virshCalls is every `virsh` invocation so far, one argv per entry.
func (h *freshHost) virshCalls() [][]string {
	h.t.Helper()
	raw, err := os.ReadFile(h.virshLog)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		h.t.Fatal(err)
	}
	var calls [][]string
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line != "" {
			calls = append(calls, strings.Fields(line))
		}
	}
	return calls
}

// virshDid reports whether `virsh <verb> <name> ...` ran.
func (h *freshHost) virshDid(verb, name string) bool {
	for _, c := range h.virshCalls() {
		if len(c) >= 2 && c[0] == verb && c[1] == name {
			return true
		}
	}
	return false
}

// virshTouched reports whether any virsh call named the VM.
func (h *freshHost) virshTouched(name string) bool {
	for _, c := range h.virshCalls() {
		for _, a := range c[1:] {
			if a == name || strings.Contains(a, string(filepath.Separator)+name+string(filepath.Separator)) {
				return true
			}
		}
	}
	return false
}

// wantTornDown asserts virsh destroyed and undefined the VM.
func (h *freshHost) wantTornDown(name string) {
	h.t.Helper()
	for _, verb := range []string{"destroy", "undefine"} {
		if !h.virshDid(verb, name) {
			h.t.Errorf("virsh %s %s never ran: this run's VM was leaked; calls: %v", verb, name, h.virshCalls())
		}
	}
}

// wantUntouched asserts nothing destroyed or undefined the VM.
func (h *freshHost) wantUntouched(name string) {
	h.t.Helper()
	for _, verb := range []string{"destroy", "undefine"} {
		if h.virshDid(verb, name) {
			h.t.Errorf("virsh %s %s ran: pilot touched a VM it did not create; calls: %v", verb, name, h.virshCalls())
		}
	}
}

// wantFactsKept asserts pilot never dropped the Ansible fact cache of a VM it
// did not create. Up drops the cache of the names it is about to create, so
// this is only meaningful for a VM that is in no topology.
func (h *freshHost) wantFactsKept(name string) {
	h.t.Helper()
	if h.dropped.has(name) {
		h.t.Errorf("pilot dropped the Ansible fact cache of %s, a VM it did not create", name)
	}
}

// spec writes a topology whose nodes are given as name:image pairs, in order,
// and returns its path. A node named in wire is wired to the next node.
func (h *freshHost) spec(wire bool, nodes ...[2]string) string {
	h.t.Helper()
	var b strings.Builder
	b.WriteString("nodes:\n")
	for i, n := range nodes {
		fmt.Fprintf(&b, "  - name: %s\n    base_image: %s\n    network: %s\n    boot_timeout: 20s\n    ssh_timeout: 20s\n", n[0], n[1], h.network)
		if wire && len(nodes) > 1 {
			fmt.Fprintf(&b, "    wire: [%s]\n", nodes[(i+1)%len(nodes)][0])
		}
	}
	p := filepath.Join(h.dir, "topology.yaml")
	if err := os.WriteFile(p, []byte(b.String()), 0o600); err != nil {
		h.t.Fatal(err)
	}
	return p
}

// run executes the real root command and returns what it wrote.
func (h *freshHost) run(args ...string) (stdout, stderr string, err error) {
	h.t.Helper()
	var out, errOut bytes.Buffer
	rootCmd.SetArgs(args)
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&errOut)
	err = rootCmd.Execute()
	return out.String(), errOut.String(), err
}

func wantOutputHas(t *testing.T, what, got string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(got, w) {
			t.Errorf("%s missing %q:\n%s", what, w, got)
		}
	}
}

// TestTopologyUpFreshProvisionFailureTearsDownOnlyThisRunsNodes: when a node
// fails to provision, `up --fresh` removes every VM this run created and only
// those, wherever the failing node sits in the spec. provisionEphemeralTopology
// used to return at the first failing node and drop every node created after
// it, so the later VM leaked and the next run refused its name. The racer
// cases cover the other half of the boundary: a name another session claims
// after the absent check is not this run's, so it must survive the teardown.
func TestTopologyUpFreshProvisionFailureTearsDownOnlyThisRunsNodes(t *testing.T) {
	cases := []struct {
		name       string
		nodes      func(h *freshHost) [][2]string
		racer      bool
		wantErrFor string // the first failing node in spec order
	}{
		{
			name:       "failing node before the good one",
			nodes:      func(h *freshHost) [][2]string { return [][2]string{{freshBad, h.missing}, {freshGood, h.base}} },
			wantErrFor: freshBad,
		},
		{
			name:       "failing node after the good one",
			nodes:      func(h *freshHost) [][2]string { return [][2]string{{freshGood, h.base}, {freshBad, h.missing}} },
			wantErrFor: freshBad,
		},
		{
			name:       "name claimed by another session before the good one",
			nodes:      func(h *freshHost) [][2]string { return [][2]string{{freshRacer, h.base}, {freshGood, h.base}} },
			racer:      true,
			wantErrFor: freshRacer,
		},
		{
			name:       "name claimed by another session after the good one",
			nodes:      func(h *freshHost) [][2]string { return [][2]string{{freshGood, h.base}, {freshRacer, h.base}} },
			racer:      true,
			wantErrFor: freshRacer,
		},
		{
			name: "two different failures around the good one: the first in spec order is reported",
			nodes: func(h *freshHost) [][2]string {
				return [][2]string{{freshBad, h.missing}, {freshRacer, h.base}, {freshGood, h.base}}
			},
			racer:      true,
			wantErrFor: freshBad,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newFreshHost(t, false)
			if tc.racer {
				h.enableRacer()
			}
			topo := h.spec(false, tc.nodes(h)...)

			stdout, stderr, err := h.run("vm-target", "topology", "up", "--fresh", "--topology", topo)
			if err == nil {
				t.Fatalf("up --fresh succeeded although a node cannot provision\nstdout:\n%s", stdout)
			}
			if !strings.Contains(err.Error(), fmt.Sprintf("node %q", tc.wantErrFor)) {
				t.Errorf("error does not name the first failing node %q: %v", tc.wantErrFor, err)
			}
			wantOutputHas(t, "stderr", stderr, "Tearing down the 1 node(s) this run created")
			wantOutputHas(t, "stdout", stdout, "ephemeral cleanup: "+freshGood+" down")

			// Pilot state: this run's VM is gone; every other session's stays.
			want := []string{freshForeign}
			if tc.racer {
				want = append(want, freshRacer)
			}
			h.wantState(want...)
			h.wantTornDown(freshGood)
			h.wantUntouched(freshForeign)
			h.wantFactsKept(freshForeign)
			h.wantUntouched(freshRacer)
			if h.virshTouched(freshBad) {
				t.Errorf("virsh was called for %s, which never got past its missing base image: %v", freshBad, h.virshCalls())
			}
		})
	}
}

// TestTopologyUpFreshWiringFailureTearsDownOnlyThisRunsNodes: every node
// boots, then wiring one of them fails. The whole topology is this run's, so
// every node goes, and the foreign VM stays.
func TestTopologyUpFreshWiringFailureTearsDownOnlyThisRunsNodes(t *testing.T) {
	h := newFreshHost(t, true)
	topo := h.spec(true, [2]string{"wire-a", h.base}, [2]string{"wire-b", h.base})

	stdout, stderr, err := h.run("vm-target", "topology", "up", "--fresh", "--topology", topo)
	if err == nil || !strings.Contains(err.Error(), `wire "wire-a"`) || !strings.Contains(err.Error(), "wiring refused by the shim") {
		t.Fatalf("want the wiring failure of wire-a, got %v\nstdout:\n%s", err, stdout)
	}
	wantOutputHas(t, "stderr", stderr, "Tearing down the 2 node(s) this run created")
	h.wantState(freshForeign)
	h.wantTornDown("wire-a")
	h.wantTornDown("wire-b")
	h.wantUntouched(freshForeign)
	h.wantFactsKept(freshForeign)
}

// TestTopologyUpFreshSuccessOwnsEveryNode: a successful `up --fresh` leaves
// every node this run created, a second `up --fresh` is refused without
// changing anything, and `topology down` of the same spec removes exactly
// those nodes, never the foreign VM that shares the host.
func TestTopologyUpFreshSuccessOwnsEveryNode(t *testing.T) {
	h := newFreshHost(t, false)
	topo := h.spec(true, [2]string{"fresh-a", h.base}, [2]string{"fresh-b", h.base})

	stdout, stderr, err := h.run("vm-target", "topology", "up", "--fresh", "--topology", topo)
	if err != nil {
		t.Fatalf("up --fresh: %v\nstdout:\n%s\nstderr:\n%s", err, stdout, stderr)
	}
	wantOutputHas(t, "stdout", stdout, "fresh-a up", "fresh-b up", "wired fresh-b -> fresh-a", "wired fresh-a -> fresh-b")
	h.wantState(freshForeign, "fresh-a", "fresh-b")
	// The host-dependent steps ran through the seams, not on this machine.
	for _, name := range []string{"fresh-a", "fresh-b"} {
		if !h.granted.has(name) || !h.dropped.has(name) {
			t.Errorf("%s: the ACL grant and fact-cache seams were not used (granted=%v dropped=%v): the test ran host-dependent steps for real", name, h.granted.has(name), h.dropped.has(name))
		}
	}
	if raw, _ := os.ReadFile(h.sshLog); strings.Count(string(raw), "cat >> /etc/hosts") != 2 {
		t.Errorf("want one /etc/hosts wiring command per node, ssh calls:\n%s", raw)
	}
	h.wantUntouched(freshForeign)
	h.wantFactsKept(freshForeign)

	// A second --fresh run must refuse the names the first one created and
	// change nothing: no libvirt call other than the status reads.
	before := len(h.virshCalls())
	_, _, err = h.run("vm-target", "topology", "up", "--fresh", "--topology", topo)
	if err == nil || !strings.Contains(err.Error(), `--fresh requires node "fresh-a" to be absent`) {
		t.Fatalf("second up --fresh: want the refusal for fresh-a, got %v", err)
	}
	for _, c := range h.virshCalls()[before:] {
		if c[0] != "domstate" {
			t.Errorf("the refused run touched libvirt: virsh %v", c)
		}
	}
	h.wantState(freshForeign, "fresh-a", "fresh-b")

	// `topology down` removes this spec's nodes and leaves the foreign VM.
	if _, stderr, err := h.run("vm-target", "topology", "down", "--topology", topo); err != nil {
		t.Fatalf("topology down: %v\nstderr:\n%s", err, stderr)
	}
	h.wantState(freshForeign)
	h.wantTornDown("fresh-a")
	h.wantTornDown("fresh-b")
	h.wantUntouched(freshForeign)
	h.wantFactsKept(freshForeign)
}

// TestTopologyTestEphemeralFailureTearsDownOnlyThisRunsNodes: the --ephemeral
// path of `topology test` shares provisionEphemeralTopology with `up --fresh`
// and had the same leak, and it has its own teardown calls for a provisioning
// and a wiring failure. --skip-lint makes the command stop before it would run
// ansible-playbook, so only the provisioning and wiring steps are exercised.
func TestTopologyTestEphemeralFailureTearsDownOnlyThisRunsNodes(t *testing.T) {
	cases := []struct {
		name        string
		wiringFails bool
		wire        bool
		racer       bool
		nodes       func(h *freshHost) [][2]string
		wantErr     []string
		wantStderr  string
		wantState   []string
		wantGone    []string
		readOnly    bool // nothing but status reads may reach libvirt
	}{
		{
			name:      "a declared node already exists",
			nodes:     func(h *freshHost) [][2]string { return [][2]string{{freshGood, h.base}, {freshForeign, h.base}} },
			wantErr:   []string{fmt.Sprintf("--ephemeral requires node %q to be absent", freshForeign)},
			wantState: []string{freshForeign},
			readOnly:  true,
		},
		{
			name:       "failing node before the good one",
			nodes:      func(h *freshHost) [][2]string { return [][2]string{{freshBad, h.missing}, {freshGood, h.base}} },
			wantErr:    []string{"ephemeral topology provisioning failed", fmt.Sprintf("node %q", freshBad)},
			wantStderr: "Tearing down 1 created node(s)",
			wantState:  []string{freshForeign},
			wantGone:   []string{freshGood},
		},
		{
			name:       "name claimed by another session before the good one",
			racer:      true,
			nodes:      func(h *freshHost) [][2]string { return [][2]string{{freshRacer, h.base}, {freshGood, h.base}} },
			wantErr:    []string{"ephemeral topology provisioning failed", fmt.Sprintf("node %q", freshRacer)},
			wantStderr: "Tearing down 1 created node(s)",
			wantState:  []string{freshForeign, freshRacer},
			wantGone:   []string{freshGood},
		},
		{
			name:        "wiring failure after every node booted",
			wiringFails: true,
			wire:        true,
			nodes:       func(h *freshHost) [][2]string { return [][2]string{{"wire-a", h.base}, {"wire-b", h.base}} },
			wantErr:     []string{`wire "wire-a"`, "wiring refused by the shim"},
			wantStderr:  "Ephemeral wiring failed",
			wantState:   []string{freshForeign},
			wantGone:    []string{"wire-a", "wire-b"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newFreshHost(t, tc.wiringFails)
			if tc.racer {
				h.enableRacer()
			}
			topo := h.spec(tc.wire, tc.nodes(h)...)

			_, stderr, err := h.run("vm-target", "topology", "test", "--ephemeral", "--skip-lint",
				"--playbook", "playbooks/test/hello-localhost.yml", "--verify", "docs/verification/none.md",
				"--topology", topo)
			if err == nil {
				t.Fatal("topology test --ephemeral succeeded although provisioning or wiring fails")
			}
			for _, w := range tc.wantErr {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error missing %q: %v", w, err)
				}
			}
			wantOutputHas(t, "stderr", stderr, tc.wantStderr)
			h.wantState(tc.wantState...)
			for _, name := range tc.wantGone {
				h.wantTornDown(name)
			}
			h.wantUntouched(freshForeign)
			h.wantFactsKept(freshForeign)
			h.wantUntouched(freshRacer)
			if tc.readOnly {
				for _, c := range h.virshCalls() {
					if c[0] != "domstate" {
						t.Errorf("the refused run touched libvirt: virsh %v", c)
					}
				}
			}
		})
	}
}
