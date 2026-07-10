package vmtarget

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// writeShim writes a /bin/sh shim for one external tool and points its
// env override at it.
func writeShim(t *testing.T, dir, name, envKey, body string) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatalf("write shim %s: %v", name, err)
	}
	t.Setenv(envKey, p)
}

// keygenShim creates the private + .pub files the way ssh-keygen would,
// so Up's `read public key` step succeeds.
const keygenShim = `f=""
while [ $# -gt 0 ]; do
  if [ "$1" = "-f" ]; then f="$2"; fi
  shift
done
echo "fake-private-key" > "$f"
echo "ssh-ed25519 AAAAFAKEKEY pilot" > "$f.pub"
exit 0`

// sshShim succeeds and, if PILOT_SSH_ARGS_FILE is set, records argv so
// the no-shell contract can be asserted.
const sshShim = `[ -n "$PILOT_SSH_ARGS_FILE" ] && echo "$@" >> "$PILOT_SSH_ARGS_FILE"
exit 0`

// newTestManager wires shims for every external tool, using the given
// virsh case-body, and shrinks the polling timeouts so loops resolve
// fast against the (instant) shims. Returns the manager + a fake base
// image path that exists on disk (Up stats it).
func newTestManager(t *testing.T, virshBody string) (*Manager, string) {
	t.Helper()
	dir := t.TempDir()
	// The virsh shim logs argv to PILOT_VIRSH_LOG (when set) so tests can
	// assert exactly how teardown/undefine was invoked.
	virshScript := "[ -n \"$PILOT_VIRSH_LOG\" ] && echo \"$@\" >> \"$PILOT_VIRSH_LOG\"\ncase \"$1\" in\n" + virshBody + "\nesac"
	writeShim(t, dir, "virsh", "PILOT_VIRSH_BIN", virshScript)
	writeShim(t, dir, "qemu-img", "PILOT_QEMU_IMG_BIN", `exit 0`)
	writeShim(t, dir, "cloud-localds", "PILOT_CLOUD_LOCALDS_BIN", `: > "$1" 2>/dev/null; exit 0`)
	writeShim(t, dir, "ssh", "PILOT_SSH_BIN", sshShim)
	writeShim(t, dir, "ssh-keygen", "PILOT_SSH_KEYGEN_BIN", keygenShim)

	base := filepath.Join(dir, "base.qcow2")
	if err := os.WriteFile(base, []byte("fake-qcow2"), 0o644); err != nil {
		t.Fatalf("write base image: %v", err)
	}

	m, err := NewManager(filepath.Join(dir, "state"), filepath.Join(dir, "vmdir"))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	m.bootTimeout = 300 * time.Millisecond
	m.sshTimeout = 300 * time.Millisecond
	m.pollInterval = 5 * time.Millisecond
	return m, base
}

// happyVirsh is the virsh body for a target that comes up cleanly: no
// pre-existing domain, gets an IP, reports running.
// domifaddr is the authoritative primary source in real libvirt: it
// reports the domain's own interface address. The happy shim returns it
// directly so Up succeeds via the primary path (mirroring production),
// without relying on the net-dhcp-leases fallback.
const happyVirsh = `  dominfo)            exit 1 ;;
  domifaddr)          echo " vnet0      52:54:00:aa:bb:cc    ipv4         192.168.122.42/24" ; exit 0 ;;
  net-dhcp-leases)    cf="/tmp/virsh-nl-count.$(echo "$0" | tr / _)" ; c=$(cat "$cf" 2>/dev/null || echo 0) ; echo $((c+1)) > "$cf" ; if [ "$c" -eq 0 ] ; then echo " Expiry Time           MAC address         Protocol   IP address           Hostname" ; echo " 2000-01-01 00:00:00   52:54:00:aa:bb:cc   ipv4       192.168.122.99/24     stale" ; else echo " Expiry Time           MAC address         Protocol   IP address           Hostname" ; echo " 2999-01-01 00:00:00   52:54:00:aa:bb:cc   ipv4       192.168.122.42/24     myvm" ; fi ; exit 0 ;;
  net-dumpxml)        echo "<network><ip><dhcp><range start='192.168.122.2' end='192.168.122.254'/></dhcp></ip></network>" ; exit 0 ;;
  net-update)         exit 0 ;;
  domstate)           echo "running" ; exit 0 ;;
  define)             exit 0 ;;
  start)              exit 0 ;;
  destroy)            exit 0 ;;
  undefine)           exit 0 ;;
  snapshot-create-as) exit 0 ;;
  snapshot-revert)    exit 0 ;;
  *)                  exit 0 ;;`

func TestUp_RejectsBlankName(t *testing.T) {
	m, base := newTestManager(t, happyVirsh)
	if _, err := m.Up(context.Background(), Options{Name: "", BaseImage: base}); err == nil || !strings.Contains(err.Error(), "name is required") {
		t.Fatalf("want name-required, got %v", err)
	}
}

func TestUp_RejectsInvalidName(t *testing.T) {
	m, base := newTestManager(t, happyVirsh)
	if _, err := m.Up(context.Background(), Options{Name: "bad name", BaseImage: base}); err == nil || !strings.Contains(err.Error(), "invalid name") {
		t.Fatalf("want invalid-name, got %v", err)
	}
}

func TestUp_RejectsBlankImage(t *testing.T) {
	m, _ := newTestManager(t, happyVirsh)
	if _, err := m.Up(context.Background(), Options{Name: "ok"}); err == nil || !strings.Contains(err.Error(), "base image is required") {
		t.Fatalf("want image-required, got %v", err)
	}
}

func TestUp_RejectsMissingBaseImage(t *testing.T) {
	m, _ := newTestManager(t, happyVirsh)
	if _, err := m.Up(context.Background(), Options{Name: "ok", BaseImage: "/no/such/image.qcow2"}); err == nil || !strings.Contains(err.Error(), "base image") {
		t.Fatalf("want base-image-stat error, got %v", err)
	}
}

func TestUp_HappyPath(t *testing.T) {
	m, base := newTestManager(t, happyVirsh)
	tgt, err := m.Up(context.Background(), Options{Name: "vm1", BaseImage: base})
	if err != nil {
		t.Fatalf("Up: %v", err)
	}
	if tgt.Status != StatusRunning {
		t.Errorf("Status = %q", tgt.Status)
	}
	if tgt.IP != "192.168.122.42" {
		t.Errorf("IP = %q (want authoritative lease IP)", tgt.IP)
	}
	if tgt.SSHUser != "root" {
		t.Errorf("SSHUser = %q (want default root)", tgt.SSHUser)
	}
	if tgt.MAC != macFor("vm1") {
		t.Errorf("MAC = %q (want deterministic)", tgt.MAC)
	}
	// Artifacts staged.
	if _, err := os.Stat(tgt.KeyPath); err != nil {
		t.Errorf("private key missing: %v", err)
	}
	// Persisted + inventory round-trips with the SSH stanza.
	got, err := m.Get(context.Background(), "vm1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	inv, err := got.RenderInventory()
	if err != nil {
		t.Fatalf("RenderInventory: %v", err)
	}
	for _, want := range []string{
		"ansible_connection: ssh",
		"ansible_host: 192.168.122.42",
		"ansible_user: root",
		"ansible_ssh_private_key_file:",
	} {
		if !strings.Contains(inv, want) {
			t.Errorf("inventory missing %q\n%s", want, inv)
		}
	}
}

func TestUp_RefusesDuplicate(t *testing.T) {
	m, base := newTestManager(t, happyVirsh)
	if _, err := m.Up(context.Background(), Options{Name: "dup", BaseImage: base}); err != nil {
		t.Fatalf("first Up: %v", err)
	}
	_, err := m.Up(context.Background(), Options{Name: "dup", BaseImage: base})
	if err == nil || !strings.Contains(err.Error(), "already in state") {
		t.Fatalf("want duplicate error, got %v", err)
	}
}

func TestUp_RefusesHijack(t *testing.T) {
	// dominfo exits 0 → a domain with this name exists outside state.
	body := strings.Replace(happyVirsh, "dominfo)            exit 1 ;;", "dominfo)            exit 0 ;;", 1)
	m, base := newTestManager(t, body)
	_, err := m.Up(context.Background(), Options{Name: "owned", BaseImage: base})
	if err == nil || !strings.Contains(err.Error(), "already exists outside pilot state") {
		t.Fatalf("want hijack-refuse, got %v", err)
	}
}

// TestUp_CleansUpOnBootTimeout: if the VM never gets an IP, Up must fail
// AND leave no state record and no on-disk artifacts (no leaked domain).
func TestUp_CleansUpOnBootTimeout(t *testing.T) {
	// Both sources return nothing → waitForIP times out.
	body := strings.Replace(happyVirsh,
		`net-dhcp-leases)    cf="/tmp/virsh-nl-count.$(echo "$0" | tr / _)" ; c=$(cat "$cf" 2>/dev/null || echo 0) ; echo $((c+1)) > "$cf" ; if [ "$c" -eq 0 ] ; then echo " Expiry Time           MAC address         Protocol   IP address           Hostname" ; echo " 2000-01-01 00:00:00   52:54:00:aa:bb:cc   ipv4       192.168.122.99/24     stale" ; else echo " Expiry Time           MAC address         Protocol   IP address           Hostname" ; echo " 2999-01-01 00:00:00   52:54:00:aa:bb:cc   ipv4       192.168.122.42/24     myvm" ; fi ; exit 0 ;;`,
		`net-dhcp-leases)    exit 0 ;;`, 1)
	body = strings.Replace(body,
		`domifaddr)          echo " vnet0      52:54:00:aa:bb:cc    ipv4         192.168.122.42/24" ; exit 0 ;;`,
		`domifaddr)          exit 0 ;;`, 1)
	m, base := newTestManager(t, body)
	_, err := m.Up(context.Background(), Options{Name: "stuck", BaseImage: base})
	if err == nil || !strings.Contains(err.Error(), "timed out waiting") {
		t.Fatalf("want boot-timeout error, got %v", err)
	}
	if _, gerr := m.Get(context.Background(), "stuck"); gerr == nil {
		t.Error("failed Up must not leave a state record")
	}
	if _, serr := os.Stat(filepath.Join(m.vmDir, "stuck")); !os.IsNotExist(serr) {
		t.Error("failed Up must remove the target dir")
	}
}

// TestUp_KeepOnFailure: if the VM never gets an IP and KeepOnFailure is true,
// Up must fail but it MUST preserve the state record and the target dir.
func TestUp_KeepOnFailure(t *testing.T) {
	body := strings.Replace(happyVirsh,
		`net-dhcp-leases)    cf="/tmp/virsh-nl-count.$(echo "$0" | tr / _)" ; c=$(cat "$cf" 2>/dev/null || echo 0) ; echo $((c+1)) > "$cf" ; if [ "$c" -eq 0 ] ; then echo " Expiry Time           MAC address         Protocol   IP address           Hostname" ; echo " 2000-01-01 00:00:00   52:54:00:aa:bb:cc   ipv4       192.168.122.99/24     stale" ; else echo " Expiry Time           MAC address         Protocol   IP address           Hostname" ; echo " 2999-01-01 00:00:00   52:54:00:aa:bb:cc   ipv4       192.168.122.42/24     myvm" ; fi ; exit 0 ;;`,
		`net-dhcp-leases)    exit 0 ;;`, 1)
	body = strings.Replace(body,
		`domifaddr)          echo " vnet0      52:54:00:aa:bb:cc    ipv4         192.168.122.42/24" ; exit 0 ;;`,
		`domifaddr)          exit 0 ;;`, 1)
	m, base := newTestManager(t, body)
	_, err := m.Up(context.Background(), Options{Name: "kept", BaseImage: base, KeepOnFailure: true})
	if err == nil || !strings.Contains(err.Error(), "timed out waiting") {
		t.Fatalf("want boot-timeout error, got %v", err)
	}
	tgt, gerr := m.Get(context.Background(), "kept")
	if gerr != nil {
		t.Fatalf("Up with KeepOnFailure must preserve state record: %v", gerr)
	}
	if tgt.Name != "kept" {
		t.Errorf("expected target name 'kept', got %q", tgt.Name)
	}
	if _, serr := os.Stat(filepath.Join(m.vmDir, "kept")); os.IsNotExist(serr) {
		t.Error("Up with KeepOnFailure must preserve the target dir")
	}
}

func TestDown_RemovesState(t *testing.T) {
	m, base := newTestManager(t, happyVirsh)
	if _, err := m.Up(context.Background(), Options{Name: "doomed", BaseImage: base}); err != nil {
		t.Fatalf("Up: %v", err)
	}
	if err := m.Down(context.Background(), "doomed"); err != nil {
		t.Fatalf("Down: %v", err)
	}
	all, _ := m.List(context.Background())
	if len(all) != 0 {
		t.Fatalf("List after Down: %+v", all)
	}
}

func TestDown_UnknownNameErrors(t *testing.T) {
	m, _ := newTestManager(t, happyVirsh)
	if err := m.Down(context.Background(), "nope"); err == nil || !strings.Contains(err.Error(), "no target named") {
		t.Fatalf("want not-found, got %v", err)
	}
}

func TestGet_RefreshStatus_Missing(t *testing.T) {
	m, base := newTestManager(t, happyVirsh)
	if _, err := m.Up(context.Background(), Options{Name: "lost", BaseImage: base}); err != nil {
		t.Fatalf("Up: %v", err)
	}
	// Swap virsh so domstate now fails (domain vanished).
	dir := filepath.Dir(os.Getenv("PILOT_VIRSH_BIN"))
	writeShim(t, dir, "virsh", "PILOT_VIRSH_BIN", "case \"$1\" in domstate) exit 1 ;; *) exit 0 ;; esac")
	got, err := m.Get(context.Background(), "lost")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != StatusMissing {
		t.Errorf("Status = %q, want Missing", got.Status)
	}
}

// TestExec_ReconstructsArgvOnRemote guarantees argv is shell-quoted so the
// REMOTE shell reconstructs it faithfully. ssh flattens command args into one
// space-joined string; without quoting, `sh -c "echo hi | tee /tmp/out"`
// would arrive as `sh -c echo hi | tee /tmp/out` (i.e. `sh -c echo` piped into
// tee). The multi-word `-c` argument must survive as a single quoted token.
func TestExec_ReconstructsArgvOnRemote(t *testing.T) {
	m, base := newTestManager(t, happyVirsh)
	if _, err := m.Up(context.Background(), Options{Name: "x", BaseImage: base}); err != nil {
		t.Fatalf("Up: %v", err)
	}
	argsFile := filepath.Join(t.TempDir(), "ssh-args")
	t.Setenv("PILOT_SSH_ARGS_FILE", argsFile)
	if _, err := m.Exec(context.Background(), "x", []string{"sh", "-c", "echo hi | tee /tmp/out"}); err != nil {
		t.Fatalf("Exec: %v", err)
	}
	data, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatalf("read args: %v", err)
	}
	// The remote command is a single argument: the safe tokens pass through,
	// the multi-word script is single-quoted.
	if !strings.Contains(string(data), "sh -c 'echo hi | tee /tmp/out'") {
		t.Errorf("argv not shell-quoted for faithful remote reconstruction:\n%s", data)
	}
}

// TestShellQuoteArg pins the quoting rule the remote-argv reconstruction
// relies on: safe tokens pass through untouched; anything with whitespace or
// metachars is single-quoted; embedded single quotes are POSIX-escaped.
func TestShellQuoteArg(t *testing.T) {
	cases := map[string]string{
		"sh":                   "sh",
		"-c":                   "-c",
		"/etc/krb5.keytab":     "/etc/krb5.keytab",
		"target_group=all":     "target_group=all",
		"echo hi | tee /tmp/x": "'echo hi | tee /tmp/x'",
		"":                     "''",
		"it's":                 `'it'\''s'`,
		"a$b`c":                "'a$b`c'",
	}
	for in, want := range cases {
		if got := shellQuoteArg(in); got != want {
			t.Errorf("shellQuoteArg(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestUp_AcceptsHostAliases(t *testing.T) {
	m, base := newTestManager(t, happyVirsh)
	tgt, err := m.Up(context.Background(), Options{Name: "core", BaseImage: base, Hosts: []string{"dns", "ntp", "core", "dns"}})
	if err != nil {
		t.Fatalf("Up: %v", err)
	}
	if len(tgt.Hosts) != 3 { // core + dns + ntp (deduped)
		t.Fatalf("Hosts = %v (want core,dns,ntp)", tgt.Hosts)
	}
	inv, _ := tgt.RenderInventory()
	for _, want := range []string{"core:", "dns:", "ntp:"} {
		if !strings.Contains(inv, want) {
			t.Errorf("inventory missing alias %q\n%s", want, inv)
		}
	}
	if c := strings.Count(inv, "ansible_host: 192.168.122.42"); c != 3 {
		t.Errorf("all aliases should route to the same IP, got %d", c)
	}
}

func TestSnapshotRollback(t *testing.T) {
	m, base := newTestManager(t, happyVirsh)
	if _, err := m.Up(context.Background(), Options{Name: "s", BaseImage: base}); err != nil {
		t.Fatalf("Up: %v", err)
	}
	if err := m.Snapshot(context.Background(), "s", "baseline"); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if err := m.Rollback(context.Background(), "s", "baseline"); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
}

// TestDown_UndefineClearsSnapshotMetadata is the regression guard for
// the leak found in the live E2E: a domain that has been snapshotted
// cannot be plain-undefined, so teardown must pass --snapshots-metadata
// or the domain dangles after `down`.
func TestDown_UndefineClearsSnapshotMetadata(t *testing.T) {
	m, base := newTestManager(t, happyVirsh)
	logFile := filepath.Join(t.TempDir(), "virsh.log")
	t.Setenv("PILOT_VIRSH_LOG", logFile)
	if _, err := m.Up(context.Background(), Options{Name: "snapd", BaseImage: base}); err != nil {
		t.Fatalf("Up: %v", err)
	}
	if err := m.Snapshot(context.Background(), "snapd", "base"); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if err := m.Down(context.Background(), "snapd"); err != nil {
		t.Fatalf("Down: %v", err)
	}
	data, _ := os.ReadFile(logFile)
	var undefineLine string
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "undefine ") {
			undefineLine = line
		}
	}
	if undefineLine == "" {
		t.Fatalf("no undefine call recorded:\n%s", data)
	}
	if !strings.Contains(undefineLine, "--snapshots-metadata") {
		t.Errorf("undefine must clear snapshot metadata, got: %q", undefineLine)
	}
}

func TestMacFor_DeterministicAndQemuOUI(t *testing.T) {
	a := macFor("vm1")
	b := macFor("vm1")
	if a != b {
		t.Errorf("macFor not deterministic: %q vs %q", a, b)
	}
	if macFor("vm1") == macFor("vm2") {
		t.Error("different names should yield different MACs")
	}
	if !strings.HasPrefix(a, "52:54:00:") {
		t.Errorf("MAC %q should use the QEMU OUI", a)
	}
}

// TestMacLeaseInfo_NeverBorrowsForeignLease guards the fix for the
// cross-VM IP bug: when our MAC has no lease yet, macLeaseInfo must
// return "" and NOT fall back to some other VM's lease. (The old
// latestLeaseInfo/latestLeaseIP any-lease fallback was removed as dead,
// hazardous code — it was the original source of this bug.)
func TestMacLeaseInfo_NeverBorrowsForeignLease(t *testing.T) {
	out := "" +
		" Expiry Time           MAC address         Protocol   IP address           Hostname\n" +
		" 2999-01-01 00:00:00   52:54:00:aa:bb:cc   ipv4       192.168.122.50/24    vm1\n"
	// Our MAC (vm2) has no lease in the table — only vm1's is present.
	if ip, _ := macLeaseInfo(out, "52:54:00:11:22:33"); ip != "" {
		t.Errorf("macLeaseInfo borrowed a foreign lease: got %q, want empty", ip)
	}
	// Once our own lease appears we pick it, latest expiry wins.
	out2 := out +
		" 2999-01-02 00:00:00   52:54:00:11:22:33   ipv4       192.168.122.51/24    vm2\n" +
		" 2026-01-01 00:00:00   52:54:00:11:22:33   ipv4       192.168.122.52/24    vm2-old\n"
	if ip, _ := macLeaseInfo(out2, "52:54:00:11:22:33"); ip != "192.168.122.51" {
		t.Errorf("macLeaseInfo = %q, want 192.168.122.51 (own, latest-expiring lease)", ip)
	}
}

// TestWaitForIP_IgnoresForeignLease is the behavioural regression: vm2
// boots while vm1 already holds a lease on the shared network and
// domifaddr has not yet reflected vm2's own lease. waitForIP must wait
// for vm2's real lease rather than latching onto vm1's IP.
func TestWaitForIP_IgnoresForeignLease(t *testing.T) {
	dir := t.TempDir()
	mac := macFor("vm2")
	countFile := filepath.Join(dir, "nl-count")
	// domifaddr always empty → force the net-dhcp-leases fallback.
	// net-dhcp-leases always shows vm1's foreign lease, and only after a
	// few polls also shows OUR lease (simulating vm2 finishing DHCP).
	body := fmt.Sprintf(`cf=%q
case "$1" in
  domifaddr) exit 0 ;;
  net-dhcp-leases)
    c=$(cat "$cf" 2>/dev/null || echo 0); echo $((c+1)) > "$cf"
    echo " Expiry Time           MAC address         Protocol   IP address           Hostname"
    echo " 2999-01-01 00:00:00   52:54:00:aa:bb:cc   ipv4       192.168.122.50/24    vm1"
    if [ "$c" -ge 3 ]; then
      echo " 2999-01-01 00:00:00   %s   ipv4       192.168.122.51/24    vm2"
    fi
    exit 0 ;;
  *) exit 0 ;;
esac`, countFile, mac)
	writeShim(t, dir, "virsh", "PILOT_VIRSH_BIN", body)

	m, err := NewManager(filepath.Join(dir, "state"), filepath.Join(dir, "vmdir"))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	m.bootTimeout = 2 * time.Second
	m.pollInterval = 5 * time.Millisecond

	tg := &Target{Name: "vm2", MAC: mac, Network: "default"}
	if err := m.waitForIP(context.Background(), tg, nil, m.bootTimeout); err != nil {
		t.Fatalf("waitForIP: %v", err)
	}
	if tg.IP != "192.168.122.51" {
		t.Errorf("vm2 IP = %q, want 192.168.122.51 (its own lease, not vm1's .50)", tg.IP)
	}
}

func TestRenderInventory_RequiresIP(t *testing.T) {
	tgt := &Target{Name: "x"}
	if _, err := tgt.RenderInventory(); err == nil || !strings.Contains(err.Error(), "no IP yet") {
		t.Fatalf("want no-IP error, got %v", err)
	}
}

func TestRenderGroupedInventory_MultipleHostsAndGroups(t *testing.T) {
	targets := map[string]*Target{
		"ipa-primary": {Name: "ipa-primary", IP: "192.168.122.10", SSHUser: "root", SSHPort: 22, KeyPath: "/keys/primary"},
		"ipa-replica": {Name: "ipa-replica", IP: "192.168.122.11", SSHUser: "root", SSHPort: 22, KeyPath: "/keys/replica"},
	}
	order := []string{"ipa_masters", "ipa_replicas"}
	groups := map[string][]string{
		"ipa_masters":  {"ipa-primary"},
		"ipa_replicas": {"ipa-replica"},
	}
	inv, err := RenderGroupedInventory(targets, order, groups)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, want := range []string{
		"    ipa-primary:", "ansible_host: 192.168.122.10", "ansible_ssh_private_key_file: /keys/primary",
		"    ipa-replica:", "ansible_host: 192.168.122.11", "ansible_ssh_private_key_file: /keys/replica",
		"  children:", "    ipa_masters:", "        ipa-primary: {}", "    ipa_replicas:", "        ipa-replica: {}",
	} {
		if !strings.Contains(inv, want) {
			t.Errorf("expected inventory to contain %q, got:\n%s", want, inv)
		}
	}
}

func TestRenderGroupedInventory_RequiresIP(t *testing.T) {
	targets := map[string]*Target{"x": {Name: "x"}}
	_, err := RenderGroupedInventory(targets, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "no IP yet") {
		t.Fatalf("want no-IP error, got %v", err)
	}
}

func TestRenderGroupedInventory_UnknownGroupMemberErrors(t *testing.T) {
	targets := map[string]*Target{"x": {Name: "x", IP: "192.168.122.10"}}
	_, err := RenderGroupedInventory(targets, []string{"g"}, map[string][]string{"g": {"not-resolved"}})
	if err == nil || !strings.Contains(err.Error(), "not-resolved") {
		t.Fatalf("want unknown-member error, got %v", err)
	}
}

func TestRenderGroupedInventory_NoTargetsErrors(t *testing.T) {
	if _, err := RenderGroupedInventory(nil, nil, nil); err == nil {
		t.Fatal("expected an error for an empty target set")
	}
}

func TestRenderDomainXML_HasKeyBits(t *testing.T) {
	tgt := &Target{Name: "vm1", MemoryMB: 2048, VCPUs: 2, MAC: "52:54:00:aa:bb:cc",
		OverlayPath: "/x/overlay.qcow2", SeedPath: "/x/seed.iso", Network: "default"}
	xml := renderDomainXML(tgt)
	for _, want := range []string{
		"<domain type='kvm'>", "<name>vm1</name>", "52:54:00:aa:bb:cc",
		"/x/overlay.qcow2", "/x/seed.iso", "source network='default'", "type='qcow2'",
		// The seed MUST ride virtio, not a cdrom — see the long comment
		// in renderDomainXML. This guards the regression directly.
		"dev='vdb' bus='virtio'",
	} {
		if !strings.Contains(xml, want) {
			t.Errorf("domain xml missing %q", want)
		}
	}
	if strings.Contains(xml, "device='cdrom'") {
		t.Error("seed must not be attached as a cdrom (ds-identify misses it on q35)")
	}
}

func TestUp_TwoVMsGetDistinctIPsAndReuse(t *testing.T) {
	virshBody := `  *) python3 "$(dirname "$0")/helper.py" "$@" ;;`
	m, base := newTestManager(t, virshBody)

	dir := filepath.Dir(base)
	xmlFile := filepath.Join(dir, "network.xml")
	initialXML := `<network>
  <name>default</name>
  <ip address='192.168.122.1' netmask='255.255.255.0'>
    <dhcp>
      <range start='192.168.122.2' end='192.168.122.254'/>
    </dhcp>
  </ip>
</network>`
	if err := os.WriteFile(xmlFile, []byte(initialXML), 0o644); err != nil {
		t.Fatalf("write xml: %v", err)
	}

	helperCode := `import sys
import hashlib
import re
import os

cmd = sys.argv[1]
dir_path = os.path.dirname(os.path.abspath(__file__))
xml_file = os.path.join(dir_path, "network.xml")

if cmd == "dominfo":
    sys.exit(1)
elif cmd == "net-dumpxml":
    with open(xml_file, "r") as f:
        print(f.read())
    sys.exit(0)
elif cmd == "net-update":
    action = sys.argv[3]
    xml_snippet = sys.argv[7]
    with open(xml_file, "r") as f:
        content = f.read()
    if action == "add":
        content = content.replace("</dhcp>", xml_snippet + "</dhcp>")
    elif action == "delete":
        content = content.replace(xml_snippet, "")
    with open(xml_file, "w") as f:
        f.write(content)
    sys.exit(0)
elif cmd == "domifaddr":
    name = sys.argv[2]
    h = hashlib.sha256(name.encode("utf-8")).digest()
    mac = "52:54:00:{:02x}:{:02x}:{:02x}".format(h[0], h[1], h[2])
    with open(xml_file, "r") as f:
        xml = f.read()
    m = re.search(rf"mac=['\"]{mac}['\"]\s+ip=['\"]([\d.]+)['\"]", xml)
    if not m:
        m = re.search(rf"ip=['\"]([\d.]+)['\"]\s+mac=['\"]{mac}['\"]", xml)
    if m:
        print(f"vnet0  {mac}  ipv4  {m.group(1)}/24")
    sys.exit(0)
elif cmd == "domstate":
    print("running")
    sys.exit(0)
else:
    sys.exit(0)
`
	if err := os.WriteFile(filepath.Join(dir, "helper.py"), []byte(helperCode), 0o755); err != nil {
		t.Fatalf("write helper.py: %v", err)
	}

	// 1. Bring up vm1
	tgt1, err := m.Up(context.Background(), Options{Name: "vm1", BaseImage: base})
	if err != nil {
		t.Fatalf("Up vm1: %v", err)
	}
	if tgt1.IP != "192.168.122.2" {
		t.Errorf("vm1 IP = %q, want 192.168.122.2", tgt1.IP)
	}

	// 2. Bring up vm2
	tgt2, err := m.Up(context.Background(), Options{Name: "vm2", BaseImage: base})
	if err != nil {
		t.Fatalf("Up vm2: %v", err)
	}
	if tgt2.IP != "192.168.122.3" {
		t.Errorf("vm2 IP = %q, want 192.168.122.3 (must be distinct from vm1)", tgt2.IP)
	}

	// 3. Bring down vm1 (should release its reservation)
	if err := m.Down(context.Background(), "vm1"); err != nil {
		t.Fatalf("Down vm1: %v", err)
	}

	// 4. Bring up vm1 again (should reuse or re-allocate, since it was released, it gets 192.168.122.2 again)
	tgt1Re, err := m.Up(context.Background(), Options{Name: "vm1", BaseImage: base})
	if err != nil {
		t.Fatalf("Up vm1 again: %v", err)
	}
	if tgt1Re.IP != "192.168.122.2" {
		t.Errorf("vm1 re-up IP = %q, want 192.168.122.2 (reused since it was released)", tgt1Re.IP)
	}
}

// TestUp_DiskGBDefault checks that Up() with DiskGB=0 defaults to DefaultDiskGB.
func TestUp_DiskGBDefault(t *testing.T) {
	m, base := newTestManager(t, happyVirsh)
	tgt, err := m.Up(context.Background(), Options{Name: "diskdef", BaseImage: base})
	if err != nil {
		t.Fatalf("Up: %v", err)
	}
	if tgt.DiskGB != DefaultDiskGB {
		t.Errorf("DiskGB = %d, want default %d", tgt.DiskGB, DefaultDiskGB)
	}
}

// TestUp_DiskGBCustom checks that a custom DiskGB is honoured and persisted.
func TestUp_DiskGBCustom(t *testing.T) {
	m, base := newTestManager(t, happyVirsh)
	tgt, err := m.Up(context.Background(), Options{Name: "disk50", BaseImage: base, DiskGB: 50})
	if err != nil {
		t.Fatalf("Up: %v", err)
	}
	if tgt.DiskGB != 50 {
		t.Errorf("DiskGB = %d, want 50", tgt.DiskGB)
	}
	// Verify persistence via Get.
	got, err := m.Get(context.Background(), "disk50")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.DiskGB != 50 {
		t.Errorf("persisted DiskGB = %d, want 50", got.DiskGB)
	}
}

// TestUp_DiskGBPassedToQemuImg verifies that the DiskGB value reaches the
// qemu-img create argv as a trailing "<N>G" argument.
func TestUp_DiskGBPassedToQemuImg(t *testing.T) {
	dir := t.TempDir()

	// qemu-img shim that records argv.
	qemuLog := filepath.Join(dir, "qemu-img.log")
	writeShim(t, dir, "qemu-img", "PILOT_QEMU_IMG_BIN",
		fmt.Sprintf(`echo "$@" >> %q; exit 0`, qemuLog))

	// Wire remaining shims.
	writeShim(t, dir, "virsh", "PILOT_VIRSH_BIN", "case \"$1\" in\n"+happyVirsh+"\nesac")
	writeShim(t, dir, "cloud-localds", "PILOT_CLOUD_LOCALDS_BIN", `: > "$1" 2>/dev/null; exit 0`)
	writeShim(t, dir, "ssh", "PILOT_SSH_BIN", sshShim)
	writeShim(t, dir, "ssh-keygen", "PILOT_SSH_KEYGEN_BIN", keygenShim)

	base := filepath.Join(dir, "base.qcow2")
	if err := os.WriteFile(base, []byte("fake"), 0o644); err != nil {
		t.Fatalf("write base: %v", err)
	}
	m, err := NewManager(filepath.Join(dir, "state"), filepath.Join(dir, "vmdir"))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	m.bootTimeout = 300 * time.Millisecond
	m.sshTimeout = 300 * time.Millisecond
	m.pollInterval = 5 * time.Millisecond

	if _, err := m.Up(context.Background(), Options{Name: "imgtest", BaseImage: base, DiskGB: 42}); err != nil {
		t.Fatalf("Up: %v", err)
	}
	data, err := os.ReadFile(qemuLog)
	if err != nil {
		t.Fatalf("read qemu-img log: %v", err)
	}
	if !strings.Contains(string(data), "42G") {
		t.Errorf("qemu-img create should include '42G' size arg, got:\n%s", data)
	}
}

// TestResizeDisk_HappyPath tests that ResizeDisk grows a target's disk
// and updates the state.
func TestResizeDisk_HappyPath(t *testing.T) {
	m, base := newTestManager(t, happyVirsh)
	if _, err := m.Up(context.Background(), Options{Name: "grow", BaseImage: base, DiskGB: 30}); err != nil {
		t.Fatalf("Up: %v", err)
	}
	if err := m.ResizeDisk(context.Background(), "grow", 60); err != nil {
		t.Fatalf("ResizeDisk: %v", err)
	}
	got, err := m.Get(context.Background(), "grow")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.DiskGB != 60 {
		t.Errorf("DiskGB after resize = %d, want 60", got.DiskGB)
	}
}

// newResizeManager builds a Manager whose virsh and qemu-img shims both log
// their argv, so a test can assert exactly which tool ResizeDisk drove. The
// virsh domstate reply is controlled by `domState` ("running" vs "shut off"),
// which is what ResizeDisk branches on. Returns the manager, a fake base
// image, and the two argv log paths.
func newResizeManager(t *testing.T, domState string) (m *Manager, base, virshLog, qemuLog string) {
	t.Helper()
	dir := t.TempDir()
	virshLog = filepath.Join(dir, "virsh.log")
	qemuLog = filepath.Join(dir, "qemu-img.log")

	// happyVirsh but with a caller-chosen domstate, and argv logging.
	body := strings.Replace(happyVirsh,
		`domstate)           echo "running" ; exit 0 ;;`,
		fmt.Sprintf(`domstate)           echo %q ; exit 0 ;;`, domState), 1)
	virshScript := fmt.Sprintf("echo \"$@\" >> %q\ncase \"$1\" in\n%s\nesac", virshLog, body)
	writeShim(t, dir, "virsh", "PILOT_VIRSH_BIN", virshScript)
	writeShim(t, dir, "qemu-img", "PILOT_QEMU_IMG_BIN",
		fmt.Sprintf(`echo "$@" >> %q; exit 0`, qemuLog))
	writeShim(t, dir, "cloud-localds", "PILOT_CLOUD_LOCALDS_BIN", `: > "$1" 2>/dev/null; exit 0`)
	writeShim(t, dir, "ssh", "PILOT_SSH_BIN", sshShim)
	writeShim(t, dir, "ssh-keygen", "PILOT_SSH_KEYGEN_BIN", keygenShim)

	base = filepath.Join(dir, "base.qcow2")
	if err := os.WriteFile(base, []byte("fake-qcow2"), 0o644); err != nil {
		t.Fatalf("write base: %v", err)
	}
	var err error
	m, err = NewManager(filepath.Join(dir, "state"), filepath.Join(dir, "vmdir"))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	m.bootTimeout = 300 * time.Millisecond
	m.sshTimeout = 300 * time.Millisecond
	m.pollInterval = 5 * time.Millisecond
	return m, base, virshLog, qemuLog
}

// TestResizeDisk_RunningUsesBlockresize locks the bug fix: on a RUNNING VM the
// overlay is locked/owned by the qemu process, so ResizeDisk must grow it via
// `virsh blockresize` (through libvirtd) and must NOT touch it with a direct
// `qemu-img resize`, which fails with "Permission denied".
func TestResizeDisk_RunningUsesBlockresize(t *testing.T) {
	m, base, virshLog, qemuLog := newResizeManager(t, "running")
	if _, err := m.Up(context.Background(), Options{Name: "grow", BaseImage: base, DiskGB: 30}); err != nil {
		t.Fatalf("Up: %v", err)
	}
	// Ignore any qemu-img create argv logged during Up.
	if err := os.WriteFile(qemuLog, nil, 0o644); err != nil {
		t.Fatalf("truncate qemu log: %v", err)
	}
	if err := m.ResizeDisk(context.Background(), "grow", 60); err != nil {
		t.Fatalf("ResizeDisk: %v", err)
	}

	vlog, _ := os.ReadFile(virshLog)
	if !strings.Contains(string(vlog), "blockresize") || !strings.Contains(string(vlog), "60G") {
		t.Errorf("running resize must call `virsh blockresize ... 60G`, virsh log:\n%s", vlog)
	}
	if qlog, _ := os.ReadFile(qemuLog); strings.Contains(string(qlog), "resize") {
		t.Errorf("running resize must NOT call `qemu-img resize` (overlay is locked by qemu); qemu-img log:\n%s", qlog)
	}
}

// TestResizeDisk_StoppedUsesQemuImg is the complement: with no running qemu
// holding the lock, ResizeDisk grows the file directly with `qemu-img resize`
// and does not need blockresize.
func TestResizeDisk_StoppedUsesQemuImg(t *testing.T) {
	m, base, virshLog, qemuLog := newResizeManager(t, "running")
	if _, err := m.Up(context.Background(), Options{Name: "grow", BaseImage: base, DiskGB: 30}); err != nil {
		t.Fatalf("Up: %v", err)
	}
	// Flip the domstate shim so the VM now reports stopped, and reset logs so
	// we only see the resize-time argv.
	writeShim(t, filepath.Dir(virshLog), "virsh", "PILOT_VIRSH_BIN",
		fmt.Sprintf("echo \"$@\" >> %q\ncase \"$1\" in domstate) echo \"shut off\" ;; *) exit 0 ;; esac", virshLog))
	if err := os.WriteFile(virshLog, nil, 0o644); err != nil {
		t.Fatalf("truncate virsh log: %v", err)
	}
	if err := os.WriteFile(qemuLog, nil, 0o644); err != nil {
		t.Fatalf("truncate qemu log: %v", err)
	}
	if err := m.ResizeDisk(context.Background(), "grow", 60); err != nil {
		t.Fatalf("ResizeDisk: %v", err)
	}

	qlog, _ := os.ReadFile(qemuLog)
	if !strings.Contains(string(qlog), "resize") || !strings.Contains(string(qlog), "60G") {
		t.Errorf("stopped resize must call `qemu-img resize ... 60G`, qemu-img log:\n%s", qlog)
	}
	if vlog, _ := os.ReadFile(virshLog); strings.Contains(string(vlog), "blockresize") {
		t.Errorf("stopped resize must NOT call `virsh blockresize`; virsh log:\n%s", vlog)
	}
}

// TestResizeDisk_RejectsShrink verifies that ResizeDisk refuses a size
// smaller than or equal to the current one.
func TestResizeDisk_RejectsShrink(t *testing.T) {
	m, base := newTestManager(t, happyVirsh)
	if _, err := m.Up(context.Background(), Options{Name: "shrk", BaseImage: base, DiskGB: 30}); err != nil {
		t.Fatalf("Up: %v", err)
	}
	// Same size.
	if err := m.ResizeDisk(context.Background(), "shrk", 30); err == nil || !strings.Contains(err.Error(), "shrink is not supported") {
		t.Fatalf("want shrink-rejected for same size, got %v", err)
	}
	// Smaller.
	if err := m.ResizeDisk(context.Background(), "shrk", 20); err == nil || !strings.Contains(err.Error(), "shrink is not supported") {
		t.Fatalf("want shrink-rejected for smaller, got %v", err)
	}
}

// TestResizeDisk_UnknownTarget errors cleanly.
func TestResizeDisk_UnknownTarget(t *testing.T) {
	m, _ := newTestManager(t, happyVirsh)
	if err := m.ResizeDisk(context.Background(), "nope", 50); err == nil || !strings.Contains(err.Error(), "no target named") {
		t.Fatalf("want not-found, got %v", err)
	}
}

// TestResizeDisk_RejectsZeroAndNegative validates input.
func TestResizeDisk_RejectsZeroAndNegative(t *testing.T) {
	m, _ := newTestManager(t, happyVirsh)
	if err := m.ResizeDisk(context.Background(), "x", 0); err == nil || !strings.Contains(err.Error(), "positive integer") {
		t.Fatalf("want positive-int error for 0, got %v", err)
	}
	if err := m.ResizeDisk(context.Background(), "x", -5); err == nil || !strings.Contains(err.Error(), "positive integer") {
		t.Fatalf("want positive-int error for -5, got %v", err)
	}
}

// newSiblingManager returns a second Manager sharing the given manager's
// state dir and vm dir — the closest in-process model of a second `pilot
// vm-target` PROCESS: it has its own in-process mutex and its own state
// lock fd, so only the cross-process flock in statefile arbitrates
// between the two.
func newSiblingManager(t *testing.T, m *Manager) *Manager {
	t.Helper()
	sib, err := NewManager(m.stateDir, m.vmDir)
	if err != nil {
		t.Fatalf("NewManager(sibling): %v", err)
	}
	sib.bootTimeout = m.bootTimeout
	sib.sshTimeout = m.sshTimeout
	sib.pollInterval = m.pollInterval
	return sib
}

// TestUp_ConcurrentDifferentNames_BothPersist is the regression test for
// the 2026-07-06 incident: two `pilot vm-target up` processes ran in
// parallel (different names), each loaded the state at the start of Up
// and re-saved that stale snapshot at the end — last writer wins, the
// other VM's entry vanished from state and its libvirt domain became an
// orphan. With the reservation + Mutate design, BOTH entries must
// survive.
func TestUp_ConcurrentDifferentNames_BothPersist(t *testing.T) {
	m1, base := newTestManager(t, happyVirsh)
	m2 := newSiblingManager(t, m1)

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, up := range []struct {
		m    *Manager
		name string
	}{{m1, "alpha"}, {m2, "beta"}} {
		wg.Add(1)
		go func(m *Manager, name string) {
			defer wg.Done()
			_, err := m.Up(context.Background(), Options{Name: name, BaseImage: base})
			errs <- err
		}(up.m, up.name)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent Up: %v", err)
		}
	}

	// Read through a FRESH manager (fresh state fd) — both entries must
	// be in the file, not just in either manager's memory.
	fresh := newSiblingManager(t, m1)
	all, err := fresh.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("state lost an entry under concurrent Up: got %d targets (%+v), want 2", len(all), all)
	}
	if all[0].Name != "alpha" || all[1].Name != "beta" {
		t.Errorf("unexpected names: %q, %q", all[0].Name, all[1].Name)
	}
}

// TestUp_ConcurrentSameName_LoserFailsCleanly: with the same name, exactly
// one Up must win; the loser must fail with the duplicate error BEFORE
// creating or tearing down anything (domain name and target dir are
// derived from the name — a losing teardown would destroy the winner's
// artifacts). The winner's record and artifacts must survive.
func TestUp_ConcurrentSameName_LoserFailsCleanly(t *testing.T) {
	m1, base := newTestManager(t, happyVirsh)
	m2 := newSiblingManager(t, m1)

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, m := range []*Manager{m1, m2} {
		wg.Add(1)
		go func(m *Manager) {
			defer wg.Done()
			_, err := m.Up(context.Background(), Options{Name: "same", BaseImage: base})
			errs <- err
		}(m)
	}
	wg.Wait()
	close(errs)
	var failures []error
	for err := range errs {
		if err != nil {
			failures = append(failures, err)
		}
	}
	if len(failures) != 1 {
		t.Fatalf("want exactly one loser, got %d failures: %v", len(failures), failures)
	}
	if !strings.Contains(failures[0].Error(), "already in state") {
		t.Errorf("loser must fail the duplicate check, got: %v", failures[0])
	}

	fresh := newSiblingManager(t, m1)
	tgt, err := fresh.Get(context.Background(), "same")
	if err != nil {
		t.Fatalf("winner's record must survive: %v", err)
	}
	if tgt.Status != StatusRunning {
		t.Errorf("winner status = %q, want running", tgt.Status)
	}
	if _, serr := os.Stat(filepath.Join(m1.vmDir, "same")); serr != nil {
		t.Errorf("winner's target dir must survive: %v", serr)
	}
}
