package vmtarget

import (
	"context"
	"os"
	"path/filepath"
	"strings"
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
const happyVirsh = `  dominfo)            exit 1 ;;
  net-dhcp-leases)    cf="/tmp/virsh-nl-count.$(echo "$0" | tr / _)" ; c=$(cat "$cf" 2>/dev/null || echo 0) ; echo $((c+1)) > "$cf" ; if [ "$c" -eq 0 ] ; then echo " Expiry Time           MAC address         Protocol   IP address           Hostname" ; echo " 2000-01-01 00:00:00   52:54:00:aa:bb:cc   ipv4       192.168.122.99/24     stale" ; else echo " Expiry Time           MAC address         Protocol   IP address           Hostname" ; echo " 2999-01-01 00:00:00   52:54:00:aa:bb:cc   ipv4       192.168.122.42/24     myvm" ; fi ; exit 0 ;;
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
	// domifaddr returns nothing → waitForIP times out.
	body := strings.Replace(happyVirsh,
		`net-dhcp-leases)    cf="/tmp/virsh-nl-count.$(echo "$0" | tr / _)" ; c=$(cat "$cf" 2>/dev/null || echo 0) ; echo $((c+1)) > "$cf" ; if [ "$c" -eq 0 ] ; then echo " Expiry Time           MAC address         Protocol   IP address           Hostname" ; echo " 2000-01-01 00:00:00   52:54:00:aa:bb:cc   ipv4       192.168.122.99/24     stale" ; else echo " Expiry Time           MAC address         Protocol   IP address           Hostname" ; echo " 2999-01-01 00:00:00   52:54:00:aa:bb:cc   ipv4       192.168.122.42/24     myvm" ; fi ; exit 0 ;;`,
		`net-dhcp-leases)    exit 0 ;;`, 1)
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

// TestExec_PassesArgvVerbatim guarantees argv reaches ssh unchanged (no
// host-shell wrapping).
func TestExec_PassesArgvVerbatim(t *testing.T) {
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
	if !strings.Contains(string(data), "sh -c echo hi | tee /tmp/out") {
		t.Errorf("argv not passed verbatim:\n%s", data)
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

func TestLatestLeaseIP(t *testing.T) {
	// Realistic net-dhcp-leases output with one active + two stale
	// leases for the same MAC. latestLeaseIP must return the
	// latest-expiring one, not the first text match.
	out := "" +
		" Expiry Time           MAC address         Protocol   IP address           Hostname\n" +
		"-------------------------------------------------------------------------------------------\n" +
		" 2026-06-01 00:00:00   52:54:00:aa:bb:cc   ipv4       10.0.0.1/24          -\n" +
		" 2026-07-01 00:00:00   52:54:00:aa:bb:cc   ipv4       10.0.0.2/24          myvm\n" +
		" 2026-06-15 00:00:00   52:54:00:aa:bb:cc   ipv4       10.0.0.3/24          -\n" +
		" 2026-07-01 12:00:00   52:54:00:dd:ee:ff   ipv4       10.0.0.99/24         other\n"
	got := latestLeaseIP(out, "52:54:00:aa:bb:cc")
	if got != "10.0.0.2" {
		t.Errorf("latestLeaseIP(...) = %q, want %q (should pick latest expiry)", got, "10.0.0.2")
	}
	// No matching MAC — falls back to latest lease overall.
	if got := latestLeaseIP(out, "00:00:00:00:00:00"); got != "10.0.0.99" {
		t.Errorf("latestLeaseIP(wrong mac) = %q, want %q (fallback to latest overall)", got, "10.0.0.99")
	}
	// Empty input
	if got := latestLeaseIP("", "52:54:00:aa:bb:cc"); got != "" {
		t.Errorf("latestLeaseIP(empty) = %q, want empty", got)
	}
}

func TestRenderInventory_RequiresIP(t *testing.T) {
	tgt := &Target{Name: "x"}
	if _, err := tgt.RenderInventory(); err == nil || !strings.Contains(err.Error(), "no IP yet") {
		t.Fatalf("want no-IP error, got %v", err)
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
