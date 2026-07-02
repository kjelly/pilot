// Package vmtarget manages "QEMU/KVM virtual machines used as target
// hosts" for pilot. It is the higher-fidelity sibling of
// internal/dockertarget:
//
//   - internal/dockertarget  a docker container as a disposable target
//     host (shares the host kernel; great for
//     package/config/systemd-service testing).
//
//   - internal/vmtarget      a real VM as a disposable target host
//     (its own kernel; needed for kernel modules,
//     reboot/bootloader, LVM/filesystem, SELinux
//     enforcing, real networking — anything a
//     shared-kernel container cannot faithfully
//     reproduce).
//
// Both expose the same shape (Up/Down/Get/List/Exec/RenderInventory +
// Snapshot/Rollback) so the CLI and the agent loop treat them
// uniformly. A vmtarget renders an `ansible_connection: ssh` inventory,
// so the proven SSH path does the actual ansible work — the only new,
// failure-prone code is "provision a VM, wait for it to boot, hand back
// an SSH endpoint", which is deliberately the smallest possible surface.
//
// Correct-by-construction design choices:
//
//   - Immutable golden image + per-target qcow2 overlay. The base image
//     is never written to; all writes land in <dir>/overlay.qcow2. A
//     fresh Up is therefore always pristine, and a rollback that
//     recreates the overlay is byte-clean by construction.
//
//   - Declarative provisioning via cloud-init (NoCloud seed ISO). Same
//     inputs => same VM. No imperative "ssh in and configure" step.
//
//   - Authoritative IP: we never guess the VM's address. After boot we
//     ask libvirt (`virsh domifaddr`, sourced from the network's dnsmasq
//     leases) for the real lease and use that. Bounded polling, loud
//     failure.
//
//   - Tag-based snapshot/rollback delegates to libvirt
//     (`virsh snapshot-create-as` / `snapshot-revert`), which owns qcow2
//     snapshot correctness (atomic, exact disk state).
package vmtarget

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/anomalyco/pilot/internal/statefile"
)

// Status is the lifecycle state of a vm target.
type Status string

const (
	StatusRunning Status = "running"
	StatusStopped Status = "stopped"
	StatusMissing Status = "missing" // record exists in state but domain is gone
)

const stateVersion = 1

// Target describes one libvirt domain that pilot is using as a target host.
type Target struct {
	Name      string `json:"name"` // libvirt domain name AND ansible inventory host key
	BaseImage string `json:"base_image"`
	Status    Status `json:"status"`
	// MAC is deterministically derived from Name so the same target
	// always claims the same address from the network's DHCP pool.
	MAC string `json:"mac"`
	// IP is the address libvirt reported once the VM acquired a lease.
	// Empty until the VM has booted far enough to DHCP.
	IP       string `json:"ip,omitempty"`
	SSHUser  string `json:"ssh_user"`
	SSHPort  int    `json:"ssh_port"`
	Network  string `json:"network"`
	VCPUs    int    `json:"vcpus"`
	MemoryMB int    `json:"memory_mb"`
	// Dir is the per-target scratch dir holding overlay.qcow2, seed.iso
	// and the ephemeral SSH keypair.
	Dir         string `json:"dir"`
	OverlayPath string `json:"overlay_path"`
	SeedPath    string `json:"seed_path"`
	KeyPath     string `json:"key_path"`
	// Hosts, when non-empty, gives the target multiple ansible host
	// names all routing to the same VM (mirrors dockertarget.Hosts).
	Hosts     []string  `json:"hosts,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	StartedAt time.Time `json:"started_at"`
}

// Options bundles user-facing knobs for Up.
type Options struct {
	Name        string // required; domain name AND ansible host key
	BaseImage   string // required; path to a qcow2 cloud image (read-only backing)
	SSHUser     string // login user created/authorised via cloud-init; default "root"
	VCPUs       int    // default 2
	MemoryMB    int    // default 2048
	Network     string // libvirt network name; default "default"
	Hosts       []string
	SSHTimeout  time.Duration // override sshTimeout  (0 = use default 2m)
	BootTimeout time.Duration // override bootTimeout (0 = use default 3m)
}

// state is the on-disk JSON shape, versioned like dockertarget's.
type state struct {
	Version int      `json:"version"`
	Targets []Target `json:"targets"`
}

// Manager owns the lifecycle of all vm targets rooted at a data dir.
// Safe for concurrent use within a process (mutex) and across processes
// (atomic state rewrite).
type Manager struct {
	mu       sync.Mutex
	imgMu    sync.Mutex // serializes base-image prepare (download/customize)
	stateDir string
	store    *statefile.Store[Target]
	vmDir    string // where per-target qcow2/seed live (libvirt-accessible)
	now      func() time.Time

	// Tunables — real defaults in NewManager; tests shrink them so the
	// boot/ssh polling loops return immediately against shims.
	bootTimeout  time.Duration
	sshTimeout   time.Duration
	pollInterval time.Duration
}

// NewManager constructs a Manager. stateDir holds the json metadata
// (docker-targets.json sibling: vm-targets.json). vmDir is where the
// qcow2 overlays / seed ISOs live — it must be readable+writable by the
// libvirt qemu process, so it defaults to a libvirt-friendly location
// rather than under $HOME.
func NewManager(stateDir, vmDir string) (*Manager, error) {
	if stateDir == "" {
		return nil, errors.New("vmtarget: stateDir is required")
	}
	if vmDir == "" {
		vmDir = "/var/lib/libvirt/images/pilot"
	}
	store, err := statefile.New[Target](stateDir, "vm-targets.json", stateVersion, "vmtarget")
	if err != nil {
		return nil, err
	}
	return &Manager{
		stateDir:     stateDir,
		store:        store,
		vmDir:        vmDir,
		now:          time.Now,
		bootTimeout:  3 * time.Minute,
		sshTimeout:   2 * time.Minute,
		pollInterval: 2 * time.Second,
	}, nil
}

// ---- state load/save (atomic; mirrors dockertarget) -----------------------

// load/save delegate persistence to the shared, tested statefile.Store
// (atomic write + version check). The local *state shape is kept so the
// rest of the package (Up/Down/Get/List) is untouched.
func (m *Manager) load() (*state, error) {
	targets, err := m.store.Load()
	if err != nil {
		return nil, err
	}
	return &state{Version: stateVersion, Targets: targets}, nil
}

func (m *Manager) save(s *state) error {
	return m.store.Save(s.Targets)
}

// ---- external command seams -----------------------------------------------

type cmdResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// run executes a binary identified by an env-overridable name. The env
// override lets tests point each tool at a shim and lets power users
// pick alternative binaries. timeout bounds a single call.
func run(ctx context.Context, envKey, dflt string, timeout time.Duration, args ...string) (*cmdResult, error) {
	bin := os.Getenv(envKey)
	if bin == "" {
		bin = dflt
	}
	c, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(c, bin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	res := &cmdResult{Stdout: stdout.String(), Stderr: stderr.String()}
	if exitErr, ok := err.(*exec.ExitError); ok {
		res.ExitCode = exitErr.ExitCode()
		return res, nil
	}
	if err != nil {
		return res, fmt.Errorf("%s %s: %w", bin, strings.Join(args, " "), err)
	}
	return res, nil
}

func (m *Manager) virsh(ctx context.Context, args ...string) (*cmdResult, error) {
	return run(ctx, "PILOT_VIRSH_BIN", "virsh", 60*time.Second, args...)
}

func (m *Manager) qemuImg(ctx context.Context, args ...string) (*cmdResult, error) {
	return run(ctx, "PILOT_QEMU_IMG_BIN", "qemu-img", 5*time.Minute, args...)
}

func (m *Manager) cloudLocalds(ctx context.Context, args ...string) (*cmdResult, error) {
	return run(ctx, "PILOT_CLOUD_LOCALDS_BIN", "cloud-localds", 60*time.Second, args...)
}

func (m *Manager) sshKeygen(ctx context.Context, args ...string) (*cmdResult, error) {
	return run(ctx, "PILOT_SSH_KEYGEN_BIN", "ssh-keygen", 30*time.Second, args...)
}

func (m *Manager) ssh(ctx context.Context, t *Target, argv []string) (*cmdResult, error) {
	args := SSHBaseArgs(t)
	args = append(args, argv...)
	return run(ctx, "PILOT_SSH_BIN", "ssh", 60*time.Second, args...)
}

// SSHBaseArgs are the connection flags shared by Exec and readiness
// probing, exported so the CLI's `vm-target ssh` / `shell`
// subcommands can build the same argv (with `-tt` for PTY on top)
// without re-listing every flag here. Host-key checking is disabled
// because the VM is disposable and its host key changes on every
// recreate — the security tradeoff is intentional for throwaway test
// targets (mirrors the docker-target stance of not caring about
// target hardening).
func SSHBaseArgs(t *Target) []string {
	return []string{
		"-i", t.KeyPath,
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "ConnectTimeout=5",
		"-o", "BatchMode=yes",
		"-p", fmt.Sprintf("%d", t.SSHPort),
		fmt.Sprintf("%s@%s", t.SSHUser, t.IP),
	}
}

// ---- Up -------------------------------------------------------------------

// Up provisions a new VM target and blocks until it has a DHCP lease and
// answers SSH. On any failure after the domain is defined, it tears the
// half-built target down so we never leak a domain or disk.
// CleanSnapshotTag is the libvirt snapshot tag captured automatically at
// the end of a successful Up. `vm-target reset` reverts to it, giving the
// dev/test loop a seconds-fast return to a pristine, freshly-booted VM
// instead of a full down/up reprovision.
const CleanSnapshotTag = "clean"

func (m *Manager) Up(ctx context.Context, opt Options) (*Target, error) {
	if opt.Name == "" {
		return nil, errors.New("vmtarget: name is required")
	}
	if !validName(opt.Name) {
		return nil, fmt.Errorf("vmtarget: invalid name %q (want [a-zA-Z0-9_.-]+)", opt.Name)
	}
	baseAbs, err := m.PrepareBaseImage(ctx, opt.BaseImage)
	if err != nil {
		return nil, fmt.Errorf("vmtarget: prepare base image: %w", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	s, err := m.load()
	if err != nil {
		return nil, err
	}
	for _, existing := range s.Targets {
		if existing.Name == opt.Name {
			return nil, fmt.Errorf("vmtarget: target %q already in state (status=%s); run `pilot vm-target down --name %s` first", opt.Name, existing.Status, opt.Name)
		}
	}
	// Refuse to hijack an unrelated libvirt domain with the same name.
	if info, derr := m.virsh(ctx, "dominfo", opt.Name); derr == nil && info.ExitCode == 0 {
		return nil, fmt.Errorf("vmtarget: a libvirt domain named %q already exists outside pilot state; pick a different --name or remove it first", opt.Name)
	}

	user := opt.SSHUser
	if user == "" {
		user = "root"
	}
	vcpus := opt.VCPUs
	if vcpus == 0 {
		vcpus = 2
	}
	mem := opt.MemoryMB
	if mem == 0 {
		mem = 2048
	}
	network := opt.Network
	if network == "" {
		network = "default"
	}

	dir := filepath.Join(m.vmDir, opt.Name)
	now := m.now()
	tg := &Target{
		Name:        opt.Name,
		BaseImage:   baseAbs,
		Status:      StatusStopped,
		MAC:         macFor(opt.Name),
		SSHUser:     user,
		SSHPort:     22,
		Network:     network,
		VCPUs:       vcpus,
		MemoryMB:    mem,
		Dir:         dir,
		OverlayPath: filepath.Join(dir, "overlay.qcow2"),
		SeedPath:    filepath.Join(dir, "seed.iso"),
		KeyPath:     filepath.Join(dir, "id_ed25519"),
		Hosts:       dedupeHosts(opt.Name, opt.Hosts),
		CreatedAt:   now,
		StartedAt:   now,
	}

	// From here on, any failure must clean up the on-disk artifacts and
	// any defined domain. The cleanup closure references tg (the local
	// build target), NOT the return value — `return nil, err` must not
	// be able to null out what teardown operates on. (err is already in
	// scope from the load/Abs calls above; the defer captures it.)
	defer func() {
		if err != nil {
			m.teardown(ctx, tg)
		}
	}()

	if err = os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("vmtarget: mkdir target dir: %w", err)
	}
	if err = m.generateKey(ctx, tg); err != nil {
		return nil, err
	}
	var pubKey []byte
	if pubKey, err = os.ReadFile(tg.KeyPath + ".pub"); err != nil {
		return nil, fmt.Errorf("vmtarget: read public key: %w", err)
	}
	if err = m.buildSeed(ctx, tg, string(pubKey)); err != nil {
		return nil, err
	}
	if err = m.createOverlay(ctx, tg); err != nil {
		return nil, err
	}
	// Capture pre-existing DHCP leases for our MAC so waitForIP
	// can ignore them — they're from previous VM runs, not this one.
	// Allocate a static DHCP reservation BEFORE starting the VM. This
	// guarantees the VM always gets the same IP and prevents the
	// "two VMs get the same IP" conflict that occurs when a previous VM
	// with the same MAC had an active lease.
	if _, err = m.allocateStaticIP(ctx, tg); err != nil {
		return nil, fmt.Errorf("vmtarget: static IP allocation: %w", err)
	}

	// Capture pre-existing DHCP leases for our MAC so waitForIP
	// can ignore them — they're from previous VM runs, not this one.
	preExistingLeases := m.captureLeaseSet(ctx, tg.Network, tg.MAC)

	if err = m.defineAndStart(ctx, tg); err != nil {
		return nil, err
	}
	// Resolve the effective timeouts for THIS call as locals. They must
	// not be written back onto the Manager: the timeout knobs are
	// per-Up options, and mutating m.{ssh,boot}Timeout would leak one
	// call's override onto every later operation that reuses the same
	// Manager (e.g. the agent loop, or a second Up without options).
	bootTimeout := m.bootTimeout
	if opt.BootTimeout > 0 {
		bootTimeout = opt.BootTimeout
	}
	sshTimeout := m.sshTimeout
	if opt.SSHTimeout > 0 {
		sshTimeout = opt.SSHTimeout
	}
	if err = m.waitForIP(ctx, tg, preExistingLeases, bootTimeout); err != nil {
		return nil, err
	}
	if err = m.waitForSSH(ctx, tg, sshTimeout); err != nil {
		return nil, err
	}
	tg.Status = StatusRunning

	s.Targets = append(s.Targets, *tg)
	if err = m.save(s); err != nil {
		return nil, err
	}

	// Capture a "clean" checkpoint of the freshly-booted VM so the
	// dev/test loop can reset to a pristine state in seconds
	// (`vm-target reset`) instead of paying a full down/up reprovision.
	// A running-domain snapshot includes RAM, so a later revert returns
	// an already-booted VM — no re-wait for DHCP/SSH. Best-effort: a
	// failure here must NOT null out the named err (that would trigger
	// the teardown defer and destroy an otherwise-healthy target).
	if snapRes, snapErr := m.virsh(ctx, "snapshot-create-as", tg.Name, CleanSnapshotTag); snapErr != nil || (snapRes != nil && snapRes.ExitCode != 0) {
		detail := ""
		if snapErr != nil {
			detail = snapErr.Error()
		} else {
			detail = snapRes.Stderr
		}
		fmt.Fprintf(os.Stderr, "  ⚠ %s: could not create %q snapshot (%s); `vm-target reset` unavailable until you snapshot manually\n", tg.Name, CleanSnapshotTag, strings.TrimSpace(detail))
	}
	return tg, nil
}

// generateKey writes an ephemeral ed25519 keypair into the target dir.
// Removes any pre-existing key first so ssh-keygen never sees an "Overwrite (y/n)?"
// prompt (which would fail in non-interactive contexts).
func (m *Manager) generateKey(ctx context.Context, t *Target) error {
	// Remove existing key so ssh-keygen never prompts for overwrite.
	_ = os.Remove(t.KeyPath)
	_ = os.Remove(t.KeyPath + ".pub")
	res, err := m.sshKeygen(ctx, "-t", "ed25519", "-N", "", "-q", "-f", t.KeyPath, "-C", "pilot-vm-target:"+t.Name)
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("vmtarget: ssh-keygen failed: %s", res.Stderr)
	}
	return nil
}

// buildSeed writes cloud-init user-data + meta-data and packs them into
// a NoCloud seed ISO. Provisioning is fully declarative: the only thing
// injected is the SSH public key (authorised for the login user) and the
// hostname.
func (m *Manager) buildSeed(ctx context.Context, t *Target, pubKey string) error {
	userData := renderUserData(t, pubKey)
	metaData := fmt.Sprintf("instance-id: %s\nlocal-hostname: %s\n", t.Name, t.Name)

	udPath := filepath.Join(t.Dir, "user-data")
	mdPath := filepath.Join(t.Dir, "meta-data")
	if err := os.WriteFile(udPath, []byte(userData), 0o644); err != nil {
		return fmt.Errorf("vmtarget: write user-data: %w", err)
	}
	if err := os.WriteFile(mdPath, []byte(metaData), 0o644); err != nil {
		return fmt.Errorf("vmtarget: write meta-data: %w", err)
	}
	res, err := m.cloudLocalds(ctx, t.SeedPath, udPath, mdPath)
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("vmtarget: cloud-localds failed: %s", res.Stderr)
	}
	return nil
}

// renderUserData produces the cloud-config that authorises the SSH key
// for the login user. For root we both flip disable_root off and write
// the key directly, so cloud images with varied root policies all work.
func renderUserData(t *Target, pubKey string) string {
	pubKey = strings.TrimSpace(pubKey)
	var sb strings.Builder
	sb.WriteString("#cloud-config\n")
	fmt.Fprintf(&sb, "hostname: %s\n", t.Name)
	sb.WriteString("preserve_hostname: false\n")
	sb.WriteString("ssh_pwauth: false\n")
	if t.SSHUser == "root" {
		sb.WriteString("disable_root: false\n")
		sb.WriteString("users:\n")
		sb.WriteString("  - name: root\n")
		sb.WriteString("    lock_passwd: true\n")
		sb.WriteString("    ssh_authorized_keys:\n")
		fmt.Fprintf(&sb, "      - %s\n", pubKey)
		// Belt and suspenders for images that ignore the users: block
		// for root.
		sb.WriteString("write_files:\n")
		sb.WriteString("  - path: /root/.ssh/authorized_keys\n")
		sb.WriteString("    permissions: '0600'\n")
		sb.WriteString("    content: |\n")
		fmt.Fprintf(&sb, "      %s\n", pubKey)
	} else {
		sb.WriteString("users:\n")
		fmt.Fprintf(&sb, "  - name: %s\n", t.SSHUser)
		sb.WriteString("    sudo: ALL=(ALL) NOPASSWD:ALL\n")
		sb.WriteString("    groups: sudo\n")
		sb.WriteString("    shell: /bin/bash\n")
		sb.WriteString("    ssh_authorized_keys:\n")
		fmt.Fprintf(&sb, "      - %s\n", pubKey)
	}
	return sb.String()
}

// createOverlay creates the per-target qcow2 overlay backed by the
// immutable base image. All writes land here; the base is never touched.
func (m *Manager) createOverlay(ctx context.Context, t *Target) error {
	res, err := m.qemuImg(ctx, "create", "-f", "qcow2",
		"-b", t.BaseImage, "-F", "qcow2", t.OverlayPath)
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("vmtarget: qemu-img create overlay failed: %s", res.Stderr)
	}
	return nil
}

// defineAndStart writes the domain XML, defines it persistently, then
// starts it. We define (not create-transient) so status/snapshot queries
// have a stable domain to talk to.
func (m *Manager) defineAndStart(ctx context.Context, t *Target) error {
	xml := renderDomainXML(t)
	xmlPath := filepath.Join(t.Dir, "domain.xml")
	if err := os.WriteFile(xmlPath, []byte(xml), 0o644); err != nil {
		return fmt.Errorf("vmtarget: write domain xml: %w", err)
	}
	if res, err := m.virsh(ctx, "define", xmlPath); err != nil {
		return err
	} else if res.ExitCode != 0 {
		return fmt.Errorf("vmtarget: virsh define failed: %s", res.Stderr)
	}
	if res, err := m.virsh(ctx, "start", t.Name); err != nil {
		return err
	} else if res.ExitCode != 0 {
		return fmt.Errorf("vmtarget: virsh start failed: %s", res.Stderr)
	}
	return nil
}

// waitForIP waits for the VM to acquire an IP address. We use
// domifaddr (which queries the live kernel ARP table) as the primary
// source, since it immediately reflects the IP the VM is actually using.
// net-dhcp-leases is only used as a fallback to detect stale leases.
//
// This two-source approach fixes the "DHCP table shows old lease" bug:
// - domifaddr always shows the current IP from the kernel ARP table
// - net-dhcp-leases may show stale leases from previous VM runs
//
// Bounded by bootTimeout (passed in so a per-Up override does not have to
// mutate shared Manager state). Progress is reported to stderr.
func (m *Manager) waitForIP(ctx context.Context, t *Target, preExisting map[string]time.Time, bootTimeout time.Duration) error {
	deadline := m.now().Add(bootTimeout)
	var lastDetail string
	lastReport := m.now()

	for {
		// Primary: try domifaddr first (kernel ARP, always current).
		ip, err := m.getIPFromDomifaddr(ctx, t.Name)
		if err == nil && ip != "" {
			// Found an IP via domifaddr. This is authoritative.
			t.IP = ip
			return nil
		}
		if err != nil {
			lastDetail = err.Error()
		} else {
			lastDetail = "no IP from domifaddr yet"
		}

		// Fallback: check net-dhcp-leases for a fresh lease.
		//
		// MAC-strict: we accept ONLY a lease whose MAC is ours. We must
		// never fall back to "the latest lease overall" here: on a shared
		// network vm2 boots while vm1 already holds a lease, and an
		// any-lease fallback would hand vm2 vm1's IP during the window
		// before vm2 has DHCPed. Since Up allocates a static reservation
		// for our exact MAC before boot, our lease is guaranteed to appear
		// under our MAC once the VM leases — there is no legitimate reason
		// to accept some other VM's address.
		res, err := m.virsh(ctx, "net-dhcp-leases", t.Network)
		if err == nil && res.ExitCode == 0 {
			dhcpIP, expiry := macLeaseInfo(res.Stdout, t.MAC)
			if dhcpIP != "" {
				preExp, ok := preExisting[dhcpIP]
				if !ok || !expiry.Equal(preExp) {
					t.IP = dhcpIP
					return nil
				}
				lastDetail = fmt.Sprintf("stale pre-existing lease %s (exp %s), waiting for renewal", dhcpIP, expiry.Format("15:04:05"))
			} else {
				lastDetail = fmt.Sprintf("no active lease for MAC %s yet", t.MAC)
			}
		}

		if m.now().After(deadline) {
			tail := ""
			if lastDetail != "" {
				tail = fmt.Sprintf("; last: %s", lastDetail)
			}
			return fmt.Errorf("vmtarget: timed out waiting for %q to acquire an IP (waited %s)%s", t.Name, bootTimeout, tail)
		}
		// Periodic progress.
		if m.now().Sub(lastReport) >= 10*time.Second {
			elapsed := m.now().Sub(deadline.Add(-bootTimeout)).Round(time.Second)
			suffix := ""
			if lastDetail != "" {
				suffix = fmt.Sprintf("  (%s)", lastDetail)
			}
			fmt.Fprintf(os.Stderr, "  … %s waiting for IP (elapsed %s)%s\n", t.Name, elapsed, suffix)
			lastReport = m.now()
		}
		if err := sleep(ctx, m.pollInterval); err != nil {
			return err
		}
	}
}

// getIPFromDomifaddr runs "virsh domifaddr <name>" and returns the IPv4
// address, or "" if not found. Returns an error only on virsh failure.
func (m *Manager) getIPFromDomifaddr(ctx context.Context, name string) (string, error) {
	res, err := m.virsh(ctx, "domifaddr", name)
	if err != nil {
		return "", fmt.Errorf("domifaddr: %w", err)
	}
	if res.ExitCode != 0 {
		return "", fmt.Errorf("domifaddr exit %d: %s", res.ExitCode, res.Stderr)
	}
	// Parse "vnetN  MAC  ipv4  IP/24" lines.
	ip := ipv4CIDR.FindString(res.Stdout)
	if ip == "" {
		return "", fmt.Errorf("no IP in domifaddr output")
	}
	if idx := strings.Index(ip, "/"); idx >= 0 {
		ip = ip[:idx]
	}
	return ip, nil
}

// waitForSSH blocks until the VM answers SSH with the injected key, i.e.
// cloud-init has applied the key and sshd is up. Bounded by sshTimeout
// (passed in so a per-Up override does not have to mutate shared Manager
// state). Progress and the last diagnostic are reported to stderr.
func (m *Manager) waitForSSH(ctx context.Context, t *Target, sshTimeout time.Duration) error {
	deadline := m.now().Add(sshTimeout)
	var lastDetail string
	lastReport := m.now()
	for {
		res, err := m.ssh(ctx, t, []string{"true"})
		if err == nil && res.ExitCode == 0 {
			return nil
		}
		// Capture the last meaningful diagnostic.
		if err != nil {
			lastDetail = err.Error()
		} else if res.ExitCode != 0 {
			detail := strings.TrimSpace(res.Stderr)
			if detail == "" {
				detail = fmt.Sprintf("exit code %d (no stderr)", res.ExitCode)
			}
			lastDetail = detail
		}
		if m.now().After(deadline) {
			tail := ""
			if lastDetail != "" {
				tail = fmt.Sprintf("; last: %s", lastDetail)
			}
			return fmt.Errorf("vmtarget: timed out waiting for %q to answer SSH at %s (waited %s)%s", t.Name, t.IP, sshTimeout, tail)
		}
		// Periodic progress.
		if m.now().Sub(lastReport) >= 10*time.Second {
			elapsed := m.now().Sub(deadline.Add(-sshTimeout)).Round(time.Second)
			suffix := ""
			if lastDetail != "" {
				suffix = fmt.Sprintf("  (%s)", lastDetail)
			}
			fmt.Fprintf(os.Stderr, "  … %s waiting for SSH at %s (elapsed %s)%s\n", t.Name, t.IP, elapsed, suffix)
			lastReport = m.now()
		}
		if err := sleep(ctx, m.pollInterval); err != nil {
			return err
		}
	}
}

// teardown best-effort removes a domain and its on-disk artifacts. Used
// both by Down and by Up's failure path.
func (m *Manager) teardown(ctx context.Context, t *Target) {
	_, _ = m.virsh(ctx, "destroy", t.Name) // ignore "not running"
	// undefine MUST clear snapshot (and managed-save / nvram) metadata,
	// or libvirt refuses to undefine any domain that has ever been
	// snapshotted — leaving a dangling defined domain pointing at a disk
	// we are about to delete. The internal qcow2 snapshots live inside
	// the overlay, which RemoveAll below discards anyway.
	_, _ = m.virsh(ctx, "undefine", t.Name,
		"--snapshots-metadata", "--managed-save", "--nvram") // ignore "not found"
	if err := m.removeStaticIP(ctx, t); err != nil {
		fmt.Fprintf(os.Stderr, "  warning: failed to remove static IP reservation for %s: %v\n", t.Name, err)
	}
	if t.Dir != "" {
		_ = os.RemoveAll(t.Dir)
	}
}

// ---- Down -----------------------------------------------------------------

// Down destroys the VM, undefines the domain, removes the per-target
// artifacts, and drops the state record. Idempotent: a target whose
// domain is already gone still has its state cleaned and returns nil.
// An unknown name errors so the CLI can surface a typo.
func (m *Manager) Down(ctx context.Context, name string) error {
	if name == "" {
		return errors.New("vmtarget: name is required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	s, err := m.load()
	if err != nil {
		return err
	}
	idx := -1
	for i, t := range s.Targets {
		if t.Name == name {
			idx = i
			break
		}
	}
	if idx < 0 {
		return fmt.Errorf("vmtarget: no target named %q in state", name)
	}
	t := s.Targets[idx]
	m.teardown(ctx, &t)
	s.Targets = append(s.Targets[:idx], s.Targets[idx+1:]...)
	return m.save(s)
}

// ---- Get / List -----------------------------------------------------------

func (m *Manager) Get(ctx context.Context, name string) (*Target, error) {
	if name == "" {
		return nil, errors.New("vmtarget: name is required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s, err := m.load()
	if err != nil {
		return nil, err
	}
	for _, t := range s.Targets {
		if t.Name == name {
			live := t
			live.Status = m.refreshStatus(ctx, t)
			return &live, nil
		}
	}
	return nil, fmt.Errorf("vmtarget: no target named %q", name)
}

func (m *Manager) List(ctx context.Context) ([]Target, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, err := m.load()
	if err != nil {
		return nil, err
	}
	out := make([]Target, 0, len(s.Targets))
	for _, t := range s.Targets {
		live := t
		live.Status = m.refreshStatus(ctx, t)
		out = append(out, live)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// refreshStatus is only safe with m.mu held. `virsh domstate` reports
// "running" / "shut off" / etc; anything we can't read is Missing.
func (m *Manager) refreshStatus(ctx context.Context, t Target) Status {
	res, err := m.virsh(ctx, "domstate", t.Name)
	if err != nil || res.ExitCode != 0 {
		return StatusMissing
	}
	switch strings.TrimSpace(strings.ToLower(res.Stdout)) {
	case "running":
		return StatusRunning
	case "shut off", "shutoff", "crashed", "paused", "pmsuspended":
		return StatusStopped
	default:
		return StatusMissing
	}
}

// ---- Exec -----------------------------------------------------------------

// Exec runs argv inside the VM over SSH. argv is passed positionally; no
// host shell is involved (matches dockertarget's no-shell contract). For
// shell features the caller invokes `sh -c "<cmd>"` themselves.
func (m *Manager) Exec(ctx context.Context, name string, argv []string) (*cmdResult, error) {
	if name == "" {
		return nil, errors.New("vmtarget: name is required")
	}
	if len(argv) == 0 {
		return nil, errors.New("vmtarget: argv is required")
	}
	t, err := m.Get(ctx, name)
	if err != nil {
		return nil, err
	}
	if t.IP == "" {
		return nil, fmt.Errorf("vmtarget: target %q has no IP yet", name)
	}
	return m.ssh(ctx, t, argv)
}

// ---- Snapshot / Rollback (delegated to libvirt) ---------------------------

// Snapshot captures the VM's current disk+memory state under a tag via
// libvirt's qcow2 snapshot support. Mirrors `pilot docker-target
// snapshot` but is atomic and exact (libvirt owns the correctness).
func (m *Manager) Snapshot(ctx context.Context, name, tag string) error {
	if name == "" || tag == "" {
		return errors.New("vmtarget: name and tag are required")
	}
	t, err := m.Get(ctx, name)
	if err != nil {
		return err
	}
	res, err := m.virsh(ctx, "snapshot-create-as", t.Name, tag)
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("vmtarget: snapshot-create-as failed: %s", res.Stderr)
	}
	return nil
}

// Rollback reverts the VM to a previously captured snapshot tag.
func (m *Manager) Rollback(ctx context.Context, name, tag string) error {
	if name == "" || tag == "" {
		return errors.New("vmtarget: name and tag are required")
	}
	t, err := m.Get(ctx, name)
	if err != nil {
		return err
	}
	res, err := m.virsh(ctx, "snapshot-revert", t.Name, tag)
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("vmtarget: snapshot-revert failed: %s", res.Stderr)
	}
	return nil
}

// Reset reverts the target to the automatic "clean" checkpoint captured
// at Up time. It is the fast path for the dev/test loop: instead of
// `down` + `up` (a full reprovision + boot wait), reset restores the
// pristine post-boot state in seconds.
func (m *Manager) Reset(ctx context.Context, name string) error {
	if err := m.Rollback(ctx, name, CleanSnapshotTag); err != nil {
		return fmt.Errorf("vmtarget: reset to %q snapshot failed — if the VM predates auto-snapshot, capture one with `vm-target snapshot --name %s --tag %s`: %w", CleanSnapshotTag, name, CleanSnapshotTag, err)
	}
	return nil
}

// ---- RenderInventory ------------------------------------------------------

// RenderInventory renders a YAML inventory targeting this VM via
// ansible_connection=ssh. The primary host key is the target Name;
// every alias in t.Hosts (passed as `--hosts dns,ntp,keycloak` at
// `up` time) appears twice:
//   - as a top-level host in `all.hosts`, so `-l <alias>` works
//   - as a single-host child group in `all.children`, so
//     `hosts: "{{ target_group }}"` apply playbooks can pick
//     a role-specific group without the user hand-writing an
//     inventory file.
//
// This is what lets `pilot vm-target run` + a role-gated apply
// playbook (`-e infra_role=dns -e target_group=dns`) work end-to-end
// with no human-built inventory.
func (t *Target) RenderInventory() (string, error) {
	if t == nil {
		return "", errors.New("vmtarget: nil target")
	}
	if t.IP == "" {
		return "", fmt.Errorf("vmtarget: target %q has no IP yet", t.Name)
	}
	var sb strings.Builder
	sb.WriteString("# Generated by pilot vm-target — do not edit by hand.\n")
	sb.WriteString("all:\n")
	sb.WriteString("  hosts:\n")
	writeHost := func(key string) {
		fmt.Fprintf(&sb, "    %s:\n", key)
		fmt.Fprintf(&sb, "      ansible_connection: ssh\n")
		fmt.Fprintf(&sb, "      ansible_host: %s\n", t.IP)
		fmt.Fprintf(&sb, "      ansible_user: %s\n", t.SSHUser)
		fmt.Fprintf(&sb, "      ansible_port: %d\n", t.SSHPort)
		fmt.Fprintf(&sb, "      ansible_ssh_private_key_file: %s\n", t.KeyPath)
		fmt.Fprintf(&sb, "      ansible_ssh_common_args: -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ControlMaster=auto -o ControlPath=~/.ansible/cp/pilot-%%r@%%h:%%p -o ControlPersist=60s\n")
		// Pipelining collapses each task to a single SSH round-trip
		// (no per-task sftp of the module) — a large win on the many
		// small tasks in a hardening playbook. Cloud images have no
		// sudoers `requiretty`, so this is safe. Belt-and-suspenders
		// with the repo ansible.cfg for when ansible is run from a
		// different cwd (e.g. a staged temp inventory).
		fmt.Fprintf(&sb, "      ansible_ssh_pipelining: true\n")
	}
	writeHost(t.Name)
	// Aliases that are NOT the primary name become both a host entry
	// AND a child group. The primary is also a self-group (children:
	// primary) so playbooks that pin to the primary by name also work.
	for _, h := range t.Hosts {
		if h == t.Name {
			continue
		}
		writeHost(h)
	}
	// We used to emit alias-name child groups here, but they trigger
	// ansible's `[WARNING]: Found both group and host with same name`
	// because the alias host entries above are also present. The
	// child groups are not actually needed: an alias host entry in
	// all.hosts.<alias> already lets `hosts: <alias>` and
	// `ansible -i inv <alias>` both match. The apply playbook's
	// `hosts: "{{ target_group | default(infra_role) }}"` then
	// resolves to the alias name, and ansible matches the host
	// directly — no group required.
	return sb.String(), nil
}

// ---- helpers --------------------------------------------------------------

// macFor derives a deterministic, locally-administered MAC from the
// target name using the QEMU OUI (52:54:00). Deterministic so the same
// target always claims the same DHCP lease.
func macFor(name string) string {
	sum := sha256.Sum256([]byte(name))
	return fmt.Sprintf("52:54:00:%02x:%02x:%02x", sum[0], sum[1], sum[2])
}

// dedupeHosts builds the alias list with the primary name first, then
// de-duplicated valid extras (invalid extras are silently dropped here;
// Up validates the primary name separately).
func dedupeHosts(primary string, extra []string) []string {
	hosts := []string{primary}
	seen := map[string]bool{primary: true}
	for _, h := range extra {
		if !seen[h] && validName(h) {
			hosts = append(hosts, h)
			seen[h] = true
		}
	}
	return hosts
}

var ipv4CIDR = regexp.MustCompile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/\d+`)

// captureLeaseSet queries net-dhcp-leases and returns a set of
// (IP → expiry) for the given MAC ONLY. Used by Up to snapshot the
// pre-existing state before starting the VM, so waitForIP can
// ignore stale leases from previous runs.
//
// NOTE: we only collect leases for THIS MAC. Collecting leases for all
// MACs caused the "IP conflict" bug where a new VM would see another
// host's old lease and incorrectly treat it as pre-existing, causing
// waitForIP to skip the new lease and use the wrong IP.
func (m *Manager) captureLeaseSet(ctx context.Context, network, mac string) map[string]time.Time {
	set := make(map[string]time.Time)
	res, err := m.virsh(ctx, "net-dhcp-leases", network)
	if err != nil || res.ExitCode != 0 {
		return set
	}
	lines := strings.Split(res.Stdout, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, mac) {
			continue
		}
		ip := ipv4CIDR.FindString(line)
		if ip == "" {
			continue
		}
		if idx := strings.Index(ip, "/"); idx >= 0 {
			ip = ip[:idx]
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			ts := fields[0] + " " + fields[1]
			if t, err := time.Parse("2006-01-02 15:04:05", ts); err == nil {
				set[ip] = t
			}
		}
	}
	return set
}

// withNetworkLock serializes libvirt network mutations (static DHCP host
// entries) ACROSS processes via an advisory file lock. allocateStaticIP and
// removeStaticIP each do a read-modify-write on the network XML through
// `virsh net-update`; the Manager mutex only covers one process, so without
// this lock two concurrent `pilot vm-target up` invocations could scan the
// same free IP and reserve it for two different VMs. The lock file lives
// next to the state json and is created on demand.
func (m *Manager) withNetworkLock(fn func() error) error {
	lockPath := filepath.Join(m.stateDir, "network.lock")
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return fmt.Errorf("vmtarget: open network lock %s: %w", lockPath, err)
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("vmtarget: acquire network lock: %w", err)
	}
	defer func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }()
	return fn()
}

// macLeaseInfo returns the latest-expiring lease belonging to mac ONLY,
// or ("", zero) if mac has no lease. Unlike latestLeaseInfo it never
// falls back to another host's lease — this is what waitForIP needs so a
// booting VM cannot latch onto a sibling VM's address during the window
// before it has acquired its own lease.
func macLeaseInfo(out, mac string) (string, time.Time) {
	var ip string
	var expiry time.Time
	if mac == "" {
		return "", time.Time{}
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, mac) {
			continue
		}
		leaseIP := ipv4CIDR.FindString(line)
		if leaseIP == "" {
			continue
		}
		if idx := strings.Index(leaseIP, "/"); idx >= 0 {
			leaseIP = leaseIP[:idx]
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		exp, err := time.Parse("2006-01-02 15:04:05", fields[0]+" "+fields[1])
		if err != nil {
			continue
		}
		if exp.After(expiry) {
			expiry = exp
			ip = leaseIP
		}
	}
	return ip, expiry
}

// validName mirrors dockertarget.validName so names are portable across
// the inventory, state file, libvirt domain name, and CLI.
func validName(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '_' || r == '.' || r == '-':
		default:
			return false
		}
	}
	return true
}

// sleep is a context-aware sleep used by the polling loops.
func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// ---- Static DHCP Reservation (IP conflict prevention) -----------------------

// allocateStaticIP finds an unused IP in the network's DHCP range and
// registers a permanent <host> entry so the VM always gets the same address.
// This prevents the "two VMs get the same IP" problem that occurs when:
//  1. VM A has an active lease for IP X
//  2. VM B's deterministic MAC produces the same lease, DHCP gives X again
//  3. → IP conflict, neither VM can be reached reliably
//
// The reservation is persistent (written to network config), so even after
// host reboots the static entries survive.
//
// Returns the allocated IP string, or an error.
//
// The whole scan-then-reserve is done under a cross-process file lock: the
// in-process mutex (m.mu) only serializes Up calls within one process, but
// two separate `pilot vm-target up` processes would otherwise both
// net-dumpxml, both pick the same first-free IP, and hand it to two VMs.
func (m *Manager) allocateStaticIP(ctx context.Context, t *Target) (string, error) {
	var ip string
	err := m.withNetworkLock(func() error {
		var e error
		ip, e = m.allocateStaticIPLocked(ctx, t)
		return e
	})
	return ip, err
}

func (m *Manager) allocateStaticIPLocked(ctx context.Context, t *Target) (string, error) {
	network := t.Network
	if network == "" {
		network = "default"
	}

	// 1. Get current network XML so we know the DHCP range.
	netRes, err := m.virsh(ctx, "net-dumpxml", network)
	if err != nil {
		return "", fmt.Errorf("vmtarget: net-dumpxml %s: %w", network, err)
	}
	if netRes.ExitCode != 0 {
		return "", fmt.Errorf("vmtarget: net-dumpxml %s failed: %s", network, netRes.Stderr)
	}

	// If a static IP reservation already exists for this MAC, reuse it.
	if existingIP := findStaticIPForMAC(netRes.Stdout, t.MAC); existingIP != "" {
		fmt.Fprintf(os.Stderr, "  ✓ reusing existing static IP %s for %s (MAC %s) on network %s\n",
			existingIP, t.Name, t.MAC, network)
		return existingIP, nil
	}

	// 2. Parse the DHCP range and existing static <host> entries from XML.
	rangeStart, rangeEnd, err := parseDHCPRange(netRes.Stdout)
	if err != nil {
		return "", fmt.Errorf("vmtarget: parse DHCP range from network %s: %w", network, err)
	}

	// 3. Collect all IPs already in use: dynamic leases + static <host> entries.
	used := make(map[string]bool)
	if err := m.collectUsedIPs(ctx, network, netRes.Stdout, used); err != nil {
		return "", fmt.Errorf("vmtarget: collect used IPs: %w", err)
	}

	// 4. Scan the DHCP range for the first unused IP.
	ip, err := findFreeIP(rangeStart, rangeEnd, used)
	if err != nil {
		return "", fmt.Errorf("vmtarget: no free IP in range %s-%s: %w", rangeStart, rangeEnd, err)
	}

	// 5. Register the static host entry with libvirt.
	//    This makes the DHCP server always give `ip` to `t.MAC`.
	hostXML := fmt.Sprintf(`<host mac='%s' ip='%s'/>`, t.MAC, ip)
	res, err := m.virsh(ctx, "net-update", network, "add", "ip-dhcp-host",
		"--live", "--config", hostXML)
	if err != nil {
		return "", fmt.Errorf("vmtarget: net-update add ip-dhcp-host: %w", err)
	}
	if res.ExitCode != 0 {
		return "", fmt.Errorf("vmtarget: net-update failed: %s", res.Stderr)
	}

	fmt.Fprintf(os.Stderr, "  ✓ reserved static IP %s for %s (MAC %s) on network %s\n",
		ip, t.Name, t.MAC, network)
	return ip, nil
}

// parseDHCPRange extracts <range start='x.x.x.x' end='y.y.y.y'/> from the
// libvirt network XML.
func parseDHCPRange(xmlContent string) (start, end string, err error) {
	startRe := regexp.MustCompile(`(?i)<range[^>]+start=['"]([\d.]+)['"][^>]*/?>`)
	endRe := regexp.MustCompile(`(?i)<range[^>]+end=['"]([\d.]+)['"][^>]*/?>`)

	sm := startRe.FindStringSubmatch(xmlContent)
	em := endRe.FindStringSubmatch(xmlContent)
	if len(sm) < 2 || len(em) < 2 {
		return "", "", fmt.Errorf("no <range start=... end=...> found in network XML")
	}
	return sm[1], em[1], nil
}

// collectUsedIPs populates `used` with every IP currently in use on the
// network: dynamic DHCP leases from net-dhcp-leases, plus static <host>
// entries parsed from the network XML.
func (m *Manager) collectUsedIPs(ctx context.Context, network, netXML string, used map[string]bool) error {
	// Dynamic leases.
	res, err := m.virsh(ctx, "net-dhcp-leases", network)
	if err == nil && res.ExitCode == 0 {
		for _, ip := range extractIPsFromLeases(res.Stdout) {
			used[ip] = true
		}
	}

	// Static <host> entries already configured in the network.
	for _, ip := range extractStaticHostIPs(netXML) {
		used[ip] = true
	}

	return nil
}

// extractIPsFromLeases parses `virsh net-dhcp-leases` output and returns all
// assigned IPs (without the /prefix).
func extractIPsFromLeases(output string) []string {
	var ips []string
	re := regexp.MustCompile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/\d+`)
	for _, match := range re.FindAllStringSubmatch(output, -1) {
		if len(match) >= 2 {
			ips = append(ips, match[1])
		}
	}
	return ips
}

// extractStaticHostIPs parses <host mac='...' ip='x.x.x.x'/> entries from the
// libvirt network XML and returns the IP addresses.
func extractStaticHostIPs(xmlContent string) []string {
	var ips []string
	re := regexp.MustCompile(`(?i)<host[^>]+ip=['"]([\d.]+)['"][^>]*/?>`)
	for _, match := range re.FindAllStringSubmatch(xmlContent, -1) {
		if len(match) >= 2 {
			ips = append(ips, match[1])
		}
	}
	return ips
}

// ipToUint32 and uint32ToIP convert a dotted-quad IPv4 address to a uint32
// and back, for numeric range scanning.
func ipToUint32(ipStr string) (uint32, error) {
	var b [4]byte
	if _, err := fmt.Fscanf(strings.NewReader(ipStr), "%d.%d.%d.%d",
		&b[0], &b[1], &b[2], &b[3]); err != nil {
		return 0, err
	}
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]), nil
}

func uint32ToIP(n uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}

// findFreeIP scans from rangeStart to rangeEnd (inclusive) and returns the
// first IP not in `used`. rangeStart and rangeEnd are inclusive.
func findFreeIP(rangeStart, rangeEnd string, used map[string]bool) (string, error) {
	start, err := ipToUint32(rangeStart)
	if err != nil {
		return "", err
	}
	end, err := ipToUint32(rangeEnd)
	if err != nil {
		return "", err
	}
	if end < start {
		return "", fmt.Errorf("range end %s < start %s", rangeEnd, rangeStart)
	}
	for ip := start; ip <= end; ip++ {
		s := uint32ToIP(ip)
		if !used[s] {
			return s, nil
		}
	}
	return "", fmt.Errorf("no free IP in range %s-%s", rangeStart, rangeEnd)
}

// removeStaticIP deletes the static DHCP host reservation for the target.
// Held under the same cross-process network lock as allocateStaticIP so a
// concurrent teardown and bring-up cannot interleave their read-modify-write
// of the network's <host> entries.
func (m *Manager) removeStaticIP(ctx context.Context, t *Target) error {
	return m.withNetworkLock(func() error { return m.removeStaticIPLocked(ctx, t) })
}

func (m *Manager) removeStaticIPLocked(ctx context.Context, t *Target) error {
	network := t.Network
	if network == "" {
		network = "default"
	}
	netRes, err := m.virsh(ctx, "net-dumpxml", network)
	if err != nil {
		return fmt.Errorf("net-dumpxml %s: %w", network, err)
	}
	if netRes.ExitCode != 0 {
		return fmt.Errorf("net-dumpxml %s failed: %s", network, netRes.Stderr)
	}

	ip := findStaticIPForMAC(netRes.Stdout, t.MAC)
	if ip == "" {
		return nil
	}

	hostXML := fmt.Sprintf(`<host mac='%s' ip='%s'/>`, t.MAC, ip)
	res, err := m.virsh(ctx, "net-update", network, "delete", "ip-dhcp-host",
		"--live", "--config", hostXML)
	if err != nil {
		return fmt.Errorf("net-update delete ip-dhcp-host: %w", err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("net-update delete failed: %s", res.Stderr)
	}
	return nil
}

// findStaticIPForMAC extracts the ip address allocated to mac from the libvirt network XML.
func findStaticIPForMAC(xmlContent, mac string) string {
	re := regexp.MustCompile(`(?i)<host\s+([^>]+)/?>`)
	matches := re.FindAllStringSubmatch(xmlContent, -1)
	for _, m := range matches {
		attrs := m[1]
		if strings.Contains(strings.ToLower(attrs), strings.ToLower(mac)) {
			ipRe := regexp.MustCompile(`(?i)ip=['"]([\d.]+)['"]`)
			ipMatch := ipRe.FindStringSubmatch(attrs)
			if len(ipMatch) >= 2 {
				return ipMatch[1]
			}
		}
	}
	return ""
}
