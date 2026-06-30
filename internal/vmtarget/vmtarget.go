// Package vmtarget manages "QEMU/KVM virtual machines used as target
// hosts" for pilot. It is the higher-fidelity sibling of
// internal/dockertarget:
//
//   - internal/dockertarget  a docker container as a disposable target
//                            host (shares the host kernel; great for
//                            package/config/systemd-service testing).
//
//   - internal/vmtarget      a real VM as a disposable target host
//                            (its own kernel; needed for kernel modules,
//                            reboot/bootloader, LVM/filesystem, SELinux
//                            enforcing, real networking — anything a
//                            shared-kernel container cannot faithfully
//                            reproduce).
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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
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
	Name      string // required; domain name AND ansible host key
	BaseImage string // required; path to a qcow2 cloud image (read-only backing)
	SSHUser   string // login user created/authorised via cloud-init; default "root"
	VCPUs     int    // default 2
	MemoryMB  int    // default 2048
	Network   string // libvirt network name; default "default"
	Hosts     []string
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
	mu        sync.Mutex
	stateDir  string
	stateFile string
	vmDir     string // where per-target qcow2/seed live (libvirt-accessible)
	now       func() time.Time

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
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		return nil, fmt.Errorf("vmtarget: mkdir %s: %w", stateDir, err)
	}
	return &Manager{
		stateDir:     stateDir,
		stateFile:    filepath.Join(stateDir, "vm-targets.json"),
		vmDir:        vmDir,
		now:          time.Now,
		bootTimeout:  3 * time.Minute,
		sshTimeout:   2 * time.Minute,
		pollInterval: 2 * time.Second,
	}, nil
}

// ---- state load/save (atomic; mirrors dockertarget) -----------------------

func (m *Manager) load() (*state, error) {
	data, err := os.ReadFile(m.stateFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &state{Version: stateVersion}, nil
		}
		return nil, fmt.Errorf("vmtarget: read state: %w", err)
	}
	var s state
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("vmtarget: parse state: %w", err)
	}
	if s.Version != stateVersion {
		return nil, fmt.Errorf("vmtarget: state version %d (want %d); refusing to load", s.Version, stateVersion)
	}
	return &s, nil
}

func (m *Manager) save(s *state) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("vmtarget: marshal state: %w", err)
	}
	tmp, err := os.CreateTemp(m.stateDir, ".vm-targets-*.json.tmp")
	if err != nil {
		return fmt.Errorf("vmtarget: create temp: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("vmtarget: write temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("vmtarget: close temp: %w", err)
	}
	if err := os.Rename(tmpName, m.stateFile); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("vmtarget: rename temp: %w", err)
	}
	return nil
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
	args := sshBaseArgs(t)
	args = append(args, argv...)
	return run(ctx, "PILOT_SSH_BIN", "ssh", 60*time.Second, args...)
}

// sshBaseArgs are the connection flags shared by Exec and readiness
// probing. Host-key checking is disabled because the VM is disposable
// and its host key changes on every recreate — the security tradeoff is
// intentional for throwaway test targets (mirrors the docker-target
// stance of not caring about target hardening).
func sshBaseArgs(t *Target) []string {
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
func (m *Manager) Up(ctx context.Context, opt Options) (*Target, error) {
	if opt.Name == "" {
		return nil, errors.New("vmtarget: name is required")
	}
	if !validName(opt.Name) {
		return nil, fmt.Errorf("vmtarget: invalid name %q (want [a-zA-Z0-9_.-]+)", opt.Name)
	}
	if opt.BaseImage == "" {
		return nil, errors.New("vmtarget: base image is required")
	}
	baseAbs, err := filepath.Abs(opt.BaseImage)
	if err != nil {
		return nil, fmt.Errorf("vmtarget: resolve base image: %w", err)
	}
	if _, err := os.Stat(baseAbs); err != nil {
		return nil, fmt.Errorf("vmtarget: base image %s: %w", baseAbs, err)
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
	if err = m.defineAndStart(ctx, tg); err != nil {
		return nil, err
	}
	if err = m.waitForIP(ctx, tg); err != nil {
		return nil, err
	}
	if err = m.waitForSSH(ctx, tg); err != nil {
		return nil, err
	}
	tg.Status = StatusRunning

	s.Targets = append(s.Targets, *tg)
	if err = m.save(s); err != nil {
		return nil, err
	}
	return tg, nil
}

// generateKey writes an ephemeral ed25519 keypair into the target dir.
func (m *Manager) generateKey(ctx context.Context, t *Target) error {
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

// waitForIP polls libvirt for the VM's DHCP lease. We use the lease (not
// a guess) as the authoritative address; this removes the classic
// "what IP did it get" race. Bounded by bootTimeout.
func (m *Manager) waitForIP(ctx context.Context, t *Target) error {
	deadline := m.now().Add(m.bootTimeout)
	for {
		res, err := m.virsh(ctx, "domifaddr", t.Name, "--source", "lease")
		if err == nil && res.ExitCode == 0 {
			if ip := parseDomifaddr(res.Stdout); ip != "" {
				t.IP = ip
				return nil
			}
		}
		if m.now().After(deadline) {
			return fmt.Errorf("vmtarget: timed out waiting for %q to acquire an IP (waited %s)", t.Name, m.bootTimeout)
		}
		if err := sleep(ctx, m.pollInterval); err != nil {
			return err
		}
	}
}

// waitForSSH blocks until the VM answers SSH with the injected key, i.e.
// cloud-init has applied the key and sshd is up. Bounded by sshTimeout.
func (m *Manager) waitForSSH(ctx context.Context, t *Target) error {
	deadline := m.now().Add(m.sshTimeout)
	for {
		res, err := m.ssh(ctx, t, []string{"true"})
		if err == nil && res.ExitCode == 0 {
			return nil
		}
		if m.now().After(deadline) {
			return fmt.Errorf("vmtarget: timed out waiting for %q to answer SSH at %s (waited %s)", t.Name, t.IP, m.sshTimeout)
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

// ---- RenderInventory ------------------------------------------------------

// RenderInventory renders a YAML inventory targeting this VM via
// ansible_connection=ssh. The primary host key is the target Name; any
// Hosts aliases route to the same IP (mirrors dockertarget).
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
		fmt.Fprintf(&sb, "      ansible_ssh_common_args: -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null\n")
	}
	writeHost(t.Name)
	for _, h := range t.Hosts {
		if h == t.Name {
			continue
		}
		writeHost(h)
	}
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

// parseDomifaddr extracts the first IPv4 address from `virsh domifaddr`
// output (which prints "192.168.122.45/24" in the Address column).
func parseDomifaddr(out string) string {
	if m := ipv4CIDR.FindStringSubmatch(out); m != nil {
		return m[1]
	}
	return ""
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
