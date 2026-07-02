package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/anomalyco/pilot/internal/sandbox"
	"github.com/anomalyco/pilot/internal/vmtarget"
)

// vmTargetCmd is the parent for `pilot vm-target ...` — the QEMU/KVM
// sibling of `pilot docker-target`. Use it when a shared-kernel
// container can't faithfully reproduce the target: kernel modules,
// reboot/bootloader, LVM/filesystem, SELinux enforcing, real networking.
//
// A vm-target renders an `ansible_connection: ssh` inventory, so the
// same run/verify plumbing as docker-target applies — only the
// connection plugin differs.
var vmTargetCmd = &cobra.Command{
	Use:   "vm-target",
	Short: "Manage QEMU/KVM virtual machines used as Ansible target hosts",
	Long: `vm-target treats a libvirt/KVM virtual machine as a disposable VM.

Higher fidelity than docker-target (its own kernel), at the cost of boot
time and a KVM-capable host. Provisioning is via cloud-init; the VM is
backed by a per-target qcow2 overlay on an immutable base image, so a
fresh up is always pristine and rollback is byte-clean.

Typical flow:
  pilot vm-target up --base-image ~/images/ubuntu-24.04.qcow2 --name infra-vm
  pilot vm-target run    --name infra-vm playbooks/apply/<x>.yml -e ...
  pilot vm-target verify --name infra-vm docs/verification/<x>.md
  pilot vm-target exec   --name infra-vm -- uname -a
  pilot vm-target down   --name infra-vm

State (json) lives under cfg.DataDir/vm-targets.json; the qcow2 overlays
and seed ISOs live under --vm-dir (default /var/lib/libvirt/images/pilot,
which the libvirt qemu process can access).
`,
}

func init() {
	rootCmd.AddCommand(vmTargetCmd)
	vmTargetCmd.AddCommand(vtUpCmd)
	vmTargetCmd.AddCommand(vtDownCmd)
	vmTargetCmd.AddCommand(vtListCmd)
	vmTargetCmd.AddCommand(vtShowInventoryCmd)
	vmTargetCmd.AddCommand(vtRunCmd)
	vmTargetCmd.AddCommand(vtVerifyCmd)
	vmTargetCmd.AddCommand(vtExecCmd)
	vmTargetCmd.AddCommand(vtSnapshotCmd)
	vmTargetCmd.AddCommand(vtRollbackCmd)
	vmTargetCmd.AddCommand(vtResetCmd)
	vmTargetCmd.AddCommand(vtSSHCmd)
	vmTargetCmd.AddCommand(vtShellCmd)
	vmTargetCmd.AddCommand(vtTestCmd)
}

// ---- shared flags ---------------------------------------------------------

var (
	vtName        string
	vtBaseImage   string
	vtSSHUser     string
	vtVCPUs       int
	vtMemoryMB    int
	vtNetwork     string
	vtHosts       []string
	vtVMDir       string
	vtSnapTag     string
	vtRollTag     string
	vtSSHTimeout  time.Duration
	vtBootTimeout time.Duration
)

// resolveVMDir returns the directory where per-target qcow2/seed live.
func resolveVMDir() string {
	if vtVMDir != "" {
		return vtVMDir
	}
	return "/var/lib/libvirt/images/pilot"
}

func vtNewManager() (*vmtarget.Manager, error) {
	return vmtarget.NewManager(resolveDataDir(), resolveVMDir())
}

// ---- up -------------------------------------------------------------------

var vtUpCmd = &cobra.Command{
	Use:   "up",
	Short: "Bring up a new VM target (provisions + waits for SSH)",
	Long: `Provision a libvirt/KVM VM as a disposable Ansible target host.

Blocks until the VM has a DHCP lease and answers SSH with the injected
key, then prints its address.

Examples:
  pilot vm-target up --base-image ~/images/ubuntu-24.04-cloud.qcow2 --name infra-vm
  pilot vm-target up --base-image ./rocky9.qcow2 --name rocky --vcpus 4 --memory 4096
`,
	RunE: runVtUp,
}

func init() {
	vtUpCmd.Flags().StringVar(&vtName, "name", "", "domain name (also ansible host key)")
	vtUpCmd.Flags().StringVar(&vtBaseImage, "base-image", "", "path or alias of qcow2 base image (defaults to ubuntu-24.04)")
	vtUpCmd.Flags().StringVar(&vtSSHUser, "ssh-user", "root", "login user authorised via cloud-init")
	vtUpCmd.Flags().IntVar(&vtVCPUs, "vcpus", 2, "number of vCPUs")
	vtUpCmd.Flags().IntVar(&vtMemoryMB, "memory", 2048, "memory in MiB")
	vtUpCmd.Flags().StringVar(&vtNetwork, "network", "default", "libvirt network name")
	vtUpCmd.Flags().StringSliceVar(&vtHosts, "hosts", nil, "additional ansible host aliases (may repeat); all route to the same VM")
	vtUpCmd.Flags().StringVar(&vtVMDir, "vm-dir", "", "directory for qcow2 overlays/seed ISOs (default /var/lib/libvirt/images/pilot)")
	vtUpCmd.Flags().DurationVar(&vtSSHTimeout, "ssh-timeout", 0, "override SSH readiness timeout (default 2m)")
	vtUpCmd.Flags().DurationVar(&vtBootTimeout, "boot-timeout", 0, "override boot/IP-acquisition timeout (default 3m)")
}

func runVtUp(cmd *cobra.Command, args []string) error {
	if vtName == "" {
		return fmt.Errorf("--name is required")
	}
	if vtBaseImage == "" {
		vtBaseImage = "ubuntu-24.04"
	}
	m, err := vtNewManager()
	if err != nil {
		return err
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "▶ provisioning VM %s (this can take a minute while it boots)…\n", vtName)
	tgt, err := m.Up(context.Background(), vmtarget.Options{
		Name:        vtName,
		BaseImage:   vtBaseImage,
		SSHUser:     vtSSHUser,
		VCPUs:       vtVCPUs,
		MemoryMB:    vtMemoryMB,
		Network:     vtNetwork,
		Hosts:       vtHosts,
		SSHTimeout:  vtSSHTimeout,
		BootTimeout: vtBootTimeout,
	})
	if err != nil {
		return err
	}
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "✓ target %s up\n", tgt.Name)
	fmt.Fprintf(out, "  ip        : %s\n", tgt.IP)
	fmt.Fprintf(out, "  ssh_user  : %s\n", tgt.SSHUser)
	fmt.Fprintf(out, "  base_image: %s\n", tgt.BaseImage)
	fmt.Fprintf(out, "  vcpus/mem : %d / %d MiB\n", tgt.VCPUs, tgt.MemoryMB)
	fmt.Fprintf(out, "  inventory : `pilot vm-target show-inventory --name %s`\n", tgt.Name)
	return nil
}

// ---- down -----------------------------------------------------------------

var vtDownCmd = &cobra.Command{
	Use:   "down",
	Short: "Tear down a VM target (destroy + undefine + clear state)",
	RunE:  runVtDown,
}

func init() { vtDownCmd.Flags().StringVar(&vtName, "name", "", "target name to tear down") }

func runVtDown(cmd *cobra.Command, args []string) error {
	if vtName == "" {
		return fmt.Errorf("--name is required")
	}
	m, err := vtNewManager()
	if err != nil {
		return err
	}
	if err := m.Down(context.Background(), vtName); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "✓ target %s down\n", vtName)
	return nil
}

// ---- list -----------------------------------------------------------------

var vtListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all VM targets with live status",
	RunE:  runVtList,
}

func init() { vtListCmd.Flags().BoolP("json", "j", false, "output as JSON (for scripts)") }

func runVtList(cmd *cobra.Command, args []string) error {
	m, err := vtNewManager()
	if err != nil {
		return err
	}
	all, err := m.List(context.Background())
	if err != nil {
		return err
	}
	if cmd.Flags().Changed("json") {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(all)
	}
	if len(all) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "(no targets — `pilot vm-target up` to start one)")
		return nil
	}
	tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tSTATUS\tIP\tVCPU\tMEM(MiB)\tCREATED")
	for _, t := range all {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%d\t%s\n",
			t.Name, t.Status, t.IP, t.VCPUs, t.MemoryMB, t.CreatedAt.Format("2006-01-02 15:04:05"))
	}
	return tw.Flush()
}

// ---- show-inventory -------------------------------------------------------

var vtShowInventoryCmd = &cobra.Command{
	Use:   "show-inventory",
	Short: "Print the generated SSH inventory for a target (YAML)",
	RunE:  runVtShowInventory,
}

func init() { vtShowInventoryCmd.Flags().StringVar(&vtName, "name", "", "target name") }

func runVtShowInventory(cmd *cobra.Command, args []string) error {
	if vtName == "" {
		return fmt.Errorf("--name is required")
	}
	m, err := vtNewManager()
	if err != nil {
		return err
	}
	t, err := m.Get(context.Background(), vtName)
	if err != nil {
		return err
	}
	inv, err := t.RenderInventory()
	if err != nil {
		return err
	}
	_, err = io.WriteString(cmd.OutOrStdout(), inv)
	return err
}

// ---- run ------------------------------------------------------------------

var vtRunCmd = &cobra.Command{
	Use:   "run <playbook.yml> [<extra>...]",
	Short: "Run an ansible playbook against the VM target",
	Long: `Passes --inventory and --limit automatically based on the target name.
Everything after the playbook is forwarded verbatim to ansible-playbook.

Use --sandbox to run ansible-playbook inside a Docker container instead of
on the host. The container image comes from the config (sandbox.image) or
can be overridden with --sandbox-image. The VM's SSH key is automatically
mounted into the container, so ansible can reach the VM over SSH without
any host-side ansible installation.`,
	Args:               cobra.MinimumNArgs(1),
	DisableFlagParsing: true,
	RunE:               runVtRun,
}

func init() { vtRunCmd.Flags().StringVar(&vtName, "name", "", "target name") }

// extractBoolFlag scans args for a boolean flag (e.g. "--sandbox"),
// removes it from the slice and returns whether it was found.
func extractBoolFlag(args []string, flag string) ([]string, bool) {
	for i, a := range args {
		if a == flag {
			return append(args[:i], args[i+1:]...), true
		}
	}
	return args, false
}

// extractValueFlag scans args for a key-value flag (e.g. "--sandbox-image img"),
// removes both elements, and returns the value. Supports both
// "--flag value" and "--flag=value" forms.
func extractValueFlag(args []string, flag string) ([]string, string) {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			val := args[i+1]
			return append(args[:i], args[i+2:]...), val
		}
		if strings.HasPrefix(a, flag+"=") {
			val := strings.TrimPrefix(a, flag+"=")
			return append(args[:i], args[i+1:]...), val
		}
	}
	return args, ""
}

func runVtRun(cmd *cobra.Command, args []string) error {
	// DisableFlagParsing is on so -e foo=bar flows through to the
	// child ansible-playbook. But we still need to honour --name
	// and --sandbox. Parse them ourselves and strip from `args`.
	if vtName == "" {
		for i := 0; i < len(args); i++ {
			if args[i] == "--name" && i+1 < len(args) {
				vtName = args[i+1]
				args = append(args[:i], args[i+2:]...)
				break
			}
			if strings.HasPrefix(args[i], "--name=") {
				vtName = strings.TrimPrefix(args[i], "--name=")
				args = append(args[:i], args[i+1:]...)
				break
			}
		}
	}

	// Parse --sandbox / --sandbox-image before forwarding to ansible.
	var useSandbox bool
	var sandboxImage string
	args, useSandbox = extractBoolFlag(args, "--sandbox")
	args, sandboxImage = extractValueFlag(args, "--sandbox-image")
	if sandboxImage != "" {
		useSandbox = true
	}

	t, cleanup, invPath, err := vtStageInventory()
	if err != nil {
		return err
	}
	defer cleanup()

	playbook := args[0]
	extra := args[1:]
	ansibleArgs := []string{playbook, "-i", invPath}
	if !extraHasTargetGroup(extra) {
		ansibleArgs = append(ansibleArgs, "-l", t.Name)
	}
	ansibleArgs = append(ansibleArgs, extra...)

	if useSandbox {
		return vtRunViaContainer(cmd, t, playbook, invPath, ansibleArgs, sandboxImage)
	}

	fmt.Fprintf(cmd.ErrOrStderr(), "▶ ansible-playbook %s\n", strings.Join(ansibleArgs, " "))
	return execAnsiblePlaybook(cmd.OutOrStdout(), ansibleArgs...)
}

// containerFixPermsScript builds the /bin/sh script run inside the sandbox
// container before ansible: it copies the bind-mounted key to a path it can
// chmod 600 (the mount may carry a foreign uid/perms), and pre-creates the
// two directories the generated inventory relies on — ~/.ssh (for
// known_hosts) and ~/.ansible/cp (the SSH ControlPath parent). Without the
// latter, ssh's ControlMaster socket creation fails inside the container
// because its parent dir does not exist, breaking every task.
func containerFixPermsScript(cntKeyPath string) string {
	return "cp " + cntKeyPath + " /tmp/pilot-ssh-key" +
		" && chmod 600 /tmp/pilot-ssh-key" +
		" && mkdir -p ~/.ssh ~/.ansible/cp" +
		" && touch ~/.ssh/known_hosts"
}

// vtRunViaContainer runs ansible-playbook inside a Docker container
// while targeting the VM over SSH. It:
//  1. Resolves the sandbox image from the explicit flag or config.
//  2. Starts a sandbox container with --network host and the SSH key
//     bind-mounted read-only.
//  3. docker-cp's the playbook and inventory into the container,
//     rewriting ansible_ssh_private_key_file to the container path.
//  4. docker exec ansible-playbook inside the container.
//  5. Tears down the container.
func vtRunViaContainer(cmd *cobra.Command, t *vmtarget.Target, playbookPath, invPath string, ansibleArgs []string, imageOverride string) error {
	ctx := context.Background()

	// 1. Resolve image: explicit flag > config > error
	image := imageOverride
	if image == "" {
		cfg := loadConfig()
		image = cfg.Sandbox.Image
	}
	if image == "" {
		return fmt.Errorf("--sandbox requires a container image; set sandbox.image in config or pass --sandbox-image")
	}

	// 2. Determine container-side SSH key path
	const cntKeyPath = "/tmp/pilot-ssh/id_ed25519"

	// 3. Rewrite the inventory: replace the host-side SSH key path
	//    with the container-side mount path. Write to a new temp file.
	invData, err := os.ReadFile(invPath)
	if err != nil {
		return fmt.Errorf("read inventory: %w", err)
	}
	rewrittenInv := strings.ReplaceAll(string(invData), t.KeyPath, cntKeyPath)
	cntInvFile, err := os.CreateTemp("", "pilot-vt-sandbox-inv-*.yaml")
	if err != nil {
		return fmt.Errorf("create rewritten inventory: %w", err)
	}
	cntInvPath := cntInvFile.Name()
	defer os.Remove(cntInvPath)
	if _, err := cntInvFile.WriteString(rewrittenInv); err != nil {
		cntInvFile.Close()
		return err
	}
	cntInvFile.Close()

	// 4. Start the container with SSH key mounted using the core DockerEnvironment backend.
	de := sandbox.NewDockerEnvironment(image)
	de.Network = "host"
	de.Mounts = []sandbox.SandboxMount{
		{
			HostPath:      t.KeyPath,
			ContainerPath: cntKeyPath,
			RO:            true,
		},
	}
	cfg := loadConfig()
	if cfg.Sandbox.Pull != "" {
		de.Pull = cfg.Sandbox.Pull
	}

	fmt.Fprintf(cmd.ErrOrStderr(), "📦 starting sandbox container (%s)...\n", image)
	if err := de.Start(ctx); err != nil {
		return fmt.Errorf("failed to start sandbox container: %w", err)
	}
	containerID := de.ContainerName
	defer func() {
		fmt.Fprintf(cmd.ErrOrStderr(), "📦 stopping sandbox container...\n")
		_ = de.Stop(context.Background())
	}()

	// 6. Fix SSH key permissions inside the container (bind mount
	//    may have different uid). Also create ~/.ssh/known_hosts and the
	//    ControlPath parent dir the generated inventory expects.
	fixPerms := newCmd(ctx, "docker", "exec", containerID,
		"/bin/sh", "-c", containerFixPermsScript(cntKeyPath))
	if out, err := fixPerms.CombinedOutput(); err != nil {
		return fmt.Errorf("fix SSH key permissions: %w\n%s", err, string(out))
	}
	// Rewrite inventory to use the copied key with correct perms
	rewrittenInv = strings.ReplaceAll(rewrittenInv, cntKeyPath, "/tmp/pilot-ssh-key")
	if err := os.WriteFile(cntInvPath, []byte(rewrittenInv), 0o644); err != nil {
		return fmt.Errorf("rewrite inventory for copied key: %w", err)
	}

	// 7. docker cp playbook + inventory into the container
	pbCnt := "/tmp/pilot-playbook.yml"
	cpPb := newCmd(ctx, "docker", "cp", playbookPath, containerID+":"+pbCnt)
	if out, err := cpPb.CombinedOutput(); err != nil {
		return fmt.Errorf("docker cp playbook: %w\n%s", err, string(out))
	}

	invCnt := "/tmp/pilot-inventory.yaml"
	cpInv := newCmd(ctx, "docker", "cp", cntInvPath, containerID+":"+invCnt)
	if out, err := cpInv.CombinedOutput(); err != nil {
		return fmt.Errorf("docker cp inventory: %w\n%s", err, string(out))
	}

	// 8. Rewrite ansibleArgs: replace host paths with container paths
	cntAnsibleArgs := make([]string, len(ansibleArgs))
	copy(cntAnsibleArgs, ansibleArgs)
	for i, a := range cntAnsibleArgs {
		if a == playbookPath {
			cntAnsibleArgs[i] = pbCnt
		}
		if a == invPath {
			cntAnsibleArgs[i] = invCnt
		}
	}

	// 9. docker exec ansible-playbook
	execArgs := []string{"exec", "-t", containerID, "ansible-playbook"}
	execArgs = append(execArgs, cntAnsibleArgs...)
	fmt.Fprintf(cmd.ErrOrStderr(), "▶ docker exec %s ansible-playbook %s\n",
		containerID, strings.Join(cntAnsibleArgs, " "))

	runCmd := newCmd(ctx, "docker", execArgs...)
	runCmd.Stdout = cmd.OutOrStdout()
	runCmd.Stderr = os.Stderr
	return runCmd.Run()
}

// ---- verify ---------------------------------------------------------------

var vtVerifyCmd = &cobra.Command{
	Use:                "verify <spec.md> [<extra>...]",
	Short:              "Run `pilot verify` against the VM target",
	Args:               cobra.MinimumNArgs(1),
	DisableFlagParsing: true,
	RunE:               runVtVerify,
}

func init() { vtVerifyCmd.Flags().StringVar(&vtName, "name", "", "target name") }

func runVtVerify(cmd *cobra.Command, args []string) error {
	// DisableFlagParsing is on so -e foo=bar flows through to the
	// child pilot verify. But we still need to honour --name. Parse
	// it ourselves when the global is empty, AND strip it from
	// `args` so we don't re-forward it to `pilot verify` (which
	// doesn't know --name).
	if vtName == "" {
		for i := 0; i < len(args); i++ {
			if args[i] == "--name" && i+1 < len(args) {
				vtName = args[i+1]
				args = append(args[:i], args[i+2:]...)
				break
			}
			if strings.HasPrefix(args[i], "--name=") {
				vtName = strings.TrimPrefix(args[i], "--name=")
				args = append(args[:i], args[i+1:]...)
				break
			}
		}
	}
	t, cleanup, invPath, err := vtStageInventory()
	if err != nil {
		return err
	}
	defer cleanup()

	spec := args[0]
	extra := args[1:]
	pilotArgs := []string{"verify", spec, "-i", invPath, "-l", t.Name}
	pilotArgs = append(pilotArgs, extra...)
	fmt.Fprintf(cmd.ErrOrStderr(), "▶ pilot %s\n", strings.Join(pilotArgs, " "))
	return execPilot(cmd.OutOrStdout(), pilotArgs...)
}

// vtStageInventory loads the (running) target and writes its generated
// inventory to a temp file. The returned cleanup removes that file —
// callers must `defer cleanup()` (the lesson from the docker-target
// tmpfile leak).
func vtStageInventory() (*vmtarget.Target, func(), string, error) {
	if vtName == "" {
		return nil, func() {}, "", fmt.Errorf("--name is required")
	}
	m, err := vtNewManager()
	if err != nil {
		return nil, func() {}, "", err
	}
	t, err := m.Get(context.Background(), vtName)
	if err != nil {
		return nil, func() {}, "", err
	}
	if t.Status != vmtarget.StatusRunning {
		return nil, func() {}, "", fmt.Errorf("target %q is not running (status=%s); bring it up first", vtName, t.Status)
	}
	inv, err := t.RenderInventory()
	if err != nil {
		return nil, func() {}, "", err
	}
	path, cleanup, err := writeTempInventory(inv)
	if err != nil {
		return nil, func() {}, "", err
	}
	return t, cleanup, path, nil
}

// ---- exec -----------------------------------------------------------------

var vtExecCmd = &cobra.Command{
	Use:   "exec -- <argv...>",
	Short: "Run a single command inside the VM target over SSH (no host shell)",
	Args:  cobra.MinimumNArgs(1),
	RunE:  runVtExec,
}

func init() { vtExecCmd.Flags().StringVar(&vtName, "name", "", "target name") }

func runVtExec(cmd *cobra.Command, args []string) error {
	if vtName == "" {
		return fmt.Errorf("--name is required")
	}
	m, err := vtNewManager()
	if err != nil {
		return err
	}
	res, err := m.Exec(context.Background(), vtName, args)
	if err != nil {
		return err
	}
	if res.Stdout != "" {
		_, _ = cmd.OutOrStdout().Write([]byte(res.Stdout))
	}
	if res.Stderr != "" {
		_, _ = cmd.ErrOrStderr().Write([]byte(res.Stderr))
	}
	// Do NOT fail on non-zero exit (matches docker-target exec): many
	// legitimate checks (grep -q, test -f) exit non-zero by design.
	return nil
}

// ---- ssh / shell ---------------------------------------------------------

// vtSSHCmd drops the user into an interactive SSH session on the VM
// target. Default remote command is the user's login shell. Pass
// extra argv after `--` to run a non-interactive command while still
// getting a PTY (useful for sudo prompts, paginators, etc).
//
// Implementation note: we exec `ssh` directly with `os.Stdin/Stdout/
// Stderr` wired in. We do NOT route through the vmtarget ssh shim
// because that one captures output — fine for ansible, wrong for
// interactive use. The `-tt` flag forces PTY allocation, which
// also makes ssh forward SIGWINCH so terminal resize Just Works.
var vtSSHCmd = &cobra.Command{
	Use:   "ssh [-- <remote-argv>...]",
	Short: "Open an interactive SSH session to the VM target (or run a remote command with a PTY)",
	Long: `Open an interactive SSH session to the VM target.

Examples:
  pilot vm-target ssh --name core
  pilot vm-target ssh --name core -- bash -l
  pilot vm-target ssh --name core -- sudo systemctl restart unbound`,
	Args: cobra.ArbitraryArgs,
	RunE: runVtSSH,
}

func init() { vtSSHCmd.Flags().StringVar(&vtName, "name", "", "target name") }

// vtShellCmd is the friendlier alias users will reach for first.
// Default remote argv is ["sh", "-c", "command -v bash >/dev/null 2>&1 && exec bash -l || exec sh -l"]
// (probed at login time, so it works on minimal cloud images without bash).
var vtShellCmd = &cobra.Command{
	Use:   "shell [-- <remote-argv>...]",
	Short: "Drop into an interactive shell on the VM target (alias for `ssh` with a default remote shell)",
	Long: `Open an interactive shell on the VM target. Equivalent to

  pilot vm-target ssh --name <n> [-- bash -l]

Examples:
  pilot vm-target shell --name core
  pilot vm-target shell --name core -- bash -c "uname -a; ip a"
  pilot vm-target shell --name core -- sudo systemctl status unbound

Note: the remote argv must NOT begin with a dash, because ssh(1) eats
leading-dash arguments as ssh flags (it inserts a space to prevent the
remote shell from parsing them, but on a hard -- boundary the space
is also dropped). Always start the remote argv with a program name
(bash, sudo, journalctl, ...) — ssh's -c flag is the only
exception we use internally and we never pass it through verbatim.`,
	Args: cobra.ArbitraryArgs,
	RunE: runVtShell,
}

func init() { vtShellCmd.Flags().StringVar(&vtName, "name", "", "target name") }

// buildVtSSHArgv composes the full argv for `ssh` against a target,
// matching what vmtarget.SSHBaseArgs would produce for `Exec` plus
// `-tt` for PTY. Centralised so the unit test can lock it in
// without touching os/exec.
func buildVtSSHArgv(t *vmtarget.Target, remote []string) []string {
	args := vmtarget.SSHBaseArgs(t)
	args = append(args, "-tt", "--")
	args = append(args, remote...)
	return args
}

func runVtSSH(cmd *cobra.Command, args []string) error {
	if vtName == "" {
		return fmt.Errorf("--name is required")
	}
	m, err := vtNewManager()
	if err != nil {
		return err
	}
	t, err := m.Get(context.Background(), vtName)
	if err != nil {
		return err
	}
	if t.Status != vmtarget.StatusRunning {
		return fmt.Errorf("target %q is not running (status=%s); bring it up first", vtName, t.Status)
	}
	if len(args) == 0 {
		args = []string{"$SHELL"}
	}
	argv := buildVtSSHArgv(t, args)
	fmt.Fprintf(cmd.ErrOrStderr(), "▶ ssh %s@%s %s\n", t.SSHUser, t.IP, strings.Join(args, " "))
	return runInteractiveSSH(argv)
}

func runVtShell(cmd *cobra.Command, args []string) error {
	if vtName == "" {
		return fmt.Errorf("--name is required")
	}
	m, err := vtNewManager()
	if err != nil {
		return err
	}
	t, err := m.Get(context.Background(), vtName)
	if err != nil {
		return err
	}
	if t.Status != vmtarget.StatusRunning {
		return fmt.Errorf("target %q is not running (status=%s); bring it up first", vtName, t.Status)
	}
	if len(args) == 0 {
		args = []string{"sh", "-c", "command -v bash >/dev/null 2>&1 && exec bash -l || exec sh -l"}
	}
	argv := buildVtSSHArgv(t, args)
	fmt.Fprintf(cmd.ErrOrStderr(), "▶ shell on %s@%s\n", t.SSHUser, t.IP)
	return runInteractiveSSH(argv)
}

// runInteractiveSSH execs ssh as a child process with the user's
// stdio piped in, returning ssh's exit code as our own. Honors
// $PILOT_SSH_BIN for the same testability as vmtarget.ssh.
func runInteractiveSSH(argv []string) error {
	bin := os.Getenv("PILOT_SSH_BIN")
	if bin == "" {
		bin = "ssh"
	}
	c := newCmd(context.Background(), bin, argv...)
	c.Stdin = os.Stdin
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	return c.Run()
}

// ---- snapshot -------------------------------------------------------------

var vtSnapshotCmd = &cobra.Command{
	Use:   "snapshot",
	Short: "Snapshot the VM's current state under a tag (libvirt qcow2 snapshot)",
	RunE:  runVtSnapshot,
}

func init() {
	vtSnapshotCmd.Flags().StringVar(&vtName, "name", "", "target name (required)")
	vtSnapshotCmd.Flags().StringVar(&vtSnapTag, "tag", "", "snapshot tag to create (required)")
	_ = vtSnapshotCmd.MarkFlagRequired("tag")
}

func runVtSnapshot(cmd *cobra.Command, args []string) error {
	if vtName == "" {
		return fmt.Errorf("--name is required")
	}
	m, err := vtNewManager()
	if err != nil {
		return err
	}
	if err := m.Snapshot(context.Background(), vtName, vtSnapTag); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "✓ snapshotted %s as %s\n", vtName, vtSnapTag)
	return nil
}

// ---- rollback -------------------------------------------------------------

var vtRollbackCmd = &cobra.Command{
	Use:   "rollback",
	Short: "Revert the VM to a previously snapshotted tag",
	RunE:  runVtRollback,
}

func init() {
	vtRollbackCmd.Flags().StringVar(&vtName, "name", "", "target name (required)")
	vtRollbackCmd.Flags().StringVar(&vtRollTag, "tag", "", "snapshot tag to revert to (required)")
	_ = vtRollbackCmd.MarkFlagRequired("tag")
}

func runVtRollback(cmd *cobra.Command, args []string) error {
	if vtName == "" {
		return fmt.Errorf("--name is required")
	}
	m, err := vtNewManager()
	if err != nil {
		return err
	}
	if err := m.Rollback(context.Background(), vtName, vtRollTag); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "✓ rolled back %s to %s\n", vtName, vtRollTag)
	return nil
}

// ---- reset ----------------------------------------------------------------

var vtResetCmd = &cobra.Command{
	Use:   "reset",
	Short: "Revert the VM to the pristine post-boot state (fast dev/test loop reset)",
	Long: `Revert the VM to the automatic "clean" checkpoint captured at 'up' time.

This is the fast path for iterating on a playbook: instead of
'vm-target down' + 'vm-target up' (a full reprovision plus boot wait),
reset restores the freshly-booted state in seconds — then re-apply.

Loop:
  pilot vm-target reset --name core
  pilot vm-target run   --name core playbooks/apply/foo-apply.yml -e ...
  # inspect, tweak the playbook, then reset + run again
`,
	RunE: runVtReset,
}

func init() {
	vtResetCmd.Flags().StringVar(&vtName, "name", "", "target name (required)")
	_ = vtResetCmd.MarkFlagRequired("name")
}

func runVtReset(cmd *cobra.Command, args []string) error {
	if vtName == "" {
		return fmt.Errorf("--name is required")
	}
	m, err := vtNewManager()
	if err != nil {
		return err
	}
	if err := m.Reset(context.Background(), vtName); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "✓ reset %s to %q (pristine post-boot state)\n", vtName, vmtarget.CleanSnapshotTag)
	return nil
}

// ---- test -----------------------------------------------------------------

var (
	vtTestPlaybook   string
	vtTestSpec       string
	vtTestSkipLint   bool
	vtTestNoRollback bool
)

var vtTestCmd = &cobra.Command{
	Use:   "test",
	Short: "Run syntax, apply, verify, and idempotency tests against a VM target",
	Long: `Run a full integration and verification test suite against a VM target.

Steps executed:
  1. L1 syntax check: 'ansible-playbook --syntax-check'
  2. Auto-snapshot: captures current state under 'pre-test' tag
  3. L4 apply: runs the playbook
  4. L5 verify: runs 'pilot verify' against the target
  5. L6 idempotency: runs the playbook again and checks that changed=0
  6. Auto-rollback: if any step fails, automatically rolls back to 'pre-test'
`,
	RunE: runVtTest,
}

func init() {
	vtTestCmd.Flags().StringVar(&vtName, "name", "", "target VM name (required)")
	vtTestCmd.Flags().StringVar(&vtTestPlaybook, "playbook", "", "path to the playbook to run (required)")
	vtTestCmd.Flags().StringVar(&vtTestSpec, "spec", "", "path to the verification spec.md (required)")
	vtTestCmd.Flags().BoolVar(&vtTestSkipLint, "skip-lint", false, "skip syntax check pre-flight")
	vtTestCmd.Flags().BoolVar(&vtTestNoRollback, "no-rollback", false, "disable automatic rollback on failure")

	_ = vtTestCmd.MarkFlagRequired("name")
	_ = vtTestCmd.MarkFlagRequired("playbook")
	_ = vtTestCmd.MarkFlagRequired("spec")
}

func runVtTest(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	m, err := vtNewManager()
	if err != nil {
		return err
	}
	t, err := m.Get(ctx, vtName)
	if err != nil {
		return err
	}
	if t.Status != vmtarget.StatusRunning {
		return fmt.Errorf("target %q is not running; bring it up first", vtName)
	}

	// Step 1: L1 Syntax Check
	if !vtTestSkipLint {
		fmt.Fprintln(cmd.OutOrStdout(), "=== [Step 1/5] L1 Syntax Check ===")
		syntaxArgs := []string{vtTestPlaybook, "--syntax-check"}
		if err := execAnsiblePlaybook(cmd.OutOrStdout(), syntaxArgs...); err != nil {
			return fmt.Errorf("syntax check failed: %w", err)
		}
		fmt.Fprintln(cmd.OutOrStdout(), "✓ Syntax check passed")
	}

	// Step 2: Auto-snapshot
	snapTag := fmt.Sprintf("pre-test-%d", time.Now().Unix())
	fmt.Fprintf(cmd.OutOrStdout(), "=== [Step 2/5] Auto-snapshotting VM state (tag: %s) ===\n", snapTag)
	if err := m.Snapshot(ctx, vtName, snapTag); err != nil {
		return fmt.Errorf("failed to create auto-snapshot: %w", err)
	}
	fmt.Fprintln(cmd.OutOrStdout(), "✓ Auto-snapshot created")

	// Helper for rollback on failure
	rollbackOnFailure := func(origErr error) error {
		if vtTestNoRollback {
			fmt.Fprintln(cmd.ErrOrStderr(), "⚠️ Auto-rollback is disabled via --no-rollback")
			return origErr
		}
		fmt.Fprintf(cmd.ErrOrStderr(), "❌ Test failed: %v. Rolling back VM to %s...\n", origErr, snapTag)
		if rerr := m.Rollback(ctx, vtName, snapTag); rerr != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "🚨 Double fault: failed to rollback: %v\n", rerr)
			return fmt.Errorf("%w (rollback also failed: %v)", origErr, rerr)
		}
		fmt.Fprintln(cmd.OutOrStdout(), "✓ Rollback successful. Target VM restored to pre-test state.")
		return origErr
	}

	// Step 3: L4 Apply
	fmt.Fprintln(cmd.OutOrStdout(), "=== [Step 3/5] L4 Apply Playbook ===")
	t, cleanup, invPath, err := vtStageInventory()
	if err != nil {
		return rollbackOnFailure(err)
	}
	defer cleanup()

	ansibleArgs := []string{vtTestPlaybook, "-i", invPath, "-l", t.Name}
	var applyBuf bytes.Buffer
	mw := io.MultiWriter(cmd.OutOrStdout(), &applyBuf)

	if err := execExternal(mw, "ansible-playbook", ansibleArgs...); err != nil {
		return rollbackOnFailure(fmt.Errorf("playbook apply failed: %w", err))
	}
	fmt.Fprintln(cmd.OutOrStdout(), "✓ Playbook apply completed")

	// Step 4: L5 Verify
	fmt.Fprintln(cmd.OutOrStdout(), "=== [Step 4/5] L5 Verification Spec ===")
	pilotArgs := []string{"verify", vtTestSpec, "-i", invPath, "-l", t.Name}

	if err := execPilot(cmd.OutOrStdout(), pilotArgs...); err != nil {
		return rollbackOnFailure(fmt.Errorf("verification failed: %w", err))
	}
	fmt.Fprintln(cmd.OutOrStdout(), "✓ Verification checks passed")

	// Step 5: L6 Idempotency Check
	fmt.Fprintln(cmd.OutOrStdout(), "=== [Step 5/5] L6 Idempotency Check ===")
	var idemBuf bytes.Buffer
	mwIdem := io.MultiWriter(cmd.OutOrStdout(), &idemBuf)
	if err := execExternal(mwIdem, "ansible-playbook", ansibleArgs...); err != nil {
		return rollbackOnFailure(fmt.Errorf("idempotency run failed: %w", err))
	}

	changed, ok := idempotencyChangedCount(idemBuf.String())
	if !ok {
		return rollbackOnFailure(fmt.Errorf("idempotency check: no PLAY RECAP found in ansible output (unable to confirm changed=0)"))
	}
	if changed > 0 {
		return rollbackOnFailure(fmt.Errorf("idempotency check failed: playbook reported %d changed task(s) on second run", changed))
	}
	fmt.Fprintln(cmd.OutOrStdout(), "✓ Idempotency check passed (changed=0)")
	fmt.Fprintln(cmd.OutOrStdout(), "🎉 ALL TESTS PASSED SUCCESSFULLY!")

	return nil
}

// recapChangedRe matches a single ansible PLAY RECAP host line and captures
// its changed count, e.g. "host : ok=5 changed=0 unreachable=0 ...".
var recapChangedRe = regexp.MustCompile(`:\s+ok=\d+\s+changed=(\d+)`)

// idempotencyChangedCount reads ONLY ansible's PLAY RECAP block and returns
// the total number of changed tasks across all hosts, plus whether a recap
// was present at all. Scoping to the recap (rather than grepping the whole
// output for "changed=N") avoids false idempotency failures from a debug or
// task line that merely prints the substring "changed=1". Returns ok=false
// when no PLAY RECAP is found, which the caller treats as an inconclusive
// (and therefore failed) idempotency check.
func idempotencyChangedCount(output string) (total int, ok bool) {
	idx := strings.Index(output, "PLAY RECAP")
	if idx < 0 {
		return 0, false
	}
	for _, m := range recapChangedRe.FindAllStringSubmatch(output[idx:], -1) {
		n, err := strconv.Atoi(m[1])
		if err != nil {
			continue
		}
		total += n
	}
	return total, true
}
