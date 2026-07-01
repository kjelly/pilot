package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

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
}

// ---- shared flags ---------------------------------------------------------

var (
	vtName      string
	vtBaseImage string
	vtSSHUser   string
	vtVCPUs     int
	vtMemoryMB  int
	vtNetwork   string
	vtHosts     []string
	vtVMDir     string
	vtSnapTag   string
	vtRollTag   string
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
	vtUpCmd.Flags().StringVar(&vtBaseImage, "base-image", "", "path to a qcow2 cloud image used as the read-only backing (required)")
	vtUpCmd.Flags().StringVar(&vtSSHUser, "ssh-user", "root", "login user authorised via cloud-init")
	vtUpCmd.Flags().IntVar(&vtVCPUs, "vcpus", 2, "number of vCPUs")
	vtUpCmd.Flags().IntVar(&vtMemoryMB, "memory", 2048, "memory in MiB")
	vtUpCmd.Flags().StringVar(&vtNetwork, "network", "default", "libvirt network name")
	vtUpCmd.Flags().StringSliceVar(&vtHosts, "hosts", nil, "additional ansible host aliases (may repeat); all route to the same VM")
	vtUpCmd.Flags().StringVar(&vtVMDir, "vm-dir", "", "directory for qcow2 overlays/seed ISOs (default /var/lib/libvirt/images/pilot)")
}

func runVtUp(cmd *cobra.Command, args []string) error {
	if vtName == "" {
		return fmt.Errorf("--name is required")
	}
	if vtBaseImage == "" {
		return fmt.Errorf("--base-image is required")
	}
	m, err := vtNewManager()
	if err != nil {
		return err
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "▶ provisioning VM %s (this can take a minute while it boots)…\n", vtName)
	tgt, err := m.Up(context.Background(), vmtarget.Options{
		Name:      vtName,
		BaseImage: vtBaseImage,
		SSHUser:   vtSSHUser,
		VCPUs:     vtVCPUs,
		MemoryMB:  vtMemoryMB,
		Network:   vtNetwork,
		Hosts:     vtHosts,
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
Everything after the playbook is forwarded verbatim to ansible-playbook.`,
	Args:              cobra.MinimumNArgs(1),
	DisableFlagParsing: true,
	RunE: runVtRun,
}

func init() { vtRunCmd.Flags().StringVar(&vtName, "name", "", "target name") }

func runVtRun(cmd *cobra.Command, args []string) error {
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
	fmt.Fprintf(cmd.ErrOrStderr(), "▶ ansible-playbook %s\n", strings.Join(ansibleArgs, " "))
	return execAnsiblePlaybook(cmd.OutOrStdout(), ansibleArgs...)
}

// ---- verify ---------------------------------------------------------------

var vtVerifyCmd = &cobra.Command{
	Use:   "verify <spec.md> [<extra>...]",
	Short: "Run `pilot verify` against the VM target",
	Args:               cobra.MinimumNArgs(1),
	DisableFlagParsing: true,
	RunE:  runVtVerify,
}

func init() { vtVerifyCmd.Flags().StringVar(&vtName, "name", "", "target name") }

func runVtVerify(cmd *cobra.Command, args []string) error {
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
	f, err := os.CreateTemp("", "pilot-vt-inv-*.yaml")
	if err != nil {
		return nil, func() {}, "", fmt.Errorf("create inventory tmpfile: %w", err)
	}
	path := f.Name()
	cleanup := func() { os.Remove(path) }
	if _, err := f.WriteString(inv); err != nil {
		f.Close()
		cleanup()
		return nil, func() {}, "", err
	}
	if err := f.Close(); err != nil {
		cleanup()
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
		cmd.OutOrStdout().Write([]byte(res.Stdout))
	}
	if res.Stderr != "" {
		cmd.ErrOrStderr().Write([]byte(res.Stderr))
	}
	// Do NOT fail on non-zero exit (matches docker-target exec): many
	// legitimate checks (grep -q, test -f) exit non-zero by design.
	return nil
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
