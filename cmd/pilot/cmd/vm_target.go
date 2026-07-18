package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/anomalyco/pilot/internal/ansible"
	"github.com/anomalyco/pilot/internal/delivery"
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
	vmTargetCmd.AddCommand(vtWireCmd)
	vmTargetCmd.AddCommand(vtSnapshotCmd)
	vmTargetCmd.AddCommand(vtRollbackCmd)
	vmTargetCmd.AddCommand(vtResetCmd)
	vmTargetCmd.AddCommand(vtSSHCmd)
	vmTargetCmd.AddCommand(vtShellCmd)
	vmTargetCmd.AddCommand(vtTestCmd)
	vmTargetCmd.AddCommand(vtResizeDiskCmd)
}

// ---- shared flags ---------------------------------------------------------

var (
	vtName          string
	vtBaseImage     string
	vtSSHUser       string
	vtVCPUs         int
	vtMemoryMB      int
	vtDiskGB        int
	vtNetwork       string
	vtHosts         []string
	vtVMDir         string
	vtSnapTag       string
	vtRollTag       string
	vtSSHTimeout    time.Duration
	vtBootTimeout   time.Duration
	vtKeepOnFailure bool

	// run batch/preflight flags (see runVtRun)
	vtDiscover        string
	vtFromStdin       bool
	vtFailFast        bool
	vtSkipSyntaxCheck bool
	vtSkipLint        bool
	vtJSON            bool
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
	vtUpCmd.Flags().StringVar(&vtBaseImage, "base-image", "", "path or alias of qcow2 base image (defaults to ubuntu-24.04, supports fedora-40, almalinux-9, centos-9)")
	vtUpCmd.Flags().StringVar(&vtSSHUser, "ssh-user", "root", "login user authorised via cloud-init")
	vtUpCmd.Flags().IntVar(&vtVCPUs, "vcpus", 2, "number of vCPUs")
	vtUpCmd.Flags().IntVar(&vtMemoryMB, "memory", 2048, "memory in MiB")
	vtUpCmd.Flags().IntVar(&vtDiskGB, "disk", vmtarget.DefaultDiskGB, "root disk size in GiB")
	vtUpCmd.Flags().StringVar(&vtNetwork, "network", "default", "libvirt network name")
	vtUpCmd.Flags().StringSliceVar(&vtHosts, "hosts", nil, "additional ansible host aliases (may repeat); all route to the same VM")
	vtUpCmd.Flags().StringVar(&vtVMDir, "vm-dir", "", "directory for qcow2 overlays/seed ISOs (default /var/lib/libvirt/images/pilot)")
	vtUpCmd.Flags().DurationVar(&vtSSHTimeout, "ssh-timeout", 0, "override SSH readiness timeout (default 2m)")
	vtUpCmd.Flags().DurationVar(&vtBootTimeout, "boot-timeout", 0, "override boot/IP-acquisition timeout (default 3m)")
	vtUpCmd.Flags().BoolVar(&vtKeepOnFailure, "keep-on-failure", false, "keep the VM and its on-disk files/state on provisioning failure for investigation")
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
		Name:          vtName,
		BaseImage:     vtBaseImage,
		SSHUser:       vtSSHUser,
		VCPUs:         vtVCPUs,
		MemoryMB:      vtMemoryMB,
		DiskGB:        vtDiskGB,
		Network:       vtNetwork,
		Hosts:         vtHosts,
		SSHTimeout:    vtSSHTimeout,
		BootTimeout:   vtBootTimeout,
		KeepOnFailure: vtKeepOnFailure,
	})
	if err != nil {
		if !vtKeepOnFailure {
			fmt.Fprintf(cmd.ErrOrStderr(), "\n💡 Hint: you can run this command with '--keep-on-failure' to preserve the VM on failure for debugging.\n")
		}
		return err
	}
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "✓ target %s up\n", tgt.Name)
	fmt.Fprintf(out, "  ip        : %s\n", tgt.IP)
	fmt.Fprintf(out, "  ssh_user  : %s\n", tgt.SSHUser)
	fmt.Fprintf(out, "  base_image: %s\n", tgt.BaseImage)
	fmt.Fprintf(out, "  vcpus/mem : %d / %d MiB\n", tgt.VCPUs, tgt.MemoryMB)
	fmt.Fprintf(out, "  disk      : %d GiB\n", tgt.DiskGB)
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
	fmt.Fprintln(tw, "NAME\tSTATUS\tIP\tVCPU\tMEM(MiB)\tDISK(GiB)\tCREATED")
	for _, t := range all {
		diskStr := "-"
		if t.DiskGB > 0 {
			diskStr = strconv.Itoa(t.DiskGB)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%d\t%s\t%s\n",
			t.Name, t.Status, t.IP, t.VCPUs, t.MemoryMB, diskStr, t.CreatedAt.Format("2006-01-02 15:04:05"))
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
any host-side ansible installation.

Batch / preflight (no LLM agent involved — plain ansible-playbook, run
directly by whatever is driving pilot):
  --discover 'playbooks/*.yml'   glob pattern or directory of playbooks
  --from-stdin                   read playbook paths from stdin (one per line)
  --fail-fast                    with --from-stdin/--discover, stop on first failure
  --skip-syntax-check            skip the ansible-playbook --syntax-check preflight
  --skip-lint                    skip the ansible-lint preflight
  --json                         parse ansible's json callback into an ok/changed/
                                  failed/unreachable summary instead of raw scrollback
                                  (not supported together with --sandbox)

Multi-node topology (e.g. FreeIPA primary+replica, which need to reach
each other over real ansible groups, not just one VM's single-host
inventory):
  --group masters=ipa-primary --group replicas=ipa-replica,ipa-replica2
                                  combine several already-up vm-targets into
                                  one inventory with real [masters]/[replicas]
                                  ansible groups (repeatable; each value is
                                  group=target1,target2). --name then only
                                  picks which target's directory gets the run
                                  transcript, and no -l limit is auto-added —
                                  use the playbook's own hosts: pattern (e.g.
                                  -e target_group=masters) to pick a subset.
                                  --sandbox mounts every referenced target's
                                  own SSH key. See also 'vm-target wire' for
                                  pinning peer IPs into /etc/hosts.

Every run also writes a full transcript under <vm-dir>/<name>/runs/, with
the path printed after the run — useful once terminal scrollback has
been truncated or you want to diff two attempts.`,
	Args:               cobra.ArbitraryArgs,
	DisableFlagParsing: true,
	RunE:               runVtRun,
}

func init() {
	vtRunCmd.Flags().StringVar(&vtName, "name", "", "target name")
	vtRunCmd.Flags().StringVar(&vtDiscover, "discover", "", "glob pattern or directory to discover playbooks")
	vtRunCmd.Flags().BoolVar(&vtFromStdin, "from-stdin", false, "read playbook paths from stdin (one per line)")
	vtRunCmd.Flags().BoolVar(&vtFailFast, "fail-fast", false, "with --from-stdin/--discover, stop on first failure")
	vtRunCmd.Flags().BoolVar(&vtSkipSyntaxCheck, "skip-syntax-check", false, "skip ansible-playbook --syntax-check preflight")
	vtRunCmd.Flags().BoolVar(&vtSkipLint, "skip-lint", false, "skip ansible-lint preflight")
	vtRunCmd.Flags().BoolVar(&vtJSON, "json", false, "parse ansible's json callback into a structured ok/changed/failed/unreachable summary (not supported with --sandbox)")
	vtRunCmd.Flags().StringArray("group", nil, "combine multiple already-up vm-targets into one grouped inventory: group=target1,target2 (repeatable)")
}

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

// extraVarsFileArg recognizes ansible's "@file" extra-vars-file syntax
// in its three accepted forms — bare "@path" (as a separate arg after
// "-e"/"--extra-vars"), glued "-e@path", and "--extra-vars=@path" — and
// returns the literal prefix to preserve plus the host path referenced.
// ok is false for anything else (a plain key=value extra-var, a flag,
// etc.), so callers can skip those without a false-positive file lookup.
func extraVarsFileArg(a string) (glue, path string, ok bool) {
	switch {
	case strings.HasPrefix(a, "--extra-vars=@"):
		return "--extra-vars=@", strings.TrimPrefix(a, "--extra-vars=@"), true
	case strings.HasPrefix(a, "-e@"):
		return "-e@", strings.TrimPrefix(a, "-e@"), true
	case strings.HasPrefix(a, "@"):
		return "@", strings.TrimPrefix(a, "@"), true
	default:
		return "", "", false
	}
}

// extractRepeatedValueFlag scans args for every occurrence of a
// repeatable key-value flag (e.g. "--group masters=a,b"), removing all
// of them and returning their values in encounter order. Supports both
// "--flag value" and "--flag=value" forms.
func extractRepeatedValueFlag(args []string, flag string) ([]string, []string) {
	var vals []string
	out := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == flag && i+1 < len(args) {
			vals = append(vals, args[i+1])
			i++
			continue
		}
		if strings.HasPrefix(a, flag+"=") {
			vals = append(vals, strings.TrimPrefix(a, flag+"="))
			continue
		}
		out = append(out, a)
	}
	return out, vals
}

// parseVtGroups parses repeated "--group name=target1,target2" values
// into an ordered group-name list (preserved for deterministic inventory
// output) plus a name -> member-target-names map. A group name repeated
// across multiple --group flags accumulates members rather than
// overwriting them.
func parseVtGroups(vals []string) (order []string, groups map[string][]string, err error) {
	groups = make(map[string][]string)
	for _, v := range vals {
		i := strings.IndexByte(v, '=')
		if i <= 0 || i == len(v)-1 {
			return nil, nil, fmt.Errorf("invalid --group %q; want group=target1,target2", v)
		}
		name := v[:i]
		var members []string
		for _, m := range strings.Split(v[i+1:], ",") {
			if m = strings.TrimSpace(m); m != "" {
				members = append(members, m)
			}
		}
		if len(members) == 0 {
			return nil, nil, fmt.Errorf("invalid --group %q: no members", v)
		}
		if _, exists := groups[name]; !exists {
			order = append(order, name)
		}
		groups[name] = append(groups[name], members...)
	}
	return order, groups, nil
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

	// Parse batch/preflight flags before forwarding the rest to ansible.
	var fromStdin, failFast, skipSyntax, skipLint, wantJSON bool
	var discover string
	args, fromStdin = extractBoolFlag(args, "--from-stdin")
	args, failFast = extractBoolFlag(args, "--fail-fast")
	args, skipSyntax = extractBoolFlag(args, "--skip-syntax-check")
	args, skipLint = extractBoolFlag(args, "--skip-lint")
	args, wantJSON = extractBoolFlag(args, "--json")
	args, discover = extractValueFlag(args, "--discover")
	var groupVals []string
	args, groupVals = extractRepeatedValueFlag(args, "--group")
	if wantJSON && useSandbox {
		return fmt.Errorf("--json is not supported together with --sandbox")
	}
	groupOrder, groups, gerr := parseVtGroups(groupVals)
	if gerr != nil {
		return gerr
	}

	// Resolve the playbook(s) to run and the extra args shared across
	// the whole batch (e.g. -e foo=bar, --tags ...). No LLM/agent
	// involved here — this mirrors `pilot run`'s --discover/--from-stdin
	// resolution (see resolveTargets in run.go) but skips everything
	// that only makes sense for the agent loop (proposals, audit log,
	// dry-run).
	var playbooks []string
	var extra []string
	switch {
	case fromStdin:
		targets, err := readTargetsFromStdin("", "")
		if err != nil {
			return err
		}
		for _, tg := range targets {
			playbooks = append(playbooks, tg.Playbook)
		}
		extra = args
	case discover != "":
		targets, err := discoverTargets(discover, "", "")
		if err != nil {
			return err
		}
		for _, tg := range targets {
			playbooks = append(playbooks, tg.Playbook)
		}
		extra = args
	default:
		if len(args) < 1 {
			return fmt.Errorf("no playbook specified; pass a positional arg, --from-stdin, or --discover")
		}
		playbooks = []string{args[0]}
		extra = args[1:]
	}

	var (
		t          *vmtarget.Target
		keyTargets []*vmtarget.Target
		cleanup    func()
		invPath    string
		err        error
		groupMode  = len(groupOrder) > 0
	)
	if groupMode {
		t, keyTargets, cleanup, invPath, err = vtStageGroupInventory(groupOrder, groups)
	} else {
		t, cleanup, invPath, err = vtStageInventory()
		keyTargets = []*vmtarget.Target{t}
	}
	if err != nil {
		return err
	}
	defer cleanup()

	runner := ansible.NewRunner()
	ctx := context.Background()
	batch := len(playbooks) > 1
	failed := 0
	for i, playbook := range playbooks {
		prefix := ""
		if batch {
			prefix = fmt.Sprintf("[%d/%d] ", i+1, len(playbooks))
		}

		ansibleArgs := []string{playbook, "-i", invPath}
		if !groupMode && !extraHasTargetGroup(extra) {
			ansibleArgs = append(ansibleArgs, "-l", t.Name)
		}
		ansibleArgs = append(ansibleArgs, extra...)

		lintIssues, perr := syntaxCheckAndLint(ctx, runner, playbook, ansibleArgs, skipSyntax, skipLint)
		if lintIssues != "" {
			fmt.Fprintf(cmd.ErrOrStderr(), "  ⚠️  ansible-lint found issues in %s:\n%s\n", playbook, indentString(lintIssues, 4))
		}
		if perr != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "  %s✗ %s (%v)\n", prefix, playbook, perr)
			failed++
			if !batch {
				return perr
			}
			if failFast {
				break
			}
			continue
		}

		logPath, logErr := vtRunLogPath(t, playbook)
		if logErr != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "  ⚠️  could not create run transcript (%v); continuing without one\n", logErr)
			logPath = ""
		}

		fmt.Fprintf(cmd.ErrOrStderr(), "▶ %sansible-playbook %s\n", prefix, strings.Join(ansibleArgs, " "))
		var runErr error
		switch {
		case useSandbox:
			runErr = vtRunViaContainer(cmd, keyTargets, playbook, invPath, ansibleArgs, sandboxImage, logPath)
		case wantJSON:
			runErr = runVtPlaybookJSON(cmd, playbook, ansibleArgs, logPath)
		default:
			runErr = runVtPlaybookPlain(cmd, ansibleArgs, logPath)
		}
		if logPath != "" {
			fmt.Fprintf(cmd.ErrOrStderr(), "  %stranscript: %s\n", prefix, logPath)
		}
		if runErr != nil {
			failed++
			fmt.Fprintf(cmd.ErrOrStderr(), "  %s✗ %s\n", prefix, playbook)
			if !batch {
				return runErr
			}
			if failFast {
				break
			}
			continue
		}
		if batch {
			fmt.Fprintf(cmd.ErrOrStderr(), "  %s✓ %s\n", prefix, playbook)
		}
	}

	if batch {
		fmt.Fprintf(cmd.ErrOrStderr(), "✓ Batch complete: %d/%d succeeded\n", len(playbooks)-failed, len(playbooks))
	}
	if failed > 0 {
		return fmt.Errorf("%d/%d playbook runs failed", failed, len(playbooks))
	}
	return nil
}

// vtRunLogPath returns where to write a transcript of one playbook
// invocation against target t, creating <t.Dir>/runs if needed. Every
// `vm-target run` writes one of these regardless of --json, so a run's
// full output survives even after terminal scrollback (or a truncated
// tool-call result) is gone.
func vtRunLogPath(t *vmtarget.Target, playbook string) (string, error) {
	dir := filepath.Join(t.Dir, "runs")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("create run transcript dir: %w", err)
	}
	base := strings.TrimSuffix(filepath.Base(playbook), filepath.Ext(playbook))
	ts := time.Now().UTC().Format("20060102T150405Z")
	return filepath.Join(dir, fmt.Sprintf("%s-%s.log", ts, base)), nil
}

// runVtPlaybookPlain runs ansible-playbook streaming to the terminal as
// before, additionally teeing the same bytes to logPath (skipped if
// logPath is empty, e.g. the transcript dir could not be created).
func runVtPlaybookPlain(cmd *cobra.Command, ansibleArgs []string, logPath string) error {
	out := cmd.OutOrStdout()
	if logPath != "" {
		if f, err := os.Create(logPath); err == nil {
			defer f.Close()
			out = io.MultiWriter(out, f)
		}
	}
	return execAnsiblePlaybook(out, ansibleArgs...)
}

// runVtPlaybookJSON runs ansible-playbook with the built-in `json`
// stdout callback and prints a parsed ok/changed/failed/unreachable
// summary instead of raw scrollback. The raw JSON document isn't meant
// for humans to read live, so it goes to logPath (if available) rather
// than the terminal.
func runVtPlaybookJSON(cmd *cobra.Command, playbook string, ansibleArgs []string, logPath string) error {
	var logFile io.Writer
	if logPath != "" {
		if f, err := os.Create(logPath); err == nil {
			defer f.Close()
			logFile = f
		}
	}
	raw, runErr := execAnsiblePlaybookCaptured(context.Background(), logFile, []string{"ANSIBLE_STDOUT_CALLBACK=json"}, ansibleArgs...)
	if res, perr := parseAnsibleJSONResult(raw); perr != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "  ⚠️  could not parse --json output for %s: %v\n", playbook, perr)
	} else {
		fmt.Fprint(cmd.OutOrStdout(), summarizeAnsibleJSONResult(res))
	}
	return runErr
}

// containerFixPermsScript builds the /bin/sh script run inside the sandbox
// container before ansible: for each bind-mounted key path in
// cntKeyPaths, it copies to an indexed path it can chmod 600 (the mount
// may carry a foreign uid/perms), and pre-creates the two directories
// the generated inventory relies on — ~/.ssh (for known_hosts) and
// ~/.ansible/cp (the SSH ControlPath parent). Without the latter, ssh's
// ControlMaster socket creation fails inside the container because its
// parent dir does not exist, breaking every task.
//
// Multiple key paths are supported because a --group multi-host
// inventory spans several vm-target VMs, each with its own generated
// SSH keypair — every one needs its own mount and fixed-permission copy.
func containerFixPermsScript(cntKeyPaths ...string) string {
	parts := []string{"mkdir -p ~/.ssh ~/.ansible/cp", "touch ~/.ssh/known_hosts"}
	for i, cntKeyPath := range cntKeyPaths {
		fixed := containerFixedKeyPath(i)
		parts = append(parts, fmt.Sprintf("cp %s %s", cntKeyPath, fixed), fmt.Sprintf("chmod 600 %s", fixed))
	}
	return strings.Join(parts, " && ")
}

// containerFixedKeyPath is the in-container path key index i's SSH key
// lives at once containerFixPermsScript has copied it out of its
// (possibly wrong-permission) bind mount.
func containerFixedKeyPath(i int) string {
	return fmt.Sprintf("/tmp/pilot-ssh-key-%d", i)
}

// vtRunViaContainer runs ansible-playbook inside a Docker container
// while targeting keyTargets over SSH. In the common case keyTargets is
// a single VM; with `run --group`, it is every VM referenced by the
// combined inventory, since each vm-target VM has its own generated SSH
// keypair and all of them need mounting for ansible inside the
// container to reach every host. It:
//  1. Resolves the sandbox image from the explicit flag or config.
//  2. Starts a sandbox container with --network host and every target's
//     SSH key bind-mounted read-only at a distinct path.
//  3. docker-cp's the playbook and inventory into the container,
//     rewriting each ansible_ssh_private_key_file to its container path.
//  4. docker exec ansible-playbook inside the container.
//  5. Tears down the container.
func vtRunViaContainer(cmd *cobra.Command, keyTargets []*vmtarget.Target, playbookPath, invPath string, ansibleArgs []string, imageOverride, logPath string) error {
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

	// 2. Determine container-side (bind-mount) key paths, one per target.
	mountPaths := make([]string, len(keyTargets))
	for i := range keyTargets {
		mountPaths[i] = fmt.Sprintf("/tmp/pilot-ssh/%d/id_ed25519", i)
	}

	// 3. Rewrite the inventory: replace each host-side SSH key path
	//    with its container-side mount path. Write to a new temp file.
	invData, err := os.ReadFile(invPath)
	if err != nil {
		return fmt.Errorf("read inventory: %w", err)
	}
	rewrittenInv := string(invData)
	for i, kt := range keyTargets {
		rewrittenInv = strings.ReplaceAll(rewrittenInv, kt.KeyPath, mountPaths[i])
	}
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

	// 4. Start the container with every target's SSH key mounted using the core DockerEnvironment backend.
	mounts := make([]sandbox.SandboxMount, len(keyTargets))
	for i, kt := range keyTargets {
		mounts[i] = sandbox.SandboxMount{HostPath: kt.KeyPath, ContainerPath: mountPaths[i], RO: true}
	}
	de := sandbox.NewDockerEnvironment(image)
	de.Network = "host"
	de.Mounts = mounts
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

	// 6. Fix SSH key permissions inside the container (bind mounts may
	//    carry a foreign uid). Also create ~/.ssh/known_hosts and the
	//    ControlPath parent dir the generated inventory expects.
	fixPerms := newCmd(ctx, "docker", "exec", containerID,
		"/bin/sh", "-c", containerFixPermsScript(mountPaths...))
	if out, err := fixPerms.CombinedOutput(); err != nil {
		return fmt.Errorf("fix SSH key permissions: %w\n%s", err, string(out))
	}
	// Rewrite inventory to use the copied keys with correct perms
	for i, mp := range mountPaths {
		rewrittenInv = strings.ReplaceAll(rewrittenInv, mp, containerFixedKeyPath(i))
	}
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

	// 8b. `-e @vars.yaml` / `-e@vars.yaml` / `--extra-vars=@vars.yaml`
	// extra-vars-file references (vault files, group_vars, etc.) name a
	// HOST path. The container has no access to the host filesystem
	// beyond what we've explicitly mounted/copied, so ansible-playbook
	// inside it would fail with "Could not find or access" on any of
	// these unless we cp each one in and rewrite the arg to match.
	for i, a := range cntAnsibleArgs {
		glue, hostPath, ok := extraVarsFileArg(a)
		if !ok {
			continue
		}
		if info, statErr := os.Stat(hostPath); statErr != nil || info.IsDir() {
			continue
		}
		cntVarsPath := fmt.Sprintf("/tmp/pilot-extra-vars-%d%s", i, filepath.Ext(hostPath))
		cp := newCmd(ctx, "docker", "cp", hostPath, containerID+":"+cntVarsPath)
		if out, err := cp.CombinedOutput(); err != nil {
			return fmt.Errorf("docker cp extra-vars file %s: %w\n%s", hostPath, err, string(out))
		}
		cntAnsibleArgs[i] = glue + cntVarsPath
	}

	// 9. docker exec ansible-playbook
	execArgs := []string{"exec", "-t", containerID, "ansible-playbook"}
	execArgs = append(execArgs, cntAnsibleArgs...)
	fmt.Fprintf(cmd.ErrOrStderr(), "▶ docker exec %s ansible-playbook %s\n",
		containerID, strings.Join(cntAnsibleArgs, " "))

	runCmd := newCmd(ctx, "docker", execArgs...)
	out := cmd.OutOrStdout()
	if logPath != "" {
		if f, err := os.Create(logPath); err == nil {
			defer f.Close()
			out = io.MultiWriter(out, f)
		}
	}
	runCmd.Stdout = out
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
	pilotArgs := []string{"verify", spec, "-i", invPath}
	// A v2 spec's contract role can be an alias of the disposable VM rather
	// than its generated target name. Honour an explicit child --limit so the
	// expected-host resolver sees the contract role, not a duplicate VM alias.
	if !verifyExtraHasLimit(extra) {
		pilotArgs = append(pilotArgs, "-l", t.Name)
	}
	pilotArgs = append(pilotArgs, extra...)
	fmt.Fprintf(cmd.ErrOrStderr(), "▶ pilot %s\n", strings.Join(pilotArgs, " "))
	return execPilot(cmd.OutOrStdout(), pilotArgs...)
}

func verifyExtraHasLimit(args []string) bool {
	for i, arg := range args {
		if arg == "-l" || arg == "--limit" {
			return i+1 < len(args)
		}
		if strings.HasPrefix(arg, "--limit=") {
			return strings.TrimPrefix(arg, "--limit=") != ""
		}
	}
	return false
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

// vtStageGroupInventory resolves every target referenced by --group,
// renders a combined multi-host inventory with real ansible groups
// (via vmtarget.RenderGroupedInventory), and writes it to a temp file.
// It returns the "primary" target (--name if given and a member,
// otherwise the first member encountered) — used only for picking
// where to write the run transcript — plus every resolved target (for
// --sandbox, which needs to mount each one's own SSH key).
func vtStageGroupInventory(groupOrder []string, groups map[string][]string) (primary *vmtarget.Target, all []*vmtarget.Target, cleanup func(), invPath string, err error) {
	noop := func() {}
	m, err := vtNewManager()
	if err != nil {
		return nil, nil, noop, "", err
	}
	ctx := context.Background()

	var memberNames []string
	seen := map[string]bool{}
	for _, g := range groupOrder {
		for _, name := range groups[g] {
			if !seen[name] {
				seen[name] = true
				memberNames = append(memberNames, name)
			}
		}
	}

	targetsByName := make(map[string]*vmtarget.Target, len(memberNames))
	for _, name := range memberNames {
		gt, gerr := m.Get(ctx, name)
		if gerr != nil {
			return nil, nil, noop, "", fmt.Errorf("resolve --group member %q: %w", name, gerr)
		}
		if gt.Status != vmtarget.StatusRunning {
			return nil, nil, noop, "", fmt.Errorf("target %q (referenced by --group) is not running (status=%s); bring it up first", name, gt.Status)
		}
		targetsByName[name] = gt
		all = append(all, gt)
	}

	if vtName != "" {
		p, ok := targetsByName[vtName]
		if !ok {
			return nil, nil, noop, "", fmt.Errorf("--name %q is not one of the --group members", vtName)
		}
		primary = p
	} else {
		primary = targetsByName[memberNames[0]]
	}

	inv, err := vmtarget.RenderGroupedInventory(targetsByName, groupOrder, groups)
	if err != nil {
		return nil, nil, noop, "", err
	}
	invPath, cleanup, err = writeTempInventory(inv)
	if err != nil {
		return nil, nil, noop, "", err
	}
	return primary, all, cleanup, invPath, nil
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
	// Forward stdin only when it is piped/redirected (not an interactive
	// terminal), so `echo secret | pilot vm-target exec -- kinit admin` works
	// while a plain interactive `exec` doesn't block waiting on the tty.
	var stdin io.Reader
	if fi, err := os.Stdin.Stat(); err == nil && (fi.Mode()&os.ModeCharDevice) == 0 {
		stdin = os.Stdin
	}
	res, err := m.ExecStdin(context.Background(), vtName, args, stdin)
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

// ---- wire -----------------------------------------------------------------

var vtWirePeers []string

var vtWireCmd = &cobra.Command{
	Use:   "wire --name <target> --peer <other-target>[=<alias>] [--peer ...]",
	Short: "Idempotently pin peer vm-targets' IPs into /etc/hosts (for multi-node playbooks like FreeIPA replication)",
	Long: `Some playbooks need real cross-host DNS/hosts resolution between
several vm-target VMs — e.g. FreeIPA server/replica install, which
writes the peer's hostname into its OWN /etc/hosts but has no path to
the OTHER host's /etc/hosts (each vm-target VM only ever sees its own
generated inventory).

wire resolves each --peer by vm-target name, then writes ONE marked
block into --name's /etc/hosts mapping every peer's current IP to its
name (or an explicit alias via name=alias). Re-running replaces the
block instead of appending, so it is safe to call again after a
'vm-target reset' wiped it, or after a peer was re-provisioned and got
a new IP.

Example (a FreeIPA primary + replica that must resolve each other):
  pilot vm-target wire --name ipa-primary --peer ipa-replica
  pilot vm-target wire --name ipa-replica --peer ipa-primary
`,
	RunE: runVtWire,
}

func init() {
	vtWireCmd.Flags().StringVar(&vtName, "name", "", "target VM whose /etc/hosts to update (required)")
	vtWireCmd.Flags().StringArrayVar(&vtWirePeers, "peer", nil, "peer vm-target name to pin (repeatable); name=alias to use a different /etc/hosts hostname")
	_ = vtWireCmd.MarkFlagRequired("name")
	_ = vtWireCmd.MarkFlagRequired("peer")
}

const (
	vtWireMarkerBegin = "# BEGIN pilot vm-target wire"
	vtWireMarkerEnd   = "# END pilot vm-target wire"
)

// buildVtWireBlock renders the marked /etc/hosts block for the given
// (ip, hostname) pairs. Pulled out as a pure function so the format is
// unit-testable without a live target or SSH connection.
func buildVtWireBlock(lines [][2]string) string {
	var b strings.Builder
	b.WriteString(vtWireMarkerBegin + "\n")
	for _, l := range lines {
		fmt.Fprintf(&b, "%s\t%s\n", l[0], l[1])
	}
	b.WriteString(vtWireMarkerEnd + "\n")
	return b.String()
}

// vtWireScript is the idempotent remote shell command: delete any prior
// marked block, then append the new one (piped via stdin). Safe to run
// repeatedly — e.g. after every `vm-target reset` — since it never
// leaves duplicate entries the way a plain `>> /etc/hosts` would.
func vtWireScript() string {
	return fmt.Sprintf(`sed -i '/^%s$/,/^%s$/d' /etc/hosts && cat >> /etc/hosts`,
		regexp.QuoteMeta(vtWireMarkerBegin), regexp.QuoteMeta(vtWireMarkerEnd))
}

func runVtWire(cmd *cobra.Command, args []string) error {
	if vtName == "" {
		return fmt.Errorf("--name is required")
	}
	if len(vtWirePeers) == 0 {
		return fmt.Errorf("at least one --peer is required")
	}
	m, err := vtNewManager()
	if err != nil {
		return err
	}
	return wireTargetToPeers(context.Background(), m, cmd.OutOrStdout(), vtName, vtWirePeers)
}

// wireTargetToPeers resolves each peer spec ("name" or "name=alias") to
// its current IP and idempotently pins it into name's /etc/hosts. Pulled
// out of runVtWire so `vm-target topology up` can wire every declared
// node without shelling back out to `pilot vm-target wire`.
func wireTargetToPeers(ctx context.Context, m *vmtarget.Manager, out io.Writer, name string, peerSpecs []string) error {
	var lines [][2]string
	for _, p := range peerSpecs {
		peerName, alias := p, p
		if i := strings.IndexByte(p, '='); i >= 0 {
			peerName, alias = p[:i], p[i+1:]
		}
		peer, err := m.Get(ctx, peerName)
		if err != nil {
			return fmt.Errorf("resolve peer %q: %w", peerName, err)
		}
		if peer.IP == "" {
			return fmt.Errorf("peer %q has no IP yet; bring it up first", peerName)
		}
		lines = append(lines, [2]string{peer.IP, alias})
	}

	res, err := m.ExecStdin(ctx, name, []string{"sh", "-c", vtWireScript()}, strings.NewReader(buildVtWireBlock(lines)))
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("wiring %s's /etc/hosts failed (exit=%d): %s", name, res.ExitCode, res.Stderr)
	}
	for _, l := range lines {
		fmt.Fprintf(out, "✓ wired %s -> %s (%s)\n", l[1], name, l[0])
	}
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

// ---- resize-disk ----------------------------------------------------------

var (
	vtResizeDiskGB int
)

var vtResizeDiskCmd = &cobra.Command{
	Use:   "resize-disk",
	Short: "Grow the root disk of an existing VM target",
	Long: `Grow the root disk of an existing VM target to a new size in GiB.

Only growing is supported — shrinking is destructive and not a safe
operation. If the VM is running, the resize is applied online (the
guest kernel sees the larger block device immediately); a stopped VM
will see the new size on next boot.

After the block device is grown, the guest still needs to expand its
partition and filesystem. Most cloud images handle this automatically
via cloud-init's growpart module. If not, run inside the VM:
  growpart /dev/vda 1 && resize2fs /dev/vda1

Examples:
  pilot vm-target resize-disk --name core --disk 50
  pilot vm-target resize-disk --name core --disk 100
`,
	RunE: runVtResizeDisk,
}

func init() {
	vtResizeDiskCmd.Flags().StringVar(&vtName, "name", "", "target name (required)")
	vtResizeDiskCmd.Flags().IntVar(&vtResizeDiskGB, "disk", 0, "new root disk size in GiB (must be larger than current)")
	_ = vtResizeDiskCmd.MarkFlagRequired("name")
	_ = vtResizeDiskCmd.MarkFlagRequired("disk")
}

func runVtResizeDisk(cmd *cobra.Command, args []string) error {
	if vtName == "" {
		return fmt.Errorf("--name is required")
	}
	if vtResizeDiskGB <= 0 {
		return fmt.Errorf("--disk must be a positive integer (got %d)", vtResizeDiskGB)
	}
	m, err := vtNewManager()
	if err != nil {
		return err
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "▶ resizing %s root disk to %d GiB…\n", vtName, vtResizeDiskGB)
	if err := m.ResizeDisk(context.Background(), vtName, vtResizeDiskGB); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "✓ %s root disk resized to %d GiB\n", vtName, vtResizeDiskGB)
	return nil
}

// ---- test -----------------------------------------------------------------

var (
	vtTestPlaybook      string
	vtTestSpec          string
	vtTestSkipLint      bool
	vtTestNoRollback    bool
	vtTestVerifyTimeout int
)

var vtTestCmd = &cobra.Command{
	Use:   "test [-- <ansible extra-vars>...]",
	Short: "Run syntax, apply, verify, and idempotency tests against a VM target",
	Long: `Run a full integration and verification test suite against a VM target.

Steps executed:
  1. L1 syntax check: 'ansible-playbook --syntax-check'
  2. Auto-snapshot: captures current state under 'pre-test' tag
  3. L4 apply: runs the playbook
  4. L5 verify: runs 'pilot verify' against the target
  5. L6 idempotency: runs the playbook again and checks that changed=0
  6. Auto-rollback: if any step fails, automatically rolls back to 'pre-test'

Everything after '--' is forwarded VERBATIM to the apply AND idempotency
ansible-playbook runs — this is how you pass playbook variables the run needs:

  pilot vm-target test --name ubuntu-vm \
      --playbook playbooks/apply/freeipa-client-apply.yml \
      --spec docs/verification/freeipa-client.md \
      -- -e target_group=all -e ipa_server_ip=192.168.123.5 \
         -e ipa_verify_user=pilotuser -e @~/.vault/freeipa-sandbox.yaml

As with 'vm-target run', passing '-e target_group=<g>' switches the apply off
the default '-l <name>' limit (the playbook's own hosts: pattern takes over).
`,
	// Extras after '--' are collected as positional args and forwarded to
	// ansible; the required flags are still parsed normally.
	Args: cobra.ArbitraryArgs,
	RunE: runVtTest,
}

func init() {
	vtTestCmd.Flags().StringVar(&vtName, "name", "", "target VM name (required)")
	vtTestCmd.Flags().StringVar(&vtTestPlaybook, "playbook", "", "path to the playbook to run (required)")
	vtTestCmd.Flags().StringVar(&vtTestSpec, "spec", "", "path to the verification spec.md (required)")
	vtTestCmd.Flags().BoolVar(&vtTestSkipLint, "skip-lint", false, "skip syntax check pre-flight")
	vtTestCmd.Flags().BoolVar(&vtTestNoRollback, "no-rollback", false, "disable automatic rollback on failure")
	vtTestCmd.Flags().IntVar(&vtTestVerifyTimeout, "verify-timeout", 0, "per-row timeout (seconds) forwarded to `pilot verify` (0 = verify's own default)")

	_ = vtTestCmd.MarkFlagRequired("name")
	_ = vtTestCmd.MarkFlagRequired("playbook")
	_ = vtTestCmd.MarkFlagRequired("spec")
}

// buildApplyArgs assembles the ansible-playbook argv for the apply +
// idempotency runs of `vm-target test`. Extras (post-`--` -e vars etc.) are
// forwarded verbatim. Like `vm-target run`, a target_group in the extras means
// the playbook's own hosts: pattern owns targeting, so the -l <name> limit is
// dropped; otherwise the run is limited to the single target host.
func buildApplyArgs(playbook, invPath, limitName string, extras []string) []string {
	out := []string{playbook, "-i", invPath}
	if !extraHasTargetGroup(extras) {
		out = append(out, "-l", limitName)
	}
	return append(out, extras...)
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

	// Step 3: L4 Apply
	fmt.Fprintln(cmd.OutOrStdout(), "=== [Step 3/5] L4 Apply Playbook ===")
	t, cleanup, invPath, err := vtStageInventory()
	if err != nil {
		return err
	}
	defer cleanup()

	// Extras after '--' (e.g. -e ipa_server_ip=…, -e @vault) are forwarded to
	// the apply run. Mirror `vm-target run`: when the caller supplies
	// target_group, the playbook's own hosts: pattern owns targeting, so drop
	// the -l <name> limit (otherwise keep it).
	ansibleArgs := buildApplyArgs(vtTestPlaybook, invPath, t.Name, args)
	var applyBuf bytes.Buffer
	mw := io.MultiWriter(cmd.OutOrStdout(), &applyBuf)

	rollbackPolicy := delivery.RollbackSnapshot
	rollback := delivery.StepFunc(func(context.Context) error {
		fmt.Fprintf(cmd.ErrOrStderr(), "❌ Test failed. Rolling back VM to %s...\n", snapTag)
		if err := m.Rollback(ctx, vtName, snapTag); err != nil {
			return err
		}
		fmt.Fprintln(cmd.OutOrStdout(), "✓ Rollback successful. Target VM restored to pre-test state.")
		return nil
	})
	if vtTestNoRollback {
		fmt.Fprintln(cmd.ErrOrStderr(), "⚠️ Auto-rollback is disabled via --no-rollback")
		rollbackPolicy = delivery.RollbackNone
		rollback = nil
	}
	transaction := delivery.Transaction{
		Apply: func(context.Context) error {
			if err := execExternal(mw, "ansible-playbook", ansibleArgs...); err != nil {
				return fmt.Errorf("playbook apply failed: %w", err)
			}
			fmt.Fprintln(cmd.OutOrStdout(), "✓ Playbook apply completed")
			return nil
		},
		Verify: func(context.Context) error {
			fmt.Fprintln(cmd.OutOrStdout(), "=== [Step 4/5] L5 Verification Spec ===")
			pilotArgs := []string{"verify", vtTestSpec, "-i", invPath, "-l", t.Name, "--allow-isolated-mutation"}
			if vtTestVerifyTimeout > 0 {
				pilotArgs = append(pilotArgs, "--timeout", strconv.Itoa(vtTestVerifyTimeout))
			}
			if err := execPilot(cmd.OutOrStdout(), pilotArgs...); err != nil {
				return fmt.Errorf("verification failed: %w", err)
			}
			fmt.Fprintln(cmd.OutOrStdout(), "✓ Verification checks passed")
			return nil
		},
		Idempotency: func(context.Context) error {
			fmt.Fprintln(cmd.OutOrStdout(), "=== [Step 5/5] L6 Idempotency Check ===")
			var idemBuf bytes.Buffer
			if err := execExternal(io.MultiWriter(cmd.OutOrStdout(), &idemBuf), "ansible-playbook", ansibleArgs...); err != nil {
				return fmt.Errorf("idempotency run failed: %w", err)
			}
			changed, ok := idempotencyChangedCount(idemBuf.String())
			if !ok {
				return fmt.Errorf("idempotency check: no PLAY RECAP found in ansible output (unable to confirm changed=0)")
			}
			if changed > 0 {
				return fmt.Errorf("idempotency check failed: playbook reported %d changed task(s) on second run", changed)
			}
			fmt.Fprintln(cmd.OutOrStdout(), "✓ Idempotency check passed (changed=0)")
			return nil
		},
		IdempotencyPolicy: delivery.IdempotencyAlways,
		Rollback:          rollback,
		RollbackPolicy:    rollbackPolicy,
	}
	outcome, err := transaction.Run(ctx)
	if err != nil {
		return fmt.Errorf("vm-target test transaction %s: %w", outcome, err)
	}
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
