// target.go provides a thin wrapper that dispatches `pilot target <subcmd>`
// to either the docker-target or the vm-target machinery, picking the
// right backend by looking at the per-target state files. The point
// is to let the user stop typing long subcommand-prefixed commands
// like:
//
//	pilot vm-target up --base-image /var/lib/libvirt/images/pilot/noble-base.qcow2 \
//	    --name core --hosts dns,ntp,keycloak
//	ansible-playbook -i /tmp/inv-core.yaml \
//	    playbooks/apply/core-infra-provider-apply.yml \
//	    -e infra_role=dns -e target_group=dns -e dns_listen_addr=127.0.0.1
//	KEYCLOAK_ISSUER=... pilot verify docs/verification/core-infra-provider.md \
//	    -i /tmp/inv-core.yaml
//
// and write instead:
//
//	pilot target up     --target core
//	pilot target run    --target core --playbook playbooks/apply/core-infra-provider-apply.yml --role dns
//	pilot target verify --target core --spec docs/verification/core-infra-provider.md
//
// The wrapper is *thin*: it does not duplicate any of the up / run /
// verify / ssh logic — it just looks up which backend owns the named
// target, then re-execs the corresponding docker-target or vm-target
// subcommand with the same argv. So all the existing flags and
// behavior stay where they are; the wrapper is a UX layer.
package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

// TargetKind enumerates the backends `pilot target` can dispatch to.
type TargetKind string

const (
	TargetKindDocker TargetKind = "docker"
	TargetKindVM     TargetKind = "vm"
)

// targetKindFromState reads ~/.local/share/pilot/{docker,vm}-targets.json
// (or the override from --data-dir) and reports which backend owns the
// given target name. Empty string means "not found in either state file".
//
// We tolerate either state file being missing (a fresh install starts
// with no targets at all) and return "" without erroring.
func targetKindFromState(name string) (TargetKind, error) {
	if name == "" {
		return "", nil
	}
	dataDir := resolveDataDir()
	// docker first (cheaper to check on a typical dev box, and
	// matches the auto-detect priority of `pilot run --sandbox`).
	if k, err := kindFromStateFile(filepath.Join(dataDir, "docker-targets.json"), name, "hostname"); err != nil {
		return "", err
	} else if k != "" {
		return TargetKind(k), nil
	}
	if k, err := kindFromStateFile(filepath.Join(dataDir, "vm-targets.json"), name, "name"); err != nil {
		return "", err
	} else if k != "" {
		return TargetKind(k), nil
	}
	return "", nil
}

// kindFromStateFile decodes the JSON state file, looks for a target
// whose keyField matches `name`, and returns the corresponding kind
// string ("docker" or "vm") or "" if not found. The key field differs
// between the two state formats: docker-targets.json uses "hostname"
// (container hostname; matches the Target.Hostname json tag),
// vm-targets.json uses "name" (matches Target.Name).
func kindFromStateFile(path, name, keyField string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	var raw struct {
		Targets []map[string]any `json:"targets"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return "", nil
	}
	for _, t := range raw.Targets {
		// json.Unmarshal is case-INsensitive for struct field tags, so
		// we should match the lowercase form. Try both just in case
		// someone hand-edits a state file with the camelCase form.
		v, ok := t[keyField].(string)
		if !ok {
			// Fallback: case-insensitive search.
			for k, vv := range t {
				if strings.EqualFold(k, keyField) {
					v, ok = vv.(string)
					break
				}
			}
		}
		if ok && v == name {
			switch keyField {
			case "hostname":
				return string(TargetKindDocker), nil
			case "name":
				return string(TargetKindVM), nil
			}
		}
	}
	return "", nil
}

// ---- target subcommand group ---------------------------------------------

var targetCmd = &cobra.Command{
	Use:   "target",
	Short: "Run ansible playbooks / verify specs against a docker or vm target (auto-detected)",
	Long: `Thin wrapper that dispatches to either pilot docker-target or
pilot vm-target based on the named target's state file. Lets you
write a single set of commands regardless of backend.

Auto-detect precedence (first match wins):
  1. --type docker or --type vm (explicit)
  2. ~/.local/share/pilot/vm-targets.json  -- if the name is there
  3. ~/.local/share/pilot/docker-targets.json -- if the name is there

Examples:
  pilot target up     --target core --vm
  pilot target run    --target core --playbook playbooks/apply/core-infra-provider-apply.yml --role dns
  pilot target verify --target core --spec docs/verification/core-infra-provider.md
  pilot target shell  --target core
  pilot target down   --target core`,
}

var (
	// target-level flags (shared by every subcommand)
	targetName string
	targetType string // "" = auto-detect, "docker" or "vm" = explicit
)

func init() {
	targetCmd.PersistentFlags().StringVar(&targetName, "target", "", "target name (auto-detected as docker or vm)")
	targetCmd.PersistentFlags().StringVar(&targetType, "type", "", "force backend type: docker|vm (default: auto-detect from state)")
	rootCmd.AddCommand(targetCmd)

	targetCmd.AddCommand(targetUpCmd)
	targetCmd.AddCommand(targetDownCmd)
	targetCmd.AddCommand(targetListCmd)
	targetCmd.AddCommand(targetRunCmd)
	targetCmd.AddCommand(targetVerifyCmd)
	targetCmd.AddCommand(targetExecCmd)
	targetCmd.AddCommand(targetSSHCmd)
	targetCmd.AddCommand(targetShellCmd)
	targetCmd.AddCommand(targetSnapshotCmd)
	targetCmd.AddCommand(targetRollbackCmd)
}

// resolveTarget figures out the backend kind for the named target.
// If --type is set explicitly, that wins. Otherwise we look at the
// state files. If neither finds the target, return the user-facing
// error they need to fix.
func resolveTarget(cmd *cobra.Command) (TargetKind, error) {
	if targetName == "" {
		return "", fmt.Errorf("--target is required")
	}
	if targetType != "" {
		switch targetType {
		case "docker", "vm":
			return TargetKind(targetType), nil
		default:
			return "", fmt.Errorf("--type must be one of: docker, vm (got %q)", targetType)
		}
	}
	kind, err := targetKindFromState(targetName)
	if err != nil {
		return "", err
	}
	if kind == "" {
		return "", fmt.Errorf("target %q not found in docker-targets.json or vm-targets.json under %s; bring it up first or pass --type", targetName, resolveDataDir())
	}
	return kind, nil
}

// backendTakesName reports whether the named backend subcommand
// needs the --name flag. `list` operates on the whole state file and
// does not take --name; everything else does.
func backendTakesName(backendSubcmd string) bool {
	switch backendSubcmd {
	case "list", "show-inventory":
		return false
	}
	return true
}

// delegate re-execs the same pilot binary as a docker-target or
// vm-target subcommand. The argv we built for the wrapper is rewritten
// to drop the "target" verb and the wrapper-only flags, and to
// substitute the right backend subcommand.
func delegate(cmd *cobra.Command, kind TargetKind, backendSubcmd string, positional []string, extra []string) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate pilot binary: %w", err)
	}
	args := []string{string(kind) + "-target", backendSubcmd}
	args = append(args, positional...)
	if backendTakesName(backendSubcmd) {
		args = append(args, "--name", targetName)
	}
	args = append(args, extra...)
	fmt.Fprintf(cmd.ErrOrStderr(), "▶ %s %s %s\n", exe, string(kind)+"-target", strings.Join(args[1:], " "))
	c := newCmd(cmd.Context(), exe, args...)
	c.Stdout = cmd.OutOrStdout()
	c.Stderr = cmd.ErrOrStderr()
	c.Stdin = os.Stdin
	return c.Run()
}

// extractTargetFlag scans args for --target <v>, --target=<v>,
// --name <v>, or --name=<v> and returns (value, remaining args)
// when found. The wrapper declares --target as the user-facing flag
// (so a user can't be expected to know the backend's --name), but
// we also accept --name so a backended invocation still works.
//
// Note: we always allocate a fresh backing array for the returned
// slice, so the caller's `args` is never mutated.
func extractTargetFlag(args []string) (string, []string) {
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--target" && i+1 < len(args):
			out := make([]string, 0, len(args)-2)
			out = append(out, args[:i]...)
			out = append(out, args[i+2:]...)
			return args[i+1], out
		case strings.HasPrefix(args[i], "--target="):
			out := make([]string, 0, len(args)-1)
			out = append(out, args[:i]...)
			out = append(out, args[i+1:]...)
			return strings.TrimPrefix(args[i], "--target="), out
		case args[i] == "--name" && i+1 < len(args):
			out := make([]string, 0, len(args)-2)
			out = append(out, args[:i]...)
			out = append(out, args[i+2:]...)
			return args[i+1], out
		case strings.HasPrefix(args[i], "--name="):
			out := make([]string, 0, len(args)-1)
			out = append(out, args[:i]...)
			out = append(out, args[i+1:]...)
			return strings.TrimPrefix(args[i], "--name="), out
		}
	}
	return "", args
}

// ---- subcommands ---------------------------------------------------------

var targetUpCmd = &cobra.Command{
	Use:   "up",
	Short: "Bring up a docker or vm target (auto-detect or --type)",
	Long: `Bring up a target. For --type vm, requires --base-image
(or uses the default /var/lib/libvirt/images/pilot/noble-base.qcow2).
For --type docker, requires --image or --image-pilot (or uses the
default pilot-target:ubuntu-24.04).`,
	Args: cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		kind, err := resolveTargetKindForUp()
		if err != nil {
			return err
		}
		return delegate(cmd, kind, "up", nil, args)
	},
}

// resolveTargetKindForUp is the one place where the user is allowed to
// bring up a target that doesn't exist yet. So we accept --type= as
// authoritative when the state files have no record.
func resolveTargetKindForUp() (TargetKind, error) {
	if targetName == "" {
		return "", fmt.Errorf("--target is required")
	}
	if targetType != "" {
		switch targetType {
		case "docker", "vm":
			return TargetKind(targetType), nil
		default:
			return "", fmt.Errorf("--type must be one of: docker, vm (got %q)", targetType)
		}
	}
	// No state: default to vm (higher-fidelity target; matches the
	// `pilot run --sandbox` dev-loop convention only for docker, so
	// when in doubt, prefer the real thing).
	return TargetKindVM, nil
}

var targetDownCmd = &cobra.Command{
	Use:   "down",
	Short: "Tear down a target",
	Args:  cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		kind, err := resolveTarget(cmd)
		if err != nil {
			return err
		}
		return delegate(cmd, kind, "down", nil, args)
	},
}

var targetListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all known targets (docker + vm, merged view)",
	Args:  cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		for _, kind := range []TargetKind{TargetKindDocker, TargetKindVM} {
			if err := delegate(cmd, kind, "list", nil, args); err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "(no %s targets)\n", kind)
			}
		}
		return nil
	},
}

var targetRunCmd = &cobra.Command{
	Use:   "run --playbook <pb> [--role <name>] [-- <extras>...]",
	Short: "Run an ansible playbook against the target. Auto-injects -i, -l, and -e target_group.",
	Long: `Run an ansible playbook against the named target.

The wrapper:
  1. Renders the right inventory (docker or vm) to a temp file.
  2. If --role <name> is given, also passes -e infra_role=<name>
     -e target_group=<name> (the common case for the role-gated
     apply playbooks in playbooks/apply/).
  3. Forwards anything after -- to ansible-playbook verbatim.

Examples:
  pilot target run --target core --playbook playbooks/apply/core-infra-provider-apply.yml --role dns
  pilot target run --target core --playbook pb.yml -- -e foo=bar --check`,
	Args:               cobra.ArbitraryArgs,
	DisableFlagParsing: true,
	RunE:               runTargetRun,
}

func runTargetRun(cmd *cobra.Command, args []string) error {
	parsed, extra, err := splitWrapperArgs(args)
	if err != nil {
		return err
	}
	if parsed.playbook == "" {
		return fmt.Errorf("--playbook is required (or pass a positional playbook arg)")
	}
	if parsed.target != "" {
		targetName = parsed.target
	}
	if targetName == "" {
		return fmt.Errorf("--target is required")
	}
	kind, err := resolveTarget(cmd)
	if err != nil {
		return err
	}
	positional := []string{parsed.playbook}
	backendExtra := []string{}
	if parsed.role != "" {
		backendExtra = append(backendExtra, "-e", "infra_role="+parsed.role, "-e", "target_group="+parsed.role)
	}
	backendExtra = append(backendExtra, extra...)
	return delegate(cmd, kind, "run", positional, backendExtra)
}

var targetVerifyCmd = &cobra.Command{
	Use:   "verify --spec <spec.md> [-- <extras>...]",
	Short: "Run pilot verify against the target. Auto-renders the right inventory and stages /etc/pilot-verify.env.",
	Long: `Run pilot verify against the named target. The wrapper handles
inventory rendering, KEYCLOAK_ISSUER staging, and the -l injection
so the user can just point at a spec.

Examples:
  pilot target verify --target core --spec docs/verification/core-infra-provider.md
  KEYCLOAK_ISSUER=http://127.0.0.1:8080/realms/master \
    pilot target verify --target core --spec docs/verification/core-infra-provider.md`,
	Args:               cobra.ArbitraryArgs,
	DisableFlagParsing: true,
	RunE:               runTargetVerify,
}

func runTargetVerify(cmd *cobra.Command, args []string) error {
	parsed, extra, err := splitWrapperArgs(args)
	if err != nil {
		return err
	}
	if parsed.spec == "" && len(extra) == 0 {
		return fmt.Errorf("--spec is required (or pass a positional spec path)")
	}
	if parsed.target != "" {
		targetName = parsed.target
	}
	if targetName == "" {
		return fmt.Errorf("--target is required")
	}
	kind, err := resolveTarget(cmd)
	if err != nil {
		return err
	}
	spec := parsed.spec
	if spec == "" && len(extra) > 0 {
		spec = extra[0]
		extra = extra[1:]
	}
	positional := []string{spec}
	return delegate(cmd, kind, "verify", positional, extra)
}

var targetExecCmd = &cobra.Command{
	Use:                "exec -- <argv...>",
	Short:              "Run a single command on the target (no PTY, captured output)",
	Args:               cobra.MinimumNArgs(1),
	DisableFlagParsing: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if v, stripped := extractTargetFlag(args); v != "" {
			targetName = v
			args = stripped
		}
		kind, err := resolveTarget(cmd)
		if err != nil {
			return err
		}
		return delegate(cmd, kind, "exec", nil, args)
	},
}

var targetSSHCmd = &cobra.Command{
	Use:                "ssh [-- <remote-argv>...]",
	Short:              "Open an interactive SSH session to the target (real PTY)",
	Args:               cobra.ArbitraryArgs,
	DisableFlagParsing: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if v, stripped := extractTargetFlag(args); v != "" {
			targetName = v
			args = stripped
		}
		kind, err := resolveTarget(cmd)
		if err != nil {
			return err
		}
		return delegate(cmd, kind, "ssh", nil, args)
	},
}

var targetShellCmd = &cobra.Command{
	Use:                "shell [-- <remote-argv>...]",
	Short:              "Drop into an interactive shell on the target (auto-detect docker|vm)",
	Args:               cobra.ArbitraryArgs,
	DisableFlagParsing: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if v, stripped := extractTargetFlag(args); v != "" {
			targetName = v
			args = stripped
		}
		kind, err := resolveTarget(cmd)
		if err != nil {
			return err
		}
		return delegate(cmd, kind, "shell", nil, args)
	},
}

var targetSnapshotCmd = &cobra.Command{
	Use:                "snapshot --tag <tag>",
	Short:              "Snapshot the target (docker commit / libvirt qcow2 snapshot)",
	Args:               cobra.ArbitraryArgs,
	DisableFlagParsing: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if v, stripped := extractTargetFlag(args); v != "" {
			targetName = v
			args = stripped
		}
		kind, err := resolveTarget(cmd)
		if err != nil {
			return err
		}
		return delegate(cmd, kind, "snapshot", nil, args)
	},
}

var targetRollbackCmd = &cobra.Command{
	Use:                "rollback --image <image>  (docker)  /  --tag <tag>  (vm)",
	Short:              "Roll back the target to a previously captured snapshot",
	Args:               cobra.ArbitraryArgs,
	DisableFlagParsing: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if v, stripped := extractTargetFlag(args); v != "" {
			targetName = v
			args = stripped
		}
		kind, err := resolveTarget(cmd)
		if err != nil {
			return err
		}
		return delegate(cmd, kind, "rollback", nil, args)
	},
}

// ---- minimal flag splitter for DisableFlagParsing subcommands ----------

type parsedTargetArgs struct {
	target   string
	playbook string
	spec     string
	role     string
}

// splitWrapperArgs is a tiny parser for the wrapper-specific flags
// (--target, --playbook, --spec, --role) plus positional arg
// detection. Everything else is returned in `extra` so the backend
// gets it verbatim.
//
// The wrapper accepts a mix of:
//
//	--target X  --playbook pb  --role dns  -- <extras>
//	--target X  pb  -e foo=bar  (positional playbook)
//	--target X  --spec spec.md -- <extras>
func splitWrapperArgs(args []string) (parsedTargetArgs, []string, error) {
	var p parsedTargetArgs
	extra := make([]string, 0, len(args))
	i := 0
	for i < len(args) {
		a := args[i]
		switch {
		case a == "--target" && i+1 < len(args):
			p.target = args[i+1]
			i += 2
		case strings.HasPrefix(a, "--target="):
			p.target = strings.TrimPrefix(a, "--target=")
			i++
		case a == "--playbook" && i+1 < len(args):
			p.playbook = args[i+1]
			i += 2
		case strings.HasPrefix(a, "--playbook="):
			p.playbook = strings.TrimPrefix(a, "--playbook=")
			i++
		case a == "--spec" && i+1 < len(args):
			p.spec = args[i+1]
			i += 2
		case strings.HasPrefix(a, "--spec="):
			p.spec = strings.TrimPrefix(a, "--spec=")
			i++
		case a == "--role" && i+1 < len(args):
			p.role = args[i+1]
			i += 2
		case strings.HasPrefix(a, "--role="):
			p.role = strings.TrimPrefix(a, "--role=")
			i++
		case a == "--":
			extra = append(extra, args[i+1:]...)
			return p, extra, nil
		case strings.HasPrefix(a, "-"):
			extra = append(extra, a)
			// Cheap heuristic: if the next arg exists and does NOT
			// start with -, treat it as the value of this flag.
			// (Backends are responsible for any stricter parsing.)
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				extra = append(extra, args[i+1])
				i += 2
				continue
			}
			i++
		default:
			if p.playbook == "" {
				p.playbook = a
			} else if p.spec == "" {
				p.spec = a
			} else {
				extra = append(extra, a)
			}
			i++
		}
	}
	return p, extra, nil
}
