package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/anomalyco/pilot/internal/vmtarget"
)

// vm-target topology treats a declarative YAML spec (a list of nodes,
// each with its own base image, ansible groups, and /etc/hosts wiring)
// as the single source of truth for a multi-VM scenario like a FreeIPA
// primary+replica+client drill — replacing a hand-assembled sequence of
// `up`/`wire`/`--group` invocations where the agent has to parse one
// step's IP out of its output to build the next step's command.
var vtTopologyCmd = &cobra.Command{
	Use:   "topology",
	Short: "Bring up, wire, and inventory a multi-VM scenario from one declarative spec file",
	Long: `A topology spec (YAML) lists every node in a multi-VM scenario once,
with how to provision it, which ansible groups it belongs to, and which
peers to pin into its /etc/hosts:

  nodes:
    - name: ipa-primary
      base_image: rocky9
      groups: [ipa_masters]
      wire: [ipa-replica, ipa-ha-client]
    - name: ipa-replica
      base_image: rocky9
      groups: [ipa_replicas]
      wire: ["ipa-primary=ipa1.ipa.pilot.internal"]
    - name: ipa-ha-client
      base_image: rocky9
      groups: [ipa_clients]
      wire: [ipa-primary, ipa-replica]

'wire' entries accept the same "name" / "name=alias" form as
'vm-target wire --peer'. 'groups' feeds vmtarget.RenderGroupedInventory
(the same mechanism 'vm-target run --group' uses), so a playbook whose
'hosts:' pattern matches a real group name (e.g. ipa_masters) needs no
-e target_group=... workaround.

  pilot vm-target topology up        --spec ha.yaml
  pilot vm-target topology inventory --spec ha.yaml
  pilot vm-target topology status    --spec ha.yaml
  pilot vm-target topology down      --spec ha.yaml
  pilot vm-target topology snapshot  --spec ha.yaml --tag pre-drill
  pilot vm-target topology rollback  --spec ha.yaml --tag pre-drill
  pilot vm-target topology reset     --spec ha.yaml

'up' provisions every not-yet-running node CONCURRENTLY (one goroutine +
one *vmtarget.Manager per node — Manager.Up holds its own in-process
lock for the whole boot/SSH wait, so goroutines sharing one Manager
would just queue; separate Managers over the same state dir do not).
This is safe: Manager.Up reserves its name via Store.Mutate (cross-
process flock) before touching disk/libvirt, closing the 2026-07-06
lost-state-entry race for good (AGENTS.md §5.1;
TestUp_ConcurrentDifferentNames_BothPersist). An already-running node
(matching name) is left alone (idempotent — safe to re-run 'up' after
adding a node to the spec). Wiring runs after every node is up, since
it needs every peer's final IP.

'snapshot'/'rollback'/'reset' apply the equivalent single-VM operation to
every node in the spec concurrently, so you can checkpoint or restore an
entire multi-VM scenario (e.g. "can replica-install rerun cleanly?")
without hand-tracking each node's snapshot state. Because the "clean"
snapshot 'up' takes automatically predates wiring, 'rollback' and 'reset'
re-apply every node's declared 'wire:' peers afterward — 'snapshot' does
not, since it doesn't touch disk state.
`,
}

var (
	vtTopoSpecPath string
	vtTopoOut      string
	vtTopoTag      string
)

func init() {
	vmTargetCmd.AddCommand(vtTopologyCmd)
	vtTopologyCmd.AddCommand(vtTopologyUpCmd)
	vtTopologyCmd.AddCommand(vtTopologyDownCmd)
	vtTopologyCmd.AddCommand(vtTopologyInventoryCmd)
	vtTopologyCmd.AddCommand(vtTopologyStatusCmd)
	vtTopologyCmd.AddCommand(vtTopologySnapshotCmd)
	vtTopologyCmd.AddCommand(vtTopologyRollbackCmd)
	vtTopologyCmd.AddCommand(vtTopologyResetCmd)

	allTopoCmds := []*cobra.Command{
		vtTopologyUpCmd, vtTopologyDownCmd, vtTopologyInventoryCmd, vtTopologyStatusCmd,
		vtTopologySnapshotCmd, vtTopologyRollbackCmd, vtTopologyResetCmd,
	}
	for _, c := range allTopoCmds {
		c.Flags().StringVar(&vtTopoSpecPath, "spec", "", "path to the topology YAML spec (required)")
		_ = c.MarkFlagRequired("spec")
	}
	vtTopologyInventoryCmd.Flags().StringVar(&vtTopoOut, "out", "", "write the rendered inventory here instead of stdout")
	vtTopologySnapshotCmd.Flags().StringVar(&vtTopoTag, "tag", "", "snapshot tag to create on every node (required)")
	_ = vtTopologySnapshotCmd.MarkFlagRequired("tag")
	vtTopologyRollbackCmd.Flags().StringVar(&vtTopoTag, "tag", "", "snapshot tag to revert every node to (required)")
	_ = vtTopologyRollbackCmd.MarkFlagRequired("tag")
}

// runTopologyNodesConcurrently runs fn once per spec node, each on its own
// *vmtarget.Manager (mirrors runVtTopologyUp: Snapshot/Rollback/Reset don't
// hold Manager's long in-process lock the way Up does, but a fresh Manager
// per goroutine keeps the pattern consistent and costs nothing). Returns
// the first error encountered, if any.
func runTopologyNodesConcurrently(spec *vmtarget.TopologySpec, fn func(nm *vmtarget.Manager, n vmtarget.TopologyNode) error) error {
	var wg sync.WaitGroup
	errs := make([]error, len(spec.Nodes))
	for i, n := range spec.Nodes {
		wg.Add(1)
		go func(i int, n vmtarget.TopologyNode) {
			defer wg.Done()
			nm, merr := vtNewManager()
			if merr != nil {
				errs[i] = merr
				return
			}
			errs[i] = fn(nm, n)
		}(i, n)
	}
	wg.Wait()
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}

// rewireTopology re-applies every node's declared 'wire:' peers. Needed
// after a cluster-wide rollback/reset: the "clean" snapshot 'up' takes
// automatically (vmtarget.go, right after boot) predates topology 'up's
// wiring loop, so reverting a node's disk to that snapshot drops its
// /etc/hosts entries.
func rewireTopology(spec *vmtarget.TopologySpec, out io.Writer) error {
	m, err := vtNewManager()
	if err != nil {
		return err
	}
	ctx := context.Background()
	for _, n := range spec.Nodes {
		if len(n.Wire) == 0 {
			continue
		}
		if err := wireTargetToPeers(ctx, m, out, n.Name, n.Wire); err != nil {
			return fmt.Errorf("wire %q: %w", n.Name, err)
		}
	}
	return nil
}

// ---- up ---------------------------------------------------------------

var vtTopologyUpCmd = &cobra.Command{
	Use:   "up",
	Short: "Bring up every node in a topology spec (concurrent, idempotent), then wire /etc/hosts",
	RunE:  runVtTopologyUp,
}

func runVtTopologyUp(cmd *cobra.Command, args []string) error {
	spec, err := vmtarget.LoadTopologySpec(vtTopoSpecPath)
	if err != nil {
		return err
	}
	m, err := vtNewManager()
	if err != nil {
		return err
	}
	ctx := context.Background()
	out := cmd.OutOrStdout()
	var outMu sync.Mutex
	printf := func(format string, a ...any) {
		outMu.Lock()
		defer outMu.Unlock()
		fmt.Fprintf(out, format, a...)
	}

	var toProvision []vmtarget.TopologyNode
	for _, n := range spec.Nodes {
		if existing, gerr := m.Get(ctx, n.Name); gerr == nil {
			printf("= %s already up (status=%s, ip=%s) — skipping\n", n.Name, existing.Status, existing.IP)
			continue
		}
		toProvision = append(toProvision, n)
	}

	// Provision concurrently: each node gets its own *vmtarget.Manager
	// pointed at the same state/vm dirs (mirrors newSiblingManager in
	// vmtarget_test.go), because Manager.Up holds an in-process mutex
	// for its ENTIRE call — including the multi-minute boot/SSH wait —
	// so goroutines sharing one Manager would only queue, not
	// parallelize. Cross-Manager safety comes from Store.Mutate's
	// cross-process flock (AGENTS.md §5.1), not from this mutex.
	var wg sync.WaitGroup
	errs := make([]error, len(toProvision))
	for i, n := range toProvision {
		wg.Add(1)
		go func(i int, n vmtarget.TopologyNode) {
			defer wg.Done()
			nm, merr := vtNewManager()
			if merr != nil {
				errs[i] = merr
				return
			}
			printf("▶ provisioning %s...\n", n.Name)
			opt, operr := n.ToOptions()
			if operr != nil {
				errs[i] = operr
				return
			}
			tgt, uerr := nm.Up(ctx, opt)
			if uerr != nil {
				errs[i] = fmt.Errorf("node %q: %w", n.Name, uerr)
				return
			}
			printf("✓ %s up (ip=%s)\n", tgt.Name, tgt.IP)
		}(i, n)
	}
	wg.Wait()
	for _, e := range errs {
		if e != nil {
			return e
		}
	}

	for _, n := range spec.Nodes {
		if len(n.Wire) == 0 {
			continue
		}
		if err := wireTargetToPeers(ctx, m, out, n.Name, n.Wire); err != nil {
			return fmt.Errorf("wire %q: %w", n.Name, err)
		}
	}

	if order, _ := spec.Groups(); len(order) > 0 {
		fmt.Fprintf(out, "\ninventory : `pilot vm-target topology inventory --spec %s`\n", vtTopoSpecPath)
	}
	return nil
}

// ---- down ---------------------------------------------------------------

var vtTopologyDownCmd = &cobra.Command{
	Use:   "down",
	Short: "Tear down every node in a topology spec",
	RunE:  runVtTopologyDown,
}

func runVtTopologyDown(cmd *cobra.Command, args []string) error {
	spec, err := vmtarget.LoadTopologySpec(vtTopoSpecPath)
	if err != nil {
		return err
	}
	m, err := vtNewManager()
	if err != nil {
		return err
	}
	ctx := context.Background()
	out := cmd.OutOrStdout()

	var firstErr error
	for _, n := range spec.Nodes {
		if err := m.Down(ctx, n.Name); err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "✗ %s: %v\n", n.Name, err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		fmt.Fprintf(out, "✓ %s down\n", n.Name)
	}
	return firstErr
}

// ---- inventory ------------------------------------------------------------

var vtTopologyInventoryCmd = &cobra.Command{
	Use:   "inventory",
	Short: "Render the grouped ansible inventory for every node's declared groups (all nodes must be running)",
	RunE:  runVtTopologyInventory,
}

func runVtTopologyInventory(cmd *cobra.Command, args []string) error {
	spec, err := vmtarget.LoadTopologySpec(vtTopoSpecPath)
	if err != nil {
		return err
	}
	order, groups := spec.Groups()
	if len(order) == 0 {
		return fmt.Errorf("topology spec %s declares no node 'groups:' — nothing to render", vtTopoSpecPath)
	}
	m, err := vtNewManager()
	if err != nil {
		return err
	}
	ctx := context.Background()

	targetsByName := make(map[string]*vmtarget.Target, len(spec.Nodes))
	for _, n := range spec.Nodes {
		t, gerr := m.Get(ctx, n.Name)
		if gerr != nil {
			return fmt.Errorf("resolve node %q: %w", n.Name, gerr)
		}
		if t.Status != vmtarget.StatusRunning {
			return fmt.Errorf("node %q is not running (status=%s); run `pilot vm-target topology up --spec %s` first", n.Name, t.Status, vtTopoSpecPath)
		}
		targetsByName[n.Name] = t
	}

	inv, err := vmtarget.RenderGroupedInventory(targetsByName, order, groups)
	if err != nil {
		return err
	}
	if vtTopoOut == "" {
		_, err := fmt.Fprint(cmd.OutOrStdout(), inv)
		return err
	}
	if err := os.WriteFile(vtTopoOut, []byte(inv), 0o644); err != nil {
		return fmt.Errorf("write inventory to %s: %w", vtTopoOut, err)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "✓ wrote inventory to %s\n", vtTopoOut)
	return nil
}

// ---- status ---------------------------------------------------------------

var vtTopologyStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show the live status/IP/groups of every node declared in a topology spec",
	RunE:  runVtTopologyStatus,
}

func runVtTopologyStatus(cmd *cobra.Command, args []string) error {
	spec, err := vmtarget.LoadTopologySpec(vtTopoSpecPath)
	if err != nil {
		return err
	}
	m, err := vtNewManager()
	if err != nil {
		return err
	}
	ctx := context.Background()

	tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tSTATUS\tIP\tGROUPS\tWIRE")
	for _, n := range spec.Nodes {
		status, ip := "(not up)", "-"
		if t, gerr := m.Get(ctx, n.Name); gerr == nil {
			status, ip = string(t.Status), t.IP
			if ip == "" {
				ip = "-"
			}
		}
		groups := "-"
		if len(n.Groups) > 0 {
			groups = strings.Join(n.Groups, ",")
		}
		wire := "-"
		if len(n.Wire) > 0 {
			wire = strings.Join(n.Wire, ",")
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", n.Name, status, ip, groups, wire)
	}
	return tw.Flush()
}

// ---- snapshot ---------------------------------------------------------

var vtTopologySnapshotCmd = &cobra.Command{
	Use:   "snapshot",
	Short: "Snapshot every node in a topology spec under one tag (concurrent)",
	RunE:  runVtTopologySnapshot,
}

func runVtTopologySnapshot(cmd *cobra.Command, args []string) error {
	spec, err := vmtarget.LoadTopologySpec(vtTopoSpecPath)
	if err != nil {
		return err
	}
	if err := runTopologyNodesConcurrently(spec, func(nm *vmtarget.Manager, n vmtarget.TopologyNode) error {
		if err := nm.Snapshot(context.Background(), n.Name, vtTopoTag); err != nil {
			return fmt.Errorf("node %q: %w", n.Name, err)
		}
		return nil
	}); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "✓ snapshotted %d node(s) as %q\n", len(spec.Nodes), vtTopoTag)
	return nil
}

// ---- rollback -------------------------------------------------------------

var vtTopologyRollbackCmd = &cobra.Command{
	Use:   "rollback",
	Short: "Revert every node in a topology spec to a snapshot tag (concurrent), then re-wire /etc/hosts",
	Long: `Reverts every node's disk to the given snapshot tag concurrently.

Because /etc/hosts wiring is written post-boot (after 'up' already
snapshots "clean"), any tag taken before wiring loses it on rollback --
this command re-applies each node's declared 'wire:' peers after every
node has reverted, mirroring 'topology up'.
`,
	RunE: runVtTopologyRollback,
}

func runVtTopologyRollback(cmd *cobra.Command, args []string) error {
	spec, err := vmtarget.LoadTopologySpec(vtTopoSpecPath)
	if err != nil {
		return err
	}
	out := cmd.OutOrStdout()
	if err := runTopologyNodesConcurrently(spec, func(nm *vmtarget.Manager, n vmtarget.TopologyNode) error {
		if err := nm.Rollback(context.Background(), n.Name, vtTopoTag); err != nil {
			return fmt.Errorf("node %q: %w", n.Name, err)
		}
		return nil
	}); err != nil {
		return err
	}
	fmt.Fprintf(out, "✓ rolled back %d node(s) to %q\n", len(spec.Nodes), vtTopoTag)
	return rewireTopology(spec, out)
}

// ---- reset ------------------------------------------------------------

var vtTopologyResetCmd = &cobra.Command{
	Use:   "reset",
	Short: "Revert every node in a topology spec to its pristine post-up state (concurrent), then re-wire /etc/hosts",
	Long: `Revert every node to the automatic "clean" checkpoint 'up' captures,
concurrently, then re-apply every node's declared 'wire:' peers (the
"clean" snapshot predates wiring, so it would otherwise be lost).

This is the fast path for re-testing "does replica-install work from a
clean cluster?" without a full 'topology down' + 'topology up':

  pilot vm-target topology reset --spec ha.yaml
  pilot vm-target run --group masters=ipa-primary --group replicas=ipa-replica ... \
    playbooks/apply/freeipa-server-replica-apply.yml -e ...
`,
	RunE: runVtTopologyReset,
}

func runVtTopologyReset(cmd *cobra.Command, args []string) error {
	spec, err := vmtarget.LoadTopologySpec(vtTopoSpecPath)
	if err != nil {
		return err
	}
	out := cmd.OutOrStdout()
	if err := runTopologyNodesConcurrently(spec, func(nm *vmtarget.Manager, n vmtarget.TopologyNode) error {
		if err := nm.Reset(context.Background(), n.Name); err != nil {
			return fmt.Errorf("node %q: %w", n.Name, err)
		}
		return nil
	}); err != nil {
		return err
	}
	fmt.Fprintf(out, "✓ reset %d node(s) to %q (pristine post-boot state)\n", len(spec.Nodes), vmtarget.CleanSnapshotTag)
	return rewireTopology(spec, out)
}
