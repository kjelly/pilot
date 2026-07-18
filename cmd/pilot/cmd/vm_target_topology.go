package cmd

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

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
  pilot vm-target topology test      --spec ha.yaml --playbook ... --verify ...

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
	vtTopologyCmd.AddCommand(vtTopologyTestCmd)

	allTopoCmds := []*cobra.Command{
		vtTopologyUpCmd, vtTopologyDownCmd, vtTopologyInventoryCmd, vtTopologyStatusCmd,
		vtTopologySnapshotCmd, vtTopologyRollbackCmd, vtTopologyResetCmd, vtTopologyTestCmd,
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

	vtTopologyTestCmd.Flags().StringVar(&vtTopoTestPlaybook, "playbook", "", "path to the playbook to run against the topology (required; e.g. playbooks/site.yml)")
	vtTopologyTestCmd.Flags().StringArrayVar(&vtTopoTestVerify, "verify", nil, "verification spec to run after apply, as 'docs/verification/<x>.md' or 'docs/verification/<x>.md=<ansible-limit>'; repeatable, at least one required")
	vtTopologyTestCmd.Flags().BoolVar(&vtTopoTestSkipLint, "skip-lint", false, "skip syntax check pre-flight")
	vtTopologyTestCmd.Flags().BoolVar(&vtTopoTestNoRollback, "no-rollback", false, "disable automatic cluster rollback on failure")
	vtTopologyTestCmd.Flags().IntVar(&vtTopoTestVerifyTimeout, "verify-timeout", 0, "per-row timeout (seconds) forwarded to `pilot verify` (0 = verify's own default)")
	_ = vtTopologyTestCmd.MarkFlagRequired("playbook")
	_ = vtTopologyTestCmd.MarkFlagRequired("verify")
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

// renderTopologyInventory resolves every node in the spec (each must be
// running — the inventory needs final IPs) and renders the grouped
// ansible inventory its 'groups:' declarations describe. Shared by
// 'topology inventory' (prints/writes it) and 'topology test' (stages it
// to a temp file for the apply/verify/idempotency runs).
func renderTopologyInventory(ctx context.Context, m *vmtarget.Manager, spec *vmtarget.TopologySpec, specPath string) (string, error) {
	order, groups := spec.Groups()
	if len(order) == 0 {
		return "", fmt.Errorf("topology spec %s declares no node 'groups:' — nothing to render", specPath)
	}
	targetsByName := make(map[string]*vmtarget.Target, len(spec.Nodes))
	for _, n := range spec.Nodes {
		t, gerr := m.Get(ctx, n.Name)
		if gerr != nil {
			return "", fmt.Errorf("resolve node %q: %w", n.Name, gerr)
		}
		if t.Status != vmtarget.StatusRunning {
			return "", fmt.Errorf("node %q is not running (status=%s); run `pilot vm-target topology up --spec %s` first", n.Name, t.Status, specPath)
		}
		targetsByName[n.Name] = t
	}
	return vmtarget.RenderGroupedInventory(targetsByName, order, groups)
}

func runVtTopologyInventory(cmd *cobra.Command, args []string) error {
	spec, err := vmtarget.LoadTopologySpec(vtTopoSpecPath)
	if err != nil {
		return err
	}
	m, err := vtNewManager()
	if err != nil {
		return err
	}
	inv, err := renderTopologyInventory(context.Background(), m, spec, vtTopoSpecPath)
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

// ---- test -------------------------------------------------------------

var (
	vtTopoTestPlaybook      string
	vtTopoTestVerify        []string
	vtTopoTestSkipLint      bool
	vtTopoTestNoRollback    bool
	vtTopoTestVerifyTimeout int
)

var vtTopologyTestCmd = &cobra.Command{
	Use:   "test [-- <ansible extra-vars>...]",
	Short: "Run syntax, apply, verify, and idempotency against a whole topology (cluster snapshot/rollback)",
	Long: `The multi-VM equivalent of 'vm-target test': one command produces the
full actual-run evidence chain (AGENTS.md §1.2/§1.4) for a scenario that
spans several nodes — e.g. site.yml against a rendered topology inventory,
or a replica-install playbook that needs primary+replica+client at once.

Steps executed:
  1. L1 syntax check: 'ansible-playbook --syntax-check'
  2. Cluster snapshot: every node under one 'pre-test-<ts>' tag (concurrent)
  3. L4 apply: the playbook against the rendered grouped inventory
  4. L5 verify: 'pilot verify' once per --verify entry
  5. L6 idempotency: apply again, assert changed=0 across ALL hosts
  6. Auto-rollback: any failure reverts EVERY node to the pre-test tag and
     re-wires /etc/hosts (mirroring 'topology rollback')

--verify is repeatable and takes 'spec.md' or 'spec.md=<ansible-limit>',
so each spec is verified only against the group it applies to:

  pilot vm-target topology test --spec ha.yaml \
      --playbook playbooks/site.yml \
      --verify docs/verification/freeipa-server.md=ipa_masters \
      --verify docs/verification/freeipa-client.md=ipa_clients \
      -- -e stage=sandbox

Everything after '--' is forwarded VERBATIM to the apply AND idempotency
runs. Unlike single-VM 'test', no '-l <name>' limit is ever added: the
rendered topology inventory's groups own targeting (that is the point of
'groups:' in the topology spec).
`,
	Args: cobra.ArbitraryArgs,
	RunE: runVtTopologyTest,
}

// topoVerify is one parsed --verify entry: a spec path plus the optional
// ansible limit pattern scoping which topology group it verifies.
type topoVerify struct {
	spec  string
	limit string
}

// parseTopoVerifyArgs splits each --verify value on the first '=' into
// spec path and limit. Spec paths never contain '='; limits are plain
// ansible patterns (group, host, union).
func parseTopoVerifyArgs(raw []string) ([]topoVerify, error) {
	out := make([]topoVerify, 0, len(raw))
	for _, r := range raw {
		specPath, limit, _ := strings.Cut(r, "=")
		if specPath == "" {
			return nil, fmt.Errorf("--verify %q: empty spec path", r)
		}
		out = append(out, topoVerify{spec: specPath, limit: limit})
	}
	return out, nil
}

func runVtTopologyTest(cmd *cobra.Command, args []string) error {
	spec, err := vmtarget.LoadTopologySpec(vtTopoSpecPath)
	if err != nil {
		return err
	}
	verifies, err := parseTopoVerifyArgs(vtTopoTestVerify)
	if err != nil {
		return err
	}
	m, err := vtNewManager()
	if err != nil {
		return err
	}
	ctx := context.Background()
	out := cmd.OutOrStdout()

	// Rendering the inventory up front doubles as the "every node is
	// running" pre-flight — fail before snapshotting anything.
	inv, err := renderTopologyInventory(ctx, m, spec, vtTopoSpecPath)
	if err != nil {
		return err
	}
	invPath, cleanup, err := writeTempInventory(inv)
	if err != nil {
		return err
	}
	defer cleanup()

	// Step 1: L1 syntax check.
	if !vtTopoTestSkipLint {
		fmt.Fprintln(out, "=== [Step 1/5] L1 Syntax Check ===")
		if err := execAnsiblePlaybook(out, vtTopoTestPlaybook, "--syntax-check"); err != nil {
			return fmt.Errorf("syntax check failed: %w", err)
		}
		fmt.Fprintln(out, "✓ Syntax check passed")
	}

	// Step 2: cluster-wide snapshot under one tag.
	snapTag := fmt.Sprintf("pre-test-%d", time.Now().Unix())
	fmt.Fprintf(out, "=== [Step 2/5] Cluster snapshot: %d node(s) (tag: %s) ===\n", len(spec.Nodes), snapTag)
	if err := runTopologyNodesConcurrently(spec, func(nm *vmtarget.Manager, n vmtarget.TopologyNode) error {
		if serr := nm.Snapshot(context.Background(), n.Name, snapTag); serr != nil {
			return fmt.Errorf("node %q: %w", n.Name, serr)
		}
		return nil
	}); err != nil {
		return fmt.Errorf("failed to snapshot cluster: %w", err)
	}
	fmt.Fprintln(out, "✓ Cluster snapshot created")

	rollbackOnFailure := func(origErr error) error {
		if vtTopoTestNoRollback {
			fmt.Fprintln(cmd.ErrOrStderr(), "⚠️ Auto-rollback is disabled via --no-rollback")
			return origErr
		}
		fmt.Fprintf(cmd.ErrOrStderr(), "❌ Test failed: %v. Rolling back every node to %s...\n", origErr, snapTag)
		if rerr := runTopologyNodesConcurrently(spec, func(nm *vmtarget.Manager, n vmtarget.TopologyNode) error {
			if e := nm.Rollback(context.Background(), n.Name, snapTag); e != nil {
				return fmt.Errorf("node %q: %w", n.Name, e)
			}
			return nil
		}); rerr != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "🚨 Double fault: cluster rollback failed: %v\n", rerr)
			return fmt.Errorf("%w (cluster rollback also failed: %v)", origErr, rerr)
		}
		// The pre-test tag postdates wiring, but Rollback restores the
		// disk verbatim — rewire anyway to mirror 'topology rollback'
		// and stay correct if wiring changed since the snapshot.
		if werr := rewireTopology(spec, out); werr != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "🚨 rollback OK but re-wiring failed: %v\n", werr)
			return fmt.Errorf("%w (re-wire after rollback failed: %v)", origErr, werr)
		}
		fmt.Fprintln(out, "✓ Rollback successful. Every node restored to pre-test state.")
		return origErr
	}

	// Step 3: L4 apply. No -l limit — the grouped inventory owns targeting.
	fmt.Fprintln(out, "=== [Step 3/5] L4 Apply Playbook (topology inventory) ===")
	ansibleArgs := append([]string{vtTopoTestPlaybook, "-i", invPath}, args...)
	if err := execExternal(out, "ansible-playbook", ansibleArgs...); err != nil {
		return rollbackOnFailure(fmt.Errorf("playbook apply failed: %w", err))
	}
	fmt.Fprintln(out, "✓ Playbook apply completed")

	// Step 4: L5 verify, one run per --verify entry.
	fmt.Fprintf(out, "=== [Step 4/5] L5 Verification Specs (%d) ===\n", len(verifies))
	for _, v := range verifies {
		pilotArgs := []string{"verify", v.spec, "-i", invPath}
		if v.limit != "" {
			pilotArgs = append(pilotArgs, "-l", v.limit)
		}
		if vtTopoTestVerifyTimeout > 0 {
			pilotArgs = append(pilotArgs, "--timeout", strconv.Itoa(vtTopoTestVerifyTimeout))
		}
		if err := execPilot(out, pilotArgs...); err != nil {
			return rollbackOnFailure(fmt.Errorf("verification failed (%s): %w", v.spec, err))
		}
	}
	fmt.Fprintln(out, "✓ Verification checks passed")

	// Step 5: L6 idempotency across the whole cluster.
	fmt.Fprintln(out, "=== [Step 5/5] L6 Idempotency Check ===")
	var idemBuf bytes.Buffer
	if err := execExternal(io.MultiWriter(out, &idemBuf), "ansible-playbook", ansibleArgs...); err != nil {
		return rollbackOnFailure(fmt.Errorf("idempotency run failed: %w", err))
	}
	changed, ok := idempotencyChangedCount(idemBuf.String())
	if !ok {
		return rollbackOnFailure(fmt.Errorf("idempotency check: no PLAY RECAP found in ansible output (unable to confirm changed=0)"))
	}
	if changed > 0 {
		return rollbackOnFailure(fmt.Errorf("idempotency check failed: playbook reported %d changed task(s) on second run", changed))
	}
	fmt.Fprintln(out, "✓ Idempotency check passed (changed=0)")
	fmt.Fprintln(out, "🎉 ALL TESTS PASSED SUCCESSFULLY!")
	return nil
}
