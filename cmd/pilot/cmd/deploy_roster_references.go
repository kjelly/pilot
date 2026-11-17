// deploy_roster_references.go is the preflight half of issue #165: a roster
// string that refers to a variable — password.initial:
// '{{ ipa_default_initial_password }}', resolved at apply time from
// .vault/main.yaml (-e @file) — fails apply when nothing defines the variable.
// The failure is inside a no_log task (its fatal result is censored), so it
// comes mid-run, after the dependency chain (freeipa-server, say) has been
// applied. `pilot deploy` and `pilot reconcile` refuse such a run before the
// plan is shown, with the names of what is missing. The reading and the verdict are internal/inventory's
// (RosterSecretVarReferences, RosterVarReferencesRenderedBy,
// MissingRosterVarReferences); this file decides which rosters and hosts a run
// touches and what it knows about their variables.
package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/kjelly/pilot/internal/contract"
	"github.com/kjelly/pilot/internal/inventory"
)

// rosterReferenceConsumers are the components whose apply playbook renders the
// roster's secret strings, with the playbook's behaviour the checks follow
// (inventory.RosterVarConsumer). TestRosterReferenceConsumersAreTheOraclePlaybooks
// pins the playbooks they name to the ones the oracle test runs.
var rosterReferenceConsumers = map[string]inventory.RosterVarConsumer{
	"freeipa-identity":   inventory.RosterConsumerFreeIPAIdentity,
	"freeipa-nfs-server": inventory.RosterConsumerFreeIPANFSServer,
}

// precheckRosterReferences refuses, before anything runs, a deploy or
// reconcile whose roster refers to a variable that nothing the run knows
// defines (see the file comment). It is the precheck of
// executeRecordedDeploymentWithAuthorizationResult and of the batch
// (precheckRosterReferencesBatch), like precheckIdentityDeploy and before the
// plan is shown, the dependency chain, any preview or any ssh.
//
// It checks nothing when the run has no vault vars file (-e @file): a run
// whose variables come from somewhere pilot cannot see is not judged. It
// checks the consumers among components (rosterReferenceConsumers), on every
// host of the resolved scope (--limit and target_group honored) and for every
// roster those hosts name in freeipa_roster_file, and judges each (host,
// roster) pair on what that host's run defines: the effective variables of
// `ansible-inventory --list` with the run's own -e and vault arguments — the
// inventory, the vault vars file and every -e, merged the way Ansible merges
// them for the playbook — and the -e names, plus the names the playbook
// defines for itself before it renders a roster string (its play vars, say:
// inventory.MissingRosterVarReferencesFor). The fields a consumer does not
// render are not judged (inventory.RosterVarReferencesRenderedBy): refusing a
// run for them would refuse one that works.
//
// Whether the identity playbook renders the roster's admin password depends on
// two facts of the run, ipa_admin_password (its `default(x, true)` fallback)
// and whether freeipa.server is declared. Each is decided from the host's raw
// variables only where it is a literal or a chain of bare {{ name }}
// references that ends in one or in an undefined name
// (inventory.RosterRunVars); anything else is unknown, never refused, and
// named in one line (a reference that would be missing, but only if the unknown
// fact turns out one way). The same one-line note covers a roster field the
// check cannot read at all (a filter, a call, a block, a value shared between
// !unsafe and normal YAML).
//
// What it cannot read is not a failure: this is a precheck and the playbook
// has its own gates. --ask-vault-pass (a prompt of its own is not made here),
// an inventory ansible-inventory cannot list with the run's arguments (a vault
// secret that is not configured, say), an encrypted roster without
// --vault-password-file, or a roster that does not read, each skip the
// check with one line on out, so the operator knows it did not run. Neither
// those lines nor the refusal show a value of the roster or of the vars file:
// field labels, variable names, host names and paths only.
func precheckRosterReferences(ctx context.Context, out io.Writer, catalog contract.Catalog, components []string, inv, limit string, extraVars []string, vault vaultInput) error {
	var consumers []string
	for _, id := range components {
		if _, ok := rosterReferenceConsumers[id]; ok {
			consumers = append(consumers, id)
		}
	}
	if len(consumers) == 0 || vault.ExtraVarsFile == "" {
		return nil
	}
	notes := rosterReferenceNotes{out: out, seen: map[string]bool{}}
	if vault.AskVaultPass {
		notes.add("這次用 --ask-vault-pass，檢查不另外問密碼")
		return nil
	}
	// Read-only, as precheckIdentityDeploy reads the scope: nothing here
	// changes what the run does (AGENTS.md §5.5).
	_, _, scope, _, _, err := resolveDeploymentScope(ctx, catalog, consumers, inv, limit, extraVars, true)
	if err != nil {
		notes.add("讀不出部署範圍(接下來的步驟會回報原因)")
		return nil
	}
	snapshot, err := loadDeployInventorySnapshotWithArgs(ctx, inv, ansibleExtraVarArgs(extraVars, vault))
	if err != nil {
		// ansible-inventory's own message can quote a vars file it failed to
		// parse, so it is not repeated here.
		notes.add("ansible-inventory 無法帶著這次的 -e／vault 參數列出變數(例如 vault 密碼沒設定；playbook 執行時會回報原因)")
		return nil
	}

	type finding struct{ roster, host, text string }
	var findings []finding
	seen := map[string]bool{}
	rosters := map[string]*rosterReferenceRoster{}
	extraNames := map[string]bool{}
	for _, extra := range extraVars {
		for _, name := range extraVarKeys(extra) {
			extraNames[name] = true
		}
	}
	for _, id := range consumers {
		component, ok := catalog.Component(id)
		if !ok {
			continue
		}
		hosts := append([]string(nil), scope.HostsByRole[component.Role]...)
		sort.Strings(hosts)
		for _, host := range hosts {
			hostVars := snapshot.HostVars[host]
			rosterVar, present := hostVars["freeipa_roster_file"]
			rosterRef, isString := rosterVar.(string)
			if present && rosterVar != nil && !isString {
				notes.add(fmt.Sprintf("%s 的 freeipa_roster_file 不是字串，沒有檢查它的 roster", host))
				continue
			}
			rosterRef = strings.TrimSpace(rosterRef)
			if rosterRef == "" {
				continue // nothing to read here; the contract's own preflight says so
			}
			rosterPath := resolveRosterPath(filepath.Dir(inv), rosterRef)
			roster, ok := rosters[rosterPath]
			if !ok {
				roster = readRosterReferences(rosterPath, vault, &notes)
				rosters[rosterPath] = roster
			}
			if roster == nil {
				continue
			}
			defined := make(map[string]bool, len(hostVars)+len(extraNames))
			for name := range hostVars {
				defined[name] = true
			}
			for name := range extraNames {
				defined[name] = true
			}
			consumer := rosterReferenceConsumers[id]
			facts := roster.renderFacts(inventory.RosterRunVars{HostVars: hostVars, ExtraNames: extraNames, Consumer: consumer})
			for _, ref := range inventory.MissingRosterVarReferencesFor(consumer, roster.refs, facts, defined) {
				key := rosterPath + "\x00" + ref.Field + "\x00" + ref.Name
				if seen[key] {
					continue
				}
				seen[key] = true
				where := fmt.Sprintf("%s (or the inventory, for %s)", vault.ExtraVarsFile, host)
				findings = append(findings, finding{roster: rosterPath, host: host, text: ref.Violation(where).String()})
			}
			for _, ref := range inventory.UnjudgedRosterVarReferencesFor(consumer, roster.refs, facts, defined) {
				notes.add(fmt.Sprintf("roster %s 的 %s 引用 %s，但這次是否會展開它取決於 %s，無法判斷，所以沒有檢查", rosterPath, ref.Field, ref.Name, roster.unknownFacts(facts)))
			}
		}
	}
	if len(findings) == 0 {
		return nil
	}
	lines := make([]string, 0, len(findings))
	for _, f := range findings {
		lines = append(lines, fmt.Sprintf("  - %s: %s", f.roster, f.text))
	}
	return fmt.Errorf("roster 變數引用檢查沒有通過(%d 項)：roster 的密碼欄位引用了下列變數，但這次執行沒有任何地方定義它們。"+
		"apply 會在 playbook 的 no_log task 因 undefined variable 失敗(該 task 的 fatal 結果被遮蔽)，所以是執行到一半才失敗，"+
		"那時前面的相依元件(例如 freeipa-server)已經套用完；這個檢查把失敗移到任何東西執行之前：\n%s\n"+
		"請把這些 key 加進 %s(或 inventory)，或改正 roster 的引用。只有 {{ name }} 形式的引用會檢查；"+
		"用 filter(例如 | default(''))、運算子或 {%% %%} 區塊的值不會判斷。", len(findings), strings.Join(lines, "\n"), vault.ExtraVarsFile)
}

// precheckRosterReferencesBatch is precheckRosterReferences for every request
// of a reconcile or deploy batch that has a vault vars file, before the batch
// shows its plan and asks the operator to authorize it (see
// precheckIdentityBatch). What it cannot resolve here, the plan step reports.
func precheckRosterReferencesBatch(ctx context.Context, out io.Writer, requests []catalogDeploymentRequest) error {
	var catalog contract.Catalog
	loaded := false
	for _, request := range requests {
		if request.vault.ExtraVarsFile == "" {
			continue
		}
		if !loaded {
			root, err := resolveContractRoot("")
			if err != nil {
				return nil
			}
			loader, err := contract.NewLoader(root)
			if err != nil {
				return nil
			}
			catalog, err = loader.LoadDefaultCatalog()
			if err != nil {
				return nil
			}
			loaded = true
		}
		components, err := componentsForPlaybook(ctx, catalog, request.playbook, request.inv, request.limit, request.tags, request.componentHints)
		if err != nil {
			continue
		}
		if err := precheckRosterReferences(ctx, out, catalog, components, request.inv, request.limit, request.extraVars, request.vault); err != nil {
			return err
		}
	}
	return nil
}

// rosterReferenceRoster is one roster's references and the facts about it
// that do not depend on the run, read once per run.
type rosterReferenceRoster struct {
	refs      []inventory.RosterVarRef
	schema    inventory.RosterFact
	server    inventory.RosterFact
	serverVar string // the variable freeipa.server is exactly, when it is a bare {{ name }}
}

// renderFacts are the facts of a run of the identity playbook for this
// roster: the roster's own, and the two that depend on the run's variables
// (inventory.RosterRunVars), each unknown unless a literal or a chain of bare
// references decides it.
func (r *rosterReferenceRoster) renderFacts(run inventory.RosterRunVars) inventory.RosterRenderFacts {
	facts := inventory.RosterRenderFacts{SchemaVersionDefined: r.schema, ServerDeclared: r.server}
	if run.Consumer != inventory.RosterConsumerFreeIPAIdentity {
		return facts
	}
	if facts.ServerDeclared == inventory.RosterFactUnknown && r.serverVar != "" {
		facts.ServerDeclared = run.ServerDeclared(r.serverVar)
	}
	facts.AdminPasswordProvided = run.AdminPasswordProvided()
	return facts
}

// unknownFacts names, for a note, what a run's facts leave undecided.
func (r *rosterReferenceRoster) unknownFacts(facts inventory.RosterRenderFacts) string {
	var names []string
	if facts.AdminPasswordProvided == inventory.RosterFactUnknown {
		names = append(names, "ipa_admin_password")
	}
	if facts.ServerDeclared == inventory.RosterFactUnknown {
		if r.serverVar != "" {
			names = append(names, "freeipa.server(="+r.serverVar+")")
		} else {
			names = append(names, "freeipa.server")
		}
	}
	if facts.SchemaVersionDefined == inventory.RosterFactUnknown {
		names = append(names, "schema_version")
	}
	return strings.Join(names, "、")
}

// readRosterReferences reads the roster at path (decrypting an encrypted one in
// memory with the run's --vault-password-file) and returns its secret
// references, or nil, with a note, when it cannot be read: the structural gate
// and the playbook own those errors.
func readRosterReferences(path string, vault vaultInput, notes *rosterReferenceNotes) *rosterReferenceRoster {
	plaintext, _, err := inventory.ReadRosterPlaintext(path, vault.VaultPasswordFile)
	switch {
	case errors.Is(err, inventory.ErrRosterEncrypted):
		notes.add(fmt.Sprintf("roster %s 是 ansible-vault 加密的，而這次沒有給 --vault-password-file", path))
		return nil
	case errors.Is(err, os.ErrNotExist):
		notes.add(fmt.Sprintf("找不到 roster %s", path))
		return nil
	case err != nil:
		notes.add(fmt.Sprintf("讀不出 roster %s(結構檢查與 playbook 會回報原因)", path))
		return nil
	}
	refs, unchecked, err := inventory.RosterSecretVarReferences(plaintext)
	if err != nil {
		notes.add(fmt.Sprintf("roster %s 不是可解析的 YAML(結構檢查會回報)", path))
		return nil
	}
	for _, field := range unchecked {
		notes.add(uncheckedFieldNote(path, field))
	}
	server, serverVar := inventory.RosterFreeIPAServerDeclared(plaintext)
	return &rosterReferenceRoster{refs: refs, schema: inventory.RosterSchemaVersionDefined(plaintext), server: server, serverVar: serverVar}
}

// uncheckedFieldNote is the line for a roster field the check cannot judge:
// its value has a filter, operator, call or {% %} block, or is shared by an
// alias or merge key between !unsafe and normal YAML. It names the roster and
// the field only.
func uncheckedFieldNote(roster, field string) string {
	return fmt.Sprintf("roster %s 的 %s %s", roster, field, uncheckedFieldReason)
}

// rosterReferenceNotes writes each reason the check was skipped once.
type rosterReferenceNotes struct {
	out  io.Writer
	seen map[string]bool
}

func (n *rosterReferenceNotes) add(reason string) {
	if n.seen[reason] {
		return
	}
	n.seen[reason] = true
	fmt.Fprintf(n.out, "ℹ️  roster 變數引用檢查已略過：%s\n", reason)
}
