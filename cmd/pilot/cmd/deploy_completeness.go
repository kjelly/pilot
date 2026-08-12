// deploy_completeness.go is a hard, unskippable Go-side gate that runs
// before any ansible-playbook invocation in `pilot deploy` — including the
// optional ansible-side preflight (runPreflight) — to catch the gaps that
// reached a real deploy silently in the minimal-poc round-15 incident: a
// host_vars var with no safe cross-host default left unset (e.g.
// prometheus_site_label), and a freeipa-identity roster missing an
// nfs.servers entry for a host carrying freeipa-nfs-server. It also runs
// three checks shared with `pilot edit`'s "🔍 檢查設定完整性" report
// (workspace_completeness.go) — an unfilled/still-CHANGE-ME vault key, the
// roster's own canonical structural rules, and the S3-target either/or
// gate (thanos_s3_target_host/-endpoint, restic_s3_target_host/
// restic_repository) — so the two never enforce different things; see
// that file's rationale for why they can't share the same *data source*
// (resolved inventory.yml here vs. raw source files there), only the same
// catalogs/validators. The resolved-inventory gate checks the roster path on
// every effective FreeIPA server target, including the day-2 reconcile target;
// the NFS-specific section below additionally validates each host's
// nfs.servers entry.
//
// `pilot inventory generate` (inventory.go's writeMissingHostVarsSkeleton /
// writeMissingNFSRosterEntries) is the mechanism that prevents these gaps
// from being created in the first place; this is the backstop for anyone
// who skipped that, hand-edited the inventory afterward, or is deploying an
// inventory pilot never generated at all.
package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"

	"github.com/kjelly/pilot/internal/inventory"
)

// completenessViolation is one hard-blocking gap: a host whose roles need
// something that isn't actually present in the resolved inventory.
type completenessViolation struct {
	Host   string
	Detail string
}

func (v completenessViolation) String() string {
	return fmt.Sprintf("%s: %s", v.Host, v.Detail)
}

// validateDeploymentCompleteness inspects the already-generated inventory
// (not hosts.yml — deploy operates on inventory.yml) for missing
// host_vars/roster requirements. Both checks run with no vault password
// (host_vars/group_vars never carry real secrets by convention — only
// .vault/main.yaml does), so this never prompts and never touches any file.
func validateDeploymentCompleteness(ctx context.Context, inv string) ([]completenessViolation, error) {
	groups, err := resolveInventoryGroups(ctx, inv)
	if err != nil {
		return nil, err
	}
	hostVars, err := resolveInventoryVariables(ctx, inv, nil, vaultInput{})
	if err != nil {
		return nil, err
	}

	var violations []completenessViolation

	var roles []string
	for role, hosts := range groups {
		if len(hosts) > 0 {
			roles = append(roles, role)
		}
	}
	for _, c := range checkVaultCompleteness(filepath.Dir(inv), roles) {
		if c.OK {
			continue
		}
		for _, d := range c.Details {
			violations = append(violations, completenessViolation{Host: "vault", Detail: fmt.Sprintf("%s: %s", c.Label, d)})
		}
	}

	for _, host := range groups["prometheus"] {
		for _, key := range inventory.ExpectedHostVarsKeysForRoles([]string{"prometheus"}) {
			value, _ := hostVars[host][key].(string)
			if value == "" {
				violations = append(violations, completenessViolation{
					Host: host,
					Detail: fmt.Sprintf(
						"has role prometheus but host_vars/%s.yml is missing %s (no safe default — see docs/verification/prometheus.md §1.5)",
						host, key),
				})
			}
		}
	}

	// Same either/or S3-target gate prometheus-apply.yml/thanos-query-apply.yml/
	// restic-backup-apply.yml assert themselves — catching it here means a
	// deploy fails fast instead of burning through preflight and most of a
	// real apply before hitting that assert. Shares the catalog with
	// workspace_completeness.go's checkGroupVarsCompleteness (see
	// groupVarsEitherOrRequirements) — only the data source differs: the
	// resolved per-host vars here vs. a raw group_vars file there.
	for _, req := range groupVarsEitherOrRequirements {
		for _, host := range groups[req.Stem] {
			targetHost, _ := hostVars[host][req.TargetHostKey].(string)
			endpointRaw, endpointSet := hostVars[host][req.EndpointKey]
			endpoint, _ := endpointRaw.(string)
			if groupVarsEitherOrSatisfied(targetHost, endpointSet, endpoint, req.Alias) {
				continue
			}
			if req.AutoDetectRole != "" && len(groups[req.AutoDetectRole]) > 0 &&
				groupVarsAutoDetectApplies(endpointSet, endpoint, req.Alias) {
				continue // the apply playbook itself auto-derives this at runtime
			}
			violations = append(violations, completenessViolation{
				Host: host,
				Detail: fmt.Sprintf(
					"has role %s but neither %s nor an overridden %s (still defaults to the shared %q alias) is set",
					req.Stem, req.TargetHostKey, req.EndpointKey, req.Alias),
			})
		}
	}

	// freeipa-identity-apply.yml targets the freeipa-server group, so the
	// roster path must be present on that effective target host. Checking only
	// freeipa-nfs-server here misses the day-2 reconcile path and lets Ansible
	// fall back to an empty legacy data model until its late roster gate.
	for _, role := range []string{"freeipa-server", "freeipa-server-replica"} {
		for _, host := range groups[role] {
			rosterPath, _ := hostVars[host]["freeipa_roster_file"].(string)
			if strings.TrimSpace(rosterPath) == "" {
				violations = append(violations, completenessViolation{
					Host:   host,
					Detail: fmt.Sprintf("has role %s but no freeipa_roster_file is set on the effective target host", role),
				})
			}
		}
	}

	for _, host := range groups["freeipa-nfs-server"] {
		rosterPath, _ := hostVars[host]["freeipa_roster_file"].(string)
		if rosterPath == "" {
			violations = append(violations, completenessViolation{
				Host:   host,
				Detail: "has role freeipa-nfs-server but no freeipa_roster_file is set",
			})
			continue
		}
		// A relative freeipa_roster_file is relative to the workspace the
		// inventory was generated into, i.e. inv's own directory — matching
		// writeMissingNFSRosterEntries' convention (inventory.go).
		rosterPath = resolveRosterPath(filepath.Dir(inv), rosterPath)

		domain, err := inventory.FreeIPADomain(filepath.Dir(inv))
		if err != nil {
			if errors.Is(err, inventory.ErrRosterEncrypted) {
				continue // can't verify without a vault password — not our call to block on
			}
			violations = append(violations, completenessViolation{
				Host:   host,
				Detail: fmt.Sprintf("has role freeipa-nfs-server but its roster %s could not be read (%v)", rosterPath, err),
			})
			continue
		}

		// Full canonical-roster structural check — shares rules with `pilot
		// edit`'s 檢查設定完整性 (workspace_completeness.go) so a roster that
		// fails this also fails there, not just at real-apply time. Only
		// reached once the inventory domain was resolved and the roster path
		// was found, so this can't itself fail with a redundant domain read.
		if structViolations, _ := inventory.ValidateRosterFile(rosterPath); len(structViolations) > 0 {
			for _, v := range structViolations {
				violations = append(violations, completenessViolation{
					Host:   host,
					Detail: fmt.Sprintf("roster %s failed a canonical check: %s", rosterPath, v.String()),
				})
			}
		}

		fqdn := inventory.RosterHostFQDN(host, domain)
		has, err := inventory.RosterHasNFSServer(rosterPath, fqdn)
		if err != nil {
			if errors.Is(err, inventory.ErrRosterEncrypted) {
				continue
			}
			violations = append(violations, completenessViolation{
				Host:   host,
				Detail: fmt.Sprintf("has role freeipa-nfs-server but its roster %s could not be read (%v)", rosterPath, err),
			})
			continue
		}
		if !has {
			violations = append(violations, completenessViolation{
				Host:   host,
				Detail: fmt.Sprintf("has role freeipa-nfs-server but roster %s has no nfs.servers entry for %s", rosterPath, fqdn),
			})
		}
	}

	sort.Slice(violations, func(i, j int) bool {
		if violations[i].Host != violations[j].Host {
			return violations[i].Host < violations[j].Host
		}
		return violations[i].Detail < violations[j].Detail
	})
	return violations, nil
}

// ensureFreeIPARostersCurrent auto-upgrades every distinct freeipa_roster_file
// referenced by an effective freeipa-server/freeipa-server-replica target to
// the current roster schema — the "pilot reconcile / freeipa-identity
// preflight" call site the roster-schema-v2 migration spec requires before
// every local mutating workflow that consumes a canonical roster.
//
// Deliberately a separate function from validateDeploymentCompleteness
// rather than folded into it: that function is documented above to "never
// touch any file," and callers (deploy.go, reconcile.go, and their tests)
// rely on that. This shares its group/hostVars resolution instead of its
// mutation.
//
// Best-effort, matching this file's existing "can't verify without a vault
// password — not our call to block on" posture toward ErrRosterEncrypted:
// a real .vault/ path is commonly encrypted, and Phase 10's vault-password
// support isn't built yet, so failing to migrate an encrypted roster here
// must never block a deploy/reconcile that worked fine before this feature
// existed. Any other migration failure (invalid v1 content, lock
// contention) is reported to out as a warning, not a new blocking
// violation — the real ansible-playbook apply's own canonical gates catch
// a genuinely broken roster exactly as they always have.
func ensureFreeIPARostersCurrent(ctx context.Context, out io.Writer, inv string) error {
	groups, err := resolveInventoryGroups(ctx, inv)
	if err != nil {
		return err
	}
	hostVars, err := resolveInventoryVariables(ctx, inv, nil, vaultInput{})
	if err != nil {
		return err
	}

	seen := map[string]bool{}
	for _, role := range []string{"freeipa-server", "freeipa-server-replica"} {
		for _, host := range groups[role] {
			rosterPath, _ := hostVars[host]["freeipa_roster_file"].(string)
			rosterPath = strings.TrimSpace(rosterPath)
			if rosterPath == "" {
				continue
			}
			rosterPath = resolveRosterPath(filepath.Dir(inv), rosterPath)
			if seen[rosterPath] {
				continue
			}
			seen[rosterPath] = true

			result, err := inventory.EnsureRosterCurrent(rosterPath, inventory.RosterMigrationOptions{})
			if err != nil {
				if !errors.Is(err, inventory.ErrRosterEncrypted) {
					fmt.Fprintf(out, "warning: could not auto-upgrade roster schema for %s: %v\n", rosterPath, err)
				}
				continue
			}
			if !result.Changed {
				continue
			}
			fmt.Fprintf(out, "Roster schema v%d detected (%s).\nAutomatically upgraded to schema v%d.\nBackup:\n  %s\n\n",
				result.FromVersion, rosterPath, result.ToVersion, result.BackupPath)
		}
	}
	return nil
}

// formatCompletenessViolations renders every violation into a single error
// so runDeployInteractive can report the whole list at once instead of
// failing on the first one found.
func formatCompletenessViolations(violations []completenessViolation) error {
	lines := make([]string, 0, len(violations)+1)
	lines = append(lines, fmt.Sprintf("inventory 完整性檢查沒過(%d 項)：", len(violations)))
	for _, v := range violations {
		lines = append(lines, "  - "+v.String())
	}
	return errors.New(strings.Join(lines, "\n"))
}
