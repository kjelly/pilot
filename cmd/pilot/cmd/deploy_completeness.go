// deploy_completeness.go is a hard, unskippable Go-side gate that runs
// before any ansible-playbook invocation in `pilot deploy` — including the
// optional ansible-side preflight (runPreflight) — to catch the two gaps
// that reached a real deploy silently in the minimal-poc round-15 incident:
// a host_vars var with no safe cross-host default left unset (e.g.
// prometheus_site_label), and a freeipa-identity roster missing an
// nfs.servers entry for a host carrying freeipa-nfs-server.
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

		domain, err := inventory.RosterDomain(rosterPath)
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
