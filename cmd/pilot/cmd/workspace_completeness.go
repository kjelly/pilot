// workspace_completeness.go implements `pilot edit`'s "🔍 檢查設定完整性"
// report: a read-only sweep of a workspace's source files — hosts.yml,
// group_vars/*.yml, host_vars/*.yml, .vault/main.yaml, and the
// freeipa-identity roster — against the exact same role contract, vault
// key catalog, host_vars catalog, and roster validator that
// deploy_completeness.go's hard deploy gate uses, so the two never
// disagree about what counts as "done".
//
// The one thing this can't share with that gate is the *data source*:
// deploy's gate reads an already-`pilot inventory generate`-d
// inventory.yml through ansible-inventory (so it sees group-inheritance
// and hosts.yml `extra:` vars folded in); this runs before that step
// even exists, so it reads hosts.yml/group_vars/host_vars/.vault
// directly. A value that only becomes correct after ansible resolves
// group inheritance (rather than living in one of the files this checks)
// won't be seen here — deploy's gate remains the final word.
package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/kjelly/pilot/internal/groupvars"
	"github.com/kjelly/pilot/internal/inventory"
	"github.com/kjelly/pilot/internal/vaultfile"
)

// completenessCheck is one row of the report: a labeled thing (a file, or
// a file/key combination) that's either fine or has one-or-more problems.
type completenessCheck struct {
	Label   string
	OK      bool
	Details []string
}

func (c completenessCheck) render() []string {
	icon := "✅"
	if !c.OK {
		icon = "❌"
	}
	lines := []string{fmt.Sprintf("%s %s", icon, c.Label)}
	for _, d := range c.Details {
		lines = append(lines, "   - "+d)
	}
	return lines
}

// formatCompletenessReport renders every check as banner text, in the
// same "✅/❌ + indented bullets" shape used elsewhere in the wizard.
func formatCompletenessReport(checks []completenessCheck) string {
	lines := []string{"設定完整性檢查"}
	for _, c := range checks {
		lines = append(lines, c.render()...)
	}
	return strings.Join(lines, "\n")
}

// checkWorkspaceCompleteness sweeps dir's hosts.yml plus everything its
// assigned roles imply: whether inventory.yml is still fresh, group_vars
// stems (plus the handful of either/or S3-target settings those imply),
// vault keys, host_vars keys, and — for any FreeIPA-related role — the
// roster it points at (or should point at).
func checkWorkspaceCompleteness(dir string) []completenessCheck {
	hostsPath := filepath.Join(dir, "hosts.yml")
	checks := []completenessCheck{checkPathExists("hosts.yml", hostsPath)}

	data, err := os.ReadFile(hostsPath)
	if err != nil {
		return append(checks, checkPathExists("inventory.yml", filepath.Join(dir, "inventory.yml")))
	}
	hf, err := inventory.Parse(data)
	if err != nil {
		checks[0] = completenessCheck{Label: "hosts.yml", OK: false, Details: []string{fmt.Sprintf("解析失敗: %v", err)}}
		return append(checks, checkPathExists("inventory.yml", filepath.Join(dir, "inventory.yml")))
	}
	checks = append(checks, checkInventoryYmlFresh(dir, hf))

	roles := inventory.UsedRoles(hf)
	checks = append(checks, checkGroupVarsCompleteness(dir, roles)...)
	checks = append(checks, checkVaultCompleteness(dir, roles)...)
	checks = append(checks, checkHostVarsCompleteness(dir, hf)...)
	checks = append(checks, checkRosterCompleteness(dir, hf)...)
	checks = append(checks, checkInternalEndpointCompleteness(dir, hf)...)
	return checks
}

func checkPathExists(label, path string) completenessCheck {
	if _, err := os.Stat(path); err != nil {
		return completenessCheck{Label: label, OK: false, Details: []string{"不存在"}}
	}
	return completenessCheck{Label: label, OK: true}
}

// checkInventoryYmlFresh reports whether inventory.yml matches what
// inventory.Generate(hf) would produce from hosts.yml right now.
// inventory.yml's content is exactly that render's output byte-for-byte
// (see inventoryGenerateCmd) with no timestamps or other non-determinism,
// so any difference means hosts.yml changed (or inventory.yml was hand-
// edited) since the last `pilot inventory generate` — a real drift `pilot
// edit` itself never re-triggers automatically.
func checkInventoryYmlFresh(dir string, hf *inventory.HostsFile) completenessCheck {
	label := "inventory.yml"
	path := filepath.Join(dir, label)
	existing, err := os.ReadFile(path)
	if err != nil {
		return completenessCheck{Label: label, OK: false, Details: []string{"不存在"}}
	}
	fresh, err := inventory.Generate(hf)
	if err != nil {
		return completenessCheck{Label: label, OK: false, Details: []string{
			fmt.Sprintf("目前的 hosts.yml 有錯誤，無法比對是否過期(%v)；先跑 `pilot inventory lint`", err),
		}}
	}
	if string(existing) != fresh {
		return completenessCheck{Label: label, OK: false, Details: []string{
			"內容跟目前的 hosts.yml 對不上，可能是改了 hosts.yml 後忘記重新執行 `pilot inventory generate`",
		}}
	}
	return completenessCheck{Label: label, OK: true}
}

// groupVarsEitherOrRequirement is the one shape of group_vars-level
// "required" setting this codebase's apply playbooks actually enforce: at
// least one of two keys must genuinely move away from the shared-alias
// default, checked via each apply playbook's own "Gate: ..." assert (see
// prometheus-apply.yml/thanos-query-apply.yml's assert on
// thanos_s3_target_host/thanos_s3_endpoint, and restic-backup-apply.yml's
// on restic_s3_target_host/restic_repository). Every OTHER group_vars
// setting that's genuinely required-with-no-default already lives in
// vault or host_vars instead (see checkVaultCompleteness/
// checkHostVarsCompleteness) — group_vars has no broader "required key"
// catalog beyond this narrow pattern.
//
// Stem doubles as the role/group name here (true for all three entries
// below) — deploy_completeness.go's copy of this catalog uses it to index
// resolveInventoryGroups' groups map directly.
//
// AutoDetectRole, when non-empty, names a role/group whose mere presence
// in the inventory means the apply playbook auto-derives TargetHostKey at
// runtime regardless of group_vars content. Restic has an in-playbook
// fallback; prometheus/thanos-query receive the same inventory-derived
// value from pilot deploy's AutoHostVars prompt before site.yml runs. A raw
// ansible-playbook invocation still needs the explicit -e value for the
// latter two roles.
type groupVarsEitherOrRequirement struct {
	Stem           string
	TargetHostKey  string
	EndpointKey    string
	Alias          string
	AutoDetectRole string
}

var groupVarsEitherOrRequirements = []groupVarsEitherOrRequirement{
	{Stem: "prometheus", TargetHostKey: "thanos_s3_target_host", EndpointKey: "thanos_s3_endpoint", Alias: "thanos-s3-backend", AutoDetectRole: "seaweedfs-s3"},
	{Stem: "thanos-query", TargetHostKey: "thanos_s3_target_host", EndpointKey: "thanos_s3_endpoint", Alias: "thanos-s3-backend", AutoDetectRole: "seaweedfs-s3"},
	{Stem: "restic-backup", TargetHostKey: "restic_s3_target_host", EndpointKey: "restic_repository", Alias: "s3-backup-server", AutoDetectRole: "seaweedfs-s3"},
}

// groupVarsEitherOrSatisfied mirrors the exact assert condition each of
// those playbooks runs: `(target_host | length > 0) or (alias not in
// endpoint)`. endpointSet=false, or endpoint being set but blank, both
// stand for "no real override is in effect" — an active-but-empty
// endpoint isn't a resolvable address any more than an absent one is,
// even though (like the real ansible assert this mirrors) an empty
// string technically doesn't contain alias either.
func groupVarsEitherOrSatisfied(targetHost string, endpointSet bool, endpoint, alias string) bool {
	if strings.TrimSpace(targetHost) != "" {
		return true
	}
	if !endpointSet || strings.TrimSpace(endpoint) == "" {
		return false
	}
	return !strings.Contains(endpoint, alias)
}

// groupVarsAutoDetectApplies mirrors the extra guard restic-backup-apply.yml's
// own "Auto-detect backup destination host from this inventory's seaweedfs-s3
// group" task carries beyond "does a fallback role exist": `when: ... and
// (restic_s3_alias in restic_repository) and ...`. An endpoint that isn't set
// anywhere still resolves to that playbook's own vars: default, which embeds
// the alias itself (restic_repository: "s3:http://{{ restic_s3_alias }}:...")
// — so "not set" counts the same as "still contains alias". But an endpoint
// that IS set to something else — including an explicit blank string, which
// contains no alias but is also not a real address — means that same
// condition would evaluate false at apply time, so the carve-out must not
// apply either; it would just silently strand the deploy with no
// destination instead of the fail-fast the rest of this gate promises.
func groupVarsAutoDetectApplies(endpointSet bool, endpoint, alias string) bool {
	if !endpointSet {
		return true
	}
	return strings.Contains(endpoint, alias)
}

func groupVarsEitherOrRequirementByStem() map[string]groupVarsEitherOrRequirement {
	out := make(map[string]groupVarsEitherOrRequirement, len(groupVarsEitherOrRequirements))
	for _, r := range groupVarsEitherOrRequirements {
		out[r.Stem] = r
	}
	return out
}

// checkGroupVarsCompleteness checks that a group_vars/<stem>.yml implied
// by roles has actually been created from its .example.yml, plus — for
// the handful of stems in groupVarsEitherOrRequirements — that the
// either/or S3-target setting those playbooks actually gate on has been
// resolved. Every other group_vars setting is left unchecked at the key
// level: it either has a genuine playbook default, or (if truly required)
// already lives in vault/host_vars instead.
func checkGroupVarsCompleteness(dir string, roles []string) []completenessCheck {
	requirements := groupVarsEitherOrRequirementByStem()

	var out []completenessCheck
	for _, stem := range inventory.GroupVarsStemsForRoles(roles) {
		label := filepath.Join("group_vars", stem+".yml")
		path := filepath.Join(dir, label)
		data, err := os.ReadFile(path)
		if err != nil {
			out = append(out, completenessCheck{Label: label, OK: false, Details: []string{"不存在"}})
			continue
		}

		var details []string
		ok := true
		if req, present := requirements[stem]; present {
			doc := groupvars.Parse(data)
			var targetVal, endpointVal string
			var targetActive, endpointActive bool
			for _, e := range doc.Entries() {
				switch e.Key {
				case req.TargetHostKey:
					targetVal, targetActive = e.Value, e.Active
				case req.EndpointKey:
					endpointVal, endpointActive = e.Value, e.Active
				}
			}
			target := ""
			if targetActive {
				target = targetVal
			}
			if !groupVarsEitherOrSatisfied(target, endpointActive, endpointVal, req.Alias) {
				switch {
				case req.AutoDetectRole != "" && hasRole(roles, req.AutoDetectRole) &&
					groupVarsAutoDetectApplies(endpointActive, endpointVal, req.Alias):
					details = append(details, fmt.Sprintf(
						"%s 未填，但 inventory 有 %s，套用時會自動推導成該主機位址",
						req.TargetHostKey, req.AutoDetectRole))
				default:
					details = append(details, fmt.Sprintf(
						"%s 未填，也沒有把 %s 改成不含 %q 的外部位址(二擇一必填)",
						req.TargetHostKey, req.EndpointKey, req.Alias))
					ok = false
				}
			}
		}
		out = append(out, completenessCheck{Label: label, OK: ok, Details: details})
	}
	return out
}

// checkVaultCompleteness inspects .vault/main.yaml — the convention
// `pilot inventory generate`'s GenerateVaultSkeleton writes to — against
// ExpectedVaultKeysForRoles. A key that's missing, empty, or still equal
// to its catalog's "CHANGE-ME-..." placeholder is reported; an encrypted
// file is reported as fine but unverifiable (no vault password here).
//
// A workspace whose vault file uses a different name/path under .vault/
// won't be found by this convention-based check — same limitation
// pushVaultPathPrompt's own default has.
func checkVaultCompleteness(dir string, roles []string) []completenessCheck {
	expected := inventory.ExpectedVaultKeysForRoles(roles)
	if len(expected) == 0 {
		return nil
	}
	label := filepath.Join(".vault", "main.yaml")
	path := filepath.Join(dir, label)

	data, err := os.ReadFile(path)
	if err != nil {
		return []completenessCheck{{Label: label, OK: false, Details: []string{"不存在"}}}
	}
	if isAnsibleVaultEncrypted(data) {
		return []completenessCheck{{Label: label, OK: true, Details: []string{"已加密，略過內容檢查"}}}
	}
	doc, err := vaultfile.Parse(data)
	if err != nil {
		return []completenessCheck{{Label: label, OK: false, Details: []string{fmt.Sprintf("解析失敗: %v", err)}}}
	}
	values := make(map[string]string, len(doc.Entries()))
	for _, e := range doc.Entries() {
		values[e.Key] = e.DisplayValue()
	}

	var details []string
	for _, key := range expected {
		v, ok := values[key]
		switch {
		case !ok || strings.TrimSpace(v) == "":
			details = append(details, fmt.Sprintf("%s 未設定", key))
		case strings.HasPrefix(v, "CHANGE-ME"):
			details = append(details, fmt.Sprintf("%s 是 CHANGE-ME(還沒填真實值)", key))
		}
	}
	return []completenessCheck{{Label: label, OK: len(details) == 0, Details: details}}
}

// checkHostVarsCompleteness checks, for every host whose roles imply
// host_vars keys with no safe cross-host default (HostVarsKeysForRoles),
// that each key is filled — either directly in hosts.yml's per-host extra
// vars (h.Extra, which render.go writes straight into inventory.yml) or in
// host_vars/<host>.yml, matching the two places such a value can actually
// come from.
func checkHostVarsCompleteness(dir string, hf *inventory.HostsFile) []completenessCheck {
	var out []completenessCheck
	for _, h := range hf.Hosts {
		keys := inventory.HostVarsKeysForRoles(h.Roles)
		if len(keys) == 0 {
			continue
		}
		label := filepath.Join("host_vars", h.Name+".yml")
		missing := missingHostVarsKeys(dir, h, keys)

		details := make([]string, len(missing))
		for i, k := range missing {
			details[i] = fmt.Sprintf("%s 未填", k)
		}
		out = append(out, completenessCheck{Label: label, OK: len(details) == 0, Details: details})
	}
	return out
}

func readYAMLMap(path string) (map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var values map[string]any
	if err := yaml.Unmarshal(data, &values); err != nil {
		return nil, err
	}
	return values, nil
}

// freeipaRosterFallbackRoles is every role whose deployment genuinely
// depends on the freeipa-identity roster, used ONLY to decide whether to
// guess a default roster path when nothing in hosts.yml names one
// explicitly (see checkRosterCompleteness below). freeipa-server (and its
// replica) is `pilot reconcile`'s freeipa-identity entry's actual target
// (deploy_catalog.go); freeipa-nfs-server needs it for the nfs.servers
// cross-check deploy_completeness.go performs. freeipa-client and
// freeipa-client is deliberately EXCLUDED: enrolling a client never reads
// the roster at all, so a workspace with only that role shouldn't be told
// to go prepare one. freeipa-nfs-client used to be excluded for the same
// reason, but f9d9f0e made it roster-driven too (it now does its own
// include_vars on freeipa_roster_file — see
// playbooks/apply/freeipa-nfs-client-apply.yml) — an explicit
// freeipa_roster_file set on any host is still honored, just not guessed
// for freeipa-client.
var freeipaRosterFallbackRoles = []string{
	"freeipa-server", "freeipa-server-replica", "freeipa-nfs-server", "freeipa-nfs-client",
}

// checkRosterCompleteness locates the freeipa-identity roster and runs
// the full canonical-roster structural validation (inventory.ValidateRosterFile)
// against it — not just the narrower nfs.servers cross-check
// deploy_completeness.go performs for freeipa-nfs-server specifically.
//
// There's no single structured place in hosts.yml a roster path must
// come from: a freeipa-nfs-server host's freeipa_roster_file extra var is
// one real source (deploy_completeness.go's own convention), but
// `pilot reconcile`'s freeipa-identity entry (the actual roster
// consumer — the reconciler that applies ipa_users/ipa_groups/
// ipa_hbac_rules/ipa_sudo_rules) targets freeipa-server and simply
// prompts for the roster path interactively (see promptVault/
// defaultVaultFile in deploy.go) — nothing in hosts.yml has to name it.
// So: prefer any freeipa_roster_file extra var found on any host
// (whatever its role); if none is set explicitly but the workspace uses a
// role that genuinely needs one (freeipaRosterFallbackRoles), fall back
// to the same default path pushRosterPathPrompt itself suggests
// (.vault/ipa-identity.yaml) — a guess, not a hard requirement, but
// better than reporting nothing for what's usually the most important
// config file in a FreeIPA workspace.
func checkRosterCompleteness(dir string, hf *inventory.HostsFile) []completenessCheck {
	var paths []string
	seen := map[string]bool{}
	for _, h := range hf.Hosts {
		raw := h.Extra["freeipa_roster_file"]
		if raw == "" {
			continue
		}
		p := resolveRosterPath(dir, raw)
		if !seen[p] {
			seen[p] = true
			paths = append(paths, p)
		}
	}

	if len(paths) == 0 {
		needsRoster := false
		for _, role := range inventory.UsedRoles(hf) {
			if hasRole(freeipaRosterFallbackRoles, role) {
				needsRoster = true
				break
			}
		}
		if !needsRoster {
			return nil
		}
		def := filepath.Join(dir, ".vault", "ipa-identity.yaml")
		return []completenessCheck{rosterCompletenessCheck("roster (預設路徑，hosts.yml 未明確指定 freeipa_roster_file)", def)}
	}

	out := make([]completenessCheck, 0, len(paths))
	for _, p := range paths {
		label := "roster"
		if len(paths) > 1 {
			label = fmt.Sprintf("roster (%s)", p)
		}
		out = append(out, rosterCompletenessCheck(label, p))
	}
	return out
}

// checkInternalEndpointCompleteness reports the internal-endpoints.yaml
// manifest's static validity — schema shape plus every check
// ValidateInternalEndpointManifest can resolve from hosts.yml alone
// (inventory_host references, reverse-proxy role coverage). It
// deliberately never touches live host state (FreeIPA enrollment,
// nginx, certmonger, actual DNS/certificates, the ownership ledger) —
// those gates fire for real at apply time
// (playbooks/apply/internal-endpoint-apply.yml), not here. Unlike
// roster/group_vars/vault, this manifest has no per-host trigger in
// hosts.yml — it's a workspace-root file like hosts.yml itself, so this
// check simply runs when the file exists and stays silent otherwise
// (internal-endpoint is an opt-in feature, not implied by any role).
func checkInternalEndpointCompleteness(dir string, hf *inventory.HostsFile) []completenessCheck {
	path := filepath.Join(dir, "internal-endpoints.yaml")
	if _, err := os.Stat(path); err != nil {
		return nil
	}

	hostvars := make(map[string]map[string]any, len(hf.Hosts))
	reverseProxyHosts := make(map[string]bool)
	for _, h := range hf.Hosts {
		hostvars[h.Name] = map[string]any{"ansible_host": h.AnsibleHost}
		if hasRole(h.Roles, "reverse-proxy") {
			reverseProxyHosts[h.Name] = true
		}
	}

	violations, err := inventory.ValidateInternalEndpointManifestFile(path, inventory.InternalEndpointValidateOptions{
		Hostvars:          hostvars,
		ReverseProxyHosts: reverseProxyHosts,
	})
	if err != nil {
		return []completenessCheck{{Label: "internal-endpoints.yaml", OK: false, Details: []string{err.Error()}}}
	}
	if len(violations) == 0 {
		return []completenessCheck{{Label: "internal-endpoints.yaml", OK: true}}
	}
	details := make([]string, len(violations))
	for i, v := range violations {
		details[i] = v.String()
	}
	return []completenessCheck{{Label: "internal-endpoints.yaml", OK: false, Details: details}}
}

func rosterCompletenessCheck(label, path string) completenessCheck {
	violations, err := inventory.ValidateRosterFile(path)
	if err != nil {
		if errors.Is(err, inventory.ErrRosterEncrypted) {
			return completenessCheck{Label: label, OK: true, Details: []string{"已加密，略過內容檢查"}}
		}
		if os.IsNotExist(err) {
			return completenessCheck{Label: label, OK: false, Details: []string{fmt.Sprintf("%s 不存在", path)}}
		}
		return completenessCheck{Label: label, OK: false, Details: []string{err.Error()}}
	}
	if len(violations) == 0 {
		return completenessCheck{Label: label, OK: true}
	}
	details := make([]string, len(violations))
	for i, v := range violations {
		details[i] = v.String()
	}
	return completenessCheck{Label: label, OK: false, Details: details}
}
