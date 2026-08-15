// internal_endpoint_cli.go implements `pilot internal-endpoint validate`, a
// thin CLI wrapper over internal/inventory's already-tested Go manifest
// validator/normalizer — the CLI shape docs/verification/internal-endpoint.md's
// own C1/C2/C3/C8/C30 probes were authored against (Phase 1) but that no
// phase since had actually built, so those five rows were either silently
// failing on their own merits or — in C1's case — silently FALSE-PASSING:
// cobra's own `unknown command "internal-endpoint" for "pilot"` error (rc=1)
// happens to contain the word "unknown", which C1's probe greps for, so
// every prior phase's "C1: pass" was a false positive, not a working check
// (found for real during Phase 10's full-topology verify round, 2026-08-14).
package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/kjelly/pilot/internal/contract"
	"github.com/kjelly/pilot/internal/inventory"
)

var (
	iepValidateManifestFlag    string
	iepValidateFreeIPADNSFlag  string
	iepValidatePrintNormalized bool

	iepSuggestInventoryFlag          string
	iepSuggestManifestFlag           string
	iepSuggestFreeIPADNSManifestFlag string
	iepSuggestZoneFlag               string
	iepSuggestProxyHostFlag          string
)

var internalEndpointCmd = &cobra.Command{
	Use:   "internal-endpoint",
	Short: "Inspect and validate internal-endpoint manifests",
}

var internalEndpointValidateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate an internal-endpoints.yaml manifest (schema + structural gates only — no live host state)",
	Args:  cobra.NoArgs,
	RunE:  runInternalEndpointValidateCmd,
}

// internalEndpointSuggestCmd is read-only and advisory: it never writes a
// manifest or touches a live host, the same character as `validate`. It
// diffs contracts (which endpoints declare autoPublish.eligible: true)
// against this inventory's actual role-group membership and an existing
// manifest's already-published upstreams, and prints ready-to-paste
// endpoints: entries. A human still decides which to actually add — via
// `pilot edit`'s internal-endpoint menu (Simulate-then-write, same gate as
// every manual entry) or by copying the printed YAML by hand. This
// deliberately stops short of a non-interactive reconcile CLI.
var internalEndpointSuggestCmd = &cobra.Command{
	Use:   "suggest",
	Short: "Suggest internal-endpoint manifest entries for deployed services with autoPublish.eligible: true (read-only, writes nothing)",
	Args:  cobra.NoArgs,
	RunE:  runInternalEndpointSuggestCmd,
}

func init() {
	internalEndpointValidateCmd.Flags().StringVar(&iepValidateManifestFlag, "manifest", "", "path to internal-endpoints.yaml (required)")
	internalEndpointValidateCmd.Flags().StringVar(&iepValidateFreeIPADNSFlag, "freeipa-dns-manifest", "", "path to freeipa-dns.yaml, for DNS-zone-existence and ownership-collision checks (spec.md §11)")
	internalEndpointValidateCmd.Flags().BoolVar(&iepValidatePrintNormalized, "print-normalized", false, "print the normalized endpoint list (one 'dns_owner fqdn' line per endpoint) instead of a violation report")
	_ = internalEndpointValidateCmd.MarkFlagRequired("manifest")
	internalEndpointCmd.AddCommand(internalEndpointValidateCmd)

	internalEndpointSuggestCmd.Flags().StringVar(&iepSuggestInventoryFlag, "inventory", "", "path to the ansible inventory (hosts.yml) describing this topology (required)")
	internalEndpointSuggestCmd.Flags().StringVar(&iepSuggestManifestFlag, "manifest", "", "path to the existing internal-endpoints.yaml, to skip already-published upstreams (optional; omit for a brand-new manifest)")
	internalEndpointSuggestCmd.Flags().StringVar(&iepSuggestFreeIPADNSManifestFlag, "freeipa-dns-manifest", "", "path to freeipa-dns.yaml, to auto-resolve the zone when it declares exactly one (ignored if --zone is set)")
	internalEndpointSuggestCmd.Flags().StringVar(&iepSuggestZoneFlag, "zone", "", "dns zone to publish suggested endpoints under (overrides --freeipa-dns-manifest auto-detection); required if that manifest declares zero or more than one zone")
	internalEndpointSuggestCmd.Flags().StringVar(&iepSuggestProxyHostFlag, "proxy-host", "", "inventory_host to use as route.proxy (overrides auto-detection from the reverse-proxy group); required if that group has more than one host")
	_ = internalEndpointSuggestCmd.MarkFlagRequired("inventory")
	internalEndpointCmd.AddCommand(internalEndpointSuggestCmd)

	rootCmd.AddCommand(internalEndpointCmd)
}

func runInternalEndpointSuggestCmd(cmd *cobra.Command, _ []string) error {
	root, err := resolveContractRoot("")
	if err != nil {
		return err
	}
	loader, err := contract.NewLoader(root)
	if err != nil {
		return err
	}
	catalog, err := loader.LoadDefaultCatalog()
	if err != nil {
		return err
	}

	groups, err := resolveInventoryGroups(cmd.Context(), iepSuggestInventoryFlag)
	if err != nil {
		return fmt.Errorf("resolve inventory groups: %w", err)
	}

	proxyHost := iepSuggestProxyHostFlag
	if proxyHost == "" {
		hosts := groups["reverse-proxy"]
		switch len(hosts) {
		case 0:
			return fmt.Errorf("no reverse-proxy host in this inventory (group %q is empty) — nothing can be published", "reverse-proxy")
		case 1:
			proxyHost = hosts[0]
		default:
			return fmt.Errorf("ambiguous reverse-proxy host: group %q has %d hosts (%s) — pass --proxy-host", "reverse-proxy", len(hosts), strings.Join(hosts, ", "))
		}
	}

	zone := iepSuggestZoneFlag
	if zone == "" {
		if iepSuggestFreeIPADNSManifestFlag == "" {
			return fmt.Errorf("pass --zone or --freeipa-dns-manifest to resolve the publishing zone")
		}
		zones, err := inventory.DNSManifestZoneNames(iepSuggestFreeIPADNSManifestFlag)
		if err != nil {
			return fmt.Errorf("load --freeipa-dns-manifest: %w", err)
		}
		switch len(zones) {
		case 0:
			return fmt.Errorf("%s declares no zones — pass --zone explicitly", iepSuggestFreeIPADNSManifestFlag)
		case 1:
			zone = zones[0]
		default:
			return fmt.Errorf("%s declares %d zones (%s) — pass --zone explicitly", iepSuggestFreeIPADNSManifestFlag, len(zones), strings.Join(zones, ", "))
		}
	}

	var existing map[string]any
	if iepSuggestManifestFlag != "" {
		if _, statErr := os.Stat(iepSuggestManifestFlag); statErr == nil {
			existing, err = inventory.LoadInternalEndpointManifest(iepSuggestManifestFlag)
			if err != nil {
				return fmt.Errorf("load --manifest: %w", err)
			}
		} else if !os.IsNotExist(statErr) {
			return fmt.Errorf("stat --manifest %s: %w", iepSuggestManifestFlag, statErr)
		}
	}

	result := inventory.SuggestInternalEndpoints(catalog.Components(), groups, proxyHost, zone, existing)

	out := cmd.OutOrStdout()
	if len(result.Candidates) == 0 {
		fmt.Fprintln(out, "# no candidates")
	}
	for _, candidate := range result.Candidates {
		rendered, err := yaml.Marshal([]any{candidate.Manifest})
		if err != nil {
			return fmt.Errorf("encode candidate %s: %w", candidate.FQDN, err)
		}
		fmt.Fprintf(out, "# %s (%s.%s) — paste this entry into internal-endpoints.yaml's endpoints:\n", candidate.FQDN, candidate.Component, candidate.Endpoint)
		fmt.Fprint(out, string(rendered))
		fmt.Fprintln(out)
	}
	if len(result.Skipped) > 0 {
		fmt.Fprintln(out, "# skipped:")
		for _, skip := range result.Skipped {
			fmt.Fprintf(out, "#   %s/%s: %s\n", skip.Component, skip.Endpoint, skip.Reason)
		}
	}
	return nil
}

func runInternalEndpointValidateCmd(cmd *cobra.Command, _ []string) error {
	root, err := inventory.LoadInternalEndpointManifest(iepValidateManifestFlag)
	if err != nil {
		return err
	}

	opts := inventory.InternalEndpointValidateOptions{}
	if iepValidateFreeIPADNSFlag != "" {
		zones, err := loadFreeIPADNSZonesForCLIValidate(iepValidateFreeIPADNSFlag)
		if err != nil {
			return fmt.Errorf("load --freeipa-dns-manifest: %w", err)
		}
		opts.FreeIPADNSZones = zones
	}

	violations := inventory.ValidateInternalEndpointManifest(root, opts)
	if len(violations) > 0 {
		for _, v := range violations {
			fmt.Fprintln(cmd.OutOrStdout(), v.String())
		}
		return fmt.Errorf("%d violation(s)", len(violations))
	}

	if iepValidatePrintNormalized {
		norm := inventory.NormalizeInternalEndpointManifest(root, nil)
		for _, e := range norm.Endpoints {
			fmt.Fprintf(cmd.OutOrStdout(), "%s %s\n", e.DNSOwner, e.FQDN)
		}
		return nil
	}

	fmt.Fprintln(cmd.OutOrStdout(), "manifest OK")
	return nil
}

// loadFreeIPADNSZonesForCLIValidate reads path's zones/records the same way
// mcp_edit_resources.go's buildInspectDNSZones does, into the
// InternalEndpointValidateOptions.FreeIPADNSZones shape
// ValidateInternalEndpointManifest needs for spec.md §11's DNS-ownership
// gates (C7 zone existence, C8 explicit-ownership collision).
func loadFreeIPADNSZonesForCLIValidate(path string) (map[string]inventory.FreeIPAZoneInfo, error) {
	zoneNames, err := inventory.DNSManifestZoneNames(path)
	if err != nil {
		return nil, err
	}
	zones := make(map[string]inventory.FreeIPAZoneInfo, len(zoneNames))
	for _, name := range zoneNames {
		zf, found, err := inventory.DNSManifestZone(path, name)
		if err != nil || !found {
			continue
		}
		state, _ := zf["state"].(string)
		present := state == "" || state == "present"
		recordsMode, _ := zf["records_mode"].(string)
		if recordsMode == "" {
			recordsMode = "merge"
		}

		owners := map[string]bool{}
		records, err := inventory.DNSManifestRecords(path, name)
		if err == nil {
			for _, rf := range records {
				recName, _ := rf["name"].(string)
				recType, _ := rf["type"].(string)
				if recName == "" || recType == "" {
					continue
				}
				owners[strings.ToLower(recName)+"|"+strings.ToLower(recType)] = true
			}
		}

		zoneKey := strings.ToLower(name)
		if !strings.HasSuffix(zoneKey, ".") {
			zoneKey += "."
		}
		zones[zoneKey] = inventory.FreeIPAZoneInfo{
			Present:        present,
			RecordsMode:    recordsMode,
			ExplicitOwners: owners,
		}
	}
	return zones, nil
}
