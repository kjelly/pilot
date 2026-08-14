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
	"strings"

	"github.com/spf13/cobra"

	"github.com/kjelly/pilot/internal/inventory"
)

var (
	iepValidateManifestFlag    string
	iepValidateFreeIPADNSFlag  string
	iepValidatePrintNormalized bool
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

func init() {
	internalEndpointValidateCmd.Flags().StringVar(&iepValidateManifestFlag, "manifest", "", "path to internal-endpoints.yaml (required)")
	internalEndpointValidateCmd.Flags().StringVar(&iepValidateFreeIPADNSFlag, "freeipa-dns-manifest", "", "path to freeipa-dns.yaml, for DNS-zone-existence and ownership-collision checks (spec.md §11)")
	internalEndpointValidateCmd.Flags().BoolVar(&iepValidatePrintNormalized, "print-normalized", false, "print the normalized endpoint list (one 'dns_owner fqdn' line per endpoint) instead of a violation report")
	_ = internalEndpointValidateCmd.MarkFlagRequired("manifest")
	internalEndpointCmd.AddCommand(internalEndpointValidateCmd)
	rootCmd.AddCommand(internalEndpointCmd)
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
