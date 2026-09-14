// portal.go implements `pilot portal` — the user-facing TUI entry point
// for pilot-access-gateway (spec.md §27/§28). It never reads roster,
// inventory, or a FreeIPA credential itself; it only ever talks to
// pilot-access-gateway over its local Unix socket, and never as a
// different Gateway/scope than whichever gateway that socket belongs to.
package cmd

import (
	"github.com/spf13/cobra"
)

// defaultAccessGatewaySocket matches spec.md §26/§29's default
// /run/pilot/access-gateway.sock.
const defaultAccessGatewaySocket = "/run/pilot/access-gateway.sock"

var portalSocketFlag string

var portalCmd = &cobra.Command{
	Use:   "portal",
	Short: "Pilot Portal — view your FreeIPA-scoped SSH/sudo access on this gateway",
	RunE: func(cmd *cobra.Command, args []string) error {
		client := newPortalClient(portalSocketFlag)
		return runPortal(cmd.Context(), client)
	},
}

func init() {
	portalCmd.Flags().StringVar(&portalSocketFlag, "socket", defaultAccessGatewaySocket, "pilot-access-gateway Unix socket path")
	rootCmd.AddCommand(portalCmd)
}
