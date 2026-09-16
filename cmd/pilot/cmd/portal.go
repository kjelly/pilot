// portal.go implements `pilot portal` — the user-facing TUI entry point
// for pilot-access-gateway (spec.md §27/§28). It never reads roster or
// inventory; its only FreeIPA credential is an ephemeral user ccache used by
// controlled Connect sessions (spec.md §32.1). Authorization still comes
// exclusively from pilot-access-gateway over its local Unix socket, and never
// from a different Gateway/scope than whichever gateway that socket belongs
// to.
package cmd

import (
	"github.com/spf13/cobra"
)

// defaultAccessGatewaySocket matches spec.md §26/§29's default
// /run/pilot/access-gateway.sock.
const defaultAccessGatewaySocket = "/run/pilot/access-gateway.sock"

var (
	portalSocketFlag    string
	portalSSHConfigFlag string
)

var portalCmd = &cobra.Command{
	Use:   "portal",
	Short: "Pilot Portal — view your FreeIPA-scoped SSH/sudo access on this gateway",
	RunE: func(cmd *cobra.Command, args []string) error {
		client := newPortalClient(portalSocketFlag)
		return runPortalWithSSHConfig(cmd.Context(), client, portalSSHConfigFlag)
	},
}

func init() {
	portalCmd.Flags().StringVar(&portalSocketFlag, "socket", defaultAccessGatewaySocket, "pilot-access-gateway Unix socket path")
	portalCmd.Flags().StringVar(&portalSSHConfigFlag, "ssh-config", defaultSSHConfigPath, "root-owned SSH client config for Connect (spec.md §32)")
	rootCmd.AddCommand(portalCmd)
}
