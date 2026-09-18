// directory.go implements `pilot directory` — the user-facing TUI entry
// point for pilot-access-directory (docs/tmp/now/spec.md §13). It never
// reads roster or inventory; its only FreeIPA-adjacent credential is an
// ephemeral session-scoped Kerberos ticket cache used by the controlled
// Directory -> Gateway Connect hop (spec.md D5). Authorization/discovery
// data comes exclusively from pilot-access-directory over its local Unix
// socket.
package cmd

import (
	"github.com/spf13/cobra"
)

// defaultAccessDirectorySocket matches spec.md §12.1's default
// /run/pilot/access-directory.sock.
const defaultAccessDirectorySocket = "/run/pilot/access-directory.sock"

var (
	directorySocketFlag    string
	directorySSHConfigFlag string
)

var directoryCmd = &cobra.Command{
	Use:   "directory",
	Short: "Pilot Access Directory — view and connect to your cross-scope FreeIPA-scoped SSH access",
	RunE: func(cmd *cobra.Command, args []string) error {
		client := newDirectoryClient(directorySocketFlag)
		return runDirectoryWithSSHConfig(cmd.Context(), client, directorySSHConfigFlag)
	},
}

func init() {
	directoryCmd.Flags().StringVar(&directorySocketFlag, "socket", defaultAccessDirectorySocket, "pilot-access-directory Unix socket path")
	directoryCmd.Flags().StringVar(&directorySSHConfigFlag, "ssh-config", defaultDirectorySSHConfigPath, "root-owned SSH client config for the Directory -> Gateway hop (spec.md §15)")
	rootCmd.AddCommand(directoryCmd)
}
