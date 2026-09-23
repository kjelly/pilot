// session_list.go, session_show.go, and session_replay.go implement
// `pilot session {list,show,replay}` (docs/tmp/now/spec.md §29): a thin
// CLI over pilot-session-store's admin read Unix socket. None of these
// commands ever touch the TLS ingest listener or an ingest token — they
// are the separate, lower-privilege read/replay credential path spec.md
// §28.2/§29 requires.
package cmd

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

// defaultSessionStoreSocket is where pilot-session-store-apply.yml puts
// the read socket (pilot_session_store_read_socket_path): the store's own
// RuntimeDirectory, not the shared /run/pilot that spec.md §29 first
// suggested (see the playbook's comment on the service unit for why).
const defaultSessionStoreSocket = "/run/pilot-session-store/session-store.sock"

var (
	sessionSocketFlag string
	sessionUserFlag   string
)

var sessionCmd = &cobra.Command{
	Use:   "session",
	Short: "Pilot Session Store — list, show, and replay recorded terminal sessions",
}

var sessionListCmd = &cobra.Command{
	Use:   "list",
	Short: "List recorded sessions",
	RunE: func(cmd *cobra.Command, args []string) error {
		client := newSessionStoreClient(sessionSocketFlag)
		resp, err := client.ListSessions(cmd.Context(), sessionUserFlag)
		if err != nil {
			return err
		}
		return printSessionList(cmd.OutOrStdout(), resp.Sessions)
	},
}

func printSessionList(w io.Writer, sessions []sessionSummary) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "SESSION_ID\tUSER\tTARGET\tSCOPE\tMODE\tSTARTED_AT\tCOMPLETE\tEVENTS")
	for _, s := range sessions {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%v\t%d\n",
			s.SessionID, s.User, s.Target, s.Scope, s.RecordingMode, s.StartedAt, s.Complete, s.EventCount)
	}
	return tw.Flush()
}

func init() {
	sessionCmd.PersistentFlags().StringVar(&sessionSocketFlag, "socket", defaultSessionStoreSocket, "pilot-session-store read-API Unix socket path")
	sessionListCmd.Flags().StringVar(&sessionUserFlag, "user", "", "filter by user")
	sessionCmd.AddCommand(sessionListCmd, sessionShowCmd, sessionReplayCmd, sessionExportCmd)
	rootCmd.AddCommand(sessionCmd)
}
