package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var sessionShowCmd = &cobra.Command{
	Use:   "show <session-id>",
	Short: "Show one recorded session's index metadata",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client := newSessionStoreClient(sessionSocketFlag)
		s, err := client.GetSession(cmd.Context(), args[0])
		if err != nil {
			return err
		}
		out := cmd.OutOrStdout()
		fmt.Fprintf(out, "session_id:      %s\n", s.SessionID)
		fmt.Fprintf(out, "user:            %s\n", s.User)
		fmt.Fprintf(out, "directory_id:    %s\n", s.DirectoryID)
		fmt.Fprintf(out, "gateway_id:      %s\n", s.GatewayID)
		fmt.Fprintf(out, "scope:           %s\n", s.Scope)
		fmt.Fprintf(out, "target:          %s\n", s.Target)
		fmt.Fprintf(out, "recording_mode:  %s\n", s.RecordingMode)
		fmt.Fprintf(out, "started_at:      %s\n", s.StartedAt)
		fmt.Fprintf(out, "ended_at:        %s\n", s.EndedAt)
		fmt.Fprintf(out, "complete:        %v\n", s.Complete)
		fmt.Fprintf(out, "bytes:           %d\n", s.Bytes)
		fmt.Fprintf(out, "event_count:     %d\n", s.EventCount)
		fmt.Fprintf(out, "key_id:          %s\n", s.KeyID)
		fmt.Fprintf(out, "policy_source:   %s\n", s.RecordingPolicySource)
		fmt.Fprintf(out, "last_seq:        %d\n", s.LastSeq)
		return nil
	},
}
