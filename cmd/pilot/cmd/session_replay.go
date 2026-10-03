package cmd

import (
	"encoding/base64"
	"fmt"
	"time"

	"github.com/spf13/cobra"
)

var sessionReplayRawFlag bool

var sessionReplayCmd = &cobra.Command{
	Use:   "replay <session-id>",
	Short: "Replay one recorded session's terminal output (decrypt, verify sequence continuity, output only)",
	Long: `Replay decrypts a recorded session and writes its terminal output to
stdout in sequence order. It never re-executes any recorded input —
output only, exactly as spec.md §29 requires.

By default, playback is paced using each event's recorded offset_nanos
(spec.md §29: "respect offset_nanos"), reproducing the original
session's real-time feel. Pass --raw to dump every event immediately
with no pacing.

If the recording has a gap (a missing sequence number — data lost to
backpressure, a crashed sink, or a truncated transfer), "RECORDING
INCOMPLETE" is printed prominently before playback, exactly as spec.md
§29 requires it never be hidden.`,
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		client := newSessionStoreClient(sessionSocketFlag)
		result, err := client.Replay(cmd.Context(), args[0], "replay")
		if err != nil {
			return err
		}

		errOut := cmd.ErrOrStderr()
		if !result.Complete {
			fmt.Fprintln(errOut, "*** RECORDING INCOMPLETE ***")
			for _, g := range result.Gaps {
				fmt.Fprintf(errOut, "    missing sequence %d..%d\n", g.FromSeq, g.ToSeq)
			}
		}

		out := cmd.OutOrStdout()
		var lastOffset int64
		for _, ev := range result.Events {
			if !sessionReplayRawFlag && ev.OffsetNanos > lastOffset {
				time.Sleep(time.Duration(ev.OffsetNanos - lastOffset))
			}
			lastOffset = ev.OffsetNanos

			switch ev.Stream {
			case "tty_output", "tty_input":
				data, decodeErr := base64.StdEncoding.DecodeString(ev.DataBase64)
				if decodeErr != nil {
					continue
				}
				_, _ = out.Write(data)
			default:
				// resize and any future stream kinds have no
				// output-visible effect in a non-interactive replay.
			}
		}
		return nil
	},
}

func init() {
	sessionReplayCmd.Flags().BoolVar(&sessionReplayRawFlag, "raw", false, "dump events immediately, ignoring recorded timing")
}
