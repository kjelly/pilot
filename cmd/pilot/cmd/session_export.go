package cmd

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/kjelly/pilot/internal/sessionrecording"
)

var (
	sessionExportFormatFlag string
	sessionExportOutputFlag string
	sessionExportForceFlag  bool
)

var sessionExportCmd = &cobra.Command{
	Use:   "export <session-id>",
	Short: "Export one recorded session as an asciicast v2 file",
	Long: `Export converts a recorded session to asciicast v2 (per-host recording
spec §28) so it can be played with standard tools. It reads the session
through the same auditor-only read API as replay and declares
purpose=export, so the store records a recording_exported audit event.

The conversion is lossy: output bytes are decoded as UTF-8 per stream,
and gaps, an incomplete recording and redacted input become "m" marker
events. The stored recording is not changed.

--output is created with mode 0600 and an existing file is refused unless
--force is given. --output - writes to stdout.`,
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runSessionExport(cmd.Context(), newSessionStoreClient(sessionSocketFlag), args[0],
			sessionExportFormatFlag, sessionExportOutputFlag, sessionExportForceFlag, cmd.OutOrStdout())
	},
}

func init() {
	sessionExportCmd.Flags().StringVar(&sessionExportFormatFlag, "format", "asciicast-v2", "export format (only asciicast-v2)")
	sessionExportCmd.Flags().StringVar(&sessionExportOutputFlag, "output", "", "file to write (created 0600), or - for stdout")
	sessionExportCmd.Flags().BoolVar(&sessionExportForceFlag, "force", false, "overwrite an existing --output file")
}

func runSessionExport(ctx context.Context, client *sessionStoreClient, sessionID, format, output string, force bool, stdout io.Writer) error {
	if format != "asciicast-v2" {
		return fmt.Errorf("unsupported --format %q (only asciicast-v2)", format)
	}
	if output == "" {
		return fmt.Errorf("--output is required (a file path, or - for stdout)")
	}
	if output != "-" && !force {
		if _, err := os.Lstat(output); err == nil {
			return fmt.Errorf("%s already exists (use --force to overwrite)", output)
		}
	}

	summary, err := client.GetSession(ctx, sessionID)
	if err != nil {
		return fmt.Errorf("show session %s: %w", sessionID, err)
	}
	startedAt, err := time.Parse(time.RFC3339Nano, summary.StartedAt)
	if err != nil {
		return fmt.Errorf("session %s has an unreadable started_at %q: %w", sessionID, summary.StartedAt, err)
	}
	replay, err := client.Replay(ctx, sessionID, "export")
	if err != nil {
		return fmt.Errorf("read session %s: %w", sessionID, err)
	}
	session, err := toExportSession(sessionID, startedAt, replay)
	if err != nil {
		return err
	}

	if output == "-" {
		return sessionrecording.WriteAsciicastV2(stdout, session)
	}
	flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if force {
		flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}
	f, err := os.OpenFile(output, flags, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("%s already exists (use --force to overwrite)", output)
	}
	if err != nil {
		return fmt.Errorf("create %s: %w", output, err)
	}
	if err := f.Chmod(0o600); err != nil { // an overwritten file keeps its old mode otherwise
		_ = f.Close()
		return fmt.Errorf("chmod %s: %w", output, err)
	}
	if err := sessionrecording.WriteAsciicastV2(f, session); err != nil {
		_ = f.Close()
		return fmt.Errorf("write %s: %w", output, err)
	}
	return f.Close()
}

func toExportSession(sessionID string, startedAt time.Time, r replayResult) (sessionrecording.ExportSession, error) {
	s := sessionrecording.ExportSession{SessionID: sessionID, StartedAt: startedAt, Complete: r.Complete}
	for _, g := range r.Gaps {
		s.Gaps = append(s.Gaps, sessionrecording.ExportGap{FromSeq: g.FromSeq, ToSeq: g.ToSeq})
	}
	for _, ev := range r.Events {
		data, err := base64.StdEncoding.DecodeString(ev.DataBase64)
		if err != nil {
			return s, fmt.Errorf("session %s event %d has invalid data_base64", sessionID, ev.Seq)
		}
		s.Events = append(s.Events, sessionrecording.ExportEvent{
			Seq: ev.Seq, Stream: ev.Stream, OffsetNanos: ev.OffsetNanos, Data: data,
			Rows: ev.Rows, Cols: ev.Cols, RedactedBytes: ev.RedactedBytes,
		})
	}
	return s, nil
}
