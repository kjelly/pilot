// Command pilot-mcp connects a coding agent to pilot's MCP server on a
// deploy node: it fetches the configuration from GitHub with the user's
// own credentials, starts one pilot-cli container over SSH and relays MCP
// over stdio. It builds for Linux and macOS.
//
// Spec: docs/superpowers/specs/2026-10-30-pilot-mcp-remote-access-spec.md.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/kjelly/pilot/internal/mcpclient"
	"github.com/spf13/cobra"
)

// version is set with -ldflags "-X main.version=…".
var version = "dev"

var (
	flagProfile string
	flagImage   string
	flagJSON    bool
	flagSession string
	flagInto    string
)

func main() {
	os.Exit(run())
}

func run() int {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	root := newRootCmd()
	err := root.ExecuteContext(ctx)
	if err == nil {
		return 0
	}
	if ctx.Err() != nil {
		select {
		case s := <-sig:
			if s == syscall.SIGTERM {
				return 143
			}
		default:
		}
		return 130
	}
	fmt.Fprintln(os.Stderr, err)
	var e *mcpclient.Error
	if errors.As(err, &e) {
		return e.ExitCode()
	}
	return 2 // cobra usage errors
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "pilot-mcp",
		Short:         "Connect a coding agent to pilot MCP on a deploy node",
		SilenceErrors: true,
		SilenceUsage:  true,
	}

	connect := &cobra.Command{
		Use:   "connect",
		Short: "Start a session and relay MCP over stdio (run by the coding agent, not by hand)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			o, err := options(cmd)
			if err != nil {
				return err
			}
			return mcpclient.Connect(cmd.Context(), o)
		},
	}
	connect.Flags().StringVar(&flagImage, "image", "", "pilot-cli image as <repository>:<tag> (overrides target.image)")

	doctor := &cobra.Command{
		Use:   "doctor",
		Short: "Check the profile, Git, SSH, the image and an MCP handshake",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			o, err := options(cmd)
			if err != nil {
				return err
			}
			rep := mcpclient.Doctor(cmd.Context(), o)
			out := cmd.OutOrStdout()
			if flagJSON {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				if err := enc.Encode(rep); err != nil {
					return err
				}
			} else {
				for _, c := range rep.Checks {
					line := fmt.Sprintf("%-15s %-4s", c.ID, c.Status)
					if c.Detail != "" {
						line += "  " + c.Detail
					}
					fmt.Fprintln(out, line)
				}
			}
			if !rep.OK() {
				return &mcpclient.Error{Code: firstFailure(rep), Msg: "doctor found a problem"}
			}
			return nil
		},
	}
	doctor.Flags().StringVar(&flagImage, "image", "", "pilot-cli image as <repository>:<tag> (overrides target.image)")
	doctor.Flags().BoolVar(&flagJSON, "json", false, "print the report as JSON")

	changes := &cobra.Command{
		Use:   "changes",
		Short: "Write an ended edit session's changes into a local clone for review",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			o, err := options(cmd)
			if err != nil {
				return err
			}
			id := flagSession
			if id == "" {
				if id, err = mcpclient.LatestEditSession(o.StatePath, o.ProfileName); err != nil {
					return err
				}
			}
			res, err := mcpclient.Changes(cmd.Context(), o, id, flagInto)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			for _, p := range res.Written {
				fmt.Fprintln(out, "wrote   "+p)
			}
			for _, p := range res.Deleted {
				fmt.Fprintln(out, "deleted "+p)
			}
			for _, p := range res.Ignored {
				fmt.Fprintln(cmd.ErrOrStderr(), "pilot-mcp: skipped (ignored by Git): "+p)
			}
			fmt.Fprintf(out, "session %s: review with git diff, then commit and open a pull request yourself\n", res.SessionID)
			return nil
		},
	}
	changes.Flags().StringVar(&flagSession, "session", "", "edit session id (default: the profile's latest edit session)")
	changes.Flags().StringVar(&flagInto, "into", "", "top level of a clean local clone of the configuration repository")
	_ = changes.MarkFlagRequired("into")

	sessions := &cobra.Command{
		Use:   "sessions",
		Short: "List the sessions this machine started",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			path, err := mcpclient.DefaultStatePath()
			if err != nil {
				return err
			}
			records, err := mcpclient.ReadRecords(path, flagProfile)
			if err != nil {
				return err
			}
			for _, r := range records {
				fmt.Fprintf(cmd.OutOrStdout(), "%s  %-20s %-8s %-7s %s  %s\n", r.Time.Format("2006-01-02 15:04:05Z"), r.Profile, r.Env, r.Mode, r.SessionID, r.CommitSHA)
			}
			return nil
		},
	}

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print the pilot-mcp version",
		Args:  cobra.NoArgs,
		Run:   func(cmd *cobra.Command, _ []string) { fmt.Fprintln(cmd.OutOrStdout(), version) },
	}

	for _, c := range []*cobra.Command{connect, doctor, changes} {
		c.Flags().StringVar(&flagProfile, "profile", "", "profile name in profiles.yaml")
		_ = c.MarkFlagRequired("profile")
	}
	sessions.Flags().StringVar(&flagProfile, "profile", "", "only this profile's sessions")
	root.AddCommand(connect, doctor, changes, sessions, versionCmd)
	return root
}

func options(cmd *cobra.Command) (*mcpclient.Options, error) {
	profilePath, err := mcpclient.DefaultProfilePath()
	if err != nil {
		return nil, &mcpclient.Error{Code: mcpclient.CodeProfileInvalid, Msg: err.Error()}
	}
	p, err := mcpclient.LoadProfile(profilePath, flagProfile)
	if err != nil {
		return nil, &mcpclient.Error{Code: mcpclient.CodeProfileInvalid, Msg: err.Error()}
	}
	cacheDir, err := mcpclient.DefaultCacheDir()
	if err != nil {
		return nil, &mcpclient.Error{Code: mcpclient.CodeProfileInvalid, Msg: err.Error()}
	}
	statePath, err := mcpclient.DefaultStatePath()
	if err != nil {
		return nil, &mcpclient.Error{Code: mcpclient.CodeProfileInvalid, Msg: err.Error()}
	}
	return &mcpclient.Options{
		ProfileName: flagProfile, Profile: p, Image: flagImage,
		Stdin: cmd.InOrStdin(), Stdout: cmd.OutOrStdout(), Stderr: cmd.ErrOrStderr(),
		CacheDir: cacheDir, StatePath: statePath,
		ClientVersion: version, ClientUser: mcpclient.CurrentUser(),
	}, nil
}

func firstFailure(rep *mcpclient.Report) string {
	for _, c := range rep.Checks {
		if c.Status == "fail" {
			if c.ReasonCode != "" {
				code, _, _ := strings.Cut(c.ReasonCode, "/")
				return code
			}
			return mcpclient.CodeRemoteRuntime
		}
	}
	return mcpclient.CodeRemoteRuntime
}
