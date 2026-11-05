// mcp_remote.go implements `pilot mcp remote`, which runs inside the
// pilot-cli container that pilot-mcp starts with one `docker run` over SSH
// (docs/superpowers/specs/2026-10-30-pilot-mcp-remote-access-spec.md §7).
// The session logic lives in internal/mcpremote; this file wires the flags
// and injects the two pieces that live in this package: inventory
// generation and the MCP server itself.
package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kjelly/pilot/internal/mcpremote"
	"github.com/kjelly/pilot/internal/mcpwire"
	"github.com/spf13/cobra"
)

var (
	mcpRemoteProtocol    string
	mcpRemoteMode        string
	mcpRemoteEnv         string
	mcpRemoteVaultDir    string
	mcpRemoteTmpDir      string
	mcpRemotePilotRoot   string
	mcpRemoteConfigLink  string
	mcpRemoteMaxDuration time.Duration
)

// mcpRemoteError is how every `pilot mcp remote` failure leaves the
// process: cmd/pilot/main.go prints Error() — exactly the
// `pilot-mcp-remote: <CODE>: <message>` line pilot-mcp parses — and exits
// with the code's exit status.
type mcpRemoteError struct {
	code string
	msg  string
}

func (e *mcpRemoteError) Error() string {
	return strings.TrimSuffix(mcpwire.ErrorLine(e.code, e.msg), "\n")
}

func (e *mcpRemoteError) ExitCode() int { return mcpwire.ExitCode(e.code) }

func mcpRemoteFail(err error) error {
	if err == nil {
		return nil
	}
	var e *mcpremote.Error
	if errors.As(err, &e) {
		return &mcpRemoteError{code: e.Code, msg: e.Err.Error()}
	}
	return &mcpRemoteError{code: mcpwire.CodeRuntimeError, msg: err.Error()}
}

func mcpRemoteUsage(format string, args ...any) error {
	return &mcpRemoteError{code: mcpwire.CodeCommandInvalid, msg: fmt.Sprintf(format, args...)}
}

var mcpRemoteCmd = &cobra.Command{
	Use:   "remote",
	Short: "Serve one pilot-mcp session inside the pilot-cli container (started by pilot-mcp over SSH)",
	Long: `pilot mcp remote runs inside the pilot-cli container that pilot-mcp starts
with one docker run over SSH. It is not meant to be run by hand: pilot-mcp
builds the docker run command, sends the configuration snapshot on stdin and
then speaks MCP over the same connection.`,
	SilenceErrors: true,
	SilenceUsage:  true,
}

var mcpRemoteVersionCmd = &cobra.Command{
	Use:           "version",
	Short:         "Print the protocol and the pilot binary's SHA-256 as JSON",
	Args:          mcpRemoteNoArgs,
	SilenceErrors: true,
	SilenceUsage:  true,
	RunE: func(cmd *cobra.Command, args []string) error {
		sum, err := mcpremote.BinarySHA256()
		if err != nil {
			return mcpRemoteFail(err)
		}
		data, err := json.Marshal(mcpwire.Version{Protocol: mcpwire.Protocol, PilotBinarySHA256: sum})
		if err != nil {
			return mcpRemoteFail(err)
		}
		_, err = fmt.Fprintln(cmd.OutOrStdout(), string(data))
		return mcpRemoteFail(err)
	},
}

var mcpRemoteSessionCmd = &cobra.Command{
	Use:           "session",
	Short:         "Read the snapshot from stdin, then serve MCP on the rest of the connection",
	Args:          mcpRemoteNoArgs,
	SilenceErrors: true,
	SilenceUsage:  true,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := mcpRemoteConfig(cmd)
		if err != nil {
			return err
		}
		return mcpRemoteFail(mcpremote.RunSession(cmd.Context(), cfg))
	},
}

var mcpRemoteChangesCmd = &cobra.Command{
	Use:           "changes <session-id>",
	Short:         "Write an ended edit session's changes as a tar to stdout",
	SilenceErrors: true,
	SilenceUsage:  true,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 || !mcpwire.ValidSessionID(args[0]) {
			return mcpRemoteUsage("changes takes exactly one session id (32 lowercase hex characters)")
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := mcpRemoteConfig(cmd)
		if err != nil {
			return err
		}
		return mcpRemoteFail(mcpremote.RunChanges(cfg, args[0]))
	},
}

func mcpRemoteNoArgs(cmd *cobra.Command, args []string) error {
	if len(args) != 0 {
		return mcpRemoteUsage("%s takes no arguments", cmd.Name())
	}
	return nil
}

// mcpRemoteConfig validates the flags and builds the session config. The
// container paths default to the mcpwire constants; the overrides exist
// only so tests can run without Docker.
func mcpRemoteConfig(cmd *cobra.Command) (*mcpremote.Config, error) {
	if mcpRemoteProtocol != mcpwire.ProtocolFlag {
		return nil, &mcpRemoteError{code: mcpwire.CodeProtocolUnsupported, msg: fmt.Sprintf("--protocol %q is not supported (want %s)", mcpRemoteProtocol, mcpwire.ProtocolFlag)}
	}
	if !mcpwire.ValidEnv(mcpRemoteEnv) {
		return nil, mcpRemoteUsage("--env must be one of %s", strings.Join(mcpwire.Envs, ", "))
	}
	if cmd.Name() == "session" && !mcpwire.ValidMode(mcpRemoteMode) {
		return nil, mcpRemoteUsage("--mode must be %s or %s", mcpwire.ModeObserve, mcpwire.ModeEdit)
	}
	if cmd.Flags().Changed("pilot-root") {
		// The container's working directory is already /pilot; tests point
		// both the cwd (copyMissingGroupVars reads ./group_vars) and
		// PILOT_ROOT at a repository checkout instead.
		if err := os.Chdir(mcpRemotePilotRoot); err != nil {
			return nil, mcpRemoteFail(fmt.Errorf("--pilot-root: %w", err))
		}
		if err := os.Setenv("PILOT_ROOT", mcpRemotePilotRoot); err != nil {
			return nil, mcpRemoteFail(err)
		}
	}
	if dataDir == "" {
		dataDir = mcpwire.ContainerDataDir
	}
	return &mcpremote.Config{
		Mode:               mcpRemoteMode,
		Env:                mcpRemoteEnv,
		VaultDir:           mcpRemoteVaultDir,
		DataDir:            dataDir,
		TmpDir:             mcpRemoteTmpDir,
		PilotRoot:          mcpRemotePilotRoot,
		ConfigLink:         mcpRemoteConfigLink,
		MaxSessionDuration: mcpRemoteMaxDuration,
		Stdin:              cmd.InOrStdin(),
		Stdout:             cmd.OutOrStdout(),
		Stderr:             cmd.ErrOrStderr(),
		GenerateInventory:  mcpRemoteGenerateInventory,
		Serve:              mcpRemoteServe,
	}, nil
}

func mcpRemoteGenerateInventory(configDir string, stderr io.Writer) error {
	_, err := autoRegenerateInventoryFromHosts(stderr, filepath.Join(configDir, "inventory.yml"))
	return err
}

// remoteServeOptions is the only place a remote session's MCP flags are
// decided: --enable-diagnose always, --allow-write in edit mode, and never
// raw, active or repair (spec §8).
func remoteServeOptions(o mcpremote.ServeOptions) mcpServeOptions {
	return mcpServeOptions{
		Dir:                 o.Dir,
		AuditDir:            o.AuditDir,
		AllowWrite:          o.AllowWrite,
		EnableDiagnose:      true,
		DiagnoseInventory:   o.DiagnoseInventory,
		DiagnoseStepTimeout: 20 * time.Second,
	}
}

func mcpRemoteServe(ctx context.Context, o mcpremote.ServeOptions) error {
	return serveMCP(ctx, remoteServeOptions(o), o.Transport)
}

func init() {
	for _, c := range []*cobra.Command{mcpRemoteSessionCmd, mcpRemoteChangesCmd} {
		c.Flags().StringVar(&mcpRemoteProtocol, "protocol", "", "wire protocol version; must be "+mcpwire.ProtocolFlag)
		c.Flags().StringVar(&mcpRemoteEnv, "env", "", "environment: "+strings.Join(mcpwire.Envs, ", "))
		c.Flags().StringVar(&mcpRemoteVaultDir, "vault-dir", mcpwire.ContainerVaultDir, "read-only .vault of --env (test override)")
		c.Flags().StringVar(&mcpRemoteTmpDir, "tmp-dir", mcpwire.ContainerTmpDir, "directory for observe sessions (test override)")
		c.Flags().StringVar(&mcpRemotePilotRoot, "pilot-root", mcpwire.ContainerPilotRoot, "directory holding contracts/ and group_vars/ (test override; also becomes the working directory)")
		c.Flags().StringVar(&mcpRemoteConfigLink, "config-link", mcpwire.ContainerConfigLink, `symlink pointed at the session workspace; "" serves the work directory directly (test override)`)
	}
	mcpRemoteSessionCmd.Flags().StringVar(&mcpRemoteMode, "mode", "", "observe or edit")
	mcpRemoteSessionCmd.Flags().DurationVar(&mcpRemoteMaxDuration, "max-session-duration", 12*time.Hour, "end the session after this long")
	for _, c := range []*cobra.Command{mcpRemoteCmd, mcpRemoteVersionCmd, mcpRemoteSessionCmd, mcpRemoteChangesCmd} {
		c.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return mcpRemoteUsage("%v", err) })
	}
	mcpRemoteCmd.AddCommand(mcpRemoteVersionCmd, mcpRemoteSessionCmd, mcpRemoteChangesCmd)
	mcpCmd.AddCommand(mcpRemoteCmd)
}
