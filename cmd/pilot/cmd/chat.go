package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/anomalyco/pilot/internal/app"
)

var (
	chatInventory           string
	chatLimit               string
	chatSandbox             bool
	chatSandboxImage        string
	chatSandboxHost         string
	chatSandboxNet          string
	chatSandboxKeep         bool
	chatSandboxPreferCached bool
	chatSandboxDryRun       bool
	// chatSandboxMode is folded into the shared `runSandboxMode`
	// global (declared in root.go) so loadConfig picks it up.
)

var chatCmd = &cobra.Command{
	Use:   "chat",
	Short: "Interactive chat with the pilot agent",
	Long: `Start an interactive REPL. Type your goals/questions, the agent will
use its tools and propose actions. Type 'exit' or Ctrl-D to quit.

Session defaults:
  --inventory <path>   Default inventory file for run_ansible / apply_patch
                       tool calls. The LLM is told this in the system prompt
                       AND the run_ansible tool will substitute it when the
                       model omits the inventory argument. Path must still
                       be under one of the configured allowed_roots.
  --limit <pattern>    Default --limit host pattern (e.g. 'web01' or
                       'webservers'). Same dual-injection behaviour as
                       --inventory.

Sandbox mode (Docker container):
  --sandbox            Run all tool calls inside a Docker container matching
                       the target OS. Same flags as ` + "`pilot run --sandbox`" + `.

For batch / multi-playbook use cases with full ansible-playbook flag
control, see 'pilot run --from-stdin' / 'pilot run --discover' and the
JSONL target format.`,
	RunE: runChat,
}

func init() {
	chatCmd.Flags().StringVar(&chatInventory, "inventory", "",
		"default inventory file applied to run_ansible / apply_patch when the model omits one")
	chatCmd.Flags().StringVar(&chatLimit, "limit", "",
		"default --limit host pattern applied to run_ansible / apply_patch when the model omits one")
	chatCmd.Flags().BoolVar(&chatSandbox, "sandbox", false, "run all tool calls inside a Docker container")
	chatCmd.Flags().StringVar(&chatSandboxImage, "sandbox-image", "", "docker image (e.g. ubuntu:22.04); overrides auto-detect")
	chatCmd.Flags().StringVar(&chatSandboxHost, "sandbox-hostname", "", "hostname for auto-detect via 'docker inspect'")
	chatCmd.Flags().StringVar(&chatSandboxNet, "sandbox-network", "", "docker --network mode (default host)")
	chatCmd.Flags().BoolVar(&chatSandboxKeep, "sandbox-keep", false, "keep container after the chat ends; reuse on next chat")
	chatCmd.Flags().BoolVar(&chatSandboxPreferCached, "sandbox-prefer-cached", false, "use --pull never when image is already cached")
	chatCmd.Flags().BoolVar(&chatSandboxDryRun, "sandbox-dry-run", false, "read-only rootfs + tmpfs /tmp")
	chatCmd.Flags().StringVar(&runSandboxMode, "sandbox-mode", "",
		"sandbox execution mode: 'docker' (default; host ansible+docker connection) or 'docker-exec' (run ansible inside the container via `docker exec`)")
}

func runChat(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	// Sandbox flags fold into the shared globals so loadConfig picks
	// them up. Chat doesn't honour --dry-run-all (interactive
	// REPL), so we never set SkipSandbox.
	if chatSandbox {
		runSandbox = true
	}
	if chatSandboxImage != "" {
		runSandboxImage = chatSandboxImage
	}
	if chatSandboxHost != "" {
		runSandboxHostname = chatSandboxHost
	}
	if chatSandboxNet != "" {
		runSandboxNetwork = chatSandboxNet
	}
	// runSandboxMode is the shared global set by --sandbox-mode;
	// nothing to copy here (the flag is already registered above).
	res, err := setupRunWithOpts(ctx, app.Options{
		ForceSandbox:        chatSandbox,
		SandboxHostname:     chatSandboxHost,
		SandboxKeep:         chatSandboxKeep,
		SandboxPreferCached: chatSandboxPreferCached,
		SandboxDryRun:       chatSandboxDryRun,
		SandboxMode:         runSandboxMode,
	})
	if err != nil {
		return err
	}
	defer res.Store.Close()

	// Inject chat-session defaults into the system prompt + the
	// run_ansible tool defaults. The system prompt is the visible
	// hint; the tool-level defaults are the deterministic safety
	// net (see internal/tools/defaults.go).
	if chatInventory != "" || chatLimit != "" {
		res.Cfg.SystemPrompt = appendSessionDefaults(res.Cfg.SystemPrompt, chatInventory, chatLimit)
		fmt.Fprintf(os.Stderr, "💬 pilot chat (type 'exit' to quit) — defaults: inventory=%q limit=%q\n",
			chatInventory, chatLimit)
	} else {
		fmt.Fprintln(os.Stderr, "💬 pilot chat (type 'exit' to quit)")
	}

	loop := newAgentLoopWithDefaults(res, res.Cfg.SystemPrompt, os.Stderr, chatInventory, chatLimit)

	run := newRunRecord(res.Cfg, "chat", "", "")
	if err := res.Store.CreateRun(run); err != nil {
		return fmt.Errorf("create run: %w", err)
	}

	// Clean up run status to "aborted" if process is interrupted
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		_ = res.Store.FinishRun(run.ID, "aborted")
		os.Exit(130)
	}()
	defer func() {
		signal.Stop(sigChan)
	}()

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for {
		fmt.Fprint(os.Stderr, "\n> ")
		if !scanner.Scan() {
			break
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if line == "exit" || line == "quit" {
			break
		}
		if err := loop.RunOnce(ctx, line); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
		}
	}

	_ = res.Store.FinishRun(run.ID, "success")
	return nil
}

// appendSessionDefaults appends a "Session defaults" block to the
// existing system prompt. The original prompt is preserved verbatim;
// the appended block is small enough to be invisible in token cost
// (~30 tokens). When neither default is set, the original prompt is
// returned unchanged (no-op).
func appendSessionDefaults(prompt, inventory, limit string) string {
	if inventory == "" && limit == "" {
		return prompt
	}
	var sb strings.Builder
	sb.WriteString(prompt)
	sb.WriteString("\n\n## Session defaults\n")
	if inventory != "" {
		fmt.Fprintf(&sb, "- Default inventory file for run_ansible / apply_patch: %q\n", inventory)
	}
	if limit != "" {
		fmt.Fprintf(&sb, "- Default --limit host pattern for run_ansible / apply_patch: %q\n", limit)
	}
	sb.WriteString("Use these defaults unless the user explicitly specifies a different value in the current turn.\n")
	return sb.String()
}
