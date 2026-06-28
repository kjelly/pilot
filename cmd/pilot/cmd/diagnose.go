package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/anomalyco/pilot/internal/ollama"
)

var (
	diagnoseStdin  bool
	diagnoseQuiet  bool
	diagnoseOutput string // "stdout" (default) or "stderr"
)

var diagnoseCmd = &cobra.Command{
	Use:   "diagnose [<log-file>]",
	Short: "Send an Ansible failure log to the LLM for diagnosis",
	Long: `Read a log file (or stdin with --stdin, JSON mode used by the
Ansible callback plugin) and ask the configured Ollama model to diagnose
the failure(s). Useful for offline post-mortem analysis.

The LLM is asked to identify root cause(s) and suggest concrete fixes
(but does NOT make any changes — this is purely an analysis command).

Modes:
  diagnose <log-file>          read text log, output diagnosis
  diagnose --stdin             read JSON from stdin (used by the Ansible
                               callback plugin), output diagnosis to stdout`,
	Args: cobra.MaximumNArgs(1),
	RunE: runDiagnose,
}

func init() {
	diagnoseCmd.Flags().BoolVar(&diagnoseStdin, "stdin", false, "read failure context as JSON from stdin (Ansible callback mode)")
	diagnoseCmd.Flags().BoolVarP(&diagnoseQuiet, "quiet", "q", false, "suppress extra header/output, only print diagnosis")
	diagnoseCmd.Flags().StringVar(&diagnoseOutput, "output", "stdout", "where to write diagnosis: stdout|stderr")
}

func runDiagnose(cmd *cobra.Command, args []string) error {
	if diagnoseStdin {
		return runDiagnoseStdin()
	}
	if len(args) != 1 {
		return fmt.Errorf("usage: pilot diagnose <log-file>  OR  pilot diagnose --stdin")
	}
	return runDiagnoseFile(args[0])
}

func runDiagnoseFile(logPath string) error {
	data, err := os.ReadFile(logPath)
	if err != nil {
		return fmt.Errorf("read log: %w", err)
	}
	logText := string(data)
	if len(logText) > 12000 {
		logText = "...[truncated head]...\n" + logText[len(logText)-12000:]
	}

	cfg := loadConfig()
	ctx := context.Background()
	client := ollama.NewClient(cfg.OllamaURL, cfg.Model)
	if err := client.Ping(ctx); err != nil {
		return fmt.Errorf("ollama not reachable at %s: %w", cfg.OllamaURL, err)
	}

	prompt := buildDiagnosePrompt(logText)
	resp, err := client.Chat(ctx,
		[]ollama.Message{
			{Role: "system", Content: cfg.SystemPrompt},
			{Role: "user", Content: prompt},
		},
		nil,
	)
	if err != nil {
		return err
	}
	out := writerFor(cfg)
	if !diagnoseQuiet {
		fmt.Fprintln(out, "=== pilot diagnosis ===")
	}
	fmt.Fprintln(out, strings.TrimSpace(resp.Message.Content))
	return nil
}

// failureContext is the JSON schema the Ansible callback plugin sends on
// stdin when it invokes `pilot diagnose --stdin`.
type failureContext struct {
	Host     string `json:"host"`
	Kind     string `json:"kind"`
	Task     string `json:"task"`
	Module   string `json:"module"`
	Error    string `json:"error"`
	TaskYAML string `json:"task_yaml"`
	Play     string `json:"play"`
	// Free-form extras (e.g. extra_context from callback config)
	Extra map[string]any `json:"extra_context,omitempty"`
}

func runDiagnoseStdin() error {
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("read stdin: %w", err)
	}
	var ctx failureContext
	if err := json.Unmarshal(data, &ctx); err != nil {
		return fmt.Errorf("invalid JSON on stdin: %w", err)
	}
	if ctx.Error == "" && ctx.Task == "" {
		return fmt.Errorf("stdin JSON must include at least 'task' or 'error'")
	}

	cfg := loadConfig()
	client := ollama.NewClient(cfg.OllamaURL, cfg.Model)
	c, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := client.Ping(c); err != nil {
		return fmt.Errorf("ollama not reachable at %s: %w", cfg.OllamaURL, err)
	}

	prompt := buildStdinPrompt(ctx)
	resp, err := client.Chat(c,
		[]ollama.Message{
			{Role: "system", Content: cfg.SystemPrompt},
			{Role: "user", Content: prompt},
		},
		nil,
	)
	if err != nil {
		return err
	}
	out := writerFor(cfg)
	if !diagnoseQuiet {
		host := ctx.Host
		if host == "" {
			host = "(unknown host)"
		}
		kind := ctx.Kind
		if kind == "" {
			kind = "failed"
		}
		fmt.Fprintf(out, "=== pilot diagnosis for %s (%s) ===\n", host, kind)
	}
	fmt.Fprintln(out, strings.TrimSpace(resp.Message.Content))
	return nil
}

func writerFor(_ any) io.Writer {
	if diagnoseOutput == "stderr" {
		return os.Stderr
	}
	return os.Stdout
}

func buildDiagnosePrompt(logText string) string {
	return fmt.Sprintf(`以下是某次 Ansible 任務失敗的日誌。請仔細分析並回答：

1. 失敗的根本原因是什麼？（不要只看表面錯誤訊息，請找出背後原因）
2. 是否有一個或多個獨立的失敗？
3. 針對每個失敗，建議的修復步驟（具體、可執行的指令或設定）
4. 是否有需要 rollback 的部分？
5. 對應到哪個 CIS Benchmark 編號（如果適用）？

請用結構化方式回答，每個失敗用標題分開。

========== 日誌內容 ==========
%s
===============================`, logText)
}

func buildStdinPrompt(ctx failureContext) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "Ansible 任務失敗，請診斷。\n\n")
	if ctx.Play != "" {
		fmt.Fprintf(&sb, "Play:    %s\n", ctx.Play)
	}
	if ctx.Host != "" {
		fmt.Fprintf(&sb, "Host:    %s\n", ctx.Host)
	}
	if ctx.Task != "" {
		fmt.Fprintf(&sb, "Task:    %s\n", ctx.Task)
	}
	if ctx.Module != "" {
		fmt.Fprintf(&sb, "Module:  %s\n", ctx.Module)
	}
	if ctx.Kind != "" {
		fmt.Fprintf(&sb, "Kind:    %s\n", ctx.Kind)
	}
	if ctx.Error != "" {
		fmt.Fprintf(&sb, "\n錯誤輸出:\n```\n%s\n```\n", ctx.Error)
	}
	if ctx.TaskYAML != "" {
		fmt.Fprintf(&sb, "\n任務定義:\n```yaml\n%s\n```\n", ctx.TaskYAML)
	}
	sb.WriteString(`
請回答：
1. 失敗的根本原因（簡短、明確）
2. 建議的修復步驟（具體指令）
3. 是否需要 rollback
4. 對應的 CIS Benchmark 編號（如果適用）
`)
	return sb.String()
}

