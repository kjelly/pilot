package tools

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Asker is the dependency-injected callback used by AskUserTool to
// route a question to the user (TUI modal, promptui, raw stdin…).
// Returning an empty string is treated as "cancelled".
type Asker func(question string, options []string) string

// AskUserTool prompts the user and returns their answer. The asker
// callback is set at construction so multiple instances in the same
// process do not interfere with each other.
type AskUserTool struct {
	// Asker is the callback used to obtain the user's answer. If nil,
	// the tool falls back to reading from os.Stdin.
	Asker Asker
}

func (t *AskUserTool) Spec() *Spec {
	return &Spec{
		Name:        "ask_user",
		Description: "Ask the user a question and wait for a response. Use this whenever you need clarification before proceeding. Provide a list of options to get a structured answer.",
		RiskLevel:   "none",
		Reversible:  true,
		DryRunSafe:  true,
		Parameters:  askUserArgs,
	}
}

func (t *AskUserTool) Execute(ctx context.Context, args json.RawMessage) (*Result, error) {
	var a struct {
		Question string   `json:"question"`
		Options  []string `json:"options"`
	}
	if err := json.Unmarshal(args, &a); err != nil {
		return nil, fmt.Errorf("ask_user: invalid args: %w", err)
	}
	if a.Question == "" {
		return nil, fmt.Errorf("ask_user: question is required")
	}

	if t.Asker != nil {
		answer := t.Asker(a.Question, a.Options)
		return &Result{Content: "User answered: " + answer}, nil
	}

	return &Result{Content: "User answered: " + readFromStdin(a.Question, a.Options)}, nil
}

// readFromStdin is the terminal fallback used when no Asker is wired.
// It is exported only via the AskUserTool body above.
func readFromStdin(question string, options []string) string {
	var sb strings.Builder
	sb.WriteString("\n")
	sb.WriteString(strings.Repeat("─", 60))
	sb.WriteString("\n")
	sb.WriteString("❓  ")
	sb.WriteString(question)
	sb.WriteString("\n")
	if len(options) > 0 {
		for i, opt := range options {
			fmt.Fprintf(&sb, "   %d) %s\n", i+1, opt)
		}
		fmt.Fprintf(&sb, "\nYour choice (number or free text): ")
	} else {
		sb.WriteString("\nYour answer: ")
	}
	fmt.Print(sb.String())

	reader := bufio.NewReader(os.Stdin)
	answer, err := reader.ReadString('\n')
	if err != nil {
		return ""
	}
	answer = strings.TrimSpace(answer)

	if len(options) > 0 {
		if n := strings.TrimSpace(answer); len(n) == 1 && n[0] >= '1' && n[0] <= '9' {
			idx := int(n[0] - '1')
			if idx < len(options) {
				answer = options[idx]
			}
		}
	}
	return answer
}
