package ansible

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

var (
	fatalLineRE = regexp.MustCompile(`(?m)^\s*(fatal|unreachable): \[([^]]+)\]: (?:FAILED!|UNREACHABLE!) => (.*)$`)
	taskLineRE  = regexp.MustCompile(`(?m)^TASK \[(.*)]\s*\*+$`)
)

// FailureSummary extracts the small, actionable part of Ansible's human
// callback output. It is intentionally best-effort: the complete output is
// still retained in Result.Stdout/Result.Stderr and in the run transcript.
func FailureSummary(output string) string {
	matches := fatalLineRE.FindAllStringSubmatch(output, -1)
	if len(matches) == 0 {
		return ""
	}

	var b strings.Builder
	b.WriteString("\n❌ Ansible 失敗摘要\n")
	for i, match := range matches {
		kind, host, details := match[1], match[2], strings.TrimSpace(match[3])
		fmt.Fprintf(&b, "  %d. host=%s (%s)\n", i+1, host, strings.ToLower(kind))
		if task := taskBefore(output, match[0]); task != "" {
			fmt.Fprintf(&b, "     task=%s\n", task)
		}
		if msg := ansibleMessage(details); msg != "" {
			fmt.Fprintf(&b, "     msg=%s\n", msg)
		} else {
			fmt.Fprintf(&b, "     detail=%s\n", compact(details))
		}
	}
	b.WriteString("  詳細輸出請查看上方內容或 run transcript。\n")
	return b.String()
}

func taskBefore(output, fatal string) string {
	idx := strings.Index(output, fatal)
	if idx < 0 {
		return ""
	}
	all := taskLineRE.FindAllStringSubmatch(output[:idx], -1)
	if len(all) == 0 {
		return ""
	}
	return strings.TrimSpace(all[len(all)-1][1])
}

func ansibleMessage(details string) string {
	start := strings.Index(details, "{")
	if start < 0 {
		return ""
	}
	var payload map[string]any
	if json.Unmarshal([]byte(details[start:]), &payload) != nil {
		return ""
	}
	if msg, ok := payload["msg"].(string); ok {
		return compact(msg)
	}
	if reason, ok := payload["reason"].(string); ok {
		return compact(reason)
	}
	return ""
}

func compact(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	const max = 500
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}
