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

// maxLoopItemsShown caps how many failed loop items get their own line in a
// summary, so one giant loop task can't drown out the rest of the failures.
const maxLoopItemsShown = 5

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
		kind, hostField, details := match[1], match[2], strings.TrimSpace(match[3])
		fmt.Fprintf(&b, "  %d. host=%s (%s)\n", i+1, displayHost(hostField), strings.ToLower(kind))
		if task := taskBefore(output, match[0]); task != "" {
			fmt.Fprintf(&b, "     task=%s\n", task)
		}
		writeFailureDetail(&b, details)
	}
	b.WriteString("  詳細輸出請查看上方內容或 run transcript。\n")
	return b.String()
}

// displayHost cleans up Ansible's "[host -> delegate]" bracket for a failed
// loop task whose delegate_to (commonly "{{ item }}") never resolved, since
// printing the raw, unrendered template is more confusing than helpful. A
// delegate that did resolve to a real host is left in place.
func displayHost(hostField string) string {
	host, delegate := hostField, ""
	if idx := strings.Index(hostField, " -> "); idx >= 0 {
		host, delegate = hostField[:idx], strings.TrimSpace(hostField[idx+len(" -> "):])
	}
	if delegate == "" || strings.Contains(delegate, "{{") {
		return host
	}
	return host + " -> " + delegate
}

// writeFailureDetail writes the msg/item lines for one fatal/unreachable
// match. Loop tasks (`loop:`/`with_items:`) fail with a single aggregate
// line whose top-level msg is Ansible's generic "All items completed", even
// though the real error is per-item, nested under payload["results"]. When
// present, those per-item errors are surfaced instead of the generic one.
func writeFailureDetail(b *strings.Builder, details string) {
	payload := parsePayload(details)
	if items := failedLoopItems(payload); len(items) > 0 {
		shown := items
		var truncated int
		if len(shown) > maxLoopItemsShown {
			truncated = len(shown) - maxLoopItemsShown
			shown = shown[:maxLoopItemsShown]
		}
		for _, it := range shown {
			if it.item != "" {
				fmt.Fprintf(b, "     item=%s\n", it.item)
			}
			if it.msg != "" {
				fmt.Fprintf(b, "     msg=%s\n", it.msg)
			}
		}
		if truncated > 0 {
			fmt.Fprintf(b, "     …還有 %d 個項目失敗（略）\n", truncated)
		}
		return
	}

	if item := itemLabel(payload); item != "" {
		fmt.Fprintf(b, "     item=%s\n", item)
	}
	if msg := payloadMessage(payload); msg != "" {
		fmt.Fprintf(b, "     msg=%s\n", msg)
		return
	}
	fmt.Fprintf(b, "     detail=%s\n", compact(details))
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

func parsePayload(details string) map[string]any {
	start := strings.Index(details, "{")
	if start < 0 {
		return nil
	}
	var payload map[string]any
	if json.Unmarshal([]byte(details[start:]), &payload) != nil {
		return nil
	}
	return payload
}

func payloadMessage(payload map[string]any) string {
	if msg, ok := payload["msg"].(string); ok {
		return compact(msg)
	}
	if reason, ok := payload["reason"].(string); ok {
		return compact(reason)
	}
	return ""
}

// itemLabel returns the loop item a single (non-aggregate) result failed
// on, if any.
func itemLabel(payload map[string]any) string {
	if item, ok := payload["item"]; ok {
		return compact(itemString(item))
	}
	if label, ok := payload["_ansible_item_label"]; ok {
		return compact(itemString(label))
	}
	return ""
}

func itemString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	if b, err := json.Marshal(v); err == nil {
		return string(b)
	}
	return fmt.Sprintf("%v", v)
}

type loopItemFailure struct {
	item string
	msg  string
}

// failedLoopItems drills into a failed loop task's payload["results"] to
// find the actual per-item errors that Ansible's own aggregate msg (e.g.
// "All items completed") hides.
func failedLoopItems(payload map[string]any) []loopItemFailure {
	results, ok := payload["results"].([]any)
	if !ok {
		return nil
	}
	var out []loopItemFailure
	for _, r := range results {
		rm, ok := r.(map[string]any)
		if !ok {
			continue
		}
		failed, _ := rm["failed"].(bool)
		unreachable, _ := rm["unreachable"].(bool)
		if !failed && !unreachable {
			continue
		}
		msg := payloadMessage(rm)
		if msg == "" {
			msg = compact(detailFallback(rm))
		}
		out = append(out, loopItemFailure{item: itemLabel(rm), msg: msg})
	}
	return out
}

// detailFallback renders a per-item result with no msg/reason field (e.g. a
// bare failed_when) as compact JSON so the item's failure isn't silently
// dropped.
func detailFallback(rm map[string]any) string {
	b, err := json.Marshal(rm)
	if err != nil {
		return ""
	}
	return string(b)
}

func compact(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	const max = 500
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}
