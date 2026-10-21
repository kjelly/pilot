package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/kjelly/pilot/internal/ansible"
	"github.com/kjelly/pilot/internal/diagnose"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// sanitizeDiagnosticText preserves command whitespace and masks structured
// secrets before bounding the response, so truncation never exposes half a secret.
func sanitizeDiagnosticText(value string) (safe string, redacted, truncated bool) {
	safe = ansible.RedactSecrets(value)
	redacted = safe != value || strings.Contains(safe, "[REDACTED]")
	if len(safe) > maxDiagnosticResponseBytes {
		const marker = "\n[response truncated by pilot after 65536 bytes]"
		limit := maxDiagnosticResponseBytes - len(marker)
		for limit > 0 && !utf8.RuneStart(safe[limit]) {
			limit--
		}
		safe, truncated = safe[:limit]+marker, true
	}
	return
}

func commandEvidence(r diagnose.AdHocResult) diagnoseStepEvidence {
	ev := diagnoseStepEvidence{RC: r.RC, RCKnown: r.RCKnown, Failed: r.Failed, Unreachable: r.Unreachable, Outcome: "completed"}
	switch {
	case r.RunErr != nil:
		ev.Outcome, ev.Error = "unknown", r.RunErr.Error()
	case r.Unreachable:
		ev.Outcome = "unreachable"
	case diagnosticAuthRequired(r):
		ev.Outcome = "auth_required"
	case !r.RCKnown:
		ev.Outcome, ev.Error = "unknown", "Ansible result did not include a command return code"
	case r.RC != 0:
		ev.Outcome = "command_nonzero"
	case r.Failed:
		ev.Outcome, ev.Error = "unknown", "Ansible reported failure despite a zero command return code"
	}
	ev.OK = ev.Outcome == "completed"
	fields := []*string{&ev.Stdout, &ev.Stderr, &ev.Message, &ev.Error}
	values := []string{r.Stdout, r.Stderr, r.Message, ev.Error}
	for i, field := range fields {
		safe, redacted, truncated := sanitizeDiagnosticText(values[i])
		*field = safe
		ev.Redacted, ev.Truncated = ev.Redacted || redacted, ev.Truncated || truncated
	}
	return ev
}

func diagnosticAuthRequired(r diagnose.AdHocResult) bool {
	if !r.Failed && r.RC == 0 {
		return false
	}
	text := strings.ToLower(r.Stderr + "\n" + r.Message)
	return strings.Contains(text, "did not receive kerberos credentials")
}

// sanitizeDiagnoseOutput is the final MCP boundary for every diagnose tool,
// including synthesized strings, nested reports and third-party query payloads.
func sanitizeDiagnoseOutput[Out any](output Out) (Out, error) {
	data, err := json.Marshal(output)
	if err != nil {
		return output, err
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber() // preserve exact counters and identifiers above 2^53
	if err := decoder.Decode(&value); err != nil {
		return output, err
	}
	redacted, truncated := false, false
	var visit func(any, bool) any
	visit = func(v any, sensitive bool) any {
		switch v := v.(type) {
		case string:
			if sensitive && v != "" {
				redacted = true
				return "[REDACTED]"
			}
			safe, red, trunc := sanitizeDiagnosticText(v)
			redacted, truncated = redacted || red, truncated || trunc || strings.Contains(safe, "[response truncated by pilot after 65536 bytes]")
			return safe
		case []any:
			for i := range v {
				v[i] = visit(v[i], sensitive)
			}
		case map[string]any:
			for key, item := range v {
				if flag, ok := item.(bool); ok {
					if key == "redacted" {
						redacted = redacted || flag
					}
					if key == "truncated" || strings.HasSuffix(key, "_truncated") {
						truncated = truncated || flag
					}
				}
				// Use the existing assignment policy to recognize sensitive keys,
				// preserving context lost when JSON strings are visited alone.
				probe := key + "=pilot-sensitive-key-probe"
				keySensitive := ansible.RedactSecrets(probe) != probe
				v[key] = visit(item, sensitive || keySensitive)
			}
		}
		return v
	}
	value = visit(value, false)
	if obj, ok := value.(map[string]any); ok {
		obj["redacted"], obj["truncated"] = redacted, truncated
	}
	data, err = json.Marshal(value)
	if err != nil {
		return output, err
	}
	err = json.Unmarshal(data, &output)
	return output, err
}

// typedToolError uses the SDK's error branch, which skips serializing Out.
// Returning IsError together with a typed zero Out instead causes SDK v1.7
// to attach an apparently valid, zero-valued structured success payload.
func typedToolError(result *mcp.CallToolResult, diagnostic bool) error {
	var messages []string
	for _, content := range result.Content {
		if text, ok := content.(*mcp.TextContent); ok {
			value := text.Text
			if diagnostic {
				var toolErr mcpToolError
				if json.Unmarshal([]byte(value), &toolErr) == nil {
					safe, err := sanitizeDiagnoseOutput(toolErr)
					if err != nil {
						return err
					}
					data, err := json.Marshal(safe)
					if err != nil {
						return err
					}
					value = string(data)
				} else {
					value, _, _ = sanitizeDiagnosticText(value)
				}
			}
			messages = append(messages, value)
		}
	}
	if len(messages) == 0 {
		return fmt.Errorf("tool execution failed")
	}
	return errors.New(strings.Join(messages, "\n"))
}
